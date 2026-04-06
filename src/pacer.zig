//! Token-bucket pacer, in the style of picoquic's `cc_common.c` pacing helpers
//! (`picoquic_update_pacing_rate`, `picoquic_update_pacing_parameters`,
//! `picoquic_is_sending_authorized_by_pacing`).
//!
//! The pacer holds a bucket of bytes that grows over time at `rate_bps` and is
//! capped at `burst_quantum_bytes`. Callers ask `canSend(n, now)` before
//! sending; on success they must call `onSent(n)` to deduct the bytes.
//! `nextSendTimeUs(n, now)` tells the caller how long to wait until `n` bytes
//! will be available, which is useful for setting a poll timeout.
//!
//! Time is monotonic microseconds (u64). Rates are bytes/sec.

const std = @import("std");

pub const Pacer = struct {
    rate_bps: u64 = 0,
    burst_quantum_bytes: u64 = 0,
    bucket_bytes: u64 = 0,
    last_update_us: u64 = 0,

    pub fn init() Pacer {
        return .{};
    }

    /// Called from C4's `update_pacing_rate_fn` hook. Refills with the current
    /// rate up to `now_us`, then switches to the new rate. The bucket size is
    /// clamped to the new quantum, but the existing credit is preserved (like
    /// picoquic's behaviour: we don't zero the bucket on a rate change).
    pub fn updateRate(self: *Pacer, rate_bps: u64, quantum_bytes: u64, now_us: u64) void {
        if (self.rate_bps != 0) self.refill(now_us);
        self.rate_bps = rate_bps;
        self.burst_quantum_bytes = quantum_bytes;
        if (self.bucket_bytes > quantum_bytes) self.bucket_bytes = quantum_bytes;
        // On first rate install, seed bucket with one full quantum so the
        // sender may burst immediately.
        if (self.last_update_us == 0) {
            self.bucket_bytes = quantum_bytes;
        }
        self.last_update_us = now_us;
    }

    /// Grow the bucket based on time elapsed since `last_update_us`.
    pub fn refill(self: *Pacer, now_us: u64) void {
        if (self.rate_bps == 0 or self.burst_quantum_bytes == 0) {
            self.last_update_us = now_us;
            return;
        }
        if (now_us <= self.last_update_us) return;
        const dt_us = now_us - self.last_update_us;
        // bytes = rate_bps * dt_us / 1_000_000, done carefully to avoid
        // overflow at high rates (rate_bps up to ~40Gbps, dt up to seconds).
        const added: u64 = mulDivSat(self.rate_bps, dt_us, 1_000_000);
        const new_bucket = saturating_add(self.bucket_bytes, added);
        self.bucket_bytes = @min(new_bucket, self.burst_quantum_bytes);
        self.last_update_us = now_us;
    }

    /// Is there enough credit to send `nbytes` right now?
    pub fn canSend(self: *Pacer, nbytes: u64, now_us: u64) bool {
        self.refill(now_us);
        if (self.rate_bps == 0) return true; // pacer inactive, don't block
        // Allow a short packet to always fit if the bucket already holds at
        // least one MTU's worth; otherwise require bucket >= nbytes. We keep
        // the simple rule: bucket >= nbytes.
        return self.bucket_bytes >= nbytes;
    }

    /// Deduct bytes from the bucket after a successful send.
    pub fn onSent(self: *Pacer, nbytes: u64) void {
        if (self.bucket_bytes >= nbytes) {
            self.bucket_bytes -= nbytes;
        } else {
            self.bucket_bytes = 0;
        }
    }

    /// Returns the absolute time (microseconds) at which `nbytes` will next
    /// be sendable. If already sendable, returns `now_us`.
    pub fn nextSendTimeUs(self: *Pacer, nbytes: u64, now_us: u64) u64 {
        self.refill(now_us);
        if (self.rate_bps == 0) return now_us;
        if (self.bucket_bytes >= nbytes) return now_us;
        const need = nbytes - self.bucket_bytes;
        // wait_us = need * 1_000_000 / rate_bps, round up.
        const wait_us = (need * 1_000_000 + self.rate_bps - 1) / self.rate_bps;
        return now_us + wait_us;
    }
};

fn saturating_add(a: u64, b: u64) u64 {
    const r = a +% b;
    if (r < a) return std.math.maxInt(u64);
    return r;
}

/// Compute `a * b / c` without overflowing when `a * b` fits in u128.
fn mulDivSat(a: u64, b: u64, c: u64) u64 {
    if (c == 0) return std.math.maxInt(u64);
    const prod: u128 = @as(u128, a) * @as(u128, b);
    const q: u128 = prod / @as(u128, c);
    if (q > std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(q);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "pacer inactive when no rate set" {
    var p = Pacer.init();
    try std.testing.expect(p.canSend(1500, 0));
    try std.testing.expectEqual(@as(u64, 100), p.nextSendTimeUs(1500, 100));
}

test "pacer initial burst" {
    var p = Pacer.init();
    // 1 MB/s, 16 KiB quantum
    p.updateRate(1_000_000, 16 * 1024, 1000);
    try std.testing.expectEqual(@as(u64, 16 * 1024), p.bucket_bytes);
    try std.testing.expect(p.canSend(1500, 1000));
    p.onSent(1500);
    try std.testing.expectEqual(@as(u64, 16 * 1024 - 1500), p.bucket_bytes);
}

test "pacer refill math" {
    var p = Pacer.init();
    p.updateRate(1_000_000, 16 * 1024, 1000); // 1 MB/s -> 1 byte/us
    p.onSent(16 * 1024);
    try std.testing.expectEqual(@as(u64, 0), p.bucket_bytes);
    // 2000us later -> 2000 bytes
    p.refill(3000);
    try std.testing.expectEqual(@as(u64, 2000), p.bucket_bytes);
    try std.testing.expect(p.canSend(1500, 3000));
    try std.testing.expect(!p.canSend(5000, 3000));
}

test "pacer burst cap" {
    var p = Pacer.init();
    p.updateRate(1_000_000, 4096, 1000);
    p.onSent(4096);
    // 1 second later refill caps at quantum
    p.refill(1_001_000);
    try std.testing.expectEqual(@as(u64, 4096), p.bucket_bytes);
}

test "pacer next send time" {
    var p = Pacer.init();
    p.updateRate(1_000_000, 4096, 1000); // 1 byte/us
    p.onSent(4096);
    // Immediately at t=1000, bucket empty. Need 1500 bytes -> 1500us wait.
    const next = p.nextSendTimeUs(1500, 1000);
    try std.testing.expectEqual(@as(u64, 2500), next);
    // Already sendable returns now.
    p.refill(3000);
    const next2 = p.nextSendTimeUs(1000, 3000);
    try std.testing.expectEqual(@as(u64, 3000), next2);
}

test "pacer rate update mid-flight preserves credit" {
    var p = Pacer.init();
    p.updateRate(1_000_000, 16 * 1024, 1000);
    p.onSent(10_000);
    try std.testing.expectEqual(@as(u64, 16 * 1024 - 10_000), p.bucket_bytes);
    // Raise rate; existing credit should remain clamped to new quantum.
    p.updateRate(2_000_000, 32 * 1024, 2000);
    // Added ~2000 bytes in the 1000us elapsed at old rate.
    try std.testing.expect(p.bucket_bytes >= 16 * 1024 - 10_000);
    try std.testing.expect(p.bucket_bytes <= 32 * 1024);
}

test "pacer onSent underflow guard" {
    var p = Pacer.init();
    p.updateRate(1_000_000, 4096, 1000);
    p.onSent(1_000_000);
    try std.testing.expectEqual(@as(u64, 0), p.bucket_bytes);
}
