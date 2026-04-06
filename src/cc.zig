//! Congestion controller shim that wires `c4.State`/`c4.CcContext` and a
//! `pacer.Pacer` together with minimal transport bookkeeping.
//!
//! The transport calls into this module with four events (onPacketSent,
//! onAck, onLoss, canSend) and a set of ambient measurements. In return it
//! gets a CWND + pacer that tracks how fast it should be sending.
//!
//! Sent packets are tracked in a 256-slot ring keyed by byte-offset range.
//! That's enough for the server->client output channel: at MTU-sized
//! packets this covers ~280 KiB in flight, well above any CWND C4 is
//! likely to compute for a terminal session.
//!
//! The ring is indexed by `(write_counter % ring_slots)`. Lookups by byte
//! offset are linear scans bounded by `ring_slots`.

const std = @import("std");
const c4 = @import("c4.zig");
const pacer_mod = @import("pacer.zig");

pub const ring_slots: usize = 256;

const SentInfo = struct {
    offset_start: u64 = 0,
    length: u32 = 0,
    send_time_us: u64 = 0,
    /// `total_delivered_bytes` snapshot at the moment this packet was sent.
    /// On ack, `delivered_now - delivered_at_send` is the bytes delivered
    /// over this packet's flight (mirrors picoquic's delivered_prior).
    total_delivered_bytes_at_send_time: u64 = 0,
    /// in_use == false means the slot is empty.
    in_use: bool = false,
};

/// Sliding window over recent rate samples for peak-bandwidth tracking.
const rate_window_len: usize = 8;

pub const CongestionController = struct {
    state: c4.State,
    ctx: c4.CcContext,
    pacer: pacer_mod.Pacer,

    ring: [ring_slots]SentInfo = [_]SentInfo{.{}} ** ring_slots,
    ring_write: usize = 0,
    /// Highest offset_start+length we've ever recorded — used as the
    /// "next sequence number" for C4's era logic.
    next_offset: u64 = 0,
    total_delivered_bytes: u64 = 0,
    /// Ring of recent delivery-rate samples (bytes/sec). Used as a windowed
    /// max for `peak_bandwidth_estimate_bps`.
    rate_samples: [rate_window_len]u64 = [_]u64{0} ** rate_window_len,
    rate_samples_head: usize = 0,

    pub fn init(self: *CongestionController, mtu: u32, now_us: u64) void {
        self.* = .{
            .state = c4.State.init(),
            .pacer = pacer_mod.Pacer.init(),
            .ctx = .{
                .send_mtu = mtu,
                .smoothed_rtt_us = 0,
                .rtt_sample_us = 0,
                .rtt_variant_us = 0,
                .bandwidth_estimate_bps = 0,
                .peak_bandwidth_estimate_bps = 0,
                .bytes_in_transit = 0,
                .last_time_acked_data_frame_sent_us = 0,
                .last_sender_limited_time_us = 0,
                .cwnd = 10 * @as(u64, mtu),
                .is_ssthresh_initialized = false,
                .lowest_not_ack_fn = lowestNotAck,
                .next_sequence_number_fn = nextSequenceNumber,
                .update_pacing_rate_fn = updatePacingRate,
                .transport_ctx = self,
                .is_ready = true,
            },
        };
        c4.reset(&self.state, &self.ctx, now_us);
    }

    // -- C4 hooks ----------------------------------------------------------

    fn lowestNotAck(opaque_ctx: *anyopaque) u64 {
        const self: *CongestionController = @ptrCast(@alignCast(opaque_ctx));
        var lowest: ?u64 = null;
        for (self.ring) |slot| {
            if (!slot.in_use) continue;
            if (lowest == null or slot.offset_start < lowest.?) lowest = slot.offset_start;
        }
        return if (lowest) |l| l else self.next_offset;
    }

    fn nextSequenceNumber(opaque_ctx: *anyopaque) u64 {
        const self: *CongestionController = @ptrCast(@alignCast(opaque_ctx));
        return self.next_offset;
    }

    fn updatePacingRate(opaque_ctx: *anyopaque, rate_bps: u64, quantum: u64) void {
        const self: *CongestionController = @ptrCast(@alignCast(opaque_ctx));
        // We don't have a wall clock here; use the last timestamp the pacer
        // saw. The transport drives refills on canSend/onSent anyway.
        self.pacer.updateRate(rate_bps, quantum, self.pacer.last_update_us);
    }

    // -- Transport-facing API ---------------------------------------------

    pub fn onPacketSent(
        self: *CongestionController,
        offset_start: u64,
        length: u32,
        now_us: u64,
    ) void {
        const idx = self.ring_write % ring_slots;
        self.ring_write += 1;
        const slot = &self.ring[idx];
        // If the slot is still occupied with a stale entry, evict it — that
        // means it was never acked and is older than our ring depth.
        if (slot.in_use) {
            if (self.ctx.bytes_in_transit >= slot.length) {
                self.ctx.bytes_in_transit -= slot.length;
            } else {
                self.ctx.bytes_in_transit = 0;
            }
        }
        slot.* = .{
            .offset_start = offset_start,
            .length = length,
            .send_time_us = now_us,
            .total_delivered_bytes_at_send_time = self.total_delivered_bytes,
            .in_use = true,
        };
        self.ctx.bytes_in_transit += length;
        const end = offset_start + length;
        if (end > self.next_offset) self.next_offset = end;
        self.pacer.onSent(length);
    }

    fn findSlot(self: *CongestionController, offset_start: u64) ?*SentInfo {
        for (&self.ring) |*slot| {
            if (!slot.in_use) continue;
            if (slot.offset_start == offset_start) return slot;
        }
        return null;
    }

    pub fn onAck(
        self: *CongestionController,
        offset_start: u64,
        length: u32,
        rtt_us: u64,
        now_us: u64,
    ) void {
        _ = length;
        const slot = self.findSlot(offset_start) orelse return;

        const size = slot.length;
        const send_time = slot.send_time_us;
        const delivered_at_send = slot.total_delivered_bytes_at_send_time;
        slot.in_use = false;

        if (self.ctx.bytes_in_transit >= size) {
            self.ctx.bytes_in_transit -= size;
        } else {
            self.ctx.bytes_in_transit = 0;
        }
        self.total_delivered_bytes += size;
        self.ctx.last_time_acked_data_frame_sent_us = send_time;

        // Delivery-rate estimation: how many bytes were delivered between
        // send-time and ack-time of this packet, divided by elapsed time.
        const delivered_delta = self.total_delivered_bytes - delivered_at_send;
        const elapsed_us_raw: u64 = if (now_us > send_time) now_us - send_time else 0;
        const elapsed_us: u64 = if (elapsed_us_raw == 0) 1 else elapsed_us_raw;
        const rate_sample_bps: u64 = (delivered_delta *% 1_000_000) / elapsed_us;

        // EWMA smoothing of bandwidth_estimate_bps with alpha=1/4 on
        // increasing samples; immediate-track on decreases is omitted (we
        // want a slow-to-shrink BW estimate, like picoquic's max filter).
        if (self.ctx.bandwidth_estimate_bps == 0) {
            self.ctx.bandwidth_estimate_bps = rate_sample_bps;
        } else if (rate_sample_bps > self.ctx.bandwidth_estimate_bps) {
            self.ctx.bandwidth_estimate_bps =
                (3 * self.ctx.bandwidth_estimate_bps + rate_sample_bps) / 4;
        } else {
            self.ctx.bandwidth_estimate_bps =
                (7 * self.ctx.bandwidth_estimate_bps + rate_sample_bps) / 8;
        }

        // Windowed max for peak.
        self.rate_samples[self.rate_samples_head] = rate_sample_bps;
        self.rate_samples_head = (self.rate_samples_head + 1) % rate_window_len;
        var peak: u64 = 0;
        for (self.rate_samples) |s| {
            if (s > peak) peak = s;
        }
        self.ctx.peak_bandwidth_estimate_bps = peak;

        if (rtt_us > 0) {
            self.ctx.rtt_sample_us = rtt_us;
            if (self.ctx.smoothed_rtt_us == 0) {
                self.ctx.smoothed_rtt_us = rtt_us;
            } else {
                // Simple RFC6298-ish smoothing, alpha=1/8.
                self.ctx.smoothed_rtt_us =
                    (self.ctx.smoothed_rtt_us * 7 + rtt_us) / 8;
            }
        }

        const ack_state = c4.AckState{
            .rtt_measurement_us = rtt_us,
            .nb_bytes_acknowledged = size,
            .nb_bytes_delivered_since_packet_sent = delivered_delta,
        };
        c4.notifyAck(&self.state, &self.ctx, ack_state, now_us);
        if (rtt_us > 0) c4.notifyRtt(&self.state, &self.ctx, rtt_us, now_us);
    }

    pub fn onLoss(
        self: *CongestionController,
        offset_start: u64,
        length: u32,
        now_us: u64,
    ) void {
        _ = length;
        if (self.findSlot(offset_start)) |slot| {
            if (self.ctx.bytes_in_transit >= slot.length) {
                self.ctx.bytes_in_transit -= slot.length;
            } else {
                self.ctx.bytes_in_transit = 0;
            }
            slot.in_use = false;
        }
        c4.notifyLoss(&self.state, &self.ctx, offset_start, now_us);
    }

    pub fn canSend(self: *CongestionController, nbytes: u64, now_us: u64) bool {
        if (self.ctx.bytes_in_transit + nbytes > self.ctx.cwnd) return false;
        return self.pacer.canSend(nbytes, now_us);
    }

    /// Returns the send timestamp (microseconds) of the in-flight slot whose
    /// byte range contains `offset`, or null if no such slot exists.
    pub fn sendTimeFor(self: *const CongestionController, offset: u64) ?u64 {
        for (&self.ring) |*slot| {
            if (!slot.in_use) continue;
            const end = slot.offset_start + slot.length;
            if (offset >= slot.offset_start and offset < end) return slot.send_time_us;
        }
        return null;
    }

    pub fn nextSendTimeUs(self: *CongestionController, nbytes: u64, now_us: u64) u64 {
        // CWND-blocked: no local time-based fix, caller should wait for acks.
        if (self.ctx.bytes_in_transit + nbytes > self.ctx.cwnd) {
            return now_us + 1000; // poll again in 1ms
        }
        return self.pacer.nextSendTimeUs(nbytes, now_us);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "cc initializes with sane defaults" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    try std.testing.expect(cc.ctx.cwnd >= 10 * 1200);
    try std.testing.expect(cc.canSend(1200, 0));
}

test "cc send then ack clears bytes_in_transit" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    cc.onPacketSent(0, 1200, 1000);
    cc.onPacketSent(1200, 1200, 2000);
    try std.testing.expectEqual(@as(u64, 2400), cc.ctx.bytes_in_transit);
    cc.onAck(0, 1200, 30_000, 31_000);
    try std.testing.expectEqual(@as(u64, 1200), cc.ctx.bytes_in_transit);
    cc.onAck(1200, 1200, 30_000, 32_000);
    try std.testing.expectEqual(@as(u64, 0), cc.ctx.bytes_in_transit);
}

test "cc canSend blocks when bytes_in_transit exceeds cwnd" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    cc.ctx.cwnd = 2400;
    cc.onPacketSent(0, 1200, 1000);
    cc.onPacketSent(1200, 1200, 1000);
    try std.testing.expect(!cc.canSend(1200, 1000));
    cc.onAck(0, 1200, 20_000, 21_000);
    try std.testing.expect(cc.canSend(1200, 21_000));
}

test "cc bandwidth_estimate_bps becomes nonzero after a send→ack cycle" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    cc.onPacketSent(0, 1200, 0);
    cc.onAck(0, 1200, 10_000, 10_000);
    try std.testing.expect(cc.ctx.bandwidth_estimate_bps > 0);
    try std.testing.expect(cc.ctx.peak_bandwidth_estimate_bps > 0);
}

test "cc peak_bandwidth_estimate_bps tracks the highest sample" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    cc.onPacketSent(0, 1200, 0);
    cc.onAck(0, 1200, 100_000, 100_000);
    const peak_low = cc.ctx.peak_bandwidth_estimate_bps;

    cc.onPacketSent(1200, 1200, 100_000);
    cc.onAck(1200, 1200, 1_000, 101_000);
    try std.testing.expect(cc.ctx.peak_bandwidth_estimate_bps > peak_low);
    try std.testing.expect(cc.ctx.peak_bandwidth_estimate_bps >= 1_000_000);
}

test "cc delivered-delta uses slot snapshot, not running total" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    cc.onPacketSent(0, 1200, 0);
    cc.onPacketSent(1200, 1200, 0);
    cc.onPacketSent(2400, 1200, 0);
    cc.onAck(0, 1200, 5_000, 5_000);
    try std.testing.expectEqual(@as(u64, 1200), cc.total_delivered_bytes);
    cc.onPacketSent(3600, 1200, 5_000);
    cc.onAck(3600, 1200, 5_000, 10_000);
    try std.testing.expectEqual(@as(u64, 2400), cc.total_delivered_bytes);
}

test "cc loss notification frees bytes_in_transit" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    cc.onPacketSent(0, 1200, 1000);
    cc.onLoss(0, 1200, 2000);
    try std.testing.expectEqual(@as(u64, 0), cc.ctx.bytes_in_transit);
}

test "cc sendTimeFor finds slot containing offset" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    cc.onPacketSent(1000, 500, 12345);
    try std.testing.expectEqual(@as(u64, 12345), cc.sendTimeFor(1000).?);
    try std.testing.expectEqual(@as(u64, 12345), cc.sendTimeFor(1499).?);
    try std.testing.expect(cc.sendTimeFor(1500) == null);
    try std.testing.expect(cc.sendTimeFor(999) == null);
}
