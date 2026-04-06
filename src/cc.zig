//! Congestion controller shim that wires `c4.State`/`c4.CcContext` and a
//! `pacer.Pacer` together with minimal transport bookkeeping.
//!
//! The transport calls into this module with four events (onPacketSent,
//! onAck, onLoss, canSend) and a set of ambient measurements. In return it
//! gets a CWND + pacer that tracks how fast it should be sending.
//!
//! Sent packets are tracked in a 2048-slot ring keyed by byte-offset range.
//! That's enough for any realistic BDP on the paths zmosh actually runs
//! over: at MTU-sized packets (1100 B) the ring holds ~2.2 MiB of
//! in-flight bytes. Sizing worked from bandwidth × RTT:
//!
//!   Gigabit LAN (120 MB/s × 1 ms)    = 120 KB  ≈ 109 packets
//!   100 Mbps home (12 MB/s × 50 ms)  = 600 KB  ≈ 545 packets
//!   Coast-to-coast (10 MB/s × 100ms) = 1 MB    ≈ 909 packets
//!   International (5 MB/s × 150 ms)  = 750 KB  ≈ 682 packets
//!
//! At 256 slots (the original sizing) any WAN burst would silently overflow
//! and evict live slots — C4 would lose feedback for the oldest in-flight
//! packets, biasing delivery-rate estimation and never seeing RTT samples
//! for them. 2048 covers everything short of satellite-class links and
//! matches the server-side retransmit ring sizing in serve.zig.
//!
//! The ring is indexed by `(write_counter % ring_slots)`. Because
//! `ring_write` is monotonic and each `onPacketSent` records an offset
//! strictly higher than the previous, insertion order == offset order.
//! Walking the ring in insertion order yields a sorted stream over in-use
//! slots (modulo wrap). `ackRange` exploits this: one linear pass retires
//! every slot fully inside an ack range, instead of calling `findSlot`
//! (O(ring_slots)) once per retired slot.
//!
//! Memory: ~50 bytes per SentInfo × 2048 ≈ 100 KB per session. Trivial.
//!
//! ### findSlot's exact-match invariant
//!
//! `findSlot` uses `slot.offset_start == target` (not range overlap). This
//! assumes every ack coming back references an offset that some slot
//! was originally recorded with — i.e. retransmits always reuse the same
//! `offset_start` and `length` as the original. serve.zig enforces this
//! by re-sending from the stored retransmit-ring payload verbatim.
//!
//! If we ever add "retransmit coalescing" (combining multiple lost
//! chunks into one bigger retransmit) or "retransmit splitting" (PMTU
//! drop forces smaller chunks), the invariant breaks and `findSlot` will
//! silently drop acks. At that point switch to range-overlap matching
//! using the `length` parameter (which is already plumbed through the
//! API for this future change). See TODO in `findSlot`.

const std = @import("std");
const c4 = @import("c4.zig");
const pacer_mod = @import("pacer.zig");

pub const ring_slots: usize = 2048;

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

    /// Find a slot by exact offset_start. O(ring_slots) linear scan.
    ///
    /// Exact-match invariant: callers must pass an `offset_start` that was
    /// used verbatim in a previous `onPacketSent` call — i.e. retransmits
    /// must preserve the original offset AND length. See module docstring
    /// for the implications if this ever needs to change.
    fn findSlot(self: *CongestionController, offset_start: u64) ?*SentInfo {
        for (&self.ring) |*slot| {
            if (!slot.in_use) continue;
            if (slot.offset_start == offset_start) return slot;
        }
        return null;
    }

    /// Process the feedback for one acked slot. Updates bytes_in_transit,
    /// delivery-rate estimates, RTT smoothing, and notifies C4. The caller
    /// owns finding the slot and marking it not-in-use.
    fn processSlotAck(self: *CongestionController, slot: *SentInfo, rtt_us: u64, now_us: u64) void {
        const size = slot.length;
        const send_time = slot.send_time_us;
        const delivered_at_send = slot.total_delivered_bytes_at_send_time;

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

    /// Single-offset ack path, used for the gap entries of a SACK (where
    /// each gap targets a specific chunk). For the contiguous prefix of a
    /// SACK, prefer `ackRange` — it's a single linear scan over the ring
    /// rather than one scan per retired slot.
    pub fn onAck(
        self: *CongestionController,
        offset_start: u64,
        length: u32,
        rtt_us: u64,
        now_us: u64,
    ) void {
        _ = length;
        const slot = self.findSlot(offset_start) orelse return;
        slot.in_use = false;
        self.processSlotAck(slot, rtt_us, now_us);
    }

    /// Bulk ack: retire every in-use slot whose byte range lies entirely
    /// within `[lo, hi)`. Walks the ring once; cost is O(ring_slots),
    /// independent of how many slots are retired.
    ///
    /// This is the picoquic-style "walk adjacent entries after finding the
    /// range" optimization, adapted to a fixed ring: because insertion
    /// order matches offset order, every slot in the target range is
    /// already "adjacent" in the ring and we don't need a findSlot-per-
    /// retirement loop.
    ///
    /// Each retired slot gets its own per-packet RTT derived from
    /// `now_us - slot.send_time_us`, so RTT fidelity matches the old
    /// single-ack path.
    pub fn ackRange(self: *CongestionController, lo: u64, hi: u64, now_us: u64) void {
        if (hi <= lo) return;
        for (&self.ring) |*slot| {
            if (!slot.in_use) continue;
            const end = slot.offset_start + slot.length;
            // Slot must lie entirely within [lo, hi).
            if (slot.offset_start < lo) continue;
            if (end > hi) continue;
            slot.in_use = false;
            const rtt_us: u64 = if (now_us > slot.send_time_us)
                now_us - slot.send_time_us
            else
                1;
            self.processSlotAck(slot, rtt_us, now_us);
        }
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

test "cc ackRange retires all slots in one walk" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    cc.onPacketSent(0, 1200, 1000);
    cc.onPacketSent(1200, 1200, 1100);
    cc.onPacketSent(2400, 1200, 1200);
    cc.onPacketSent(3600, 1200, 1300);
    try std.testing.expectEqual(@as(u64, 4800), cc.ctx.bytes_in_transit);

    // Ack everything below 3600 in one bulk call.
    cc.ackRange(0, 3600, 5000);
    try std.testing.expectEqual(@as(u64, 1200), cc.ctx.bytes_in_transit);
    try std.testing.expectEqual(@as(u64, 3600), cc.total_delivered_bytes);
    // The last slot (offset 3600, end 4800 > 3600) is untouched.
    try std.testing.expectEqual(@as(u64, 1300), cc.sendTimeFor(3600).?);
}

test "cc ackRange respects hi boundary (partial-overlap slot untouched)" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    cc.onPacketSent(0, 1200, 1000);
    cc.onPacketSent(1200, 1200, 1100);

    // Ack [0, 1500): slot 0 fits (end=1200), slot 1 does not (end=2400).
    cc.ackRange(0, 1500, 5000);
    try std.testing.expectEqual(@as(u64, 1200), cc.ctx.bytes_in_transit);
    try std.testing.expect(cc.sendTimeFor(1200) != null);
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
