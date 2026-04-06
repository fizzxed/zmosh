//! Congestion controller shim that wires `c4.State`/`c4.CcContext` and a
//! `pacer.Pacer` together with minimal transport bookkeeping.
//!
//! The transport calls into this module with four events (onPacketSent,
//! onAck, onLoss, canSend) and a set of ambient measurements. In return it
//! gets a CWND + pacer that tracks how fast it should be sending.
//!
//! Sent packets are tracked in a 256-slot ring indexed by `seq mod 256`.
//! That's enough for the server->client output channel: at MTU-sized
//! packets this covers ~280 KiB in flight, well above any CWND C4 is
//! likely to compute for a terminal session.

const std = @import("std");
const c4 = @import("c4.zig");
const pacer_mod = @import("pacer.zig");

pub const ring_slots: usize = 256;

const SentInfo = struct {
    seq: u32 = 0,
    size: u32 = 0,
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
    next_seq: u32 = 1,
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
        var lowest: ?u32 = null;
        for (self.ring) |slot| {
            if (!slot.in_use) continue;
            if (lowest == null or slot.seq < lowest.?) lowest = slot.seq;
        }
        return if (lowest) |l| @as(u64, l) else @as(u64, self.next_seq);
    }

    fn nextSequenceNumber(opaque_ctx: *anyopaque) u64 {
        const self: *CongestionController = @ptrCast(@alignCast(opaque_ctx));
        return self.next_seq;
    }

    fn updatePacingRate(opaque_ctx: *anyopaque, rate_bps: u64, quantum: u64) void {
        const self: *CongestionController = @ptrCast(@alignCast(opaque_ctx));
        // We don't have a wall clock here; use the last timestamp the pacer
        // saw. The transport drives refills on canSend/onSent anyway.
        self.pacer.updateRate(rate_bps, quantum, self.pacer.last_update_us);
    }

    // -- Transport-facing API ---------------------------------------------

    pub fn onPacketSent(self: *CongestionController, seq: u32, size: u32, now_us: u64) void {
        const slot = &self.ring[seq % ring_slots];
        // If the slot is still occupied with a stale entry, evict it — that
        // means it was never acked and is older than our ring depth.
        if (slot.in_use) {
            // Treat as lost for bookkeeping purposes.
            if (self.ctx.bytes_in_transit >= slot.size) {
                self.ctx.bytes_in_transit -= slot.size;
            } else {
                self.ctx.bytes_in_transit = 0;
            }
        }
        slot.* = .{
            .seq = seq,
            .size = size,
            .send_time_us = now_us,
            .total_delivered_bytes_at_send_time = self.total_delivered_bytes,
            .in_use = true,
        };
        self.ctx.bytes_in_transit += size;
        if (seq >= self.next_seq) self.next_seq = seq + 1;
        self.pacer.onSent(size);
    }

    pub fn onAck(
        self: *CongestionController,
        acked_seq: u32,
        rtt_us: u64,
        now_us: u64,
    ) void {
        const slot = &self.ring[acked_seq % ring_slots];
        if (!slot.in_use or slot.seq != acked_seq) return;

        const size = slot.size;
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

    pub fn onLoss(self: *CongestionController, lost_seq: u32, now_us: u64) void {
        const slot = &self.ring[lost_seq % ring_slots];
        if (slot.in_use and slot.seq == lost_seq) {
            if (self.ctx.bytes_in_transit >= slot.size) {
                self.ctx.bytes_in_transit -= slot.size;
            } else {
                self.ctx.bytes_in_transit = 0;
            }
            slot.in_use = false;
        }
        c4.notifyLoss(&self.state, &self.ctx, @as(u64, lost_seq), now_us);
    }

    pub fn canSend(self: *CongestionController, nbytes: u64, now_us: u64) bool {
        if (self.ctx.bytes_in_transit + nbytes > self.ctx.cwnd) return false;
        return self.pacer.canSend(nbytes, now_us);
    }

    /// Returns the send timestamp (microseconds) of an in-flight packet by
    /// sequence number, or null if the slot is empty / occupied by a
    /// different seq.
    pub fn sendTimeFor(self: *const CongestionController, seq: u32) ?u64 {
        const slot = &self.ring[seq % ring_slots];
        if (!slot.in_use or slot.seq != seq) return null;
        return slot.send_time_us;
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
    cc.onPacketSent(1, 1200, 1000);
    cc.onPacketSent(2, 1200, 2000);
    try std.testing.expectEqual(@as(u64, 2400), cc.ctx.bytes_in_transit);
    cc.onAck(1, 30_000, 31_000);
    try std.testing.expectEqual(@as(u64, 1200), cc.ctx.bytes_in_transit);
    cc.onAck(2, 30_000, 32_000);
    try std.testing.expectEqual(@as(u64, 0), cc.ctx.bytes_in_transit);
}

test "cc canSend blocks when bytes_in_transit exceeds cwnd" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    // Artificially shrink cwnd.
    cc.ctx.cwnd = 2400;
    cc.onPacketSent(1, 1200, 1000);
    cc.onPacketSent(2, 1200, 1000);
    try std.testing.expect(!cc.canSend(1200, 1000));
    cc.onAck(1, 20_000, 21_000);
    try std.testing.expect(cc.canSend(1200, 21_000));
}

test "cc bandwidth_estimate_bps becomes nonzero after a send→ack cycle" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    cc.onPacketSent(1, 1200, 0);
    // 1200 bytes delivered over 10ms => 120_000 bytes/sec
    cc.onAck(1, 10_000, 10_000);
    try std.testing.expect(cc.ctx.bandwidth_estimate_bps > 0);
    try std.testing.expect(cc.ctx.peak_bandwidth_estimate_bps > 0);
}

test "cc peak_bandwidth_estimate_bps tracks the highest sample" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    // First sample: 1200 bytes / 100ms = 12_000 bps
    cc.onPacketSent(1, 1200, 0);
    cc.onAck(1, 100_000, 100_000);
    const peak_low = cc.ctx.peak_bandwidth_estimate_bps;

    // Second sample: 1200 bytes / 1ms = 1_200_000_000 bps (much higher).
    cc.onPacketSent(2, 1200, 100_000);
    cc.onAck(2, 1_000, 101_000);
    try std.testing.expect(cc.ctx.peak_bandwidth_estimate_bps > peak_low);
    try std.testing.expect(cc.ctx.peak_bandwidth_estimate_bps >= 1_000_000);
}

test "cc delivered-delta uses slot snapshot, not running total" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    // Burst-send three packets at the same instant.
    cc.onPacketSent(1, 1200, 0);
    cc.onPacketSent(2, 1200, 0);
    cc.onPacketSent(3, 1200, 0);
    // Slot 1's snapshot must be 0 (nothing delivered when sent).
    try std.testing.expectEqual(@as(u64, 0), cc.ring[1 % ring_slots].total_delivered_bytes_at_send_time);
    // Ack #1 — delivered_delta should be 1200 (one packet's worth), not 0,
    // and not the running total (which would be 1200 either way here, but
    // observe slot #2/#3 captured 0 too — they were sent BEFORE #1's ack).
    cc.onAck(1, 5_000, 5_000);
    try std.testing.expectEqual(@as(u64, 1200), cc.total_delivered_bytes);
    try std.testing.expectEqual(@as(u64, 0), cc.ring[2 % ring_slots].total_delivered_bytes_at_send_time);
    // Now send a fourth packet — its snapshot should reflect the post-ack
    // running total.
    cc.onPacketSent(4, 1200, 5_000);
    try std.testing.expectEqual(@as(u64, 1200), cc.ring[4 % ring_slots].total_delivered_bytes_at_send_time);
    cc.onAck(4, 5_000, 10_000);
    // delivered_delta for #4 = total_delivered (now 2400) - 1200 = 1200,
    // NOT the full running total of 2400.
    // We can't read it directly, but we can sanity-check total_delivered.
    try std.testing.expectEqual(@as(u64, 2400), cc.total_delivered_bytes);
}

test "cc loss notification frees bytes_in_transit" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    cc.onPacketSent(1, 1200, 1000);
    cc.onLoss(1, 2000);
    try std.testing.expectEqual(@as(u64, 0), cc.ctx.bytes_in_transit);
}
