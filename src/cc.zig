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
    /// in_use == false means the slot is empty.
    in_use: bool = false,
};

pub const CongestionController = struct {
    state: c4.State,
    ctx: c4.CcContext,
    pacer: pacer_mod.Pacer,

    ring: [ring_slots]SentInfo = [_]SentInfo{.{}} ** ring_slots,
    next_seq: u32 = 1,
    total_delivered_bytes: u64 = 0,

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
        slot.in_use = false;

        if (self.ctx.bytes_in_transit >= size) {
            self.ctx.bytes_in_transit -= size;
        } else {
            self.ctx.bytes_in_transit = 0;
        }
        self.total_delivered_bytes += size;
        self.ctx.last_time_acked_data_frame_sent_us = send_time;

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
            .nb_bytes_delivered_since_packet_sent = self.total_delivered_bytes,
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

test "cc loss notification frees bytes_in_transit" {
    var cc: CongestionController = undefined;
    cc.init(1200, 0);
    cc.onPacketSent(1, 1200, 1000);
    cc.onLoss(1, 2000);
    try std.testing.expectEqual(@as(u64, 0), cc.ctx.bytes_in_transit);
}
