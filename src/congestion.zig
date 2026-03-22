const std = @import("std");
const transport = @import("transport.zig");

/// Nanoseconds per second.
const ns_per_s: u64 = std.time.ns_per_s;
const max_payload_len: u32 = transport.max_payload_len;

// ---------------------------------------------------------------------------
// Constants (BBR v3, draft-ietf-ccwg-bbr-05)
// ---------------------------------------------------------------------------

pub const max_datagram_size: u32 = 1200; // C.SMSS
pub const initial_cwnd: u32 = 10 * max_datagram_size; // 12,000
/// Minimum cwnd floor. The spec's 4*SMSS (4800 bytes) is designed for
/// bulk TCP transfers. Terminal traffic is bursty (image previews, screen
/// updates) and needs a larger floor to avoid throttling bursts. 64KB
/// ensures a 100KB image preview completes in ~30ms at 20ms RTT instead
/// of ~400ms with the spec's 4800-byte floor.
pub const min_cwnd: u32 = 64 * 1024;

/// MinRTTFilterLen = 10 seconds (spec section 2.13.1)
const min_rtt_filter_len_ns: i64 = 10 * std.time.ns_per_s;
/// ProbeRTTDuration = 200ms (spec section 2.13.2)
const probe_rtt_duration_ns: i64 = 200 * std.time.ns_per_ms;
/// ProbeRTTInterval = 5 seconds (spec section 2.13.2)
const probe_rtt_interval_ns: i64 = 5 * std.time.ns_per_s;
/// MaxBwFilterLen = 2 ProbeBW cycles (spec section 2.10)
const max_bw_filter_len: u64 = 2;
/// ExtraAckedFilterLen = 10 round trips (spec section 2.11)
const extra_acked_filter_len: u64 = 10;
/// Startup full-pipe detection: 3 rounds (spec section 5.3.1.2)
const full_pipe_rounds: u32 = 3;
/// StartupFullLossCnt = 6 (spec section 5.3.1.3)
const startup_full_loss_cnt: u32 = 6;

/// 8.8 fixed-point gains (256 = 1.0x)
/// StartupPacingGain = 2.77 ~= 4*ln(2) (spec section 2.4) => 709/256
const startup_pacing_gain: u32 = 709;
/// DrainPacingGain = 0.5 (spec section 2.4) => 128/256
const drain_pacing_gain: u32 = 128;
/// DefaultCwndGain = 2 (spec section 2.5) => 512/256
const default_cwnd_gain: u32 = 512;
/// ProbeRTTCwndGain = 0.5 (spec section 2.13.2) => 128/256
const probe_rtt_cwnd_gain: u32 = 128;

const probe_bw_down_pacing: u32 = 230; // 0.90x
const probe_bw_cruise_pacing: u32 = 256; // 1.0x
const probe_bw_refill_pacing: u32 = 256; // 1.0x
const probe_bw_up_pacing: u32 = 320; // 1.25x
const probe_bw_up_cwnd_gain: u32 = 576; // 2.25x

/// LossThresh = 2% (spec section 2.7)
const loss_thresh_num: u64 = 2;
const loss_thresh_den: u64 = 100;
/// Beta = 0.7 (spec section 2.7)
const beta_num: u64 = 7;
const beta_den: u64 = 10;
/// Headroom = 0.15 (spec section 2.7)
const headroom_num: u64 = 15;
const headroom_den: u64 = 100;
/// PacingMarginPercent = 1 (spec section 5.6.2)
const pacing_margin_percent: u64 = 1;

const max_u32: u32 = std.math.maxInt(u32);
const max_u64: u64 = std.math.maxInt(u64);
const max_i64: i64 = std.math.maxInt(i64);

// ---------------------------------------------------------------------------
// Windowed Max Filter (Kathleen Nichols' algorithm, 2-slot for max_bw)
// ---------------------------------------------------------------------------

pub const MaxFilter = struct {
    const Entry = struct { val: u64, time: u64 };
    win: [2]Entry = .{ .{ .val = 0, .time = 0 }, .{ .val = 0, .time = 0 } },

    /// Update with a new sample. `window_len` is the filter window length.
    /// For max_bw: window_len = 2, time = cycle_count.
    /// For extra_acked: window_len = 10, time = round_count.
    pub fn update(self: *MaxFilter, val: u64, time: u64, window_len: u64) void {
        // If new value >= current best, or window expired, reset all slots.
        if (val >= self.win[0].val or (time -% self.win[0].time) >= window_len) {
            self.win[1] = .{ .val = val, .time = time };
            self.win[0] = .{ .val = val, .time = time };
            return;
        }
        if (val >= self.win[1].val or (time -% self.win[1].time) >= window_len) {
            self.win[1] = .{ .val = val, .time = time };
            return;
        }
    }

    pub fn getBest(self: *const MaxFilter) u64 {
        return self.win[0].val;
    }

    pub fn reset(self: *MaxFilter) void {
        self.win = .{ .{ .val = 0, .time = 0 }, .{ .val = 0, .time = 0 } };
    }
};

// ---------------------------------------------------------------------------
// Delivery Rate Estimation
// ---------------------------------------------------------------------------

/// A0 reference point for ACK-rate computation (overestimate avoidance).
/// Saved at ACK aggregation epoch boundaries to provide a stable baseline
/// for ack_rate that spans the full epoch, preventing burst compression
/// from inflating bandwidth estimates. (Google/Cloudflare bandwidth sampler)
const AckPoint = struct {
    ack_time: i64,
    total_bytes_acked: u64,
};
const a0_capacity = 8;

pub const DeliveryState = struct {
    delivered: u64 = 0,
    delivered_time: i64 = 0,
    first_sent_time: i64 = 0,
    is_app_limited: bool = false,
    tx_in_flight: u32 = 0,
    lost: u64 = 0, // C.lost at time of send (for RS.lost = C.lost - P.lost)
    // Google/Cloudflare bandwidth sampler: per-packet snapshots
    total_bytes_sent: u64 = 0, // cumulative bytes sent when this packet was sent
    total_bytes_sent_at_last_acked: u64 = 0, // total_bytes_sent when last-acked pkt was sent
    last_acked_pkt_sent_time: i64 = 0, // sent_time of the most recently acked packet
};

pub const RateSample = struct {
    delivery_rate: u64 = 0,
    rtt_ns: i64 = 0,
    is_app_limited: bool = false,
    delivered: u64 = 0,
    newly_acked: u32 = 0,
    lost: u64 = 0,
    tx_in_flight: u32 = 0,
    prior_delivered: u64 = 0, // P.delivered: snapshot of C.delivered when packet was sent
};

// ---------------------------------------------------------------------------
// Acked packet info (passed from loss detector -> BBR)
// ---------------------------------------------------------------------------

pub const AckedPacket = struct {
    size: u32,
    sent_time: i64,
    delivery_state: DeliveryState,
    rtt_ns: i64,
};

// ---------------------------------------------------------------------------
// BBR v3 State Machine
// ---------------------------------------------------------------------------

pub const BbrState = enum {
    startup,
    drain,
    probe_bw,
    probe_rtt,
};

pub const ProbeBwPhase = enum {
    down,
    cruise,
    refill,
    up,
};

pub const AckPhase = enum {
    acks_init,
    acks_refilling,
    acks_probe_starting,
    acks_probe_feedback,
    acks_probe_stopping,
};

// ---------------------------------------------------------------------------
// Simple xorshift64 PRNG (inline, no deps)
// ---------------------------------------------------------------------------
fn xorshift64(state: *u64) u64 {
    var x = state.*;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state.* = x;
    return x;
}

// ---------------------------------------------------------------------------
// BBR v3 (draft-ietf-ccwg-bbr-05)
// ---------------------------------------------------------------------------

pub const Bbr = struct {
    state: BbrState = .startup,
    probe_bw_phase: ProbeBwPhase = .down,
    ack_phase: AckPhase = .acks_init,

    // --- Bandwidth model (long-term) ---
    max_bw: u64 = 0,
    max_bw_filter: MaxFilter = .{},
    cycle_count: u64 = 0,

    // --- Bandwidth model (short-term) ---
    bw_shortterm: u64 = max_u64, // Infinity
    bw: u64 = 0,

    // --- Short-term delivery signals ---
    bw_latest: u64 = 0,
    inflight_latest: u64 = 0,
    loss_round_start: bool = false,
    loss_round_delivered: u64 = 0,
    loss_in_round: bool = false,

    // --- RTT estimation ---
    min_rtt: i64 = max_i64, // Infinity until first sample
    min_rtt_stamp: i64 = 0,
    probe_rtt_min_delay: i64 = max_i64,
    probe_rtt_min_stamp: i64 = 0,
    probe_rtt_expired: bool = false,

    // --- Inflight model ---
    inflight_longterm: u32 = max_u32, // Infinity
    inflight_shortterm: u32 = max_u32, // Infinity
    max_inflight: u32 = initial_cwnd,
    extra_acked: u64 = 0,

    // --- Pacing + window ---
    // BBRInitPacingRate: initial_cwnd / 1ms * StartupPacingGain
    // = 12000 / 0.001 * (709/256) = 12,000,000 * 2.77 ≈ 33,234,375
    pacing_rate: u64 = @as(u64, initial_cwnd) * ns_per_s / std.time.ns_per_ms * startup_pacing_gain / 256,
    cwnd: u32 = initial_cwnd,
    /// Hard ceiling for cwnd, set from the receiver's UDP socket buffer size.
    /// Prevents inflight from exceeding what the receiver's kernel can buffer
    /// between poll() wakeups. Default = no cap.
    max_cwnd: u32 = max_u32,
    inflight: u32 = 0,

    // --- Delivery tracking ---
    delivered: u64 = 0,
    delivered_time: i64 = 0,
    first_sent_time: i64 = 0,
    total_lost: u64 = 0, // C.lost: cumulative bytes declared lost
    total_bytes_sent: u64 = 0, // cumulative bytes sent

    // --- Google/Cloudflare bandwidth sampler state ---
    total_bytes_sent_at_last_acked: u64 = 0, // total_bytes_sent when last-acked pkt was sent
    last_acked_pkt_sent_time: i64 = 0, // sent_time of the most recently acked packet

    // --- A0 point candidates (overestimate avoidance) ---
    a0_candidates: [a0_capacity]AckPoint = [1]AckPoint{.{ .ack_time = 0, .total_bytes_acked = 0 }} ** a0_capacity,
    a0_count: u32 = 0,

    // --- Round tracking ---
    round_count: u64 = 0,
    round_start: bool = false,
    next_round_delivered: u64 = 0,
    rounds_since_bw_probe: u64 = 0,

    // --- Startup full-pipe detection ---
    full_bw: u64 = 0,
    full_bw_count: u32 = 0,
    full_bw_now: bool = false,
    full_bw_reached: bool = false,

    // --- ProbeBW state ---
    cycle_stamp: i64 = 0,
    bw_probe_wait: i64 = 0, // ns
    bw_probe_up_rounds: u32 = 0,
    bw_probe_up_acks: u32 = 0,
    probe_up_cnt: u32 = max_u32,
    bw_probe_samples: bool = false,
    prior_cwnd: u32 = 0,

    // --- Drain state ---
    drain_start_round: u64 = 0,

    // --- ProbeRTT state ---
    probe_rtt_done_stamp: i64 = 0,
    probe_rtt_round_done: bool = false,

    // --- App-limited ---
    is_app_limited: bool = false,
    app_limited_seq: u64 = 0,

    // --- Extra ACKed tracking ---
    extra_acked_filter: MaxFilter = .{},
    extra_acked_interval_start: i64 = 0,
    extra_acked_delivered: u64 = 0,

    // --- Idle restart ---
    idle_restart: bool = false,

    // --- Startup high-loss tracking ---
    startup_loss_events: u32 = 0, // discontiguous loss events in current round
    bytes_lost_in_round: u64 = 0, // bytes lost in current round
    last_startup_lost_offset: u32 = 0, // last lost offset for discontiguous tracking
    has_last_startup_lost: bool = false, // whether last_startup_lost_offset is valid

    // --- Loss recovery state ---
    in_loss_recovery: bool = false, // set by onSevereLoss, cleared by restoreCwnd

    // --- Undo state (for spurious loss recovery) ---
    undo_state: BbrState = .startup,
    undo_probe_bw_phase: ProbeBwPhase = .down,
    undo_bw_shortterm: u64 = max_u64,
    undo_inflight_shortterm: u32 = max_u32,
    undo_inflight_longterm: u32 = max_u32,

    // --- PRNG state ---
    rng_state: u64 = 0,

    // --- Per-ACK-event accumulation (spec §5.2.3 batching) ---
    pending_ack_newly_acked: u32 = 0,
    pending_ack_best_pkt: ?AckedPacket = null, // most recently sent (IsNewestPacket)

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// OnPacketSent (spec §4.1.2.2): initialize, update inflight, snapshot.
    /// Returns the delivery state to record in the send buffer.
    /// Replaces the old separate getDeliveryState() + onSend() pair.
    pub fn onSend(self: *Bbr, bytes: u32, now: i64) DeliveryState {
        // BBRHandleRestartFromIdle (spec 5.4.1)
        self.handleRestartFromIdle(now);

        // Spec §4.1.2.2: "if (C.inflight == 0)"
        // Reset timestamps so the first packet in a flight gets valid values.
        if (self.inflight == 0) {
            self.first_sent_time = now;
            self.delivered_time = now;
        }

        // Update inflight and cumulative sent BEFORE snapshot
        self.inflight += bytes;
        self.total_bytes_sent += bytes;

        // Snapshot delivery state (spec: P.delivered_time = C.delivered_time, etc.)
        const ds = DeliveryState{
            .delivered = self.delivered,
            .delivered_time = self.delivered_time,
            .first_sent_time = self.first_sent_time,
            .is_app_limited = self.is_app_limited,
            .tx_in_flight = self.inflight,
            .lost = self.total_lost,
            .total_bytes_sent = self.total_bytes_sent,
            .total_bytes_sent_at_last_acked = self.total_bytes_sent_at_last_acked,
            .last_acked_pkt_sent_time = self.last_acked_pkt_sent_time,
        };

        // Spec §4.1.2.2: C.first_send_time = P.send_time (for next packet)
        self.first_sent_time = now;

        // Clear app-limited once we've sent enough to fill the pipe (spec 4.1.2.4)
        if (self.is_app_limited and self.delivered + self.inflight > self.app_limited_seq) {
            self.is_app_limited = false;
        }

        // Seed PRNG on first send
        if (self.rng_state == 0) {
            self.rng_state = @as(u64, @bitCast(now)) | 1;
        }

        return ds;
    }

    /// Legacy single-packet ACK handler. Wraps beginAck/onAckPacket/endAck
    /// for backward compatibility with tests and single-packet ACK paths.
    pub fn onAck(self: *Bbr, pkt: AckedPacket, newly_acked: u32, now: i64) void {
        _ = newly_acked;
        self.beginAck();
        self.onAckPacket(pkt, false);
        self.endAck(now);
    }

    /// Begin processing an ACK event. Call before onAckPacket calls.
    /// Per spec §5.2.3: BBRUpdateOnACK runs once per ACK event, not per packet.
    pub fn beginAck(self: *Bbr) void {
        self.pending_ack_newly_acked = 0;
        self.pending_ack_best_pkt = null;
    }

    /// Process one ACKed packet within an ACK event (spec §4.1.2.3).
    /// Updates C.delivered and tracks the most recently sent packet
    /// for rate sampling (IsNewestPacket). Call endAck() after all packets.
    pub fn onAckPacket(self: *Bbr, pkt: AckedPacket, is_retransmit: bool) void {
        self.inflight -|= pkt.size;
        self.delivered += pkt.size;
        self.pending_ack_newly_acked += pkt.size;

        // Skip retransmits for rate sampling (stale delivery_state)
        if (is_retransmit) return;

        // IsNewestPacket (spec §4.1.2.3): pick the most recently sent packet
        if (self.pending_ack_best_pkt == null or
            pkt.sent_time >= self.pending_ack_best_pkt.?.sent_time)
        {
            self.pending_ack_best_pkt = pkt;
        }
    }

    /// Finalize ACK event: compute rate sample and run model+control updates
    /// once per ACK event (spec §5.2.3: BBRUpdateOnACK).
    pub fn endAck(self: *Bbr, now: i64) void {
        self.delivered_time = now;

        // GenerateRateSample: clear app-limited if bubble is ACKed (spec §4.1.2.3)
        if (self.is_app_limited and self.delivered > self.app_limited_seq) {
            self.is_app_limited = false;
        }

        const best_pkt = self.pending_ack_best_pkt orelse return;

        var rs = self.computeRateSample(best_pkt, now);
        rs.newly_acked = self.pending_ack_newly_acked;

        // Update "last acked" state for future packets' send_rate.
        // best_pkt is the most recently sent packet in this ACK event.
        self.total_bytes_sent_at_last_acked = best_pkt.delivery_state.total_bytes_sent;
        self.last_acked_pkt_sent_time = best_pkt.sent_time;

        // --- BBRUpdateModelAndState ---
        // BBRUpdateLatestDeliverySignals (spec 5.5.10.3)
        self.updateLatestDeliverySignals(rs);
        // BBRUpdateCongestionSignals (spec 5.5.10.3)
        self.updateCongestionSignals(rs, now);
        // BBRUpdateACKAggregation (spec 5.5.9)
        self.updateACKAggregation(rs, now);
        // BBRCheckFullBWReached (spec 5.3.1.2)
        self.checkFullBWReached(rs);
        // BBRCheckStartupDone (spec 5.3.1)
        self.checkStartupDone(rs);
        // BBRCheckDrainDone (spec 5.3.2)
        self.checkDrainDone(now);
        // BBRUpdateProbeBWCyclePhase (spec 5.3.3.6)
        self.updateProbeBWCyclePhase(rs, now);
        // BBRUpdateMinRTT (spec 5.3.4.3)
        self.updateMinRTT(rs, now);
        // BBRCheckProbeRTT (spec 5.3.4.3)
        self.checkProbeRTT(rs, now);
        // BBRAdvanceLatestDeliverySignals (spec 5.5.10.3)
        self.advanceLatestDeliverySignals(rs);
        // BBRBoundBWForModel (spec 5.5.10.3)
        self.boundBWForModel();

        // --- BBRUpdateControlParameters ---
        // BBRSetPacingRate (spec 5.6.2)
        self.setPacingRate();
        // BBRSetCwnd (spec 5.6.4.6)
        self.setCwnd(rs);
    }

    /// Per-loss handler: BBRHandleLostPacket (spec 5.5.10.2)
    /// lost_offset: byte offset of the lost packet
    /// pkt_size: size of the lost packet
    /// lost: cumulative data lost since this packet was sent (RS.lost)
    /// tx_in_flight: C.inflight when this packet was sent (RS.tx_in_flight)
    /// is_app_limited_at_send: P.is_app_limited
    pub fn onLoss(self: *Bbr, lost_offset: u32, pkt_size: u32, lost: u64, tx_in_flight: u32, is_app_limited: bool) void {
        self.inflight -|= pkt_size;
        self.total_lost += pkt_size;
        self.bytes_lost_in_round += pkt_size;

        // BBRNoteLoss (spec 5.5.10.2)
        if (!self.loss_in_round) {
            self.loss_round_delivered = self.delivered;
            self.saveStateUponLoss();
        }
        self.loss_in_round = true;

        // Count discontiguous loss events during Startup (for D8 criterion 3).
        // Two consecutive lost packets (offset N and N+max_payload_len) are one loss event.
        if (!self.bw_probe_samples) {
            if (!self.has_last_startup_lost or lost_offset != self.last_startup_lost_offset +% max_payload_len) {
                self.startup_loss_events += 1;
            }
            self.last_startup_lost_offset = lost_offset;
            self.has_last_startup_lost = true;
            return;
        }

        // Check IsInflightTooHigh using cumulative lost/tx_in_flight
        if (isInflightTooHigh(lost, tx_in_flight)) {
            // BBRInflightAtLoss: estimate where loss threshold was crossed
            const inflight_prev: u64 = @as(u64, tx_in_flight) -| @as(u64, pkt_size);
            const lost_prev: u64 = lost -| @as(u64, pkt_size);
            // lost_prefix = (LossThresh * inflight_prev - lost_prev) / (1 - LossThresh)
            // Using fixed-point: numerator = (2 * inflight_prev / 100) - lost_prev
            //                    denominator = 98/100
            // Simplified: lost_prefix = (2*inflight_prev - 100*lost_prev) / 98
            const thresh_inflight = blk: {
                const numer_term1 = loss_thresh_num * inflight_prev;
                const numer_term2 = loss_thresh_den * lost_prev;
                if (numer_term1 <= numer_term2) break :blk inflight_prev;
                const numer = numer_term1 - numer_term2;
                const denom = loss_thresh_den - loss_thresh_num;
                const lost_prefix = numer / denom;
                break :blk inflight_prev + lost_prefix;
            };

            // BBRHandleInflightTooHigh (spec 5.5.10.2)
            self.bw_probe_samples = false;
            if (!is_app_limited) {
                const target = self.targetInflight();
                const base = @max(thresh_inflight, @as(u64, target) * beta_num / beta_den);
                self.inflight_longterm = @intCast(@min(base, max_u32));
            }
            if (self.state == .probe_bw and self.probe_bw_phase == .up) {
                // We don't have `now` in onLoss; use cycle_stamp as fallback
                self.startProbeBW_DOWN(self.cycle_stamp);
            }
        }
    }

    pub fn canSend(self: *const Bbr) bool {
        return self.inflight < self.cwnd;
    }

    pub fn setAppLimited(self: *Bbr) void {
        self.is_app_limited = true;
        self.app_limited_seq = self.delivered + self.inflight;
        if (self.app_limited_seq == 0) self.app_limited_seq = 1;
    }

    pub fn bdp(self: *const Bbr) u64 {
        const mrtt = self.getMinRtt();
        if (mrtt <= 0 or self.bw == 0) return @as(u64, initial_cwnd);
        return self.bw * @as(u64, @intCast(mrtt)) / ns_per_s;
    }

    pub fn getMinRtt(self: *const Bbr) i64 {
        if (self.min_rtt == max_i64) return 0;
        return self.min_rtt;
    }

    // ------------------------------------------------------------------
    // Internal: Delivery Rate Sample
    // ------------------------------------------------------------------

    /// Delivery rate sample per spec §4.1.1.2.4:
    ///   delivery_rate = data_acked / max(ack_elapsed, send_elapsed)
    ///
    /// This is equivalent to min(send_rate, ack_rate) when both share
    /// data_acked as numerator. Using max(elapsed) as denominator is
    /// better for bursty terminal traffic than Google's separate-numerator
    /// approach, which penalizes idle periods between bursts.
    fn computeRateSample(self: *const Bbr, pkt: AckedPacket, now: i64) RateSample {
        const ds = pkt.delivery_state;
        const delivered_delta = self.delivered - ds.delivered;
        if (delivered_delta == 0) return .{ .prior_delivered = ds.delivered };

        const send_elapsed = pkt.sent_time - ds.first_sent_time;
        const ack_elapsed = now - ds.delivered_time;
        const interval = @max(send_elapsed, ack_elapsed);

        // 1ms floor: before first RTT sample, prevents degenerate TB/s estimates.
        const min_rtt_val = self.getMinRtt();
        const min_interval: i64 = if (min_rtt_val > 0) min_rtt_val else std.time.ns_per_ms;
        if (interval < min_interval) {
            return .{
                .rtt_ns = pkt.rtt_ns,
                .delivered = delivered_delta,
                .lost = self.total_lost -| ds.lost,
                .tx_in_flight = ds.tx_in_flight,
                .prior_delivered = ds.delivered,
            };
        }

        const rate = delivered_delta * ns_per_s / @as(u64, @intCast(interval));

        return .{
            .delivery_rate = rate,
            .rtt_ns = pkt.rtt_ns,
            .is_app_limited = ds.is_app_limited,
            .delivered = delivered_delta,
            .lost = self.total_lost -| ds.lost,
            .tx_in_flight = ds.tx_in_flight,
            .prior_delivered = ds.delivered,
        };
    }

    /// Select the A0 candidate whose total_bytes_acked is closest to (but not
    /// exceeding) the target. This gives the widest valid ACK measurement
    /// baseline for the packet that was sent when C.delivered == target.
    fn selectA0(self: *const Bbr, target_bytes_acked: u64) ?AckPoint {
        var best: ?AckPoint = null;
        for (self.a0_candidates[0..self.a0_count]) |candidate| {
            if (candidate.total_bytes_acked <= target_bytes_acked) {
                if (best == null or candidate.total_bytes_acked > best.?.total_bytes_acked) {
                    best = candidate;
                }
            }
        }
        return best;
    }

    /// Push an A0 candidate at an ACK aggregation epoch boundary.
    fn pushA0Candidate(self: *Bbr, point: AckPoint) void {
        if (self.a0_count < a0_capacity) {
            self.a0_candidates[self.a0_count] = point;
            self.a0_count += 1;
        } else {
            // Shift left, drop oldest
            for (0..a0_capacity - 1) |i| {
                self.a0_candidates[i] = self.a0_candidates[i + 1];
            }
            self.a0_candidates[a0_capacity - 1] = point;
        }
    }

    // ------------------------------------------------------------------
    // Internal: Round counting (spec 5.5.1)
    // ------------------------------------------------------------------

    fn updateRound(self: *Bbr, pkt_delivered: u64) void {
        // Spec §5.5.1: "if (packet.delivered >= BBR.next_round_delivered)"
        // packet.delivered is P.delivered: the snapshot of C.delivered when packet was sent.
        if (pkt_delivered >= self.next_round_delivered) {
            self.startRound();
            self.round_count += 1;
            self.rounds_since_bw_probe += 1;
            self.round_start = true;
        } else {
            self.round_start = false;
        }
    }

    fn startRound(self: *Bbr) void {
        self.next_round_delivered = self.delivered;
    }

    // ------------------------------------------------------------------
    // Internal: Latest Delivery Signals (spec 5.5.10.3)
    // ------------------------------------------------------------------

    fn updateLatestDeliverySignals(self: *Bbr, rs: RateSample) void {
        self.loss_round_start = false;
        self.bw_latest = @max(self.bw_latest, rs.delivery_rate);
        self.inflight_latest = @max(self.inflight_latest, rs.delivered);
        // Spec line 3672: "if (RS.prior_delivered >= BBR.loss_round_delivered)"
        // RS.prior_delivered is P.delivered of the most recently delivered packet.
        if (rs.prior_delivered >= self.loss_round_delivered) {
            self.loss_round_delivered = self.delivered;
            self.loss_round_start = true;
        }
    }

    fn advanceLatestDeliverySignals(self: *Bbr, rs: RateSample) void {
        if (self.loss_round_start) {
            self.bw_latest = rs.delivery_rate;
            self.inflight_latest = rs.delivered;
        }
    }

    // ------------------------------------------------------------------
    // Internal: Congestion Signals (spec 5.5.10.3)
    // ------------------------------------------------------------------

    fn resetCongestionSignals(self: *Bbr) void {
        self.loss_in_round = false;
        self.bw_latest = 0;
        self.inflight_latest = 0;
        self.startup_loss_events = 0;
        self.bytes_lost_in_round = 0;
        self.has_last_startup_lost = false;
    }

    fn updateCongestionSignals(self: *Bbr, rs: RateSample, now: i64) void {
        // BBRUpdateMaxBw (spec 5.5.5)
        self.updateRound(rs.prior_delivered);
        self.updateMaxBw(rs);
        _ = now;

        if (!self.loss_round_start)
            return; // wait until end of round trip

        self.adaptLowerBoundsFromCongestion();

        // NOTE: checkStartupHighLoss is called here (inside updateCongestionSignals)
        // rather than from checkStartupDone as the spec pseudocode suggests (§5.2.3).
        // This is an intentional ordering correction: the spec's BBRUpdateCongestionSignals
        // resets loss_in_round/bytes_lost_in_round/startup_loss_events at the end of each
        // loss round, but BBRCheckStartupHighLoss (called later via BBRCheckStartupDone)
        // needs those values. Calling it here — after adaptLowerBoundsFromCongestion but
        // before the reset — matches the spec's INTENT (exit Startup on sustained high
        // loss) even though it diverges from the spec's literal call ordering.
        self.checkStartupHighLoss(rs);

        self.loss_in_round = false;
        self.startup_loss_events = 0;
        self.bytes_lost_in_round = 0;
        self.has_last_startup_lost = false;
    }

    fn updateMaxBw(self: *Bbr, rs: RateSample) void {
        if (rs.delivery_rate > 0 and
            (rs.delivery_rate >= self.max_bw or !rs.is_app_limited))
        {
            self.max_bw_filter.update(rs.delivery_rate, self.cycle_count, max_bw_filter_len);
        }
        self.max_bw = self.max_bw_filter.getBest();
    }

    fn adaptLowerBoundsFromCongestion(self: *Bbr) void {
        // BBRAdaptLowerBoundsFromCongestion (spec 5.5.10.3)
        if (self.isProbingBW()) return;
        if (self.loss_in_round) {
            self.initLowerBounds();
            self.lossLowerBounds();
        }
    }

    fn initLowerBounds(self: *Bbr) void {
        if (self.bw_shortterm == max_u64) {
            self.bw_shortterm = self.max_bw;
        }
        if (self.inflight_shortterm == max_u32) {
            self.inflight_shortterm = self.cwnd;
        }
    }

    fn lossLowerBounds(self: *Bbr) void {
        // bw_shortterm = max(bw_latest, Beta * bw_shortterm)
        self.bw_shortterm = @max(
            self.bw_latest,
            self.bw_shortterm * beta_num / beta_den,
        );
        // inflight_shortterm = max(inflight_latest, Beta * inflight_shortterm)
        const beta_inflight = @as(u64, self.inflight_shortterm) * beta_num / beta_den;
        self.inflight_shortterm = @intCast(@min(
            @max(self.inflight_latest, beta_inflight),
            max_u32,
        ));
    }

    fn resetShortTermModel(self: *Bbr) void {
        self.bw_shortterm = max_u64;
        self.inflight_shortterm = max_u32;
    }

    fn boundBWForModel(self: *Bbr) void {
        self.bw = @min(self.max_bw, self.bw_shortterm);
    }

    // ------------------------------------------------------------------
    // Internal: ACK Aggregation (spec 5.5.9)
    // ------------------------------------------------------------------

    fn updateACKAggregation(self: *Bbr, rs: RateSample, now: i64) void {
        // Find excess ACKed beyond expected amount over this interval
        const interval_ns: u64 = if (now > self.extra_acked_interval_start)
            @intCast(now - self.extra_acked_interval_start)
        else
            0;
        // u128 intermediate: interval_ns can span seconds, so bw * interval_ns
        // can exceed u64 at realistic bandwidths (e.g., 1 GB/s * 10s = 1e19).
        // This matches tquic: (self.bw as u128).saturating_mul(interval.as_micros())
        var expected_delivered: u64 = @intCast(@as(u128, self.bw) * interval_ns / ns_per_s);

        // Reset interval if ACK rate is below expected rate (spec §5.5.9)
        if (self.extra_acked_delivered <= expected_delivered) {
            self.extra_acked_delivered = 0;
            self.extra_acked_interval_start = now;
            expected_delivered = 0;
            // Save A0 candidate at epoch boundary (overestimate avoidance)
            self.pushA0Candidate(.{ .ack_time = now, .total_bytes_acked = self.delivered });
        }
        self.extra_acked_delivered += rs.newly_acked;

        const raw_extra = self.extra_acked_delivered -| expected_delivered;
        const extra = @min(raw_extra, self.cwnd);

        const filter_len: u64 = if (self.full_bw_reached) extra_acked_filter_len else 1;
        self.extra_acked_filter.update(extra, self.round_count, filter_len);
        self.extra_acked = self.extra_acked_filter.getBest();
    }

    // ------------------------------------------------------------------
    // Internal: Startup (spec 5.3.1)
    // ------------------------------------------------------------------

    fn resetFullBW(self: *Bbr) void {
        self.full_bw = 0;
        self.full_bw_count = 0;
        self.full_bw_now = false;
    }

    fn checkFullBWReached(self: *Bbr, rs: RateSample) void {
        if (self.full_bw_now or !self.round_start or rs.is_app_limited) return;
        if (rs.delivery_rate >= self.full_bw + self.full_bw / 4) {
            // BW still growing: reset
            self.resetFullBW();
            self.full_bw = rs.delivery_rate;
            return;
        }
        self.full_bw_count += 1;
        self.full_bw_now = (self.full_bw_count >= full_pipe_rounds);
        if (self.full_bw_now) {
            self.full_bw_reached = true;
        }
    }

    fn checkStartupDone(self: *Bbr, rs: RateSample) void {
        // Note: checkStartupHighLoss is called from updateCongestionSignals
        // BEFORE per-round counters are reset, so it can read loss_in_round etc.
        _ = rs;
        if (self.state == .startup and self.full_bw_reached) {
            self.enterDrain();
        }
    }

    fn checkStartupHighLoss(self: *Bbr, rs: RateSample) void {
        _ = rs;
        if (self.state != .startup) return;

        // Spec 5.3.1.3: ALL three criteria must be met:
        // 1. A loss round has completed (loss_round_start is set)
        if (!self.loss_round_start) return;
        // 2. Loss rate exceeds LossThresh (2%): bytes_lost_in_round / inflight_latest > 2%
        if (!self.loss_in_round) return;
        if (self.inflight_latest == 0) return;
        const loss_rate_high = self.bytes_lost_in_round * loss_thresh_den >
            self.inflight_latest * loss_thresh_num;
        if (!loss_rate_high) return;
        // 3. At least StartupFullLossCnt (6) discontiguous loss events in round
        if (self.startup_loss_events < startup_full_loss_cnt) return;

        // Exit Startup due to high loss
        self.full_bw_reached = true;
        // inflight_longterm = max(bdp, inflight_latest)
        const bdp_val = self.bdp();
        self.inflight_longterm = @intCast(@min(
            @max(bdp_val, self.inflight_latest),
            max_u32,
        ));
    }

    fn enterStartup(self: *Bbr) void {
        self.state = .startup;
    }

    fn enterDrain(self: *Bbr) void {
        self.state = .drain;
        self.drain_start_round = self.round_count;
    }

    fn checkDrainDone(self: *Bbr, now: i64) void {
        if (self.state != .drain) return;
        _ = now;
        // Spec 5.3.2: exit Drain when inflight <= BBRInflight(1.0) or 3 rounds elapsed
        if (self.inflight <= self.bbrInflight(256) or
            self.round_count > self.drain_start_round + 3)
        {
            self.enterProbeBW();
        }
    }

    fn enterProbeBW(self: *Bbr) void {
        self.startProbeBW_DOWN(self.cycle_stamp);
    }

    // ------------------------------------------------------------------
    // Internal: ProbeBW (spec 5.3.3.6)
    // ------------------------------------------------------------------

    fn updateProbeBWCyclePhase(self: *Bbr, rs: RateSample, now: i64) void {
        if (!self.full_bw_reached) return;
        self.adaptLongTermModel(rs, now);
        if (self.state != .probe_bw) return;

        switch (self.probe_bw_phase) {
            .down => {
                if (self.isTimeToProbeBW(now)) return;
                if (self.isTimeToCruise()) {
                    self.startProbeBW_CRUISE();
                }
            },
            .cruise => {
                if (self.isTimeToProbeBW(now)) return;
            },
            .refill => {
                if (self.round_start) {
                    self.bw_probe_samples = true;
                    self.startProbeBW_UP(rs, now);
                }
            },
            .up => {
                if (self.isTimeToGoDown(rs)) {
                    self.startProbeBW_DOWN(now);
                }
            },
        }
    }

    fn startProbeBW_DOWN(self: *Bbr, now: i64) void {
        self.resetCongestionSignals();
        self.probe_up_cnt = max_u32;
        self.pickProbeWait();
        self.cycle_stamp = now;
        self.ack_phase = .acks_probe_stopping;
        self.startRound();
        self.state = .probe_bw;
        self.probe_bw_phase = .down;
    }

    fn startProbeBW_CRUISE(self: *Bbr) void {
        self.state = .probe_bw;
        self.probe_bw_phase = .cruise;
    }

    fn startProbeBW_REFILL(self: *Bbr) void {
        self.resetShortTermModel();
        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acks = 0;
        self.ack_phase = .acks_refilling;
        self.startRound();
        self.state = .probe_bw;
        self.probe_bw_phase = .refill;
    }

    fn startProbeBW_UP(self: *Bbr, rs: RateSample, now: i64) void {
        _ = now;
        self.ack_phase = .acks_probe_starting;
        self.startRound();
        self.resetFullBW();
        self.full_bw = rs.delivery_rate;
        self.state = .probe_bw;
        self.probe_bw_phase = .up;
        self.raiseInflightLongtermSlope();
    }

    fn isTimeToProbeBW(self: *Bbr, now: i64) bool {
        if (self.hasElapsedInPhase(now, self.bw_probe_wait) or
            self.isRenoCoexistenceProbeTime())
        {
            self.startProbeBW_REFILL();
            return true;
        }
        return false;
    }

    fn pickProbeWait(self: *Bbr) void {
        // Randomized: rounds_since_bw_probe = random 0 or 1
        self.rounds_since_bw_probe = xorshift64(&self.rng_state) & 1;
        // bw_probe_wait = 2 + random [0.0, 1.0) seconds, in nanoseconds
        const rand_frac_ns: i64 = @intCast(xorshift64(&self.rng_state) % @as(u64, @intCast(std.time.ns_per_s)));
        self.bw_probe_wait = 2 * std.time.ns_per_s + rand_frac_ns;
    }

    fn isRenoCoexistenceProbeTime(self: *const Bbr) bool {
        const target = self.targetInflight();
        const reno_rounds = @min(@as(u64, target), 63);
        return self.rounds_since_bw_probe >= reno_rounds;
    }

    fn hasElapsedInPhase(self: *const Bbr, now: i64, interval: i64) bool {
        return now > self.cycle_stamp + interval;
    }

    fn isTimeToCruise(self: *const Bbr) bool {
        if (self.inflight > self.inflightWithHeadroom()) return false;
        if (self.inflight > self.bbrInflight(256)) return false; // 1.0 gain
        return true;
    }

    fn isTimeToGoDown(self: *Bbr, rs: RateSample) bool {
        // Spec: if cwnd-limited and cwnd >= inflight_longterm, reset fullBW
        // We approximate is_cwnd_limited as (inflight >= cwnd - max_datagram_size)
        const cwnd_limited = (self.inflight + max_datagram_size >= self.cwnd);
        if (cwnd_limited and self.cwnd >= self.inflight_longterm) {
            self.resetFullBW();
            self.full_bw = rs.delivery_rate; // spec: BBR.full_bw = RS.delivery_rate
        } else if (self.full_bw_now) {
            return true;
        }
        return false;
    }

    fn inflightWithHeadroom(self: *const Bbr) u32 {
        if (self.inflight_longterm == max_u32) return max_u32;
        // headroom = max(1*SMSS, Headroom * inflight_longterm)
        const headroom_val = @max(
            @as(u64, max_datagram_size),
            @as(u64, self.inflight_longterm) * headroom_num / headroom_den,
        );
        const result = @as(u64, self.inflight_longterm) -| headroom_val;
        return @intCast(@max(result, min_cwnd));
    }

    fn raiseInflightLongtermSlope(self: *Bbr) void {
        const shift_amt: u5 = @intCast(@min(self.bw_probe_up_rounds, 30));
        const growth_this_round: u64 = @as(u64, max_datagram_size) << shift_amt;
        self.bw_probe_up_rounds = @min(self.bw_probe_up_rounds + 1, 30);
        self.probe_up_cnt = @intCast(@max(@as(u64, self.cwnd) / @max(growth_this_round, 1), 1));
    }

    fn probeInflightLongtermUpward(self: *Bbr, rs: RateSample) void {
        // Spec: if (!C.is_cwnd_limited || C.cwnd < BBR.inflight_longterm) return
        const cwnd_limited = (self.inflight + max_datagram_size >= self.cwnd);
        if (!cwnd_limited or self.cwnd < self.inflight_longterm) return;

        self.bw_probe_up_acks += rs.newly_acked;
        if (self.bw_probe_up_acks >= self.probe_up_cnt and self.probe_up_cnt > 0) {
            const delta = self.bw_probe_up_acks / self.probe_up_cnt;
            self.bw_probe_up_acks -= delta * self.probe_up_cnt;
            self.inflight_longterm +|= delta;
        }
        if (self.round_start) {
            self.raiseInflightLongtermSlope();
        }
    }

    fn adaptLongTermModel(self: *Bbr, rs: RateSample, now: i64) void {
        _ = now;
        // BBRAdaptLongTermModel (spec 5.3.3.6)
        if (self.ack_phase == .acks_probe_starting and self.round_start) {
            self.ack_phase = .acks_probe_feedback;
        }
        if (self.ack_phase == .acks_probe_stopping and self.round_start) {
            if (self.state == .probe_bw and !rs.is_app_limited) {
                self.advanceMaxBwFilter();
            }
        }

        if (!isInflightTooHigh(rs.lost, rs.tx_in_flight)) {
            // Loss rate is safe. Adjust upper bounds upward.
            if (self.inflight_longterm == max_u32) return;
            if (rs.tx_in_flight > self.inflight_longterm) {
                self.inflight_longterm = rs.tx_in_flight;
            }
            if (self.state == .probe_bw and self.probe_bw_phase == .up) {
                self.probeInflightLongtermUpward(rs);
            }
        }
    }

    fn advanceMaxBwFilter(self: *Bbr) void {
        self.cycle_count +%= 1;
    }

    fn isProbingBW(self: *const Bbr) bool {
        return (self.state == .startup or
            (self.state == .probe_bw and self.probe_bw_phase == .refill) or
            (self.state == .probe_bw and self.probe_bw_phase == .up));
    }

    // ------------------------------------------------------------------
    // Internal: ProbeRTT (spec 5.3.4.3)
    // ------------------------------------------------------------------

    fn updateMinRTT(self: *Bbr, rs: RateSample, now: i64) void {
        self.probe_rtt_expired = now > self.probe_rtt_min_stamp + probe_rtt_interval_ns;

        if (rs.rtt_ns > 0 and
            (rs.rtt_ns < self.probe_rtt_min_delay or self.probe_rtt_expired))
        {
            self.probe_rtt_min_delay = rs.rtt_ns;
            self.probe_rtt_min_stamp = now;
        }

        const min_rtt_expired = now > self.min_rtt_stamp + min_rtt_filter_len_ns;
        if (self.probe_rtt_min_delay < self.min_rtt or min_rtt_expired) {
            self.min_rtt = self.probe_rtt_min_delay;
            self.min_rtt_stamp = self.probe_rtt_min_stamp;
        }
    }

    fn checkProbeRTT(self: *Bbr, rs: RateSample, now: i64) void {
        // Don't enter ProbeRTT during Startup — bandwidth hasn't stabilized yet
        if (self.state != .probe_rtt and self.probe_rtt_expired and
            !self.idle_restart and self.state != .startup)
        {
            self.enterProbeRTT();
            self.saveCwnd();
            self.probe_rtt_done_stamp = 0;
            self.ack_phase = .acks_probe_stopping;
            self.startRound();
        }
        if (self.state == .probe_rtt) {
            self.handleProbeRTT(now);
        }
        if (rs.delivered > 0) {
            self.idle_restart = false;
        }
    }

    fn enterProbeRTT(self: *Bbr) void {
        self.state = .probe_rtt;
        // pacing_gain = 1.0, cwnd_gain = ProbeRTTCwndGain (0.5)
    }

    fn handleProbeRTT(self: *Bbr, now: i64) void {
        // Mark connection as app-limited during ProbeRTT
        self.setAppLimited();

        if (self.probe_rtt_done_stamp == 0 and
            self.inflight <= self.probeRTTCwnd())
        {
            self.probe_rtt_done_stamp = now + probe_rtt_duration_ns;
            self.probe_rtt_round_done = false;
            self.startRound();
        } else if (self.probe_rtt_done_stamp != 0) {
            if (self.round_start) {
                self.probe_rtt_round_done = true;
            }
            if (self.probe_rtt_round_done) {
                self.checkProbeRTTDone(now);
            }
        }
    }

    fn probeRTTCwnd(self: *const Bbr) u32 {
        const probe_cwnd = self.bdpMultiple(probe_rtt_cwnd_gain);
        return @intCast(@max(probe_cwnd, min_cwnd));
    }

    fn checkProbeRTTDone(self: *Bbr, now: i64) void {
        if (self.probe_rtt_done_stamp != 0 and now > self.probe_rtt_done_stamp) {
            self.probe_rtt_min_stamp = now;
            self.restoreCwnd();
            self.exitProbeRTT(now);
        }
    }

    fn exitProbeRTT(self: *Bbr, now: i64) void {
        self.resetShortTermModel();
        if (self.full_bw_reached) {
            self.startProbeBW_DOWN(now);
            self.startProbeBW_CRUISE();
        } else {
            self.enterStartup();
        }
    }

    fn saveCwnd(self: *Bbr) void {
        if (!self.in_loss_recovery and self.state != .probe_rtt) {
            self.prior_cwnd = self.cwnd;
        } else {
            self.prior_cwnd = @max(self.prior_cwnd, self.cwnd);
        }
    }

    fn restoreCwnd(self: *Bbr) void {
        self.cwnd = @max(self.cwnd, self.prior_cwnd);
        self.in_loss_recovery = false;
    }

    fn saveStateUponLoss(self: *Bbr) void {
        self.undo_state = self.state;
        self.undo_probe_bw_phase = self.probe_bw_phase;
        self.undo_bw_shortterm = self.bw_shortterm;
        self.undo_inflight_shortterm = self.inflight_shortterm;
        self.undo_inflight_longterm = self.inflight_longterm;
    }

    /// BBRHandleSpuriousLossDetection (spec 5.5.11.2)
    /// Called when a loss recovery episode is declared spurious.
    pub fn handleSpuriousLossDetection(self: *Bbr) void {
        self.loss_in_round = false;
        self.resetFullBW();
        self.bw_shortterm = @max(self.bw_shortterm, self.undo_bw_shortterm);
        self.inflight_shortterm = @max(self.inflight_shortterm, self.undo_inflight_shortterm);
        self.inflight_longterm = @max(self.inflight_longterm, self.undo_inflight_longterm);
        // If flow was probing bandwidth, return to that state
        const undo_is_probe_bw_up = (self.undo_state == .probe_bw and
            self.undo_probe_bw_phase == .up);
        const same_state = (self.state == self.undo_state) and
            (self.state != .probe_bw or self.probe_bw_phase == self.undo_probe_bw_phase);
        if (self.state != .probe_rtt and !same_state) {
            if (self.undo_state == .startup) {
                self.enterStartup();
            } else if (undo_is_probe_bw_up) {
                // undo_state == ProbeBW_UP: use max_bw as proxy for RS.delivery_rate
                const dummy_rs = RateSample{ .delivery_rate = self.max_bw };
                self.startProbeBW_UP(dummy_rs, self.cycle_stamp);
            }
        }
    }

    /// BBROnEnterRTO (spec 5.6.4.4): severe loss response (RTO-equivalent).
    /// Saves cwnd and state, then reduces cwnd to allow 1 packet.
    pub fn onSevereLoss(self: *Bbr) void {
        self.saveCwnd();
        self.saveStateUponLoss();
        self.in_loss_recovery = true;
        self.cwnd = @as(u32, self.inflight) +| max_datagram_size;
    }

    // ------------------------------------------------------------------
    // Internal: Idle Restart (spec 5.4.1)
    // ------------------------------------------------------------------

    fn handleRestartFromIdle(self: *Bbr, now: i64) void {
        if (self.inflight == 0 and self.is_app_limited) {
            self.idle_restart = true;
            self.extra_acked_interval_start = now;
            if (self.state == .probe_bw) {
                self.setPacingRateWithGain(256); // 1.0x
            } else if (self.state == .probe_rtt) {
                self.checkProbeRTTDone(now);
            }
        }
    }

    // ------------------------------------------------------------------
    // Internal: Inflight calculations (spec 5.6.4.2)
    // ------------------------------------------------------------------

    fn bdpMultiple(self: *const Bbr, gain: u32) u64 {
        if (self.min_rtt == max_i64) return @as(u64, initial_cwnd);
        const bdp_val = self.bw * @as(u64, @intCast(self.min_rtt)) / ns_per_s;
        // u128 for gain multiply: bdp_val * 709 can approach u64 max on fast/high-RTT paths
        return @intCast(@min(bdp_val * @as(u64, gain) / 256, max_u32));
    }

    // NOTE: BBRSetSendQuantum (spec §5.6.3) is intentionally not implemented.
    // Our QUIC-like protocol sends individual UDP datagrams (1 SMSS each) without
    // TSO/GSO offload. The spec explicitly allows this (§5.5.8.2): "For QUIC, in
    // the simplest case, offload_budget is equal to the send quantum." Our implicit
    // send_quantum = offload_budget = 1 * SMSS = max_datagram_size.
    fn quantizationBudget(self: *const Bbr, inflight_cap: u64) u32 {
        var cap = inflight_cap;
        cap = @max(cap, max_datagram_size); // offload_budget = 1 SMSS
        cap = @max(cap, min_cwnd);
        if (self.state == .probe_bw and self.probe_bw_phase == .up) {
            cap += 2 * max_datagram_size;
        }
        return @intCast(@min(cap, max_u32));
    }

    fn bbrInflight(self: *const Bbr, gain: u32) u32 {
        const cap = self.bdpMultiple(gain);
        return self.quantizationBudget(cap);
    }

    fn updateMaxInflight(self: *Bbr) void {
        var cap = self.bdpMultiple(self.cwndGain());
        cap += self.extra_acked;
        self.max_inflight = self.quantizationBudget(cap);
    }

    fn targetInflight(self: *const Bbr) u32 {
        // BBRTargetInflight: min(bdp, cwnd)
        const bdp_val = self.bdp();
        return @intCast(@min(bdp_val, @as(u64, self.cwnd)));
    }

    pub fn isInflightTooHigh(lost: u64, tx_in_flight: u32) bool {
        if (tx_in_flight == 0) return false;
        return lost * loss_thresh_den > @as(u64, tx_in_flight) * loss_thresh_num;
    }

    // ------------------------------------------------------------------
    // Internal: Pacing Rate (spec 5.6.2)
    // ------------------------------------------------------------------

    fn pacingGain(self: *const Bbr) u32 {
        return switch (self.state) {
            .startup => startup_pacing_gain,
            .drain => drain_pacing_gain,
            .probe_rtt => 256, // 1.0x per spec
            .probe_bw => switch (self.probe_bw_phase) {
                .down => probe_bw_down_pacing,
                .cruise => probe_bw_cruise_pacing,
                .refill => probe_bw_refill_pacing,
                .up => probe_bw_up_pacing,
            },
        };
    }

    fn cwndGain(self: *const Bbr) u32 {
        return switch (self.state) {
            .startup => default_cwnd_gain,
            .drain => default_cwnd_gain,
            .probe_rtt => probe_rtt_cwnd_gain,
            .probe_bw => switch (self.probe_bw_phase) {
                .up => probe_bw_up_cwnd_gain,
                else => default_cwnd_gain,
            },
        };
    }

    fn setPacingRateWithGain(self: *Bbr, gain: u32) void {
        const rate = self.bw * @as(u64, gain) / 256 * (100 - pacing_margin_percent) / 100;
        if (self.full_bw_reached or rate > self.pacing_rate) {
            self.pacing_rate = rate;
        }
    }

    fn setPacingRate(self: *Bbr) void {
        self.boundBWForModel();
        if (self.bw == 0) return;
        self.setPacingRateWithGain(self.pacingGain());
    }

    // ------------------------------------------------------------------
    // Internal: Cwnd (spec 5.6.4)
    // ------------------------------------------------------------------

    fn setCwnd(self: *Bbr, rs: RateSample) void {
        self.updateMaxInflight();

        if (self.full_bw_reached) {
            // Grow up to max_inflight
            var new_cwnd = @as(u64, self.cwnd) + @as(u64, rs.newly_acked);
            new_cwnd = @min(new_cwnd, @as(u64, self.max_inflight));
            self.cwnd = @intCast(@min(new_cwnd, max_u32));
        } else if (self.cwnd < self.max_inflight or self.delivered < initial_cwnd) {
            self.cwnd +|= rs.newly_acked;
        }

        self.cwnd = @max(self.cwnd, min_cwnd);
        self.cwnd = @min(self.cwnd, self.max_cwnd);
        self.boundCwndForProbeRTT();
        self.boundCwndForModel();
    }

    fn boundCwndForProbeRTT(self: *Bbr) void {
        if (self.state == .probe_rtt) {
            self.cwnd = @min(self.cwnd, self.probeRTTCwnd());
        }
    }

    fn boundCwndForModel(self: *Bbr) void {
        // Spec 5.6.4.7: BBRBoundCwndForModel
        var cap: u64 = max_u64;

        if (self.state == .probe_bw and self.probe_bw_phase != .cruise) {
            cap = @as(u64, self.inflight_longterm);
        } else if (self.state == .probe_rtt or
            (self.state == .probe_bw and self.probe_bw_phase == .cruise))
        {
            cap = @as(u64, self.inflightWithHeadroom());
        }

        // Apply inflight_shortterm
        cap = @min(cap, @as(u64, self.inflight_shortterm));
        cap = @max(cap, min_cwnd);
        if (cap < max_u64) {
            self.cwnd = @intCast(@min(@as(u64, self.cwnd), cap));
        }
    }
};

// ---------------------------------------------------------------------------
// Pacer
// ---------------------------------------------------------------------------

pub const Pacer = struct {
    next_send_time: i64 = 0,
    /// Remaining burst budget in bytes. When the pacer fires, it grants
    /// send_quantum bytes that can be sent without per-packet pacing.
    /// This amortizes poll() overhead (millisecond granularity) for sub-ms
    /// pacing intervals. Matches QUIC implementations (quinn, quiche,
    /// quic-go) that send aggregated bursts on each timer tick.
    burst_remaining: u32 = 0,

    /// Low bandwidth threshold below which bursting is limited to 1 packet.
    /// Matches Cloudflare quiche's LUMPY_PACING_MIN_BANDWIDTH_KBPS = 1.2 Mbps.
    const low_bw_threshold: u64 = 150_000; // 1.2 Mbps = 150 KB/s

    /// Initial burst size after quiescence (idle → sending), in packets.
    /// Matches Cloudflare quiche's INITIAL_UNPACED_BURST = 10.
    const initial_burst_packets: u32 = 10;

    pub fn canSend(self: *const Pacer, now: i64) bool {
        return self.burst_remaining > 0 or now >= self.next_send_time;
    }

    pub fn onSend(self: *Pacer, now: i64, packet_size: u32, pacing_rate: u64, inflight: u32, cwnd: u32) void {
        if (self.burst_remaining >= packet_size) {
            self.burst_remaining -= packet_size;
            return;
        }
        self.burst_remaining = 0;

        // Determine burst size based on congestion state:
        // - Cwnd-limited: single packet (don't overshoot the window)
        // - Low bandwidth: single packet (~10ms of queuing per packet)
        // - Normal: full send_quantum per spec §5.6.3
        const quantum = if (inflight +| packet_size >= cwnd)
            packet_size // cwnd-limited
        else if (pacing_rate < low_bw_threshold)
            packet_size // low bandwidth
        else
            sendQuantum(pacing_rate);

        if (pacing_rate == 0) {
            self.next_send_time = now;
            self.burst_remaining = quantum -| packet_size;
            return;
        }

        // Schedule next burst after quantum bytes worth of pacing time.
        const burst_interval_ns: i64 = @intCast(@as(u64, quantum) * ns_per_s / pacing_rate);

        if (now >= self.next_send_time) {
            self.next_send_time = now + burst_interval_ns;
        } else {
            self.next_send_time += burst_interval_ns;
        }
        self.burst_remaining = quantum -| packet_size;
    }

    /// Grant an initial burst after quiescence (connection was idle).
    /// Matches Cloudflare quiche's INITIAL_UNPACED_BURST = 10 packets.
    pub fn onIdleRestart(self: *Pacer) void {
        self.burst_remaining = initial_burst_packets * max_datagram_size;
    }

    /// Clear burst budget on loss (stop bursting during recovery).
    pub fn onLoss(self: *Pacer) void {
        self.burst_remaining = 0;
    }

    /// BBRSetSendQuantum (spec §5.6.3):
    ///   C.send_quantum = C.pacing_rate * 1ms
    ///   C.send_quantum = min(C.send_quantum, 64 KBytes)
    ///   C.send_quantum = max(C.send_quantum, 2 * C.SMSS)
    fn sendQuantum(pacing_rate: u64) u32 {
        const floor = 2 * max_datagram_size; // 2 SMSS
        const ceil = 65535; // 64 KBytes
        if (pacing_rate == 0) return floor;
        // pacing_rate (bytes/sec) * 1ms = pacing_rate / 1000
        const dynamic: u64 = pacing_rate / 1000;
        return @intCast(@min(ceil, @max(floor, dynamic)));
    }

    pub fn pollTimeoutMs(self: *const Pacer, now: i64) i32 {
        if (self.burst_remaining > 0 or now >= self.next_send_time) return 0;
        const remaining_ns = self.next_send_time - now;
        const ms = @divFloor(remaining_ns, std.time.ns_per_ms);
        return @intCast(@max(@as(i64, 0), @min(ms, 1000)));
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "MaxFilter 2-cycle windowed max" {
    var f = MaxFilter{};
    try std.testing.expectEqual(@as(u64, 0), f.getBest());

    // Cycle 0: sample 100
    f.update(100, 0, 2);
    try std.testing.expectEqual(@as(u64, 100), f.getBest());

    // Cycle 0: sample 200 replaces
    f.update(200, 0, 2);
    try std.testing.expectEqual(@as(u64, 200), f.getBest());

    // Cycle 1: lower sample doesn't replace best
    f.update(150, 1, 2);
    try std.testing.expectEqual(@as(u64, 200), f.getBest());

    // Cycle 2: window expired, lower value becomes best
    f.update(80, 2, 2);
    try std.testing.expectEqual(@as(u64, 80), f.getBest());
}

test "Bbr initial state" {
    var bbr = Bbr{};
    try std.testing.expectEqual(BbrState.startup, bbr.state);
    try std.testing.expectEqual(initial_cwnd, bbr.cwnd);
    try std.testing.expect(bbr.canSend());
    try std.testing.expectEqual(@as(u32, 0), bbr.inflight);
    try std.testing.expect(!bbr.full_bw_reached);
    try std.testing.expectEqual(@as(u64, max_u64), bbr.bw_shortterm);
    try std.testing.expectEqual(@as(u32, max_u32), bbr.inflight_shortterm);
    try std.testing.expectEqual(@as(u32, max_u32), bbr.inflight_longterm);
}

test "Bbr onSend tracks inflight, total_bytes_sent, and sampler state" {
    var bbr = Bbr{};
    const now: i64 = 1_000_000_000;

    const ds1 = bbr.onSend(1200, now);
    try std.testing.expectEqual(@as(u32, 1200), bbr.inflight);
    try std.testing.expectEqual(@as(u64, 1200), bbr.total_bytes_sent);
    try std.testing.expectEqual(@as(u64, 1200), ds1.total_bytes_sent);
    // Before any ack, last_acked fields are 0
    try std.testing.expectEqual(@as(u64, 0), ds1.total_bytes_sent_at_last_acked);
    try std.testing.expectEqual(@as(i64, 0), ds1.last_acked_pkt_sent_time);

    const ds2 = bbr.onSend(1200, now + 1000);
    try std.testing.expectEqual(@as(u32, 2400), bbr.inflight);
    try std.testing.expectEqual(@as(u64, 2400), bbr.total_bytes_sent);
    try std.testing.expectEqual(@as(u64, 2400), ds2.total_bytes_sent);
}

test "Bbr onAck updates delivery and max_bw" {
    var bbr = Bbr{};
    const t0: i64 = 1_000_000_000;

    // onSend returns DeliveryState (combined init+snapshot per spec §4.1.2.2)
    const ds = bbr.onSend(1200, t0);

    // Simulate ACK arriving 50ms later
    const t1 = t0 + 50 * std.time.ns_per_ms;
    bbr.onAck(.{
        .size = 1200,
        .sent_time = t0,
        .delivery_state = ds,
        .rtt_ns = 50 * std.time.ns_per_ms,
    }, 1200, t1);

    try std.testing.expectEqual(@as(u32, 0), bbr.inflight);
    try std.testing.expectEqual(@as(u64, 1200), bbr.delivered);
    try std.testing.expect(bbr.max_bw > 0);
}

test "Bbr startup to drain transition" {
    var bbr = Bbr{};
    var now: i64 = 1_000_000_000;

    // Send many packets with stable delivery rate to trigger full-pipe detection
    var seq: u32 = 0;
    while (seq < 100) : (seq += 1) {
        const ds = bbr.onSend(1200, now);
        now += 1 * std.time.ns_per_ms;

        bbr.onAck(.{
            .size = 1200,
            .sent_time = now - 1 * std.time.ns_per_ms,
            .delivery_state = ds,
            .rtt_ns = 50 * std.time.ns_per_ms,
        }, 1200, now);
    }

    // After enough rounds with stable BW, should exit startup
    try std.testing.expect(bbr.full_bw_reached);
}

test "Bbr loss response with bw_probe_samples guard" {
    var bbr = Bbr{};
    bbr.state = .probe_bw;
    bbr.probe_bw_phase = .up;
    bbr.inflight = 10000;
    bbr.max_bw = 100_000;
    bbr.bw = 100_000;
    bbr.bw_probe_samples = true;

    // Lose 500 out of 10000 in-flight (5% loss rate > 2% threshold)
    bbr.onLoss(10, 500, 500, 10000, false);
    try std.testing.expectEqual(@as(u32, 9500), bbr.inflight);
    // inflight_longterm should be reduced
    try std.testing.expect(bbr.inflight_longterm < max_u32);

    // Second loss should not react again (bw_probe_samples was cleared)
    const prev_longterm = bbr.inflight_longterm;
    bbr.bw_probe_samples = false;
    bbr.onLoss(11, 500, 1000, 10000, false);
    try std.testing.expectEqual(prev_longterm, bbr.inflight_longterm);
}

test "Pacer timing" {
    var p = Pacer{};
    const now: i64 = 1_000_000_000;

    try std.testing.expect(p.canSend(now));

    // At 1 MB/s pacing rate, send_quantum = 2400 (floor). With inflight=0, cwnd=12000.
    p.onSend(now, 1200, 1_000_000, 0, 12000);
    // Burst remaining: 2400 - 1200 = 1200, so can still send
    try std.testing.expect(p.canSend(now));
    p.onSend(now, 1200, 1_000_000, 1200, 12000);
    // Burst exhausted, must wait for next interval
    try std.testing.expect(!p.canSend(now));
    try std.testing.expect(p.canSend(now + 3 * std.time.ns_per_ms));
}

test "Pacer cwnd-limited: single packet burst" {
    var p = Pacer{};
    const now: i64 = 1_000_000_000;

    // inflight (11000) + packet (1200) >= cwnd (12000) → single packet burst
    p.onSend(now, 1200, 10_000_000, 11000, 12000);
    // After sending, burst_remaining should be 0 (single packet quantum)
    try std.testing.expectEqual(@as(u32, 0), p.burst_remaining);
}

test "Pacer low bandwidth: single packet burst" {
    var p = Pacer{};
    const now: i64 = 1_000_000_000;

    // pacing_rate = 100000 (100 KB/s) < 150000 threshold → single packet
    p.onSend(now, 1200, 100_000, 0, 12000);
    try std.testing.expectEqual(@as(u32, 0), p.burst_remaining);
}

test "Pacer idle restart: initial burst" {
    var p = Pacer{};
    const now: i64 = 1_000_000_000;

    p.onIdleRestart();
    // Should have 10 packets * 1200 = 12000 bytes of burst
    try std.testing.expectEqual(@as(u32, 10 * 1200), p.burst_remaining);

    // Can send multiple packets from burst
    try std.testing.expect(p.canSend(now));
    p.onSend(now, 1200, 1_000_000, 0, 50000);
    try std.testing.expect(p.canSend(now)); // still have burst
    try std.testing.expectEqual(@as(u32, 10800), p.burst_remaining);
}

test "Pacer loss clears burst" {
    var p = Pacer{};
    p.onIdleRestart();
    try std.testing.expect(p.burst_remaining > 0);
    p.onLoss();
    try std.testing.expectEqual(@as(u32, 0), p.burst_remaining);
}

test "Pacer normal high bandwidth: full quantum" {
    var p = Pacer{};
    const now: i64 = 1_000_000_000;

    // 10 MB/s, plenty of cwnd room → full quantum = 10000 bytes
    p.onSend(now, 1200, 10_000_000, 0, 100000);
    // quantum = 10000, burst_remaining = 10000 - 1200 = 8800
    try std.testing.expectEqual(@as(u32, 8800), p.burst_remaining);
}

test "BDP computation at realistic rates" {
    var bbr = Bbr{};
    // 100 MB/s bandwidth, 50ms RTT → BDP = 5 MB
    bbr.bw = 100_000_000;
    bbr.min_rtt = 50 * std.time.ns_per_ms;
    const result = bbr.bdp();
    try std.testing.expectEqual(@as(u64, 5_000_000), result);
}

test "rate sampling: burst send, ack_rate wins via min" {
    var bbr = Bbr{};
    const base: i64 = 1_000_000_000;

    // Send 10 packets in a burst at time T=0
    for (0..10) |_| {
        _ = bbr.onSend(1200, base);
    }

    // Simulate ACK arriving at T+50ms
    bbr.delivered = 12000;
    bbr.delivered_time = base + 50 * std.time.ns_per_ms;
    bbr.total_bytes_sent = 12000;

    const ds = DeliveryState{
        .delivered = 0,
        .delivered_time = base,
        .first_sent_time = base,
        .total_bytes_sent = 0,
        // No prior ack: send_rate invalid, ack_rate carries the sample
        .total_bytes_sent_at_last_acked = 0,
        .last_acked_pkt_sent_time = 0,
    };
    const rs = bbr.computeRateSample(.{
        .size = 1200,
        .sent_time = base,
        .delivery_state = ds,
        .rtt_ns = 50 * std.time.ns_per_ms,
    }, base + 50 * std.time.ns_per_ms);

    // send_rate: invalid (last_acked_pkt_sent_time = 0) → max_u64
    // ack_rate: 12000 / 50ms = 240000 bytes/s
    // min(max_u64, 240000) = 240000
    try std.testing.expectEqual(@as(u64, 240_000), rs.delivery_rate);
}

test "rate sampling: max interval caps short ack_elapsed" {
    var bbr = Bbr{};
    const base: i64 = 1_000_000_000;

    // Send one packet at T=0 with first_sent_time = T-25ms
    bbr.first_sent_time = base - 25 * std.time.ns_per_ms;
    bbr.delivered_time = base - 5 * std.time.ns_per_ms;
    const ds = bbr.onSend(1200, base);

    // Simulate ACK at T+5ms
    bbr.delivered = 1200;
    bbr.delivered_time = base + 5 * std.time.ns_per_ms;
    bbr.min_rtt = 5 * std.time.ns_per_ms;

    const rs = bbr.computeRateSample(.{
        .size = 1200,
        .sent_time = base,
        .delivery_state = ds,
        .rtt_ns = 5 * std.time.ns_per_ms,
    }, base + 5 * std.time.ns_per_ms);

    // send_elapsed = T=0 - (T-25ms) = 25ms
    // ack_elapsed = (T+5ms) - (T-5ms) = 10ms
    // interval = max(25ms, 10ms) = 25ms
    // rate = 1200 / 25ms = 48000
    try std.testing.expectEqual(@as(u64, 48_000), rs.delivery_rate);
}

test "A0 point selection: closest match" {
    var bbr = Bbr{};
    const base: i64 = 1_000_000_000;

    // Push A0 candidates at different delivered levels
    bbr.pushA0Candidate(.{ .ack_time = base, .total_bytes_acked = 0 });
    bbr.pushA0Candidate(.{ .ack_time = base + 10 * std.time.ns_per_ms, .total_bytes_acked = 5000 });
    bbr.pushA0Candidate(.{ .ack_time = base + 20 * std.time.ns_per_ms, .total_bytes_acked = 10000 });

    // Target 7000: should pick the candidate with 5000 (closest below)
    const a0 = bbr.selectA0(7000);
    try std.testing.expect(a0 != null);
    try std.testing.expectEqual(@as(u64, 5000), a0.?.total_bytes_acked);

    // Target 15000: should pick 10000
    const a1 = bbr.selectA0(15000);
    try std.testing.expect(a1 != null);
    try std.testing.expectEqual(@as(u64, 10000), a1.?.total_bytes_acked);

    // Target 0: only candidate with 0 qualifies
    const a2 = bbr.selectA0(0);
    try std.testing.expect(a2 != null);
    try std.testing.expectEqual(@as(u64, 0), a2.?.total_bytes_acked);
}

test "A0 point deque eviction" {
    var bbr = Bbr{};
    // Push more than a0_capacity candidates
    for (0..a0_capacity + 4) |i| {
        bbr.pushA0Candidate(.{ .ack_time = @intCast(i * 1000), .total_bytes_acked = @intCast(i * 100) });
    }
    // Should have exactly a0_capacity entries
    try std.testing.expectEqual(a0_capacity, bbr.a0_count);
    // Oldest should have been evicted; first entry is from i=4
    try std.testing.expectEqual(@as(u64, 400), bbr.a0_candidates[0].total_bytes_acked);
}

test "isInflightTooHigh" {
    // 500 lost out of 10000 = 5% > 2% threshold
    try std.testing.expect(Bbr.isInflightTooHigh(500, 10000));
    // 100 lost out of 10000 = 1% < 2% threshold
    try std.testing.expect(!Bbr.isInflightTooHigh(100, 10000));
    // Edge case: 200 out of 10000 = 2% - not strictly greater
    try std.testing.expect(!Bbr.isInflightTooHigh(200, 10000));
    // 201 out of 10000 > 2%
    try std.testing.expect(Bbr.isInflightTooHigh(201, 10000));
    // Zero inflight
    try std.testing.expect(!Bbr.isInflightTooHigh(0, 0));
}
