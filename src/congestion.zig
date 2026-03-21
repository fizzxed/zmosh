const std = @import("std");

/// Nanoseconds per second.
const ns_per_s: u64 = std.time.ns_per_s;

// ---------------------------------------------------------------------------
// Constants (BBR v3, draft-cardwell-ccwg-bbr-00)
// ---------------------------------------------------------------------------

pub const max_datagram_size: u32 = 1200;
pub const initial_cwnd: u32 = 10 * max_datagram_size; // 12,000
pub const min_cwnd: u32 = 4 * max_datagram_size; // 4,800
const min_rtt_window_ns: i64 = 10 * std.time.ns_per_s;
const probe_rtt_duration_ns: i64 = 200 * std.time.ns_per_ms;
const probe_rtt_interval_ns: i64 = 5 * std.time.ns_per_s;
const max_bw_filter_len: u64 = 10; // round-trips
const full_pipe_rounds: u32 = 3;
const startup_loss_events: u32 = 6;

/// 8.8 fixed-point gains (256 = 1.0×)
const startup_pacing_gain: u32 = 726; // 2.89× ≈ 2/ln2
const startup_cwnd_gain: u32 = 512; // 2.0×
const drain_pacing_gain: u32 = 89; // 1/2.89×
const probe_bw_down_pacing: u32 = 230; // 0.90×
const probe_bw_cruise_pacing: u32 = 256; // 1.0×
const probe_bw_refill_pacing: u32 = 256; // 1.0×
const probe_bw_up_pacing: u32 = 320; // 1.25×
const probe_bw_up_cwnd_gain: u32 = 576; // 2.25×
const probe_bw_default_cwnd_gain: u32 = 512; // 2.0×

/// Loss response thresholds (fixed-point: 2% = 2/100)
const loss_thresh_num: u64 = 2;
const loss_thresh_den: u64 = 100;
const beta_num: u64 = 7;
const beta_den: u64 = 10;

const max_u32: u32 = std.math.maxInt(u32);
const max_u64: u64 = std.math.maxInt(u64);

// ---------------------------------------------------------------------------
// Windowed Max Filter (3-entry, for max_bw and extra_acked)
// ---------------------------------------------------------------------------

pub const MaxFilter = struct {
    const Entry = struct { val: u64, round: u64 };
    win: [3]Entry = .{ .{ .val = 0, .round = 0 }, .{ .val = 0, .round = 0 }, .{ .val = 0, .round = 0 } },

    pub fn update(self: *MaxFilter, val: u64, round: u64) void {
        // Slot 0 is the best (max). Maintain a monotone decreasing window.
        if (val >= self.win[0].val or round - self.win[0].round >= max_bw_filter_len) {
            self.win[2] = .{ .val = val, .round = round };
            self.win[1] = .{ .val = val, .round = round };
            self.win[0] = .{ .val = val, .round = round };
            return;
        }
        if (val >= self.win[1].val or round - self.win[1].round >= max_bw_filter_len) {
            self.win[2] = .{ .val = val, .round = round };
            self.win[1] = .{ .val = val, .round = round };
            return;
        }
        if (val >= self.win[2].val or round - self.win[2].round >= max_bw_filter_len) {
            self.win[2] = .{ .val = val, .round = round };
        }
    }

    pub fn getBest(self: *const MaxFilter) u64 {
        return self.win[0].val;
    }

    pub fn reset(self: *MaxFilter) void {
        self.win = .{.{ .val = 0, .round = 0 }} ** 3;
    }
};

// ---------------------------------------------------------------------------
// Min Filter (for min_rtt — 10-second sliding window)
// ---------------------------------------------------------------------------

pub const MinFilter = struct {
    val: i64 = std.math.maxInt(i64),
    stamp: i64 = 0,

    pub fn update(self: *MinFilter, sample: i64, now: i64) void {
        if (sample <= self.val or self.expired(now, min_rtt_window_ns)) {
            self.val = sample;
            self.stamp = now;
        }
    }

    pub fn expired(self: *const MinFilter, now: i64, window_ns: i64) bool {
        return (now - self.stamp) >= window_ns;
    }
};

// ---------------------------------------------------------------------------
// Delivery Rate Estimation
// ---------------------------------------------------------------------------

pub const DeliveryState = struct {
    delivered: u64 = 0,
    delivered_time: i64 = 0,
    first_sent_time: i64 = 0,
    is_app_limited: bool = false,
    tx_in_flight: u32 = 0,
};

pub const RateSample = struct {
    delivery_rate: u64 = 0,
    rtt_ns: i64 = 0,
    is_app_limited: bool = false,
    delivered: u64 = 0,
    lost: u64 = 0,
    tx_in_flight: u32 = 0,
};

// ---------------------------------------------------------------------------
// Acked packet info (passed from loss detector → BBR)
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

pub const Bbr = struct {
    state: BbrState = .startup,
    probe_bw_phase: ProbeBwPhase = .down,

    // --- Bandwidth estimation (dual bounds) ---
    max_bw: u64 = 0,
    max_bw_filter: MaxFilter = .{},
    bw_lo: u64 = max_u64,
    bw_hi: u64 = max_u64,
    bw: u64 = 0,

    // --- RTT estimation ---
    min_rtt_filter: MinFilter = .{},
    probe_rtt_min_filter: MinFilter = .{},

    // --- Inflight control (dual bounds) ---
    inflight_hi: u32 = max_u32,
    inflight_lo: u32 = max_u32,

    // --- Pacing + window ---
    pacing_rate: u64 = 0,
    cwnd: u32 = initial_cwnd,
    inflight: u32 = 0,

    // --- Delivery tracking ---
    delivered: u64 = 0,
    delivered_time: i64 = 0,
    first_sent_time: i64 = 0,

    // --- Loss tracking (v3) ---
    lost_in_round: u64 = 0,
    loss_events_in_round: u32 = 0,
    loss_round_delivered: u64 = 0,

    // --- Round tracking ---
    round_count: u64 = 0,
    round_start: bool = false,
    next_round_delivered: u64 = 0,

    // --- Startup full-pipe detection ---
    full_bw: u64 = 0,
    full_bw_count: u32 = 0,
    filled_pipe: bool = false,

    // --- ProbeBW state ---
    cycle_stamp: i64 = 0,
    probe_up_cnt: u32 = max_datagram_size,
    probe_up_rounds: u32 = 0,
    bw_probe_samples: bool = false,
    prior_cwnd: u32 = 0,

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

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    pub fn getDeliveryState(self: *const Bbr) DeliveryState {
        return .{
            .delivered = self.delivered,
            .delivered_time = self.delivered_time,
            .first_sent_time = self.first_sent_time,
            .is_app_limited = self.is_app_limited,
            .tx_in_flight = self.inflight,
        };
    }

    pub fn onSend(self: *Bbr, bytes: u32, now: i64) void {
        self.inflight += bytes;
        if (self.first_sent_time == 0) self.first_sent_time = now;
    }

    pub fn onAck(self: *Bbr, pkt: AckedPacket, now: i64) void {
        self.inflight -|= pkt.size;
        self.delivered += pkt.size;
        self.delivered_time = now;

        // Round tracking
        if (self.delivered >= self.next_round_delivered) {
            self.next_round_delivered = self.delivered;
            self.round_count += 1;
            self.round_start = true;
            // Reset per-round loss counters
            self.lost_in_round = 0;
            self.loss_events_in_round = 0;
        } else {
            self.round_start = false;
        }

        // Compute delivery rate sample
        const rs = self.computeRateSample(pkt, now);

        // Update min_rtt
        if (pkt.rtt_ns > 0) {
            self.min_rtt_filter.update(pkt.rtt_ns, now);
            self.probe_rtt_min_filter.update(pkt.rtt_ns, now);
        }

        // Update max_bw (skip app-limited samples unless they exceed current max)
        if (!rs.is_app_limited or rs.delivery_rate > self.max_bw_filter.getBest()) {
            self.max_bw_filter.update(rs.delivery_rate, self.round_count);
        }
        self.max_bw = self.max_bw_filter.getBest();

        // State machine transitions
        self.updateStateMachine(rs, now);

        // Update pacing rate and cwnd
        self.updatePacingRate();
        self.updateCwnd();
    }

    pub fn onLoss(self: *Bbr, bytes: u32, tx_in_flight: u32) void {
        self.inflight -|= bytes;
        self.lost_in_round += bytes;
        self.loss_events_in_round += 1;

        // Check if inflight is too high (>2% loss rate)
        if (isInflightTooHigh(bytes, tx_in_flight)) {
            self.onInflightTooHigh(tx_in_flight);
        }
    }

    pub fn canSend(self: *const Bbr) bool {
        return self.inflight < self.cwnd;
    }

    pub fn setAppLimited(self: *Bbr) void {
        self.is_app_limited = true;
        self.app_limited_seq = self.delivered;
    }

    pub fn bdp(self: *const Bbr) u64 {
        const min_rtt_ns = self.getMinRtt();
        if (min_rtt_ns <= 0 or self.bw == 0) return @as(u64, initial_cwnd);
        return self.bw * @as(u64, @intCast(min_rtt_ns)) / ns_per_s;
    }

    pub fn getMinRtt(self: *const Bbr) i64 {
        if (self.min_rtt_filter.val == std.math.maxInt(i64)) return 0;
        return self.min_rtt_filter.val;
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn computeRateSample(self: *const Bbr, pkt: AckedPacket, now: i64) RateSample {
        const ds = pkt.delivery_state;
        const delivered = self.delivered - ds.delivered;
        if (delivered == 0) return .{};

        const send_elapsed = pkt.sent_time - ds.first_sent_time;
        const ack_elapsed = now - ds.delivered_time;
        var interval = @max(send_elapsed, ack_elapsed);
        if (interval <= 0) interval = 1;

        const rate = delivered * ns_per_s / @as(u64, @intCast(interval));

        return .{
            .delivery_rate = rate,
            .rtt_ns = pkt.rtt_ns,
            .is_app_limited = ds.is_app_limited and self.delivered <= self.app_limited_seq,
            .delivered = delivered,
            .tx_in_flight = ds.tx_in_flight,
        };
    }

    fn updateStateMachine(self: *Bbr, rs: RateSample, now: i64) void {
        switch (self.state) {
            .startup => self.updateStartup(rs),
            .drain => self.updateDrain(),
            .probe_bw => self.updateProbeBw(rs, now),
            .probe_rtt => self.updateProbeRtt(now),
        }

        // Check if we need to enter ProbeRTT
        if (self.state != .probe_rtt and self.state != .startup) {
            if (self.probe_rtt_min_filter.expired(now, probe_rtt_interval_ns)) {
                self.enterProbeRtt(now);
            }
        }
    }

    fn updateStartup(self: *Bbr, rs: RateSample) void {
        // Check for full pipe
        if (!self.filled_pipe) {
            if (rs.delivery_rate > 0) {
                if (self.full_bw == 0 or rs.delivery_rate >= self.full_bw + self.full_bw / 4) {
                    // 25% growth
                    self.full_bw = rs.delivery_rate;
                    self.full_bw_count = 0;
                } else if (self.round_start) {
                    self.full_bw_count += 1;
                    if (self.full_bw_count >= full_pipe_rounds) {
                        self.filled_pipe = true;
                    }
                }
            }
        }

        // Loss-based startup exit (v3)
        if (self.round_start and self.loss_events_in_round >= startup_loss_events) {
            self.filled_pipe = true;
        }

        if (self.filled_pipe) {
            self.state = .drain;
        }
    }

    fn updateDrain(self: *Bbr) void {
        if (self.inflight <= @as(u32, @intCast(@min(self.bdp(), max_u32)))) {
            self.enterProbeBwDown(0); // now=0 is fine, cycle_stamp set on first real call
        }
    }

    fn updateProbeBw(self: *Bbr, rs: RateSample, now: i64) void {
        switch (self.probe_bw_phase) {
            .down => {
                const target = self.targetInflight();
                if (self.inflight <= target or self.elapsedSincePhase(now) >= self.getMinRtt()) {
                    self.enterProbeBwCruise(now);
                }
            },
            .cruise => {
                // Probe timer: stay in cruise for ~1 RTT, then probe
                if (self.elapsedSincePhase(now) >= @max(self.getMinRtt(), 50 * std.time.ns_per_ms)) {
                    self.enterProbeBwRefill(now);
                }
            },
            .refill => {
                // 1 round elapsed → transition to UP
                if (self.round_start) {
                    // Reset short-term bounds
                    self.bw_lo = max_u64;
                    self.inflight_lo = max_u32;
                    self.enterProbeBwUp(now);
                }
            },
            .up => {
                // Exit on loss or exceeded inflight
                if (self.loss_events_in_round > 0 and self.round_start) {
                    self.enterProbeBwDown(now);
                    return;
                }
                // Check if we've probed long enough
                if (self.round_start) {
                    self.probe_up_rounds += 1;
                }
                _ = rs;
                const bdp_val = self.bdp();
                const threshold = bdp_val + bdp_val / 4; // 1.25 × BDP
                if (self.inflight >= @as(u32, @intCast(@min(threshold, max_u32)))) {
                    if (self.elapsedSincePhase(now) >= self.getMinRtt()) {
                        self.enterProbeBwDown(now);
                    }
                }
            },
        }
    }

    fn updateProbeRtt(self: *Bbr, now: i64) void {
        if (self.probe_rtt_done_stamp == 0) {
            // First ACK in ProbeRTT — set timer
            if (self.inflight <= min_cwnd) {
                self.probe_rtt_done_stamp = now + probe_rtt_duration_ns;
                self.probe_rtt_round_done = false;
                self.next_round_delivered = self.delivered;
            }
            return;
        }

        if (self.round_start) {
            self.probe_rtt_round_done = true;
        }

        if (self.probe_rtt_round_done and now >= self.probe_rtt_done_stamp) {
            // Reset min_rtt probe timer
            self.probe_rtt_min_filter.stamp = now;
            // Restore cwnd and enter ProbeBW DOWN
            self.cwnd = @max(self.prior_cwnd, min_cwnd);
            self.enterProbeBwDown(now);
        }
    }

    fn enterProbeBwDown(self: *Bbr, now: i64) void {
        self.state = .probe_bw;
        self.probe_bw_phase = .down;
        self.cycle_stamp = now;
        self.probe_up_rounds = 0;
        self.bw_probe_samples = false;
    }

    fn enterProbeBwCruise(self: *Bbr, now: i64) void {
        self.probe_bw_phase = .cruise;
        self.cycle_stamp = now;
    }

    fn enterProbeBwRefill(self: *Bbr, now: i64) void {
        self.probe_bw_phase = .refill;
        self.cycle_stamp = now;
    }

    fn enterProbeBwUp(self: *Bbr, now: i64) void {
        self.probe_bw_phase = .up;
        self.cycle_stamp = now;
        self.probe_up_rounds = 0;
        self.probe_up_cnt = max_datagram_size;
        self.bw_probe_samples = true;
    }

    fn enterProbeRtt(self: *Bbr, now: i64) void {
        self.prior_cwnd = self.cwnd;
        self.state = .probe_rtt;
        self.probe_rtt_done_stamp = 0;
        self.probe_rtt_round_done = false;
        _ = now;
    }

    fn elapsedSincePhase(self: *const Bbr, now: i64) i64 {
        if (self.cycle_stamp == 0) return 0;
        return now - self.cycle_stamp;
    }

    fn targetInflight(self: *const Bbr) u32 {
        const bdp_val = self.bdp();
        var target: u64 = bdp_val;
        // Cap by inflight_hi/inflight_lo
        if (self.inflight_hi != max_u32)
            target = @min(target, @as(u64, self.inflight_hi));
        if (self.inflight_lo != max_u32)
            target = @min(target, @as(u64, self.inflight_lo));
        return @intCast(@max(@min(target, max_u32), min_cwnd));
    }

    fn onInflightTooHigh(self: *Bbr, tx_in_flight: u32) void {
        // inflight_hi = max(inflight, target) * beta
        const base = @max(@as(u64, tx_in_flight), self.bdp());
        self.inflight_hi = @intCast(@min(base * beta_num / beta_den, max_u32));
        self.bw_hi = self.max_bw;

        if (self.state == .startup) {
            self.filled_pipe = true;
        }
    }

    fn isInflightTooHigh(lost: u32, tx_in_flight: u32) bool {
        if (tx_in_flight == 0) return false;
        return @as(u64, lost) * loss_thresh_den > @as(u64, tx_in_flight) * loss_thresh_num;
    }

    fn pacingGain(self: *const Bbr) u32 {
        return switch (self.state) {
            .startup => startup_pacing_gain,
            .drain => drain_pacing_gain,
            .probe_rtt => probe_bw_cruise_pacing, // 1.0×
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
            .startup => startup_cwnd_gain,
            .drain => startup_cwnd_gain,
            .probe_rtt => probe_bw_default_cwnd_gain,
            .probe_bw => switch (self.probe_bw_phase) {
                .up => probe_bw_up_cwnd_gain,
                else => probe_bw_default_cwnd_gain,
            },
        };
    }

    fn updatePacingRate(self: *Bbr) void {
        // effective bw = min(max_bw, bw_lo, bw_hi)
        var eff_bw = self.max_bw;
        if (self.bw_lo != max_u64) eff_bw = @min(eff_bw, self.bw_lo);
        if (self.bw_hi != max_u64) eff_bw = @min(eff_bw, self.bw_hi);
        self.bw = eff_bw;

        if (eff_bw == 0) return;

        // pacing_rate = bw * pacing_gain / 256 * (1 - pacing_margin)
        const gain = self.pacingGain();
        const rate = eff_bw * @as(u64, gain) / 256;
        // Apply 1% pacing margin: rate * 99/100
        self.pacing_rate = rate * 99 / 100;
    }

    fn updateCwnd(self: *Bbr) void {
        if (self.state == .probe_rtt) {
            self.cwnd = min_cwnd;
            return;
        }

        const bdp_val = self.bdp();
        const gain = self.cwndGain();
        var new_cwnd = @as(u64, bdp_val) * @as(u64, gain) / 256;

        // Cap by inflight_hi in ProbeBW
        if (self.state == .probe_bw and self.inflight_hi != max_u32) {
            new_cwnd = @min(new_cwnd, @as(u64, self.inflight_hi));
        }

        new_cwnd = @max(new_cwnd, min_cwnd);
        self.cwnd = @intCast(@min(new_cwnd, max_u32));
    }
};

// ---------------------------------------------------------------------------
// Pacer
// ---------------------------------------------------------------------------

pub const Pacer = struct {
    next_send_time: i64 = 0,

    pub fn canSend(self: *const Pacer, now: i64) bool {
        return now >= self.next_send_time;
    }

    pub fn onSend(self: *Pacer, now: i64, packet_size: u32, pacing_rate: u64) void {
        if (pacing_rate == 0) {
            self.next_send_time = now;
            return;
        }

        const interval_ns: i64 = @intCast(@as(u64, packet_size) * ns_per_s / pacing_rate);

        if (now >= self.next_send_time) {
            // If behind schedule, reset to now (no burst catch-up)
            self.next_send_time = now + interval_ns;
        } else {
            self.next_send_time += interval_ns;
        }
    }

    pub fn pollTimeoutMs(self: *const Pacer, now: i64) i32 {
        if (now >= self.next_send_time) return 0;
        const remaining_ns = self.next_send_time - now;
        const ms = @divFloor(remaining_ns, std.time.ns_per_ms);
        return @intCast(@max(@as(i64, 0), @min(ms, 1000)));
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "MaxFilter basic" {
    var f = MaxFilter{};
    try std.testing.expectEqual(@as(u64, 0), f.getBest());

    f.update(100, 1);
    try std.testing.expectEqual(@as(u64, 100), f.getBest());

    f.update(200, 2);
    try std.testing.expectEqual(@as(u64, 200), f.getBest());

    // Lower value doesn't replace best
    f.update(50, 3);
    try std.testing.expectEqual(@as(u64, 200), f.getBest());

    // After window expires, new lower value becomes best
    f.update(80, 15);
    try std.testing.expectEqual(@as(u64, 80), f.getBest());
}

test "MinFilter basic" {
    var f = MinFilter{};
    const now: i64 = 1_000_000_000;

    f.update(100, now);
    try std.testing.expectEqual(@as(i64, 100), f.val);

    // Lower value replaces
    f.update(50, now + 1);
    try std.testing.expectEqual(@as(i64, 50), f.val);

    // Higher value doesn't replace
    f.update(200, now + 2);
    try std.testing.expectEqual(@as(i64, 50), f.val);

    // After window expires, new higher value replaces
    f.update(150, now + min_rtt_window_ns + 1);
    try std.testing.expectEqual(@as(i64, 150), f.val);
}

test "Bbr initial state" {
    var bbr = Bbr{};
    try std.testing.expectEqual(BbrState.startup, bbr.state);
    try std.testing.expectEqual(initial_cwnd, bbr.cwnd);
    try std.testing.expect(bbr.canSend());
    try std.testing.expectEqual(@as(u32, 0), bbr.inflight);
}

test "Bbr onSend tracks inflight" {
    var bbr = Bbr{};
    const now: i64 = 1_000_000_000;

    bbr.onSend(1200, now);
    try std.testing.expectEqual(@as(u32, 1200), bbr.inflight);

    bbr.onSend(1200, now + 1000);
    try std.testing.expectEqual(@as(u32, 2400), bbr.inflight);
}

test "Bbr onAck updates delivery" {
    var bbr = Bbr{};
    const t0: i64 = 1_000_000_000;

    // Simulate sending
    const ds = bbr.getDeliveryState();
    bbr.onSend(1200, t0);

    // Simulate ACK arriving 50ms later
    const t1 = t0 + 50 * std.time.ns_per_ms;
    bbr.onAck(.{
        .size = 1200,
        .sent_time = t0,
        .delivery_state = ds,
        .rtt_ns = 50 * std.time.ns_per_ms,
    }, t1);

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
        const ds = bbr.getDeliveryState();
        bbr.onSend(1200, now);
        now += 1 * std.time.ns_per_ms;

        bbr.onAck(.{
            .size = 1200,
            .sent_time = now - 1 * std.time.ns_per_ms,
            .delivery_state = ds,
            .rtt_ns = 50 * std.time.ns_per_ms,
        }, now);
    }

    // After enough rounds with stable BW, should exit startup
    try std.testing.expect(bbr.filled_pipe);
}

test "Bbr loss response" {
    var bbr = Bbr{};
    bbr.state = .probe_bw;
    bbr.probe_bw_phase = .up;
    bbr.inflight = 10000;
    bbr.max_bw = 100_000;

    // Lose 500 out of 10000 in-flight (5% loss rate > 2% threshold)
    bbr.onLoss(500, 10000);
    try std.testing.expectEqual(@as(u32, 9500), bbr.inflight);
    // inflight_hi should be reduced
    try std.testing.expect(bbr.inflight_hi < max_u32);
}

test "Pacer timing" {
    var p = Pacer{};
    const now: i64 = 1_000_000_000;

    try std.testing.expect(p.canSend(now));

    // At 1 MB/s pacing rate, 1200 byte packet → 1.2ms interval
    p.onSend(now, 1200, 1_000_000);
    try std.testing.expect(!p.canSend(now));
    try std.testing.expect(p.canSend(now + 2 * std.time.ns_per_ms));

    // Poll timeout should reflect remaining time
    const timeout = p.pollTimeoutMs(now);
    try std.testing.expect(timeout >= 0);
    try std.testing.expect(timeout <= 2);
}

test "Pacer no burst catchup" {
    var p = Pacer{};
    const now: i64 = 1_000_000_000;
    p.onSend(now, 1200, 1_000_000);

    // If we fall behind schedule, reset to now
    const late = now + 100 * std.time.ns_per_ms;
    try std.testing.expect(p.canSend(late));
    p.onSend(late, 1200, 1_000_000);
    // next_send_time should be late + interval, not catching up
    try std.testing.expect(p.next_send_time > late);
}

test "isInflightTooHigh" {
    // 500 lost out of 10000 = 5% > 2% threshold
    try std.testing.expect(Bbr.isInflightTooHigh(500, 10000));
    // 100 lost out of 10000 = 1% < 2% threshold
    try std.testing.expect(!Bbr.isInflightTooHigh(100, 10000));
    // Edge case: 200 out of 10000 = 2% — not strictly greater
    try std.testing.expect(!Bbr.isInflightTooHigh(200, 10000));
    // 201 out of 10000 > 2%
    try std.testing.expect(Bbr.isInflightTooHigh(201, 10000));
}
