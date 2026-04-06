//! C4 congestion control algorithm.
//!
//! Port of picoquic's c4.c (Christian Huitema, 2025) to Zig.
//!
//! C4 is a rate-based CCA with four main states:
//!
//! - initial:  Hystart-like slow start. CWND doubles each RTT until a signal
//!             (sustained RTT inflation, loss) indicates we should exit.
//! - recovery: Freeze for one RTT after a congestion event, giving time to
//!             measure whether the previous push actually moved things.
//! - cruising: Hold nominal rate for N cruise periods (Fibonacci backoff on
//!             the probe level), then push. Listen for delay/loss signals.
//! - pushing:  One RTT of probing 3.125%..25% above nominal to look for
//!             available headroom, then transition to recovery.
//!
//! The algorithm tracks `nominal_rate` (bytes/sec) and `nominal_max_rtt`
//! (microseconds) as its control variables. CWND is derived from them:
//! `cwnd = nominal_max_rtt * pacing_rate / 1_000_000`, with a margin added in
//! the non-initial states.
//!
//! Sensitivity curve: flows below 50 kB/s are treated as insensitive; between
//! 50 kB/s and 10 MB/s the sensitivity ramps up; above 10 MB/s the flow reacts
//! fully to loss/delay signals. This keeps short or low-rate flows (like a
//! terminal session's heartbeat) from being shoved around by a single delayed
//! ACK, while letting bulk transfers reliably back off.
//!
//! All arithmetic is integer. Ratios use 1024-scale fixed point (so `alpha =
//! 1024` means 100%). Rates are bytes/sec, RTTs are microseconds, CWND is
//! bytes.

const std = @import("std");

// -- Constants --------------------------------------------------------------

/// Ceiling on the delay threshold, 25 ms in microseconds.
pub const delay_threshold_max_us: u64 = 25_000;

/// 1024-scale alpha values. `alpha = 1024` means "pacing rate = nominal".
pub const alpha_neutral_1024: u64 = 1024; // 100%
pub const alpha_recover_1024: u64 = 960; // 93.75% — first-stage recovery
pub const alpha_recover2_1024: u64 = 896; // 87.5% — second-stage recovery
pub const alpha_cruise_1024: u64 = 1024; // 100% — cruise
pub const alpha_push_1024: u64 = 1280; // 125% — aggressive push
pub const alpha_push_low_1024: u64 = 1088; // 106.25% — moderate push
pub const alpha_push_very_low_1024: u64 = 1056; // 103.125% — cautious push
pub const alpha_initial: u64 = 2048; // 200% — slow-start multiplier
pub const alpha_previous_low: u64 = 960;

/// Loss-event beta: 25%, i.e. drop nominal rate by 1/4 on a sustained loss.
pub const beta_loss_1024: u64 = 256;

/// Number of packets we tolerate in startup before exiting on first loss.
pub const nb_packets_before_loss: u64 = 20;

/// Default number of cruise periods before we enter the push phase.
pub const nb_cruise_before_push: u64 = 4;

/// Extra RTT margin baked into non-initial CWND to smooth over jitter.
pub const rtt_margin_delay_us: u64 = 15_000;

/// Lower bound on `nominal_max_rtt`. Clamped to 1 ms.
pub const max_rtt_min_us: u64 = 1000;

/// Cap on sample-to-running jitter to avoid aberrant max-RTT inflation.
pub const max_jitter_us: u64 = 250_000;

pub const probe_level_max: u8 = 3;
pub const probe_level_default: u8 = 1;

/// Push-rate alpha by probe level. Level 3 matches the "aggressive" level 2
/// rate; the divergence is in cruise-cycle count, not push amplitude.
pub const push_rate_by_probe_level: [probe_level_max + 1]u64 = .{
    alpha_push_very_low_1024,
    alpha_push_low_1024,
    alpha_push_1024,
    alpha_push_1024,
};

/// EWMA parameters for the per-packet loss-rate estimator. Matches
/// picoquic's `PICOQUIC_SMOOTHED_LOSS_*` constants.
pub const smoothed_loss_scope: u64 = 32;
pub const smoothed_loss_factor: f64 = 0.125; // 1/8

// -- Enums ------------------------------------------------------------------

pub const AlgState = enum(u8) {
    initial = 0,
    recovery,
    cruising,
    pushing,
};

pub const CongestionMode = enum(u8) {
    none = 0,
    delay,
    loss,
};

// -- CC context interface ---------------------------------------------------

/// Minimal surface of the transport path/connection that C4 reads and writes.
/// Corresponds to the subset of picoquic's `picoquic_path_t` that `c4.c`
/// actually touches. The transport layer owns and populates this; C4 only
/// reads measurements and writes back `cwnd` and pacing parameters.
pub const CcContext = struct {
    // -- Path measurements (read-only for C4) -------------------------------

    /// Maximum segment size the path will send.
    send_mtu: u32,
    /// Current smoothed RTT in microseconds.
    smoothed_rtt_us: u64,
    /// Latest RTT sample in microseconds.
    rtt_sample_us: u64,
    /// RTT variance (RFC 6298 rttvar) in microseconds.
    rtt_variant_us: u64,
    /// Delivery-rate estimate in bytes/sec. Updated by the transport on ACK.
    bandwidth_estimate_bps: u64,
    /// Highest delivery rate ever observed.
    peak_bandwidth_estimate_bps: u64,
    /// Bytes sent but not yet acknowledged.
    bytes_in_transit: u64,
    /// Time (microseconds, monotonic) the most recent ack'd data frame was sent.
    last_time_acked_data_frame_sent_us: u64,
    /// Most recent time the sender was application-limited.
    last_sender_limited_time_us: u64,

    // -- CC outputs (written by C4) -----------------------------------------

    /// Current congestion window, in bytes. Set by `applyRateAndCwin`.
    cwnd: u64,
    /// True once C4 has committed to a non-initial CWND.
    is_ssthresh_initialized: bool,

    // -- Hooks the transport must provide -----------------------------------

    /// Lowest in-flight packet number that has not yet been acknowledged.
    /// Used for era tracking (`eraCheck`).
    lowest_not_ack_fn: *const fn (ctx: *anyopaque) u64,
    /// Next packet number to send. Used to seed `era_sequence`.
    next_sequence_number_fn: *const fn (ctx: *anyopaque) u64,
    /// Apply a newly-computed pacing rate (bytes/sec) and burst quantum (bytes).
    update_pacing_rate_fn: *const fn (ctx: *anyopaque, rate_bps: u64, quantum: u64) void,
    /// Opaque transport pointer passed to the hooks.
    transport_ctx: *anyopaque,
    /// True once the transport is out of its handshake / ready to produce
    /// meaningful era measurements.
    is_ready: bool,
};

/// Per-ACK state fed to `notifyAck`. Mirrors picoquic's
/// `picoquic_per_ack_state_t` down to only what C4 uses.
pub const AckState = struct {
    /// RTT of this ACK in microseconds. Zero if no new RTT sample.
    rtt_measurement_us: u64 = 0,
    /// Bytes delivered over the interval (send_time..ack_time) of the newly
    /// acked packet. Used for the "not-limited" test in `handleAck`.
    nb_bytes_delivered_since_packet_sent: u64 = 0,
    /// Bytes freshly acknowledged by this ACK.
    nb_bytes_acknowledged: u64 = 0,
    /// Packet number of a lost packet (only for the repeat notification).
    lost_packet_number: u64 = 0,
};

// -- Internal C4 state ------------------------------------------------------

pub const State = struct {
    alg_state: AlgState = .initial,

    /// Nominal sending rate in bytes/sec. C4's primary control variable.
    nominal_rate: u64 = 0,
    /// Estimate of the queue-free max RTT, microseconds.
    nominal_max_rtt_us: u64 = 0,
    /// CWND snapshot maintained while in the initial phase.
    initial_cwnd: u64 = 0,
    /// Coarse running estimate of min RTT, microseconds.
    running_min_rtt_us: u64 = std.math.maxInt(u64),

    /// Current and previous alpha (1024-scale). `alpha_current` multiplies
    /// nominal_rate to produce the pacing rate.
    alpha_1024_current: u64 = alpha_initial,
    alpha_1024_previous: u64 = 0,

    /// Count of packets sent since entering the initial phase. Rough bound
    /// on how long we will tolerate loss before exiting.
    nb_packets_in_startup: u64 = 0,

    /// Packet number of the first packet sent in the current era. An era
    /// ends when this number is acknowledged.
    era_sequence: u64 = 0,

    /// Cruise cycles remaining before transitioning to push.
    nb_cruise_left_before_push: u64 = 0,

    /// Seeded CWND from a previous trial (optional).
    seed_cwnd: u64 = 0,
    seed_rate_bps: u64 = 0,

    /// Probe level (0..probe_level_max). Controls push amplitude and the
    /// number of cruise cycles before pushing.
    probe_level: u8 = probe_level_default,
    nb_eras_no_increase: u32 = 0,

    /// Rate and alpha at the start of the most recent push; used by
    /// `growthEvaluate` to decide whether the push found any headroom.
    push_rate_old: u64 = 0,
    push_alpha: u64 = 0,

    /// Per-era min/max RTT samples, used to update `nominal_max_rtt_us`.
    era_max_rtt_us: u64 = 0,
    era_min_rtt_us: u64 = std.math.maxInt(u64),

    /// Current delay threshold (microseconds) derived from sensitivity.
    delay_threshold_us: u64 = 0,
    /// Excess delay observed on the latest sample above `delay_threshold_us`.
    recent_delay_excess_us: u64 = 0,

    /// Loss-rate tracking.
    last_lost_packet_number: u64 = 0,
    smoothed_drop_rate: f64 = 0,

    /// Sticky signal that a congestion event has been observed during the
    /// current era. Cleared by `growthReset`.
    congestion_notified: bool = false,
    /// Set when the push-era measurement indicates that the application was
    /// not limiting the send rate (i.e. the measurement is trustworthy).
    push_was_not_limited: bool = false,
    /// Seed CWND is active.
    use_seed_cwnd: bool = false,
    /// We have already re-entered Initial once due to jitter; don't do it
    /// again.
    initial_after_jitter: bool = false,

    pub fn init() State {
        return .{};
    }
};

// -- Helpers ----------------------------------------------------------------

/// `MULT1024(c, v)` in picoquic: `(v * c) >> 10`, i.e. multiply by a 1024-scale
/// fixed-point ratio.
inline fn mult1024(c: u64, v: u64) u64 {
    return (v *% c) >> 10;
}

/// `PICOQUIC_BYTES_FROM_RATE(rtt_us, rate_bps)` = rate * rtt / 1e6
inline fn bytesFromRate(rtt_us: u64, rate_bps: u64) u64 {
    return (rate_bps *% rtt_us) / 1_000_000;
}

/// `PICOQUIC_RATE_FROM_BYTES(bytes, rtt_us)` = bytes * 1e6 / rtt
inline fn rateFromBytes(bytes: u64, rtt_us: u64) u64 {
    if (rtt_us == 0) return 0;
    return (bytes *% 1_000_000) / rtt_us;
}

/// Initial cwnd in packets, mirrors picoquic's `PICOQUIC_CWIN_INITIAL`
/// (= 10 * MAX_PACKET_SIZE). Caller provides mtu.
inline fn initialCwnd(mtu: u32) u64 {
    return 10 * @as(u64, mtu);
}

// -- Sensitivity / threshold helpers ----------------------------------------

/// Sensitivity in 1024-scale. Low rate -> insensitive; high rate -> sensitive.
pub fn sensitivity1024(state: *const State) u64 {
    const rate = state.nominal_rate;
    if (rate < 50_000) return 0;
    if (rate > 10_000_000) return 1024;
    if (rate < 1_000_000) return (rate - 50_000) * 963 / 950_000;
    return 963 + ((rate - 1_000_000) * 61 / 9_000_000);
}

/// Delay threshold in microseconds for declaring congestion.
pub fn delayThreshold(state: *const State) u64 {
    const sens = sensitivity1024(state);
    const fraction = 64 + mult1024(1024 - sens, 196);
    var delay = mult1024(fraction, state.nominal_max_rtt_us);
    if (delay > delay_threshold_max_us) delay = delay_threshold_max_us;
    return delay;
}

/// Loss-rate threshold as a fraction in [0,1]. Picoquic uses a double here.
pub fn lossThreshold(state: *const State) f64 {
    const sens = sensitivity1024(state);
    const fraction = @as(f64, @floatFromInt(sens)) / 1024.0;
    return 0.02 + 0.50 * (1.0 - fraction);
}

// -- Era / growth bookkeeping -----------------------------------------------

fn eraCheck(state: *State, ctx: *CcContext) bool {
    if (!ctx.is_ready) return false;
    return ctx.lowest_not_ack_fn(ctx.transport_ctx) > state.era_sequence;
}

fn eraReset(state: *State, ctx: *CcContext) void {
    state.era_sequence = ctx.next_sequence_number_fn(ctx.transport_ctx);
    state.era_max_rtt_us = 0;
    state.era_min_rtt_us = std.math.maxInt(u64);
    state.alpha_1024_previous = state.alpha_1024_current;
}

fn growthReset(state: *State) void {
    state.congestion_notified = false;
    state.push_was_not_limited = false;
    state.push_rate_old = state.nominal_rate;
    state.push_alpha = state.alpha_1024_current;
}

fn growthEvaluate(state: *const State) bool {
    if (state.push_alpha > alpha_push_low_1024) {
        const target_rate = (3 * state.push_rate_old +
            mult1024(state.push_alpha, state.push_rate_old)) / 4;
        return state.nominal_rate > target_rate;
    }
    return state.nominal_rate > state.push_rate_old and !state.congestion_notified;
}

// -- apply rate & cwnd ------------------------------------------------------

fn applyRateAndCwin(state: *State, ctx: *CcContext) void {
    var pacing_rate = mult1024(state.alpha_1024_current, state.nominal_rate);
    var target_cwin: u64 = initialCwnd(ctx.send_mtu);
    if (state.nominal_max_rtt_us != 0 and state.nominal_rate != 0) {
        target_cwin = bytesFromRate(state.nominal_max_rtt_us, pacing_rate);
    }

    if (state.alg_state == .initial) {
        if (target_cwin < state.initial_cwnd) target_cwin = state.initial_cwnd;
        if (state.nb_packets_in_startup > 0) {
            if (ctx.peak_bandwidth_estimate_bps > pacing_rate) {
                pacing_rate = (pacing_rate + ctx.peak_bandwidth_estimate_bps) / 2;
                const min_win = bytesFromRate(ctx.smoothed_rtt_us, ctx.peak_bandwidth_estimate_bps) / 2;
                if (min_win > target_cwin) target_cwin = min_win;
            }
        }
        if (state.use_seed_cwnd and state.seed_cwnd > target_cwin) {
            target_cwin = (state.seed_cwnd + target_cwin) / 2;
            state.seed_rate_bps = rateFromBytes(state.seed_cwnd, ctx.smoothed_rtt_us);
            if (state.seed_rate_bps > pacing_rate) pacing_rate = state.seed_rate_bps;
        }
        state.initial_cwnd = target_cwin;
    } else {
        var delta_rtt_target: u64 = rtt_margin_delay_us;
        if (state.nominal_max_rtt_us < 4 * rtt_margin_delay_us) {
            delta_rtt_target = state.nominal_max_rtt_us / 4;
        }
        target_cwin += bytesFromRate(delta_rtt_target, pacing_rate);

        if (state.alg_state == .pushing) {
            const delta_alpha = state.alpha_1024_current - 1024;
            const delta_rate = mult1024(delta_alpha, state.nominal_rate);
            const delta_cwin = bytesFromRate(state.nominal_max_rtt_us, delta_rate);
            if (delta_cwin < ctx.send_mtu) {
                target_cwin += @as(u64, ctx.send_mtu) - delta_cwin;
            }
        }
    }

    ctx.cwnd = target_cwin;

    // Burst quantum: ~4ms worth, min 2*mtu, max 64KiB.
    var quantum: u64 = mult1024(4, pacing_rate);
    if (quantum > 0x10000) {
        quantum = 0x10000;
    } else if (quantum < 2 * @as(u64, ctx.send_mtu)) {
        quantum = 2 * @as(u64, ctx.send_mtu);
    }
    ctx.update_pacing_rate_fn(ctx.transport_ctx, pacing_rate, quantum);
}

// -- State transitions ------------------------------------------------------

fn enterInitial(state: *State, ctx: *CcContext) void {
    state.alg_state = .initial;
    state.initial_cwnd = ctx.cwnd;
    state.probe_level = probe_level_default;
    state.alpha_1024_current = alpha_initial;
    state.nb_packets_in_startup = 0;
    eraReset(state, ctx);
    state.nb_eras_no_increase = 0;
    growthReset(state);
}

fn exitInitial(state: *State, ctx: *CcContext) void {
    if (state.nominal_rate == 0) return;
    const ssthresh = state.initial_cwnd / 2;
    var nominal_max_rtt = ssthresh * 1_000_000 / state.nominal_rate;
    if (nominal_max_rtt < max_rtt_min_us) nominal_max_rtt = max_rtt_min_us;
    state.nominal_max_rtt_us = nominal_max_rtt;
    state.delay_threshold_us = delayThreshold(state);
    state.nb_eras_no_increase = 0;
    state.probe_level = probe_level_default;
    enterRecovery(state, ctx);
}

fn enterRecovery(state: *State, ctx: *CcContext) void {
    if (state.alg_state == .initial) {
        growthReset(state);
    }
    if (state.alg_state != .recovery) {
        state.alg_state = .recovery;
        eraReset(state, ctx);
        state.alpha_1024_current = alpha_recover_1024;
    }
}

fn exitRecovery(state: *State, ctx: *CcContext) void {
    const is_growing = growthEvaluate(state);
    if (is_growing) {
        if (state.probe_level < 255) state.probe_level += 1;
    } else if (state.push_was_not_limited) {
        state.probe_level = 1;
    }
    growthReset(state);
    state.recent_delay_excess_us = 0;
    state.smoothed_drop_rate = 0;

    if (state.probe_level > probe_level_max) {
        enterInitial(state, ctx);
    } else {
        enterCruise(state, ctx);
    }
}

fn enterCruise(state: *State, ctx: *CcContext) void {
    eraReset(state, ctx);
    state.use_seed_cwnd = false;

    if (state.probe_level > probe_level_default) {
        state.nb_cruise_left_before_push = 0;
    } else if (state.nb_cruise_left_before_push == 0) {
        state.nb_cruise_left_before_push = if (state.probe_level == 0) 1 else nb_cruise_before_push;
    }
    state.alpha_1024_current = alpha_cruise_1024;
    if (ctx.smoothed_rtt_us < max_rtt_min_us) {
        state.alpha_1024_current += 48;
    }
    state.alg_state = .cruising;
}

fn enterPush(state: *State, ctx: *CcContext) void {
    state.alpha_1024_current = push_rate_by_probe_level[state.probe_level];
    state.push_alpha = state.alpha_1024_current;
    eraReset(state, ctx);
    state.alg_state = .pushing;
}

// -- Public entry points ----------------------------------------------------

/// Reset state and enter the initial phase. Called at startup and on
/// connection reset.
pub fn reset(state: *State, ctx: *CcContext, now_us: u64) void {
    _ = now_us;
    state.* = State{};
    state.running_min_rtt_us = std.math.maxInt(u64);
    state.alpha_1024_current = alpha_initial;
    enterInitial(state, ctx);
}

/// ACK notification.
pub fn notifyAck(state: *State, ctx: *CcContext, ack: AckState, now_us: u64) void {
    handleAck(state, ctx, ack, now_us);
    applyRateAndCwin(state, ctx);
}

/// Sustained-loss notification (a packet has been declared lost and the
/// smoothed loss rate may now exceed the threshold).
pub fn notifyLoss(state: *State, ctx: *CcContext, lost_packet_number: u64, now_us: u64) void {
    _ = now_us;
    if (state.alg_state == .recovery and lost_packet_number < state.era_sequence) {
        return;
    }
    updateLossRate(state, lost_packet_number);
    if (state.smoothed_drop_rate > lossThreshold(state)) {
        if (state.alg_state == .initial) {
            initialHandleLoss(state, ctx);
        } else {
            notifyCongestion(state, ctx, 0, .loss);
        }
    }
}

/// New RTT measurement notification.
pub fn notifyRtt(state: *State, ctx: *CcContext, rtt_measurement_us: u64, now_us: u64) void {
    _ = now_us;
    updateRtt(state, rtt_measurement_us);
    if (state.alg_state == .initial) {
        initialHandleRtt(state, ctx);
        applyRateAndCwin(state, ctx);
    } else {
        handleRtt(state, ctx);
    }
}

// -- Congestion notification ------------------------------------------------

fn updateLossRate(state: *State, lost_packet_number: u64) void {
    var next_number = state.last_lost_packet_number;
    if (lost_packet_number <= next_number) return;

    if (next_number + smoothed_loss_scope < lost_packet_number) {
        next_number = lost_packet_number - smoothed_loss_scope;
    }
    while (next_number < lost_packet_number) : (next_number += 1) {
        state.smoothed_drop_rate *= (1.0 - smoothed_loss_factor);
    }
    state.smoothed_drop_rate += (1.0 - state.smoothed_drop_rate) * smoothed_loss_factor;
    state.last_lost_packet_number = lost_packet_number;
}

fn notifyCongestion(state: *State, ctx: *CcContext, rtt_latest: u64, c_mode: CongestionMode) void {
    _ = rtt_latest;
    var beta: u64 = beta_loss_1024;
    state.congestion_notified = true;

    switch (c_mode) {
        .loss => {
            beta = (beta_loss_1024 + mult1024(sensitivity1024(state), beta_loss_1024)) / 2;
        },
        .delay => {
            if (state.delay_threshold_us > 0) {
                beta = state.recent_delay_excess_us * 1024 / state.delay_threshold_us;
            }
            if (beta > beta_loss_1024) beta = beta_loss_1024;
            // Cap delay beta at 25% (picoquic matches — not 512).
        },
        .none => {},
    }

    if (c_mode != .delay) {
        state.recent_delay_excess_us = 0;
    }

    if (state.alg_state == .recovery) {
        if (state.alpha_1024_current == alpha_recover_1024) {
            state.alpha_1024_current = alpha_recover2_1024;
            state.era_sequence = ctx.next_sequence_number_fn(ctx.transport_ctx);
        }
    } else {
        if (state.alg_state != .pushing) {
            state.nominal_rate -= mult1024(beta, state.nominal_rate);
            if (c_mode == .loss) {
                state.nominal_max_rtt_us -= mult1024(beta, state.nominal_max_rtt_us);
                if (state.nominal_max_rtt_us < max_rtt_min_us) {
                    state.nominal_max_rtt_us = max_rtt_min_us;
                }
                state.delay_threshold_us = delayThreshold(state);
            }
        }
        enterRecovery(state, ctx);
    }

    applyRateAndCwin(state, ctx);
    ctx.is_ssthresh_initialized = true;
}

// -- Initial-phase handlers -------------------------------------------------

fn initialHandleRtt(state: *State, ctx: *CcContext) void {
    if (state.recent_delay_excess_us > 0 and
        state.nb_eras_no_increase > 1 and
        state.push_rate_old >= state.nominal_rate)
    {
        exitInitial(state, ctx);
    }
}

fn initialHandleLoss(state: *State, ctx: *CcContext) void {
    state.nb_packets_in_startup += 1;
    if (state.nb_packets_in_startup > nb_packets_before_loss) {
        exitInitial(state, ctx);
    }
}

fn initialHandleAck(state: *State, ctx: *CcContext, ack: AckState) void {
    state.nb_packets_in_startup += 1;
    // Reno-ish slow start with shift damping near exit.
    const shift: u6 = @intCast(@min(@as(u32, 63), 3 * state.nb_eras_no_increase));
    state.initial_cwnd += ack.nb_bytes_acknowledged >> shift;

    if (state.use_seed_cwnd and state.seed_rate_bps > 0 and
        state.nominal_rate >= state.seed_rate_bps)
    {
        state.use_seed_cwnd = false;
    }

    if (eraCheck(state, ctx)) {
        const is_growing = growthEvaluate(state);
        if (is_growing) {
            state.nb_eras_no_increase = 0;
        } else if (state.push_was_not_limited and state.nominal_rate > 0) {
            state.nb_eras_no_increase += 1;
        }
        eraReset(state, ctx);
        if (state.nb_eras_no_increase >= 3) {
            exitInitial(state, ctx);
            return;
        } else {
            growthReset(state);
        }
    }
}

// -- RTT update -------------------------------------------------------------

fn updateRtt(state: *State, rtt_measurement_us: u64) void {
    if (rtt_measurement_us > state.era_max_rtt_us) state.era_max_rtt_us = rtt_measurement_us;
    if (rtt_measurement_us < state.era_min_rtt_us) state.era_min_rtt_us = rtt_measurement_us;
    if (rtt_measurement_us < state.running_min_rtt_us) state.running_min_rtt_us = rtt_measurement_us;

    if (state.nominal_max_rtt_us == 0) {
        state.nominal_max_rtt_us = rtt_measurement_us;
        if (state.nominal_max_rtt_us < max_rtt_min_us) {
            state.nominal_max_rtt_us = max_rtt_min_us;
        }
        state.delay_threshold_us = delayThreshold(state);
        state.recent_delay_excess_us = 0;
    } else {
        const target_rtt = state.nominal_max_rtt_us + state.delay_threshold_us;
        state.recent_delay_excess_us = if (rtt_measurement_us > target_rtt)
            rtt_measurement_us - target_rtt
        else
            0;
    }
}

fn updateMinMaxRtt(state: *State, ctx: *CcContext) void {
    if (ctx.rtt_sample_us > state.era_max_rtt_us) state.era_max_rtt_us = ctx.rtt_sample_us;
    if (ctx.rtt_sample_us < state.era_min_rtt_us) state.era_min_rtt_us = ctx.rtt_sample_us;

    if (state.alpha_1024_previous <= alpha_neutral_1024) {
        if (state.era_min_rtt_us < state.running_min_rtt_us) {
            state.running_min_rtt_us = state.era_min_rtt_us;
        } else {
            state.running_min_rtt_us = (7 * state.running_min_rtt_us + state.era_min_rtt_us) / 8;
        }

        const corrected_max = if (state.era_max_rtt_us < state.running_min_rtt_us + max_jitter_us)
            state.era_max_rtt_us
        else
            state.running_min_rtt_us + max_jitter_us;

        if (corrected_max > state.nominal_max_rtt_us) {
            state.nominal_max_rtt_us = corrected_max;
        } else {
            state.nominal_max_rtt_us = (7 * state.nominal_max_rtt_us + corrected_max) / 8;
        }
        state.delay_threshold_us = delayThreshold(state);
    } else if (state.nominal_max_rtt_us == 0) {
        state.nominal_max_rtt_us = state.era_max_rtt_us;
        state.delay_threshold_us = delayThreshold(state);
    }

    if (state.nominal_max_rtt_us < max_rtt_min_us) {
        state.nominal_max_rtt_us = max_rtt_min_us;
        state.delay_threshold_us = delayThreshold(state);
    }
}

// -- Non-initial ACK / RTT handling -----------------------------------------

fn handleAck(state: *State, ctx: *CcContext, ack: AckState, now_us: u64) void {
    _ = now_us;
    const previous_rate = state.nominal_rate;

    if (ack.rtt_measurement_us > 0 and ack.nb_bytes_delivered_since_packet_sent > 0) {
        const rate_measurement = ctx.bandwidth_estimate_bps;

        if (rate_measurement > state.nominal_rate and
            !(state.alg_state == .recovery and state.congestion_notified))
        {
            state.push_was_not_limited = true;
            state.nominal_rate = rate_measurement;
            state.delay_threshold_us = delayThreshold(state);
        } else {
            const target_cwin = bytesFromRate(state.running_min_rtt_us, previous_rate);
            if (ack.nb_bytes_delivered_since_packet_sent > target_cwin) {
                state.push_was_not_limited = true;
            }
        }
    }

    if (state.alg_state == .initial) {
        initialHandleAck(state, ctx, ack);
        return;
    }

    if (!eraCheck(state, ctx)) return;

    updateMinMaxRtt(state, ctx);

    if (!state.initial_after_jitter and
        state.nominal_max_rtt_us > 50_000 and
        state.nominal_rate < 1_000_000 and
        5 * state.running_min_rtt_us < 2 * state.nominal_max_rtt_us)
    {
        state.initial_after_jitter = true;
        enterInitial(state, ctx);
        return;
    }

    switch (state.alg_state) {
        .recovery => exitRecovery(state, ctx),
        .cruising => {
            if (state.nb_cruise_left_before_push > 0) state.nb_cruise_left_before_push -= 1;
            eraReset(state, ctx);
            if (state.nb_cruise_left_before_push == 0 and
                ctx.last_time_acked_data_frame_sent_us > ctx.last_sender_limited_time_us)
            {
                enterPush(state, ctx);
            }
        },
        .pushing => enterRecovery(state, ctx),
        .initial => eraReset(state, ctx),
    }
}

fn handleRtt(state: *State, ctx: *CcContext) void {
    if (state.recent_delay_excess_us > 0 and state.alpha_1024_previous > 1024) {
        notifyCongestion(state, ctx, 0, .delay);
    }
}

// -- Tests ------------------------------------------------------------------

const testing = std.testing;

const TestHooks = struct {
    lowest_not_ack: u64 = 1,
    next_seq: u64 = 1,
    last_pacing_rate: u64 = 0,
    last_quantum: u64 = 0,

    fn lowestNotAck(ptr: *anyopaque) u64 {
        const self: *TestHooks = @ptrCast(@alignCast(ptr));
        return self.lowest_not_ack;
    }
    fn nextSeq(ptr: *anyopaque) u64 {
        const self: *TestHooks = @ptrCast(@alignCast(ptr));
        return self.next_seq;
    }
    fn updatePacing(ptr: *anyopaque, rate_bps: u64, quantum: u64) void {
        const self: *TestHooks = @ptrCast(@alignCast(ptr));
        self.last_pacing_rate = rate_bps;
        self.last_quantum = quantum;
    }
};

fn makeCtx(hooks: *TestHooks) CcContext {
    return .{
        .send_mtu = 1500,
        .smoothed_rtt_us = 20_000,
        .rtt_sample_us = 20_000,
        .rtt_variant_us = 2_000,
        .bandwidth_estimate_bps = 0,
        .peak_bandwidth_estimate_bps = 0,
        .bytes_in_transit = 0,
        .last_time_acked_data_frame_sent_us = 2,
        .last_sender_limited_time_us = 1,
        .cwnd = 10 * 1500,
        .is_ssthresh_initialized = false,
        .lowest_not_ack_fn = TestHooks.lowestNotAck,
        .next_sequence_number_fn = TestHooks.nextSeq,
        .update_pacing_rate_fn = TestHooks.updatePacing,
        .transport_ctx = hooks,
        .is_ready = true,
    };
}

test "reset puts state in initial with expected constants" {
    var hooks = TestHooks{};
    var ctx = makeCtx(&hooks);
    var st = State{};
    reset(&st, &ctx, 0);
    try testing.expectEqual(AlgState.initial, st.alg_state);
    try testing.expectEqual(@as(u64, alpha_initial), st.alpha_1024_current);
    try testing.expectEqual(@as(u8, probe_level_default), st.probe_level);
    try testing.expectEqual(@as(u32, 0), st.nb_eras_no_increase);
    try testing.expectEqual(@as(u64, 15_000), st.initial_cwnd);
}

test "initial exits after 3 eras with no increase" {
    var hooks = TestHooks{};
    var ctx = makeCtx(&hooks);
    var st = State{};
    reset(&st, &ctx, 0);

    // Put something in nominal_rate so exitInitial is non-trivial.
    st.nominal_rate = 500_000;
    ctx.bandwidth_estimate_bps = 500_000;

    // Drive 3 era boundaries with "not growing" + "not limited".
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        // Advance era by moving lowest-not-ack past era_sequence.
        hooks.lowest_not_ack = st.era_sequence + 10;
        hooks.next_seq = st.era_sequence + 10;
        st.push_was_not_limited = true; // simulate non-app-limited
        const ack = AckState{
            .rtt_measurement_us = 20_000,
            .nb_bytes_delivered_since_packet_sent = 1500,
            .nb_bytes_acknowledged = 1500,
        };
        notifyAck(&st, &ctx, ack, 0);
        if (st.alg_state != .initial) break;
    }
    try testing.expect(st.alg_state != .initial);
}

test "loss from non-initial enters recovery and reduces rate" {
    var hooks = TestHooks{};
    var ctx = makeCtx(&hooks);
    var st = State{};
    reset(&st, &ctx, 0);
    // Force into cruising manually.
    st.alg_state = .cruising;
    st.nominal_rate = 1_000_000;
    st.nominal_max_rtt_us = 20_000;
    st.alpha_1024_current = alpha_cruise_1024;
    st.smoothed_drop_rate = 1.0; // above any threshold

    const before = st.nominal_rate;
    notifyLoss(&st, &ctx, 100, 0);
    try testing.expectEqual(AlgState.recovery, st.alg_state);
    try testing.expect(st.nominal_rate < before);
}

test "delay excess triggers congestion notification" {
    var hooks = TestHooks{};
    var ctx = makeCtx(&hooks);
    var st = State{};
    reset(&st, &ctx, 0);
    // Non-initial so handleRtt path runs.
    st.alg_state = .cruising;
    st.nominal_rate = 2_000_000;
    st.nominal_max_rtt_us = 20_000;
    st.delay_threshold_us = 5_000;
    st.alpha_1024_previous = alpha_push_1024; // > 1024
    st.alpha_1024_current = alpha_cruise_1024;

    // RTT well above target should set delay excess and notify.
    notifyRtt(&st, &ctx, 100_000, 0);
    try testing.expectEqual(AlgState.recovery, st.alg_state);
}

test "C4 unwedges from initial when bandwidth_estimate_bps is fed" {
    // Reproduces the wedge: prior to commit 1, ctx.bandwidth_estimate_bps
    // stayed 0 forever, so handleAck never set state.nominal_rate, so
    // exitInitial bailed early. With the cc-layer fix in place, a synthetic
    // sequence that supplies a non-zero bandwidth estimate must drive C4
    // through initial -> recovery -> cruising -> pushing -> recovery.
    var hooks = TestHooks{};
    var ctx = makeCtx(&hooks);
    var st = State{};
    reset(&st, &ctx, 0);

    try testing.expectEqual(AlgState.initial, st.alg_state);

    // Drive era boundaries with a healthy bandwidth estimate; nominal_rate
    // should latch to the measured rate, then after 3 no-increase eras the
    // state machine exits initial.
    // Feed bandwidth_estimate_bps so handleAck latches a non-zero
    // nominal_rate (the pre-fix wedge). This is the critical step that
    // would have failed before commit 1: ctx.bandwidth_estimate_bps was
    // 0, so state.nominal_rate stayed 0, so exitInitial bailed out.
    ctx.bandwidth_estimate_bps = 800_000;

    var i: u32 = 0;
    while (i < 12 and st.alg_state == .initial) : (i += 1) {
        hooks.lowest_not_ack = st.era_sequence + 10;
        hooks.next_seq = st.era_sequence + 10;
        // Hold push_was_not_limited high so the no-increase counter ticks
        // (the synthetic harness has no real RTT/delivery flow).
        st.push_was_not_limited = true;
        const ack = AckState{
            .rtt_measurement_us = 20_000,
            .nb_bytes_delivered_since_packet_sent = 1500,
            .nb_bytes_acknowledged = 1500,
        };
        notifyAck(&st, &ctx, ack, 0);
    }
    try testing.expect(st.nominal_rate > 0); // pre-fix wedge: this stayed 0
    try testing.expect(st.alg_state != .initial);

    // Walk forward — under steady acks the machine should reach pushing
    // and then bounce back to recovery.
    var saw_cruising = false;
    var saw_pushing = false;
    var saw_recovery_after = false;
    var safety: u32 = 0;
    while (safety < 30) : (safety += 1) {
        if (st.alg_state == .cruising) saw_cruising = true;
        if (st.alg_state == .pushing) saw_pushing = true;
        if (saw_pushing and st.alg_state == .recovery) {
            saw_recovery_after = true;
            break;
        }
        hooks.lowest_not_ack = st.era_sequence + 10;
        hooks.next_seq = st.era_sequence + 10;
        const ack = AckState{
            .rtt_measurement_us = 20_000,
            .nb_bytes_delivered_since_packet_sent = 1500,
            .nb_bytes_acknowledged = 1500,
        };
        notifyAck(&st, &ctx, ack, 0);
    }
    try testing.expect(saw_cruising);
    try testing.expect(saw_pushing);
    try testing.expect(saw_recovery_after);
}

test "C4 cruising -> recovery on synthetic loss with rate decrease" {
    var hooks = TestHooks{};
    var ctx = makeCtx(&hooks);
    var st = State{};
    reset(&st, &ctx, 0);

    st.alg_state = .cruising;
    st.nominal_rate = 5_000_000; // well above sensitivity floor
    st.nominal_max_rtt_us = 20_000;
    st.alpha_1024_current = alpha_cruise_1024;
    // Force loss-rate above lossThreshold by hand.
    st.smoothed_drop_rate = 0.9;

    const before = st.nominal_rate;
    notifyLoss(&st, &ctx, 100, 0);
    try testing.expectEqual(AlgState.recovery, st.alg_state);
    try testing.expect(st.nominal_rate < before);
}

test "C4 delay excess in cruising enters recovery" {
    var hooks = TestHooks{};
    var ctx = makeCtx(&hooks);
    var st = State{};
    reset(&st, &ctx, 0);

    st.alg_state = .cruising;
    st.nominal_rate = 5_000_000;
    st.nominal_max_rtt_us = 20_000;
    st.delay_threshold_us = 5_000;
    st.alpha_1024_previous = alpha_push_1024;
    st.alpha_1024_current = alpha_cruise_1024;

    ctx.rtt_sample_us = 200_000;
    notifyRtt(&st, &ctx, 200_000, 0);
    try testing.expectEqual(AlgState.recovery, st.alg_state);
}

test "recovery -> cruising -> pushing -> recovery under healthy link" {
    var hooks = TestHooks{};
    var ctx = makeCtx(&hooks);
    var st = State{};
    reset(&st, &ctx, 0);
    // Jump to recovery with reasonable params.
    st.alg_state = .recovery;
    st.nominal_rate = 1_000_000;
    st.nominal_max_rtt_us = 20_000;
    st.alpha_1024_current = alpha_recover_1024;
    st.initial_after_jitter = true; // don't bounce back to initial
    eraReset(&st, &ctx);
    growthReset(&st);
    // Pretend previous push was healthy.
    st.push_was_not_limited = true;
    st.push_alpha = alpha_push_1024;
    st.push_rate_old = 900_000;

    // Advance era -> exitRecovery -> cruising.
    hooks.lowest_not_ack = st.era_sequence + 5;
    hooks.next_seq = st.era_sequence + 5;
    ctx.rtt_sample_us = 20_000;
    const ack = AckState{
        .rtt_measurement_us = 20_000,
        .nb_bytes_delivered_since_packet_sent = 1500,
        .nb_bytes_acknowledged = 1500,
    };
    notifyAck(&st, &ctx, ack, 0);
    try testing.expectEqual(AlgState.cruising, st.alg_state);

    // Burn down cruise cycles; each era boundary decrements the counter.
    var safety: u32 = 0;
    while (st.alg_state == .cruising and safety < 10) : (safety += 1) {
        hooks.lowest_not_ack = st.era_sequence + 5;
        hooks.next_seq = st.era_sequence + 5;
        notifyAck(&st, &ctx, ack, 0);
    }
    try testing.expectEqual(AlgState.pushing, st.alg_state);

    // One more era -> pushing transitions to recovery.
    hooks.lowest_not_ack = st.era_sequence + 5;
    hooks.next_seq = st.era_sequence + 5;
    notifyAck(&st, &ctx, ack, 0);
    try testing.expectEqual(AlgState.recovery, st.alg_state);
}
