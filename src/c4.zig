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
//!             the probe level), then push. Listen for delay/ECN/loss signals.
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

/// ECN alpha EWMA gain: `g = 1/2^4`.
pub const ecn_shift_g: u6 = 4;

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
    ecn,
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

    /// ECN alpha EWMA and the threshold at which ECN marks are treated as a
    /// congestion event.
    ecn_alpha_1024: u64 = 0,
    ecn_ect1: u64 = 0,
    ecn_ce: u64 = 0,
    ecn_threshold_1024: u64 = 0,

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
    /// Excess ECN CE marks were observed after the most recent push.
    excess_ce_after_push: bool = false,

    pub fn init() State {
        return .{};
    }
};

// -- Public entry points (stubs; implemented in later commits) --------------

/// Reset state and enter the initial phase. Called at startup and on
/// connection reset.
pub fn reset(state: *State, ctx: *CcContext, now_us: u64) void {
    _ = state;
    _ = ctx;
    _ = now_us;
    // TODO: implemented in next commit.
}

/// ACK notification.
pub fn notifyAck(state: *State, ctx: *CcContext, ack: AckState, now_us: u64) void {
    _ = state;
    _ = ctx;
    _ = ack;
    _ = now_us;
    // TODO: implemented in next commit.
}

/// Sustained-loss notification (a packet has been declared lost and the
/// smoothed loss rate may now exceed the threshold).
pub fn notifyLoss(state: *State, ctx: *CcContext, lost_packet_number: u64, now_us: u64) void {
    _ = state;
    _ = ctx;
    _ = lost_packet_number;
    _ = now_us;
    // TODO: implemented in next commit.
}

/// New RTT measurement notification.
pub fn notifyRtt(state: *State, ctx: *CcContext, rtt_measurement_us: u64, now_us: u64) void {
    _ = state;
    _ = ctx;
    _ = rtt_measurement_us;
    _ = now_us;
    // TODO: implemented in next commit.
}
