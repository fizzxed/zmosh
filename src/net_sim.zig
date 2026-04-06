//! In-process reliability test harness for the byte-offset output stream.
//!
//! Design:
//!  - Virtual clock: every time-dependent call takes `now_us`. Tests advance
//!    the clock manually via `Scenario.runUntilDelivered`. There are no real
//!    syscalls or wall-clock reads inside the harness.
//!  - Real wire bytes: packets are framed with `transport.buildUnreliable`,
//!    `writeOutputOffset`, and `buildOutputAckPayload`, then parsed with
//!    `transport.parsePacket` / `parseOutputAckPayload`. Crypto is NOT
//!    applied — the harness exercises the reliability layer, not the AEAD.
//!    The bytes that traverse `FakeNet` are plaintext transport frames.
//!  - The endpoint structs (`ServerEndpoint` / `ClientEndpoint`) re-implement
//!    the reliability state machines that live inside `serve.Gateway` and
//!    `remote.remoteAttach`'s main loop. The shared substrate
//!    (`cc.CongestionController`, `reorder_buffer.ReorderBuffer`,
//!    `transport.*` encoders) is the same code production runs.
//!
//! Out of scope: SSH bootstrap, terminal raw-mode, IPC framing, the Unix
//! socket relay. Only the server→client output channel (and its SACK ack
//! channel) are simulated.

const std = @import("std");
const transport = @import("transport.zig");
const cc_mod = @import("cc.zig");
const reorder_buffer = @import("reorder_buffer.zig");

// ---------------------------------------------------------------------------
// Tunables that mirror the production code
// ---------------------------------------------------------------------------

const mtu: u32 = transport.max_payload_len + 20;
const retransmit_ring_slots: usize = 2048;
const ack_min_interval_us: u64 = 20_000; // matches output_ack_min_interval_ns
const ack_max_unacked: u32 = 16;
const default_srtt_us: u64 = 100_000;

// ---------------------------------------------------------------------------
// Virtual clock
// ---------------------------------------------------------------------------

pub const Clock = struct {
    now_us: u64 = 0,
    pub fn advance(self: *Clock, delta_us: u64) void {
        self.now_us += delta_us;
    }
};

// ---------------------------------------------------------------------------
// Fake network
// ---------------------------------------------------------------------------

pub const NetConfig = struct {
    latency_us: u64 = 10_000,
    jitter_us: u64 = 0,
    loss_pct: u8 = 0,
    bandwidth_bps: u64 = 0,
    seed: u64 = 0xC0FFEE,
    /// Per-output-packet-index drop list. The Nth (0-based) original output
    /// packet sent by the server is dropped if its index appears here.
    /// Retransmits are NOT counted toward this index.
    drop_output_packets: []const u32 = &.{},
    /// Per-output-packet-index extra latency. Adds `extra_us` to the
    /// delivery time of the matching original packet. Used to force
    /// reordering deterministically.
    extra_latency: []const ExtraLatency = &.{},
    /// If true, drop ALL retransmits as well as their first transmission.
    /// Used by stale-gap-timeout scenarios.
    drop_retransmits: bool = false,
};

pub const ExtraLatency = struct {
    idx: u32,
    extra_us: u64,
};

pub const Direction = enum { s2c, c2s };

const InFlight = struct {
    deliver_at_us: u64,
    seq: u64, // monotonic submit-order tiebreaker
    bytes: []u8,
};

pub const FakeNet = struct {
    alloc: std.mem.Allocator,
    cfg: NetConfig,
    s2c: std.ArrayList(InFlight),
    c2s: std.ArrayList(InFlight),
    rng: std.Random.DefaultPrng,
    submit_seq: u64 = 0,

    pub fn init(alloc: std.mem.Allocator, cfg: NetConfig) !FakeNet {
        return .{
            .alloc = alloc,
            .cfg = cfg,
            .s2c = try std.ArrayList(InFlight).initCapacity(alloc, 64),
            .c2s = try std.ArrayList(InFlight).initCapacity(alloc, 64),
            .rng = std.Random.DefaultPrng.init(cfg.seed),
        };
    }

    pub fn deinit(self: *FakeNet) void {
        for (self.s2c.items) |p| self.alloc.free(p.bytes);
        for (self.c2s.items) |p| self.alloc.free(p.bytes);
        self.s2c.deinit(self.alloc);
        self.c2s.deinit(self.alloc);
    }

    fn queue(self: *FakeNet, dir: Direction) *std.ArrayList(InFlight) {
        return switch (dir) {
            .s2c => &self.s2c,
            .c2s => &self.c2s,
        };
    }

    /// Submit `bytes` (caller-owned) for delivery in direction `dir`.
    /// Returns true if the packet was queued, false if it was dropped by
    /// the random loss model. `extra_us` is added on top of base latency.
    pub fn submit(
        self: *FakeNet,
        clock: *const Clock,
        dir: Direction,
        bytes: []const u8,
        extra_us: u64,
    ) !bool {
        if (self.cfg.loss_pct > 0) {
            const r = self.rng.random().intRangeLessThan(u8, 0, 100);
            if (r < self.cfg.loss_pct) return false;
        }
        const owned = try self.alloc.dupe(u8, bytes);
        const jitter: u64 = if (self.cfg.jitter_us == 0) 0 else self.rng.random().uintLessThan(u64, self.cfg.jitter_us);
        const ser_us: u64 = if (self.cfg.bandwidth_bps == 0) 0 else (@as(u64, bytes.len) * 8 * 1_000_000) / self.cfg.bandwidth_bps;
        const deliver_at = clock.now_us + self.cfg.latency_us + jitter + ser_us + extra_us;
        self.submit_seq += 1;
        try self.queue(dir).append(self.alloc, .{
            .deliver_at_us = deliver_at,
            .seq = self.submit_seq,
            .bytes = owned,
        });
        return true;
    }

    /// Pop the next due packet in `dir`, or null if none ready.
    pub fn popDue(self: *FakeNet, clock: *const Clock, dir: Direction) ?[]u8 {
        const q = self.queue(dir);
        var best_i: ?usize = null;
        var best_at: u64 = std.math.maxInt(u64);
        var best_seq: u64 = std.math.maxInt(u64);
        for (q.items, 0..) |p, i| {
            if (p.deliver_at_us > clock.now_us) continue;
            if (p.deliver_at_us < best_at or (p.deliver_at_us == best_at and p.seq < best_seq)) {
                best_at = p.deliver_at_us;
                best_seq = p.seq;
                best_i = i;
            }
        }
        if (best_i) |idx| {
            const p = q.orderedRemove(idx);
            return p.bytes;
        }
        return null;
    }

    pub fn nextDeliveryUs(self: *const FakeNet) ?u64 {
        var earliest: ?u64 = null;
        for (self.s2c.items) |p| {
            if (earliest == null or p.deliver_at_us < earliest.?) earliest = p.deliver_at_us;
        }
        for (self.c2s.items) |p| {
            if (earliest == null or p.deliver_at_us < earliest.?) earliest = p.deliver_at_us;
        }
        return earliest;
    }

    pub fn isEmpty(self: *const FakeNet) bool {
        return self.s2c.items.len == 0 and self.c2s.items.len == 0;
    }
};

// ---------------------------------------------------------------------------
// Server endpoint
// ---------------------------------------------------------------------------

const RetransmitSlot = struct {
    offset_start: u64 = 0,
    length: u32 = 0,
    send_time_us: u64 = 0,
    last_retransmit_us: u64 = 0,
    payload: [transport.max_output_data_len]u8 = undefined,
    in_use: bool = false,
};

pub const ServerEndpoint = struct {
    alloc: std.mem.Allocator,
    cc: cc_mod.CongestionController,
    ring: []RetransmitSlot,
    ring_write: usize = 0,
    pending: std.ArrayList(u8),
    next_output_offset: u64 = 0,
    output_packet_index: u32 = 0,
    resync_requested: bool = false,
    last_resync_us: u64 = 0,
    /// Cached most-recent SACK; used by `tick` to retry retransmits when the
    /// per-gap RTT cooldown blocked the previous attempt.
    last_sack: ?transport.OutputAckPayload = null,
    last_sack_at: u64 = 0,

    pub fn init(alloc: std.mem.Allocator, now_us: u64) !ServerEndpoint {
        var ep: ServerEndpoint = .{
            .alloc = alloc,
            .cc = undefined,
            .ring = try alloc.alloc(RetransmitSlot, retransmit_ring_slots),
            .pending = try std.ArrayList(u8).initCapacity(alloc, 4096),
        };
        ep.cc.init(mtu, now_us);
        for (ep.ring) |*s| s.* = .{};
        return ep;
    }

    pub fn deinit(self: *ServerEndpoint) void {
        self.alloc.free(self.ring);
        self.pending.deinit(self.alloc);
    }

    pub fn enqueue(self: *ServerEndpoint, data: []const u8) !void {
        try self.pending.appendSlice(self.alloc, data);
    }

    fn shouldDropOriginal(net: *const FakeNet, idx: u32) bool {
        for (net.cfg.drop_output_packets) |d| {
            if (d == idx) return true;
        }
        return false;
    }

    fn extraLatencyFor(net: *const FakeNet, idx: u32) u64 {
        for (net.cfg.extra_latency) |e| {
            if (e.idx == idx) return e.extra_us;
        }
        return 0;
    }

    fn buildAndSubmitOutput(
        self: *ServerEndpoint,
        net: *FakeNet,
        clock: *const Clock,
        offset: u64,
        data: []const u8,
        is_retransmit: bool,
    ) !void {
        std.debug.assert(data.len <= transport.max_output_data_len);
        var payload_buf: [transport.max_payload_len]u8 = undefined;
        transport.writeOutputOffset(payload_buf[0..transport.output_offset_prefix_len], offset);
        @memcpy(payload_buf[transport.output_offset_prefix_len..][0..data.len], data);
        const payload = payload_buf[0 .. transport.output_offset_prefix_len + data.len];

        var pkt_buf: [1200]u8 = undefined;
        const pkt = try transport.buildUnreliable(.output, 0, 0, 0, payload, &pkt_buf);

        var force_drop = false;
        var extra: u64 = 0;
        if (is_retransmit) {
            if (net.cfg.drop_retransmits) force_drop = true;
        } else {
            const idx = self.output_packet_index;
            self.output_packet_index += 1;
            if (shouldDropOriginal(net, idx)) force_drop = true;
            extra = extraLatencyFor(net, idx);
        }

        self.cc.onPacketSent(offset, @intCast(data.len), clock.now_us);

        if (!force_drop) {
            _ = try net.submit(clock, .s2c, pkt, extra);
        }
    }

    /// Try to flush as many bytes from `pending` as the CC allows.
    pub fn flush(self: *ServerEndpoint, net: *FakeNet, clock: *const Clock) !void {
        var sent: usize = 0;
        while (sent < self.pending.items.len) {
            const remain = self.pending.items.len - sent;
            const take = @min(remain, transport.max_output_data_len);
            const pkt_size: u64 = take + transport.output_offset_prefix_len + 20;
            if (!self.cc.canSend(pkt_size, clock.now_us)) break;

            const offset = self.next_output_offset;
            const chunk = self.pending.items[sent..][0..take];

            // Record before submitting (so the slot exists even if dropped).
            const idx = self.ring_write % self.ring.len;
            self.ring_write += 1;
            const slot = &self.ring[idx];
            slot.offset_start = offset;
            slot.length = @intCast(take);
            slot.send_time_us = clock.now_us;
            slot.last_retransmit_us = 0;
            @memcpy(slot.payload[0..take], chunk);
            slot.in_use = true;

            try self.buildAndSubmitOutput(net, clock, offset, chunk, false);
            self.next_output_offset += take;
            sent += take;
        }
        if (sent > 0) {
            const remaining = self.pending.items.len - sent;
            std.mem.copyForwards(u8, self.pending.items[0..remaining], self.pending.items[sent..]);
            self.pending.shrinkRetainingCapacity(remaining);
        }
    }

    fn findRetransmitSlot(self: *ServerEndpoint, offset_start: u64) ?*RetransmitSlot {
        for (self.ring) |*slot| {
            if (!slot.in_use) continue;
            if (slot.offset_start == offset_start) return slot;
        }
        return null;
    }

    fn ackContiguousBelow(self: *ServerEndpoint, cutoff: u64, now_us: u64) void {
        for (self.ring) |*slot| {
            if (!slot.in_use) continue;
            const end = slot.offset_start + slot.length;
            if (end <= cutoff) {
                const send_time = slot.send_time_us;
                const rtt_us: u64 = if (now_us > send_time) now_us - send_time else 1;
                self.cc.onAck(slot.offset_start, slot.length, rtt_us, now_us);
                slot.in_use = false;
            }
        }
    }

    fn cooldownUs(self: *const ServerEndpoint) u64 {
        const srtt = self.cc.ctx.smoothed_rtt_us;
        const c = if (srtt == 0) default_srtt_us else srtt;
        return @max(c, @as(u64, 20_000));
    }

    fn applySack(
        self: *ServerEndpoint,
        net: *FakeNet,
        clock: *const Clock,
        sack: transport.OutputAckPayload,
    ) !void {
        self.ackContiguousBelow(sack.highest_contiguous_offset, clock.now_us);
        self.last_sack = sack;
        self.last_sack_at = clock.now_us;

        var i: usize = 0;
        while (i < sack.n_gaps) : (i += 1) {
            const gap = sack.gaps[i];
            if (gap.len == 0) continue;
            const gap_start = sack.highest_contiguous_offset + gap.start_rel;
            if (self.findRetransmitSlot(gap_start)) |slot| {
                self.cc.onLoss(slot.offset_start, slot.length, clock.now_us);
                if (clock.now_us - slot.last_retransmit_us >= self.cooldownUs()) {
                    slot.last_retransmit_us = clock.now_us;
                    try self.buildAndSubmitOutput(net, clock, slot.offset_start, slot.payload[0..slot.length], true);
                }
            } else {
                // Range evicted from ring → escalate to resync.
                self.cc.onLoss(gap_start, gap.len, clock.now_us);
                self.requestResync(clock);
            }
        }
    }

    fn requestResync(self: *ServerEndpoint, clock: *const Clock) void {
        if (self.resync_requested and clock.now_us - self.last_resync_us < 250_000) return;
        self.resync_requested = true;
        self.last_resync_us = clock.now_us;
    }

    /// Drain s2c→c2s ack queue: receive any pending acks. Called by Scenario.
    pub fn handleIncoming(self: *ServerEndpoint, net: *FakeNet, clock: *const Clock) !void {
        while (net.popDue(clock, .c2s)) |bytes| {
            defer net.alloc.free(bytes);
            const packet = transport.parsePacket(bytes) catch continue;
            if (packet.channel != .output_ack) continue;
            const sack = transport.parseOutputAckPayload(packet.payload) orelse continue;
            try self.applySack(net, clock, sack);
        }
    }

    /// Periodic tick: try to flush more pending bytes (CWND may have opened).
    pub fn tick(self: *ServerEndpoint, net: *FakeNet, clock: *const Clock) !void {
        try self.flush(net, clock);
    }
};

// ---------------------------------------------------------------------------
// Client endpoint
// ---------------------------------------------------------------------------

pub const ClientEndpoint = struct {
    alloc: std.mem.Allocator,
    reorder: reorder_buffer.ReorderBuffer,
    next_deliver_offset: u64 = 0,
    delivered: std.ArrayList(u8),
    unacked_count: u32 = 0,
    last_ack_us: u64 = 0,
    resync_requested: bool = false,
    last_resync_us: u64 = 0,

    pub fn init(alloc: std.mem.Allocator) !ClientEndpoint {
        return .{
            .alloc = alloc,
            .reorder = try reorder_buffer.ReorderBuffer.init(alloc),
            .delivered = try std.ArrayList(u8).initCapacity(alloc, 4096),
        };
    }

    pub fn deinit(self: *ClientEndpoint) void {
        self.reorder.deinit();
        self.delivered.deinit(self.alloc);
    }

    fn requestResync(self: *ClientEndpoint, clock: *const Clock) void {
        if (self.resync_requested and clock.now_us - self.last_resync_us < 250_000) return;
        self.resync_requested = true;
        self.last_resync_us = clock.now_us;
    }

    fn handleOutputPacket(
        self: *ClientEndpoint,
        clock: *const Clock,
        payload: []const u8,
    ) !void {
        const start_offset = transport.readOutputOffset(payload) orelse return;
        const data_full = payload[transport.output_offset_prefix_len..];
        if (data_full.len == 0) return;

        var data: []const u8 = data_full;
        var offset: u64 = start_offset;
        if (offset < self.next_deliver_offset) {
            const skip = self.next_deliver_offset - offset;
            if (skip >= data.len) {
                self.unacked_count +%= 1;
                return;
            }
            data = data[@intCast(skip)..];
            offset = self.next_deliver_offset;
        }

        self.unacked_count +%= 1;

        if (offset == self.next_deliver_offset) {
            try self.delivered.appendSlice(self.alloc, data);
            self.next_deliver_offset += data.len;
            while (self.reorder.popAt(self.next_deliver_offset)) |buf_bytes| {
                defer self.alloc.free(buf_bytes);
                try self.delivered.appendSlice(self.alloc, buf_bytes);
                self.next_deliver_offset += buf_bytes.len;
            }
        } else {
            try self.reorder.insert(offset, data, clock.now_us);
            if (self.reorder.isOverCapacity()) {
                self.reorder.clear();
                self.requestResync(clock);
            }
        }
    }

    pub fn handleIncoming(self: *ClientEndpoint, net: *FakeNet, clock: *const Clock) !void {
        while (net.popDue(clock, .s2c)) |bytes| {
            defer net.alloc.free(bytes);
            const packet = transport.parsePacket(bytes) catch continue;
            if (packet.channel != .output) continue;
            try self.handleOutputPacket(clock, packet.payload);
        }
    }

    fn srttUs(self: *const ClientEndpoint) u64 {
        _ = self;
        return default_srtt_us;
    }

    pub fn tick(self: *ClientEndpoint, net: *FakeNet, clock: *const Clock) !void {
        // Stale-gap detection.
        if (self.reorder.oldestArrivedUs()) |oldest| {
            if (clock.now_us > oldest and (clock.now_us - oldest) > reorder_buffer.staleGapTimeoutUs(self.srttUs())) {
                self.reorder.clear();
                self.requestResync(clock);
            }
        }

        const have_gaps = self.reorder.fragments.items.len > 0;
        if (self.unacked_count > 0 or have_gaps) {
            const due_by_time = (clock.now_us - self.last_ack_us) >= ack_min_interval_us;
            const due_by_count = self.unacked_count >= ack_max_unacked;
            if (due_by_time or due_by_count) {
                try self.sendAck(net, clock);
            }
        }
    }

    pub fn sendAck(self: *ClientEndpoint, net: *FakeNet, clock: *const Clock) !void {
        var gaps: [transport.max_sack_gaps]transport.SackGap = undefined;
        const n = self.reorder.computeGaps(self.next_deliver_offset, &gaps);
        var ack_buf: [transport.output_ack_max_encoded_len]u8 = undefined;
        const ack_payload = transport.buildOutputAckPayload(self.next_deliver_offset, gaps[0..n], &ack_buf);
        var pkt_buf: [128]u8 = undefined;
        const pkt = try transport.buildUnreliable(.output_ack, 0, 0, 0, ack_payload, &pkt_buf);
        _ = try net.submit(clock, .c2s, pkt, 0);
        self.last_ack_us = clock.now_us;
        self.unacked_count = 0;
    }
};

// ---------------------------------------------------------------------------
// Scenario runner
// ---------------------------------------------------------------------------

pub const Scenario = struct {
    alloc: std.mem.Allocator,
    clock: Clock = .{},
    net: FakeNet,
    server: ServerEndpoint,
    client: ClientEndpoint,

    pub fn init(alloc: std.mem.Allocator, cfg: NetConfig) !Scenario {
        return .{
            .alloc = alloc,
            .net = try FakeNet.init(alloc, cfg),
            .server = try ServerEndpoint.init(alloc, 0),
            .client = try ClientEndpoint.init(alloc),
        };
    }

    pub fn deinit(self: *Scenario) void {
        self.net.deinit();
        self.server.deinit();
        self.client.deinit();
    }

    pub fn writeBytes(self: *Scenario, data: []const u8) !void {
        try self.server.enqueue(data);
    }

    /// Drive the simulation until either the client has delivered
    /// `target_bytes`, a resync was requested by either side, or
    /// `max_iter` iterations have elapsed.
    pub fn runUntilDelivered(self: *Scenario, target_bytes: usize, max_iter: u32) !void {
        var i: u32 = 0;
        while (i < max_iter) : (i += 1) {
            try self.server.tick(&self.net, &self.clock);
            try self.client.handleIncoming(&self.net, &self.clock);
            try self.client.tick(&self.net, &self.clock);
            try self.server.handleIncoming(&self.net, &self.clock);

            if (self.client.delivered.items.len >= target_bytes) return;
            if (self.server.resync_requested or self.client.resync_requested) return;

            // Advance the clock: jump to the next interesting deadline so we
            // don't waste loops idling. The interesting deadlines are
            // (a) next packet delivery and (b) the client's next ack window.
            const next_pkt = self.net.nextDeliveryUs();
            var next_evt: u64 = self.clock.now_us + 1_000;
            if (next_pkt) |t| next_evt = @max(self.clock.now_us + 1, t);
            const ack_due = self.client.last_ack_us + ack_min_interval_us;
            if (self.client.unacked_count > 0 and ack_due > self.clock.now_us and ack_due < next_evt) {
                next_evt = ack_due;
            }
            if (next_evt <= self.clock.now_us) next_evt = self.clock.now_us + 1_000;
            self.clock.now_us = next_evt;
        }
    }

    pub fn assertDeliveredEquals(self: *const Scenario, expected: []const u8) !void {
        try std.testing.expectEqualSlices(u8, expected, self.client.delivered.items);
    }

    pub fn assertNoResync(self: *const Scenario) !void {
        try std.testing.expect(!self.server.resync_requested);
        try std.testing.expect(!self.client.resync_requested);
    }

    pub fn assertResyncTriggered(self: *const Scenario) !void {
        try std.testing.expect(self.server.resync_requested or self.client.resync_requested);
    }
};

// ---------------------------------------------------------------------------
// Helpers for tests
// ---------------------------------------------------------------------------

fn makePayload(alloc: std.mem.Allocator, n: usize, seed: u8) ![]u8 {
    const buf = try alloc.alloc(u8, n);
    var x: u8 = seed;
    for (buf) |*b| {
        b.* = x;
        x +%= 31;
    }
    return buf;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "net_sim: clean link delivers byte-exact" {
    var s = try Scenario.init(std.testing.allocator, .{});
    defer s.deinit();
    const payload = try makePayload(std.testing.allocator, 4096, 0);
    defer std.testing.allocator.free(payload);
    try s.writeBytes(payload);
    try s.runUntilDelivered(payload.len, 10_000);
    try s.assertDeliveredEquals(payload);
    try s.assertNoResync();
}

test "net_sim: single mid-stream loss recovered via SACK" {
    var s = try Scenario.init(std.testing.allocator, .{
        .drop_output_packets = &.{2},
    });
    defer s.deinit();
    const payload = try makePayload(std.testing.allocator, 8192, 7);
    defer std.testing.allocator.free(payload);
    try s.writeBytes(payload);
    try s.runUntilDelivered(payload.len, 10_000);
    try s.assertDeliveredEquals(payload);
    try s.assertNoResync();
}

test "net_sim: multiple gaps in single ack window" {
    var s = try Scenario.init(std.testing.allocator, .{
        .drop_output_packets = &.{ 2, 4, 6 },
    });
    defer s.deinit();
    const payload = try makePayload(std.testing.allocator, 12_000, 13);
    defer std.testing.allocator.free(payload);
    try s.writeBytes(payload);
    try s.runUntilDelivered(payload.len, 10_000);
    try s.assertDeliveredEquals(payload);
    try s.assertNoResync();
}

test "net_sim: reorder absorption (1,3,2,4,5)" {
    // Delay packet 1 (the second original) so it arrives after packet 2.
    var s = try Scenario.init(std.testing.allocator, .{
        .extra_latency = &.{.{ .idx = 1, .extra_us = 5_000 }},
    });
    defer s.deinit();
    const payload = try makePayload(std.testing.allocator, 5500, 21);
    defer std.testing.allocator.free(payload);
    try s.writeBytes(payload);
    try s.runUntilDelivered(payload.len, 10_000);
    try s.assertDeliveredEquals(payload);
    try s.assertNoResync();
}

test "net_sim: duplicate retransmit dropped silently" {
    // Drop the original packet 1; the SACK-driven retransmit will recover
    // it. Then we re-inject the SAME slot bytes a second time and verify
    // the client treats the late "duplicate" as a no-op.
    var s = try Scenario.init(std.testing.allocator, .{
        .drop_output_packets = &.{1},
    });
    defer s.deinit();
    const payload = try makePayload(std.testing.allocator, 6000, 99);
    defer std.testing.allocator.free(payload);
    try s.writeBytes(payload);
    try s.runUntilDelivered(payload.len, 10_000);
    try s.assertDeliveredEquals(payload);

    // Forge a duplicate of every still-known retransmit slot — at least the
    // recovered one should still be in the ring. The client must ignore it.
    for (s.server.ring) |*slot| {
        if (!slot.in_use) continue;
        try s.server.buildAndSubmitOutput(&s.net, &s.clock, slot.offset_start, slot.payload[0..slot.length], true);
        break;
    }
    var i: u32 = 0;
    while (i < 200 and !s.net.isEmpty()) : (i += 1) {
        try s.client.handleIncoming(&s.net, &s.clock);
        s.clock.advance(1_000);
    }
    try s.assertDeliveredEquals(payload);
    try s.assertNoResync();
}

test "net_sim: ring eviction triggers resync" {
    // Tiny ring → easy eviction. Drop very early packet then send enough
    // bytes that the ring wraps past the evicted slot.
    var s = try Scenario.init(std.testing.allocator, .{
        .drop_output_packets = &.{0},
    });
    defer s.deinit();

    // Force eviction by manually shrinking the ring to a few slots.
    // The harness owns the ring slice, so we just truncate it.
    s.alloc.free(s.server.ring);
    s.server.ring = try s.alloc.alloc(RetransmitSlot, 4);
    for (s.server.ring) |*slot| slot.* = .{};

    const payload = try makePayload(std.testing.allocator, 32_000, 5);
    defer std.testing.allocator.free(payload);
    try s.writeBytes(payload);
    try s.runUntilDelivered(payload.len, 20_000);
    try s.assertResyncTriggered();
}

test "net_sim: stale gap timeout triggers resync" {
    // Drop packet 1 AND every retransmit so the gap never closes.
    var s = try Scenario.init(std.testing.allocator, .{
        .drop_output_packets = &.{1},
        .drop_retransmits = true,
    });
    defer s.deinit();
    const payload = try makePayload(std.testing.allocator, 8000, 3);
    defer std.testing.allocator.free(payload);
    try s.writeBytes(payload);
    try s.runUntilDelivered(payload.len, 50_000);
    try s.assertResyncTriggered();
}

test "net_sim: escape sequences survive 5% loss" {
    var s = try Scenario.init(std.testing.allocator, .{
        .loss_pct = 5,
        .seed = 42,
    });
    defer s.deinit();
    var payload_list = try std.ArrayList(u8).initCapacity(std.testing.allocator, 8192);
    defer payload_list.deinit(std.testing.allocator);
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        try payload_list.appendSlice(std.testing.allocator, "\x1b[2J\x1b[H\x1b[31mred\x1b[0m hello world ");
    }
    const payload = payload_list.items;
    try s.writeBytes(payload);
    try s.runUntilDelivered(payload.len, 200_000);
    try s.assertDeliveredEquals(payload);
}

test "net_sim: reorder buffer overflow triggers resync" {
    // Drop a very early packet so a permanent gap exists, then stream
    // enough subsequent bytes that the client's reorder buffer exceeds the
    // 1024-fragment cap before any retransmit can land.
    var s = try Scenario.init(std.testing.allocator, .{
        .drop_output_packets = &.{2},
        .drop_retransmits = true,
        .latency_us = 1, // make the client see lots of out-of-order packets fast
    });
    defer s.deinit();
    // 1100 packets * ~1092 bytes ≈ 1.2 MB. > 1024 fragments → overflow.
    const payload = try makePayload(std.testing.allocator, 1100 * transport.max_output_data_len, 11);
    defer std.testing.allocator.free(payload);
    try s.writeBytes(payload);
    try s.runUntilDelivered(payload.len, 200_000);
    try s.assertResyncTriggered();
}

test "net_sim: retransmit rate-limited per RTT" {
    var s = try Scenario.init(std.testing.allocator, .{
        .drop_output_packets = &.{1},
    });
    defer s.deinit();
    const payload = try makePayload(std.testing.allocator, 6000, 17);
    defer std.testing.allocator.free(payload);
    try s.writeBytes(payload);

    // Pump until the gap appears; then issue several SACKs in a tight window.
    try s.server.tick(&s.net, &s.clock);
    var i: u32 = 0;
    while (i < 50) : (i += 1) {
        try s.client.handleIncoming(&s.net, &s.clock);
        s.clock.advance(1_000);
    }
    // Snapshot the slot's last_retransmit_us before/after a burst of SACKs.
    const slot_offset: u64 = transport.max_output_data_len; // packet idx 1's offset
    var first_rtx_us: u64 = 0;
    var rtx_count: u32 = 0;
    var k: u32 = 0;
    while (k < 5) : (k += 1) {
        try s.client.sendAck(&s.net, &s.clock);
        try s.server.handleIncoming(&s.net, &s.clock);
        if (s.server.findRetransmitSlot(slot_offset)) |slot| {
            if (slot.last_retransmit_us != 0 and slot.last_retransmit_us != first_rtx_us) {
                if (first_rtx_us == 0) first_rtx_us = slot.last_retransmit_us;
                rtx_count += 1;
            }
        }
        s.clock.advance(1_000); // less than cooldown (~20ms)
    }
    // Only one retransmit should have fired in the cooldown window.
    try std.testing.expect(rtx_count <= 1);
}

test "net_sim: repeated retransmit attempts eventually resync (drop_retransmits)" {
    // With drop_retransmits=true the gap never closes, so the harness
    // observes the stale-gap-timeout escalation. Documented outcome.
    var s = try Scenario.init(std.testing.allocator, .{
        .drop_output_packets = &.{1},
        .drop_retransmits = true,
    });
    defer s.deinit();
    const payload = try makePayload(std.testing.allocator, 6000, 41);
    defer std.testing.allocator.free(payload);
    try s.writeBytes(payload);
    try s.runUntilDelivered(payload.len, 100_000);
    try s.assertResyncTriggered();
}

test "net_sim: bulk 256 KB at 3% loss delivers byte-exact and progresses C4" {
    var s = try Scenario.init(std.testing.allocator, .{
        .loss_pct = 3,
        .seed = 0xBEEF,
    });
    defer s.deinit();
    const payload = try makePayload(std.testing.allocator, 256 * 1024, 77);
    defer std.testing.allocator.free(payload);
    try s.writeBytes(payload);
    try s.runUntilDelivered(payload.len, 1_000_000);
    try s.assertDeliveredEquals(payload);
    // C4 should have left .initial state by the time bulk delivery completes.
    // (We only check it's no longer the initial reset state.)
    try std.testing.expect(s.server.cc.ctx.bandwidth_estimate_bps > 0);
}
