const std = @import("std");
const ipc = @import("ipc.zig");

pub const version: u8 = 2;
pub const max_payload_len: usize = 1100;
const header_len: usize = 20;

pub const Channel = enum(u8) {
    heartbeat = 0,
    reliable_ipc = 1,
    output = 2,
    control = 3,
};

pub const Control = enum(u8) {
    resync_request = 1,
};

pub const Packet = struct {
    channel: Channel,
    seq: u32,
    ack: u32,
    ack_bits: u32,
    payload: []const u8,
};

pub const ReliableAction = enum {
    accept,
    duplicate,
    stale,
};

pub const OutputAction = enum {
    delivered,
    buffered,
    duplicate,
    stale,
    gap_resync,
};

pub const RecvState = struct {
    latest: u32 = 0,
    mask: u32 = 0,
    has_latest: bool = false,

    pub fn onReliable(self: *RecvState, seq: u32) ReliableAction {
        if (!self.has_latest) {
            self.latest = seq;
            self.mask = 0;
            self.has_latest = true;
            return .accept;
        }

        if (seq > self.latest) {
            const shift = seq - self.latest;
            if (shift >= 32) {
                self.mask = 0;
            } else {
                self.mask <<= @intCast(shift);
                self.mask |= @as(u32, 1) << @intCast(shift - 1);
            }
            self.latest = seq;
            return .accept;
        }

        const diff = self.latest - seq;
        if (diff == 0) return .duplicate;
        if (diff > 32) return .stale;

        const bit: u32 = @as(u32, 1) << @intCast(diff - 1);
        if (self.mask & bit != 0) return .duplicate;
        self.mask |= bit;
        return .accept;
    }

    pub fn ack(self: *const RecvState) u32 {
        return if (self.has_latest) self.latest else 0;
    }

    pub fn ackBits(self: *const RecvState) u32 {
        return if (self.has_latest) self.mask else 0;
    }
};

pub const step: u32 = max_payload_len;

pub const OutputRecvState = struct {
    pub const window_size = 256;

    next_offset: u32 = 0,
    has_expected: bool = false,

    slots: [window_size]Slot = [1]Slot{.{}} ** window_size,
    deliver_start: u32 = 0,
    deliver_count: usize = 0,

    // Diagnostic counters
    delivered_total: u64 = 0,
    buffered_total: u64 = 0,
    gap_resync_total: u64 = 0,
    max_reorder_dist: u32 = 0,

    const Slot = struct {
        occupied: bool = false,
        len: usize = 0,
        data: [max_payload_len]u8 = undefined,
    };

    fn slotIdx(offset: u32) usize {
        return (offset / step) % window_size;
    }

    pub const DeliverySlice = struct {
        state: *const OutputRecvState,

        pub fn len(self: DeliverySlice) usize {
            return self.state.deliver_count;
        }

        pub fn get(self: DeliverySlice, i: usize) []const u8 {
            const offset = self.state.deliver_start +% @as(u32, @intCast(i)) *% step;
            const slot = &self.state.slots[slotIdx(offset)];
            return slot.data[0..slot.len];
        }
    };

    pub fn onPacket(self: *OutputRecvState, offset: u32, payload: []const u8) OutputAction {
        self.deliver_count = 0;

        if (!self.has_expected) {
            self.next_offset = offset;
            self.has_expected = true;
        }

        if (offset == self.next_offset) {
            // In-order: store, deliver this + any consecutive buffered
            self.storeSlot(offset, payload);
            self.deliver_start = offset;
            var next = offset +% step;
            var count: usize = 1;
            while (count < window_size) {
                if (!self.slots[slotIdx(next)].occupied) break;
                next +%= step;
                count += 1;
            }
            self.deliver_count = count;
            self.delivered_total += count;
            // Clear delivered slots (data stays valid until next onPacket call)
            var s = offset;
            for (0..count) |_| {
                self.slots[slotIdx(s)].occupied = false;
                s +%= step;
            }
            self.next_offset = next;
            return .delivered;
        }

        // Offset is behind next_offset (duplicate or stale retransmit).
        // Use wrapping-aware comparison: diff > 0 and < 0x80000000 means behind.
        const behind_diff = self.next_offset -% offset;
        if (behind_diff > 0 and behind_diff < 0x80000000) {
            return if (behind_diff <= @as(u32, window_size) * step) .duplicate else .stale;
        }

        // offset > next_offset: out-of-order
        const gap = (offset -% self.next_offset) / step;
        if (gap >= window_size) {
            // Too far ahead — unrecoverable gap
            self.clearAllSlots();
            self.next_offset = offset +% step;
            self.gap_resync_total += 1;
            return .gap_resync;
        }

        // Within window: buffer (detect duplicate buffered packets)
        if (self.slots[slotIdx(offset)].occupied) return .duplicate;
        self.storeSlot(offset, payload);
        self.buffered_total += 1;
        self.max_reorder_dist = @max(self.max_reorder_dist, gap);
        return .buffered;
    }

    fn storeSlot(self: *OutputRecvState, offset: u32, payload: []const u8) void {
        const idx = slotIdx(offset);
        @memcpy(self.slots[idx].data[0..payload.len], payload);
        self.slots[idx].len = payload.len;
        self.slots[idx].occupied = true;
    }

    fn clearAllSlots(self: *OutputRecvState) void {
        for (&self.slots) |*slot| {
            slot.occupied = false;
        }
    }

    pub fn deliverSlice(self: *const OutputRecvState) DeliverySlice {
        return .{ .state = self };
    }
};

pub const ReliableSend = struct {
    alloc: std.mem.Allocator,
    next_seq: u32 = 1,
    pending: std.ArrayList(Pending),

    const Pending = struct {
        seq: u32,
        sent_ns: i64,
        retries: u8,
        packet: []u8,
    };

    pub fn init(alloc: std.mem.Allocator) !ReliableSend {
        return .{
            .alloc = alloc,
            .pending = try std.ArrayList(Pending).initCapacity(alloc, 16),
        };
    }

    pub fn deinit(self: *ReliableSend) void {
        for (self.pending.items) |p| {
            self.alloc.free(p.packet);
        }
        self.pending.deinit(self.alloc);
    }

    pub fn hasPending(self: *const ReliableSend) bool {
        return self.pending.items.len > 0;
    }

    pub fn buildAndTrack(
        self: *ReliableSend,
        channel: Channel,
        payload: []const u8,
        ack_seq: u32,
        ack_bits: u32,
        now_ns: i64,
    ) ![]const u8 {
        const seq = self.next_seq;
        self.next_seq +%= 1;

        const packet = try self.alloc.alloc(u8, header_len + payload.len);
        writeHeader(packet[0..header_len], channel, seq, ack_seq, ack_bits, payload.len);
        if (payload.len > 0) {
            @memcpy(packet[header_len..], payload);
        }

        try self.pending.append(self.alloc, .{
            .seq = seq,
            .sent_ns = now_ns,
            .retries = 0,
            .packet = packet,
        });

        return packet;
    }

    pub fn ack(self: *ReliableSend, ack_seq: u32, ack_bits: u32) void {
        var i: usize = self.pending.items.len;
        while (i > 0) {
            i -= 1;
            const p = self.pending.items[i];
            if (isAcked(p.seq, ack_seq, ack_bits)) {
                self.alloc.free(p.packet);
                _ = self.pending.swapRemove(i);
            }
        }
    }

    pub fn collectRetransmits(
        self: *ReliableSend,
        alloc: std.mem.Allocator,
        now_ns: i64,
        rto_us: i64,
    ) !std.ArrayList([]const u8) {
        var out = try std.ArrayList([]const u8).initCapacity(alloc, 4);
        const interval_ns = @max(@as(i64, 1), rto_us) * std.time.ns_per_us;

        for (self.pending.items) |*p| {
            if (now_ns - p.sent_ns >= interval_ns) {
                p.sent_ns = now_ns;
                p.retries +%= 1;
                try out.append(alloc, p.packet);
            }
        }

        return out;
    }

    fn isAcked(seq: u32, ack_seq: u32, ack_bits: u32) bool {
        if (ack_seq == 0) return false;
        if (seq == ack_seq) return true;
        if (seq > ack_seq) return false;

        const diff = ack_seq - seq;
        if (diff == 0) return true;
        if (diff > 32) return false;

        const bit: u32 = @as(u32, 1) << @intCast(diff - 1);
        return (ack_bits & bit) != 0;
    }
};

pub fn writeHeader(dst: []u8, channel: Channel, seq: u32, ack: u32, ack_bits: u32, payload_len: usize) void {
    std.debug.assert(dst.len >= header_len);
    std.debug.assert(payload_len <= std.math.maxInt(u16));

    dst[0] = version;
    dst[1] = @intFromEnum(channel);
    dst[2] = 0;
    dst[3] = 0;

    std.mem.writeInt(u32, dst[4..8], seq, .big);
    std.mem.writeInt(u32, dst[8..12], ack, .big);
    std.mem.writeInt(u32, dst[12..16], ack_bits, .big);
    std.mem.writeInt(u16, dst[16..18], @intCast(payload_len), .big);
    std.mem.writeInt(u16, dst[18..20], 0, .big);
}

pub fn parsePacket(data: []const u8) !Packet {
    if (data.len < header_len) return error.PacketTooShort;
    if (data[0] != version) return error.UnsupportedVersion;

    const channel_int = data[1];
    const channel = std.meta.intToEnum(Channel, channel_int) catch return error.InvalidChannel;

    const seq = std.mem.readInt(u32, data[4..8], .big);
    const ack = std.mem.readInt(u32, data[8..12], .big);
    const ack_bits = std.mem.readInt(u32, data[12..16], .big);
    const len = std.mem.readInt(u16, data[16..18], .big);

    if (data.len != header_len + len) return error.InvalidLength;

    return .{
        .channel = channel,
        .seq = seq,
        .ack = ack,
        .ack_bits = ack_bits,
        .payload = data[header_len..],
    };
}

pub fn buildUnreliable(
    channel: Channel,
    seq: u32,
    ack: u32,
    ack_bits: u32,
    payload: []const u8,
    out: []u8,
) ![]const u8 {
    const total = header_len + payload.len;
    if (out.len < total) return error.BufferTooSmall;
    writeHeader(out[0..header_len], channel, seq, ack, ack_bits, payload.len);
    if (payload.len > 0) {
        @memcpy(out[header_len..total], payload);
    }
    return out[0..total];
}

pub fn buildControl(control: Control, out: *[8]u8) []const u8 {
    out[0] = @intFromEnum(control);
    @memset(out[1..], 0);
    return out[0..1];
}

pub fn parseControl(payload: []const u8) !Control {
    if (payload.len < 1) return error.InvalidControl;
    return std.meta.intToEnum(Control, payload[0]) catch error.InvalidControl;
}

pub fn buildIpcBytes(tag: ipc.Tag, payload: []const u8, buf: []u8) []const u8 {
    const header = ipc.Header{ .tag = tag, .len = @intCast(payload.len) };
    const hdr_bytes = std.mem.asBytes(&header);
    const total = @sizeOf(ipc.Header) + payload.len;
    std.debug.assert(buf.len >= total);
    @memcpy(buf[0..@sizeOf(ipc.Header)], hdr_bytes);
    if (payload.len > 0) {
        @memcpy(buf[@sizeOf(ipc.Header)..total], payload);
    }
    return buf[0..total];
}

test "transport header round trip" {
    var buf: [64]u8 = undefined;
    const payload = "abc";
    const pkt = try buildUnreliable(.output, 7, 6, 0x55, payload, &buf);
    const parsed = try parsePacket(pkt);
    try std.testing.expect(parsed.channel == .output);
    try std.testing.expectEqual(@as(u32, 7), parsed.seq);
    try std.testing.expectEqual(@as(u32, 6), parsed.ack);
    try std.testing.expectEqual(@as(u32, 0x55), parsed.ack_bits);
    try std.testing.expectEqualStrings(payload, parsed.payload);
}

test "reliable recv window" {
    var recv = RecvState{};
    try std.testing.expect(recv.onReliable(10) == .accept);
    try std.testing.expect(recv.onReliable(9) == .accept);
    try std.testing.expect(recv.onReliable(9) == .duplicate);
    try std.testing.expect(recv.onReliable(11) == .accept);
    try std.testing.expectEqual(@as(u32, 11), recv.ack());
}

test "output reorder within window" {
    var out = OutputRecvState{};

    // Packet at offset 0 in order
    try std.testing.expect(out.onPacket(0, "aaa") == .delivered);
    try std.testing.expectEqual(@as(usize, 1), out.deliverSlice().len());
    try std.testing.expectEqualStrings("aaa", out.deliverSlice().get(0));

    // Packet at offset 2200 out of order (buffered)
    try std.testing.expect(out.onPacket(2200, "ccc") == .buffered);

    // Packet at offset 1100 fills the gap, delivers 1100 and 2200
    try std.testing.expect(out.onPacket(1100, "bbb") == .delivered);
    const d = out.deliverSlice();
    try std.testing.expectEqual(@as(usize, 2), d.len());
    try std.testing.expectEqualStrings("bbb", d.get(0));
    try std.testing.expectEqualStrings("ccc", d.get(1));
}

test "output no false gap on reorder" {
    var out = OutputRecvState{};
    try std.testing.expect(out.onPacket(0, "a") == .delivered);
    try std.testing.expect(out.onPacket(3300, "d") == .buffered);
    try std.testing.expect(out.onPacket(2200, "c") == .buffered);
    try std.testing.expect(out.onPacket(1100, "b") == .delivered);
    const d = out.deliverSlice();
    try std.testing.expectEqual(@as(usize, 3), d.len());
    try std.testing.expectEqualStrings("b", d.get(0));
    try std.testing.expectEqualStrings("c", d.get(1));
    try std.testing.expectEqualStrings("d", d.get(2));
}

test "output true gap beyond window" {
    var out = OutputRecvState{};
    try std.testing.expect(out.onPacket(0, "a") == .delivered);
    // Offset 300*1100 is 299 slots away from next_offset=1100, which is >= window_size (256)
    try std.testing.expect(out.onPacket(300 * 1100, "z") == .gap_resync);
}

test "output old retransmit beyond window is stale, not gap_resync" {
    var out = OutputRecvState{};
    // Advance to offset 400*1100 = 440000
    for (0..400) |i| {
        const offset: u32 = @intCast(i * max_payload_len);
        try std.testing.expect(out.onPacket(offset, "x") == .delivered);
    }
    // next_offset = 400*1100 = 440000
    // Old retransmit at offset 100*1100 = 110000 (330 slots behind, > window)
    // This should be .stale, NOT .gap_resync
    try std.testing.expect(out.onPacket(100 * 1100, "old") == .stale);
    // Verify next_offset wasn't reset
    try std.testing.expectEqual(@as(u32, 440000), out.next_offset);
}

test "output duplicate detection with reorder buffer" {
    var out = OutputRecvState{};
    try std.testing.expect(out.onPacket(0, "a") == .delivered);
    try std.testing.expect(out.onPacket(0, "a") == .duplicate);
    try std.testing.expect(out.onPacket(2200, "c") == .buffered);
    try std.testing.expect(out.onPacket(2200, "c") == .duplicate);
}

test "output large sequential burst" {
    var out = OutputRecvState{};
    for (0..100) |i| {
        const offset: u32 = @intCast(i * max_payload_len);
        try std.testing.expect(out.onPacket(offset, "x") == .delivered);
        try std.testing.expectEqual(@as(usize, 1), out.deliverSlice().len());
    }
}
