const std = @import("std");
const ipc = @import("ipc.zig");

pub const version: u8 = 2;
pub const max_payload_len: usize = 1100;
const header_len: usize = 20;

/// On the output channel, payloads are prefixed with an 8-byte big-endian
/// `start_offset: u64`. The remaining bytes are the actual stream data
/// starting at that byte offset. The output channel is now a reliable,
/// ordered byte stream — the server retransmits gaps in response to SACKs
/// from the client and the client reorders before delivering to stdout.
pub const output_offset_prefix_len: usize = 8;
pub const max_output_data_len: usize = max_payload_len - output_offset_prefix_len;

pub fn writeOutputOffset(buf: []u8, offset: u64) void {
    std.debug.assert(buf.len >= output_offset_prefix_len);
    std.mem.writeInt(u64, buf[0..8], offset, .big);
}

pub fn readOutputOffset(payload: []const u8) ?u64 {
    if (payload.len < output_offset_prefix_len) return null;
    return std.mem.readInt(u64, payload[0..8], .big);
}

pub const Channel = enum(u8) {
    heartbeat = 0,
    reliable_ipc = 1,
    output = 2,
    control = 3,
    output_ack = 4,
};

/// Payload of an output_ack packet. SACK over the byte-offset output stream.
///
/// `highest_contiguous_offset` — all bytes strictly below this are received
/// in order. `gaps` — up to 8 missing ranges above the high-water mark, with
/// `start` expressed as a byte offset RELATIVE to `highest_contiguous_offset`
/// (so it fits in u32 even on long-running sessions).
pub const max_sack_gaps: usize = 8;

pub const SackGap = struct {
    start_rel: u32,
    len: u32,
};

pub const OutputAckPayload = struct {
    highest_contiguous_offset: u64,
    gaps: [max_sack_gaps]SackGap = [_]SackGap{.{ .start_rel = 0, .len = 0 }} ** max_sack_gaps,
    n_gaps: u8 = 0,
};

/// Maximum encoded length of an output_ack payload (8 + 1 + 8*8 = 73).
pub const output_ack_max_encoded_len: usize = 9 + max_sack_gaps * 8;

pub fn buildOutputAckPayload(
    highest_contiguous_offset: u64,
    gaps: []const SackGap,
    out: []u8,
) []const u8 {
    std.debug.assert(gaps.len <= max_sack_gaps);
    const total = 9 + gaps.len * 8;
    std.debug.assert(out.len >= total);
    std.mem.writeInt(u64, out[0..8], highest_contiguous_offset, .big);
    out[8] = @intCast(gaps.len);
    var i: usize = 0;
    while (i < gaps.len) : (i += 1) {
        const base = 9 + i * 8;
        std.mem.writeInt(u32, out[base..][0..4], gaps[i].start_rel, .big);
        std.mem.writeInt(u32, out[base + 4 ..][0..4], gaps[i].len, .big);
    }
    return out[0..total];
}

pub fn parseOutputAckPayload(payload: []const u8) ?OutputAckPayload {
    if (payload.len < 9) return null;
    const high = std.mem.readInt(u64, payload[0..8], .big);
    const n: usize = payload[8];
    if (n > max_sack_gaps) return null;
    if (payload.len < 9 + n * 8) return null;
    var out: OutputAckPayload = .{ .highest_contiguous_offset = high, .n_gaps = @intCast(n) };
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const base = 9 + i * 8;
        out.gaps[i] = .{
            .start_rel = std.mem.readInt(u32, payload[base..][0..4], .big),
            .len = std.mem.readInt(u32, payload[base + 4 ..][0..4], .big),
        };
    }
    return out;
}

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

/// Heartbeat payload: advertises receiver-side flow-control window for the
/// output byte stream. `max_byte_offset` is the highest output-channel byte
/// offset the client is willing to accept. The server must not send output
/// packets whose `start_offset + payload_len` exceeds `max_byte_offset`.
pub const HeartbeatPayload = extern struct {
    max_byte_offset: u64,
};

pub fn buildHeartbeatPayload(max_byte_offset: u64, out: *[8]u8) []const u8 {
    std.mem.writeInt(u64, out, max_byte_offset, .big);
    return out[0..8];
}

pub fn parseHeartbeatPayload(payload: []const u8) ?HeartbeatPayload {
    if (payload.len < 8) return null;
    const max_byte_offset = std.mem.readInt(u64, payload[0..8], .big);
    return .{ .max_byte_offset = max_byte_offset };
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

test "output_ack SACK round trip" {
    var buf: [output_ack_max_encoded_len]u8 = undefined;

    // No-gap case.
    const empty: []const SackGap = &.{};
    const p_empty = buildOutputAckPayload(123_456, empty, &buf);
    const parsed_empty = parseOutputAckPayload(p_empty).?;
    try std.testing.expectEqual(@as(u64, 123_456), parsed_empty.highest_contiguous_offset);
    try std.testing.expectEqual(@as(u8, 0), parsed_empty.n_gaps);

    // Gappy case: 3 gaps of varying sizes.
    var buf2: [output_ack_max_encoded_len]u8 = undefined;
    const gaps = [_]SackGap{
        .{ .start_rel = 100, .len = 50 },
        .{ .start_rel = 200, .len = 75 },
        .{ .start_rel = 1000, .len = 1 },
    };
    const p2 = buildOutputAckPayload(0xDEAD_BEEF_CAFE_0000, gaps[0..], &buf2);
    const parsed2 = parseOutputAckPayload(p2).?;
    try std.testing.expectEqual(@as(u64, 0xDEAD_BEEF_CAFE_0000), parsed2.highest_contiguous_offset);
    try std.testing.expectEqual(@as(u8, 3), parsed2.n_gaps);
    try std.testing.expectEqual(@as(u32, 100), parsed2.gaps[0].start_rel);
    try std.testing.expectEqual(@as(u32, 50), parsed2.gaps[0].len);
    try std.testing.expectEqual(@as(u32, 200), parsed2.gaps[1].start_rel);
    try std.testing.expectEqual(@as(u32, 75), parsed2.gaps[1].len);
    try std.testing.expectEqual(@as(u32, 1000), parsed2.gaps[2].start_rel);
    try std.testing.expectEqual(@as(u32, 1), parsed2.gaps[2].len);

    // Truncated payload should fail.
    try std.testing.expect(parseOutputAckPayload(p2[0 .. p2.len - 1]) == null);
}

test "heartbeat byte-offset round trip" {
    var buf: [8]u8 = undefined;
    const payload = buildHeartbeatPayload(0x1122_3344_5566_7788, &buf);
    const parsed = parseHeartbeatPayload(payload).?;
    try std.testing.expectEqual(@as(u64, 0x1122_3344_5566_7788), parsed.max_byte_offset);
}

test "output offset prefix round trip" {
    var buf: [output_offset_prefix_len]u8 = undefined;
    writeOutputOffset(&buf, 0xCAFEBABE_DEADBEEF);
    try std.testing.expectEqual(@as(u64, 0xCAFEBABE_DEADBEEF), readOutputOffset(&buf).?);
}
