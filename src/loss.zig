const std = @import("std");
const transport = @import("transport.zig");
const congestion = @import("congestion.zig");

// ---------------------------------------------------------------------------
// ACK Range Codec (QUIC-style, for heartbeat payload)
// ---------------------------------------------------------------------------

pub const AckRanges = struct {
    largest_acked: u32,
    first_range: u16,
    gaps: []const Gap,

    pub const Gap = struct { gap: u16, range: u16 };
    pub const max_gaps = 16;
    /// Header: largest_acked(4) + first_range(2) + num_gaps(1) = 7
    pub const header_size = 7;

    pub fn encode(self: *const AckRanges, buf: []u8) ![]const u8 {
        const needed = header_size + self.gaps.len * 4;
        if (buf.len < needed) return error.BufferTooSmall;

        std.mem.writeInt(u32, buf[0..4], self.largest_acked, .big);
        std.mem.writeInt(u16, buf[4..6], self.first_range, .big);
        buf[6] = @intCast(self.gaps.len);

        var off: usize = header_size;
        for (self.gaps) |g| {
            std.mem.writeInt(u16, buf[off..][0..2], g.gap, .big);
            std.mem.writeInt(u16, buf[off + 2 ..][0..2], g.range, .big);
            off += 4;
        }

        return buf[0..off];
    }

    pub fn decode(data: []const u8, gap_storage: []Gap) !AckRanges {
        if (data.len < header_size) return error.TooShort;

        const largest = std.mem.readInt(u32, data[0..4], .big);
        const first_range = std.mem.readInt(u16, data[4..6], .big);
        const num_gaps: usize = data[6];

        if (num_gaps > gap_storage.len) return error.TooManyGaps;
        if (data.len < header_size + num_gaps * 4) return error.TooShort;

        for (0..num_gaps) |i| {
            const off = header_size + i * 4;
            gap_storage[i] = .{
                .gap = std.mem.readInt(u16, data[off..][0..2], .big),
                .range = std.mem.readInt(u16, data[off + 2 ..][0..2], .big),
            };
        }

        return .{
            .largest_acked = largest,
            .first_range = first_range,
            .gaps = gap_storage[0..num_gaps],
        };
    }

    /// Iterate all ACKed sequence numbers and call callback(seq) for each.
    pub fn iterateAcked(self: *const AckRanges, callback: anytype) void {
        // First range: [largest - first_range, largest]
        var seq = self.largest_acked;
        var i: u32 = 0;
        while (i <= self.first_range) : (i += 1) {
            callback.call(seq);
            if (seq == 0) return;
            seq -%= 1;
        }

        // Additional ranges
        for (self.gaps) |g| {
            // Skip gap
            if (seq < g.gap) return;
            seq -%= g.gap;
            // Ack range
            var j: u32 = 0;
            while (j <= g.range) : (j += 1) {
                callback.call(seq);
                if (seq == 0) return;
                seq -%= 1;
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Send Buffer (server side — stores sent packets for retransmission)
// ---------------------------------------------------------------------------

pub const SendBuffer = struct {
    pub const capacity = 2048;

    const Entry = struct {
        seq: u32 = 0,
        sent_time: i64 = 0,
        size: u32 = 0,
        acked: bool = false,
        retransmit_count: u8 = 0,
        in_use: bool = false,
        delivery_state: congestion.DeliveryState = .{},
        data: [transport.max_payload_len]u8 = undefined,
        data_len: u16 = 0,
    };

    entries: []Entry,
    head_seq: u32 = 1,
    tail_seq: u32 = 1,

    pub fn init(alloc: std.mem.Allocator) !SendBuffer {
        const entries = try alloc.alloc(Entry, capacity);
        @memset(entries, Entry{});
        return .{ .entries = entries };
    }

    pub fn deinit(self: *SendBuffer, alloc: std.mem.Allocator) void {
        alloc.free(self.entries);
    }

    fn idx(seq: u32) usize {
        return seq % capacity;
    }

    pub fn recordSend(
        self: *SendBuffer,
        seq: u32,
        payload: []const u8,
        now: i64,
        ds: congestion.DeliveryState,
    ) void {
        const i = idx(seq);
        self.entries[i] = .{
            .seq = seq,
            .sent_time = now,
            .size = @intCast(payload.len),
            .acked = false,
            .retransmit_count = 0,
            .in_use = true,
            .delivery_state = ds,
            .data_len = @intCast(payload.len),
        };
        @memcpy(self.entries[i].data[0..payload.len], payload);
        self.tail_seq = seq +% 1;
    }

    pub fn markAcked(self: *SendBuffer, seq: u32) ?*const Entry {
        const i = idx(seq);
        const entry = &self.entries[i];
        if (!entry.in_use or entry.seq != seq or entry.acked) return null;
        entry.acked = true;
        return entry;
    }

    pub fn getForRetransmit(self: *SendBuffer, seq: u32) ?*Entry {
        const i = idx(seq);
        const entry = &self.entries[i];
        if (!entry.in_use or entry.seq != seq or entry.acked) return null;
        return entry;
    }

    pub fn getPayload(self: *const SendBuffer, seq: u32) ?[]const u8 {
        const i = idx(seq);
        const entry = &self.entries[i];
        if (!entry.in_use or entry.seq != seq) return null;
        return entry.data[0..entry.data_len];
    }

    pub fn pruneAcked(self: *SendBuffer) void {
        while (self.head_seq != self.tail_seq) {
            const i = idx(self.head_seq);
            const entry = &self.entries[i];
            if (!entry.in_use or !entry.acked) break;
            entry.in_use = false;
            self.head_seq +%= 1;
        }
    }
};

// ---------------------------------------------------------------------------
// Loss Detector (RFC 9002 style)
// ---------------------------------------------------------------------------

pub const LossDetector = struct {
    const packet_threshold: u32 = 3;
    const time_threshold_num: i64 = 9;
    const time_threshold_den: i64 = 8;

    largest_acked: u32 = 0,
    has_largest_acked: bool = false,

    pub fn onAck(self: *LossDetector, largest: u32) void {
        if (!self.has_largest_acked or seqGt(largest, self.largest_acked)) {
            self.largest_acked = largest;
            self.has_largest_acked = true;
        }
    }

    /// Detect lost packets and append to retransmit_list.
    /// Returns the earliest time a not-yet-lost packet might become lost
    /// (for setting a loss detection timer), or 0 if no timer needed.
    pub fn detectLosses(
        self: *LossDetector,
        send_buf: *SendBuffer,
        now: i64,
        srtt_ns: i64,
        latest_rtt_ns: i64,
        retransmit_list: *std.ArrayListUnmanaged(u32),
    ) i64 {
        if (!self.has_largest_acked) return 0;

        // Add max_ack_delay (5ms) to account for the client's ACK processing
        // time, preventing spurious retransmits (similar to QUIC PTO).
        const max_ack_delay_ns: i64 = 5 * std.time.ns_per_ms;
        const loss_delay = @divFloor(time_threshold_num * @max(srtt_ns, latest_rtt_ns), time_threshold_den) + max_ack_delay_ns;
        var earliest_loss_time: i64 = 0;

        var seq = send_buf.head_seq;
        while (seq != send_buf.tail_seq) : (seq +%= 1) {
            const i = SendBuffer.idx(seq);
            const entry = &send_buf.entries[i];
            if (!entry.in_use or entry.acked or entry.seq != seq) continue;

            // Packet threshold: lost if 3 later packets ACKed
            if (self.largest_acked -% seq >= packet_threshold) {
                // Skip if already queued for retransmit
                if (!isInQueue(retransmit_list, seq)) {
                    retransmit_list.appendBounded(seq) catch continue;
                }
                continue;
            }

            // Time threshold
            if (now - entry.sent_time >= loss_delay) {
                if (!isInQueue(retransmit_list, seq)) {
                    retransmit_list.appendBounded(seq) catch continue;
                }
            } else {
                // Track earliest time this packet would become lost
                const loss_time = entry.sent_time + loss_delay;
                if (earliest_loss_time == 0 or loss_time < earliest_loss_time) {
                    earliest_loss_time = loss_time;
                }
            }
        }

        return earliest_loss_time;
    }

    fn isInQueue(list: *const std.ArrayListUnmanaged(u32), seq: u32) bool {
        for (list.items) |s| {
            if (s == seq) return true;
        }
        return false;
    }
};

/// Sequence number comparison (handles wrapping)
fn seqGt(a: u32, b: u32) bool {
    const diff = a -% b;
    return diff > 0 and diff < 0x80000000;
}

// ---------------------------------------------------------------------------
// Output ACK Tracker (client side — bitmap-based)
// ---------------------------------------------------------------------------

pub const OutputAckTracker = struct {
    largest_recv: u32 = 0,
    has_received: bool = false,
    // 512-bit bitmap: tracks which of the 512 seqs before largest_recv were received
    bitmap: [16]u32 = [1]u32{0} ** 16,

    pub fn onRecv(self: *OutputAckTracker, seq: u32) void {
        if (!self.has_received) {
            self.largest_recv = seq;
            self.has_received = true;
            @memset(&self.bitmap, 0);
            return;
        }

        if (seqGt(seq, self.largest_recv)) {
            // New highest seq — shift bitmap
            const shift = seq -% self.largest_recv;
            self.shiftBitmap(shift);
            self.largest_recv = seq;
        } else if (seq == self.largest_recv) {
            // Duplicate of largest — already tracked
            return;
        } else {
            // Old seq — set bit in bitmap
            const diff = self.largest_recv -% seq;
            if (diff > 0 and diff <= 512) {
                self.setBit(diff - 1);
            }
        }
    }

    pub fn generateAckRanges(self: *const OutputAckTracker, gap_storage: []AckRanges.Gap) AckRanges {
        if (!self.has_received) {
            return .{ .largest_acked = 0, .first_range = 0, .gaps = &[0]AckRanges.Gap{} };
        }

        // Count consecutive acked from largest going backward
        var first_range: u16 = 0;
        var pos: u32 = 1;
        while (pos <= 512) : (pos += 1) {
            if (!self.hasBit(pos - 1)) break;
            first_range += 1;
        }

        // Find gap-range pairs
        var num_gaps: usize = 0;
        const max_gaps = @min(gap_storage.len, AckRanges.max_gaps);

        while (pos <= 512 and num_gaps < max_gaps) {
            // Count gap (unacked)
            var gap_count: u16 = 0;
            while (pos <= 512 and !self.hasBit(pos - 1)) : (pos += 1) {
                gap_count += 1;
            }
            if (gap_count == 0 or pos > 512) break;

            // Count range (acked)
            var range_count: u16 = 0;
            while (pos <= 512 and self.hasBit(pos - 1)) : (pos += 1) {
                range_count += 1;
            }
            if (range_count == 0) break;

            gap_storage[num_gaps] = .{ .gap = gap_count, .range = range_count - 1 };
            num_gaps += 1;
        }

        return .{
            .largest_acked = self.largest_recv,
            .first_range = first_range,
            .gaps = gap_storage[0..num_gaps],
        };
    }

    fn shiftBitmap(self: *OutputAckTracker, shift: u32) void {
        if (shift >= 512) {
            @memset(&self.bitmap, 0);
            return;
        }

        // Shift in units of bits across the u32 array
        const word_shift = shift / 32;
        const bit_shift: u5 = @intCast(shift % 32);

        if (word_shift > 0) {
            var i: usize = 15;
            while (i >= word_shift) : (i -= 1) {
                self.bitmap[i] = self.bitmap[i - word_shift];
                if (i == word_shift) break;
            }
            for (0..@min(word_shift, 16)) |j| {
                self.bitmap[j] = 0;
            }
        }

        if (bit_shift > 0) {
            const anti: u5 = @intCast(32 - @as(u6, bit_shift));
            var i: usize = 15;
            while (i > 0) : (i -= 1) {
                self.bitmap[i] = (self.bitmap[i] << bit_shift) | (self.bitmap[i - 1] >> anti);
            }
            self.bitmap[0] <<= bit_shift;
        }

        // The old largest_recv is now at bit position (shift-1). Set it.
        if (shift > 0 and shift <= 512) {
            self.setBit(shift - 1);
        }
    }

    fn setBit(self: *OutputAckTracker, bit_pos: u32) void {
        if (bit_pos >= 512) return;
        const word = bit_pos / 32;
        const bit: u5 = @intCast(bit_pos % 32);
        self.bitmap[word] |= @as(u32, 1) << bit;
    }

    fn hasBit(self: *const OutputAckTracker, bit_pos: u32) bool {
        if (bit_pos >= 512) return false;
        const word = bit_pos / 32;
        const bit: u5 = @intCast(bit_pos % 32);
        return (self.bitmap[word] & (@as(u32, 1) << bit)) != 0;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "AckRanges encode/decode roundtrip" {
    const gaps = [_]AckRanges.Gap{
        .{ .gap = 2, .range = 3 },
        .{ .gap = 1, .range = 1 },
    };
    const ranges = AckRanges{
        .largest_acked = 100,
        .first_range = 5,
        .gaps = &gaps,
    };

    var buf: [128]u8 = undefined;
    const encoded = try ranges.encode(&buf);
    try std.testing.expectEqual(@as(usize, 7 + 2 * 4), encoded.len);

    var gap_buf: [16]AckRanges.Gap = undefined;
    const decoded = try AckRanges.decode(encoded, &gap_buf);
    try std.testing.expectEqual(@as(u32, 100), decoded.largest_acked);
    try std.testing.expectEqual(@as(u16, 5), decoded.first_range);
    try std.testing.expectEqual(@as(usize, 2), decoded.gaps.len);
    try std.testing.expectEqual(@as(u16, 2), decoded.gaps[0].gap);
    try std.testing.expectEqual(@as(u16, 3), decoded.gaps[0].range);
}

test "AckRanges empty decode" {
    const ranges = AckRanges{
        .largest_acked = 42,
        .first_range = 0,
        .gaps = &[0]AckRanges.Gap{},
    };
    var buf: [128]u8 = undefined;
    const encoded = try ranges.encode(&buf);
    try std.testing.expectEqual(@as(usize, 7), encoded.len);

    var gap_buf: [16]AckRanges.Gap = undefined;
    const decoded = try AckRanges.decode(encoded, &gap_buf);
    try std.testing.expectEqual(@as(u32, 42), decoded.largest_acked);
    try std.testing.expectEqual(@as(usize, 0), decoded.gaps.len);
}

test "AckRanges iterate acked sequences" {
    const gaps = [_]AckRanges.Gap{
        .{ .gap = 2, .range = 1 },
    };
    const ranges = AckRanges{
        .largest_acked = 10,
        .first_range = 2,
        .gaps = &gaps,
    };

    var acked: [32]u32 = undefined;
    var count: usize = 0;

    const Collector = struct {
        acked_buf: *[32]u32,
        count_ptr: *usize,

        pub fn call(self: @This(), seq: u32) void {
            if (self.count_ptr.* < 32) {
                self.acked_buf[self.count_ptr.*] = seq;
                self.count_ptr.* += 1;
            }
        }
    };

    ranges.iterateAcked(Collector{
        .acked_buf = &acked,
        .count_ptr = &count,
    });

    // Expected: 10, 9, 8 (first_range=2) + gap=2 (skip 7,6) + range=1 → 5, 4
    try std.testing.expectEqual(@as(usize, 5), count);
    try std.testing.expectEqual(@as(u32, 10), acked[0]);
    try std.testing.expectEqual(@as(u32, 9), acked[1]);
    try std.testing.expectEqual(@as(u32, 8), acked[2]);
    try std.testing.expectEqual(@as(u32, 5), acked[3]);
    try std.testing.expectEqual(@as(u32, 4), acked[4]);
}

test "SendBuffer record and ack" {
    var buf = try SendBuffer.init(std.testing.allocator);
    defer buf.deinit(std.testing.allocator);

    const payload = "hello";
    buf.recordSend(1, payload, 1000, .{});
    buf.recordSend(2, payload, 2000, .{});

    // Mark seq 1 acked
    const entry = buf.markAcked(1);
    try std.testing.expect(entry != null);
    try std.testing.expect(entry.?.acked);

    // Duplicate ack returns null
    try std.testing.expect(buf.markAcked(1) == null);

    // Prune: seq 1 is acked, head advances
    buf.pruneAcked();
    try std.testing.expectEqual(@as(u32, 2), buf.head_seq);
}

test "SendBuffer get payload" {
    var buf = try SendBuffer.init(std.testing.allocator);
    defer buf.deinit(std.testing.allocator);

    buf.recordSend(5, "test data", 1000, .{});
    const payload = buf.getPayload(5);
    try std.testing.expect(payload != null);
    try std.testing.expectEqualStrings("test data", payload.?);

    // Non-existent seq
    try std.testing.expect(buf.getPayload(99) == null);
}

test "LossDetector packet threshold" {
    var det = LossDetector{};
    var send_buf = try SendBuffer.init(std.testing.allocator);
    defer send_buf.deinit(std.testing.allocator);

    // Record sends for seq 1..6
    for (1..7) |i| {
        send_buf.recordSend(@intCast(i), "x", @intCast(i * 1000), .{});
    }

    // ACK seq 4
    _ = send_buf.markAcked(4);
    det.onAck(4);

    var lost_buf: [64]u32 = undefined;
    var lost = std.ArrayListUnmanaged(u32).initBuffer(&lost_buf);
    det.detectLosses(&send_buf, 100000, 50_000_000, 50_000_000, &lost);

    // Seq 1 is lost (4 - 1 = 3 >= threshold)
    try std.testing.expectEqual(@as(usize, 1), lost.items.len);
    try std.testing.expectEqual(@as(u32, 1), lost.items[0]);
}

test "OutputAckTracker sequential" {
    var tracker = OutputAckTracker{};

    // Receive seq 1, 2, 3 in order
    tracker.onRecv(1);
    tracker.onRecv(2);
    tracker.onRecv(3);

    var gap_buf: [16]AckRanges.Gap = undefined;
    const ranges = tracker.generateAckRanges(&gap_buf);
    try std.testing.expectEqual(@as(u32, 3), ranges.largest_acked);
    try std.testing.expectEqual(@as(u16, 2), ranges.first_range); // 3, 2, 1 consecutive
    try std.testing.expectEqual(@as(usize, 0), ranges.gaps.len);
}

test "OutputAckTracker with gap" {
    var tracker = OutputAckTracker{};

    // Receive 1, 2, 3, then skip 4, receive 5
    tracker.onRecv(1);
    tracker.onRecv(2);
    tracker.onRecv(3);
    tracker.onRecv(5); // gap at 4

    var gap_buf: [16]AckRanges.Gap = undefined;
    const ranges = tracker.generateAckRanges(&gap_buf);
    try std.testing.expectEqual(@as(u32, 5), ranges.largest_acked);
    try std.testing.expectEqual(@as(u16, 0), ranges.first_range); // only 5 is consecutive
    try std.testing.expectEqual(@as(usize, 1), ranges.gaps.len); // gap=1 (seq 4), range for 1,2,3
}

test "OutputAckTracker out of order" {
    var tracker = OutputAckTracker{};

    tracker.onRecv(1);
    tracker.onRecv(3); // skip 2
    tracker.onRecv(2); // fill gap

    var gap_buf: [16]AckRanges.Gap = undefined;
    const ranges = tracker.generateAckRanges(&gap_buf);
    try std.testing.expectEqual(@as(u32, 3), ranges.largest_acked);
    try std.testing.expectEqual(@as(u16, 2), ranges.first_range); // 3, 2, 1 all present
    try std.testing.expectEqual(@as(usize, 0), ranges.gaps.len);
}

test "OutputAckTracker encode roundtrip" {
    var tracker = OutputAckTracker{};
    for (1..20) |i| {
        if (i != 5 and i != 10) {
            tracker.onRecv(@intCast(i));
        }
    }

    var gap_buf: [16]AckRanges.Gap = undefined;
    const ranges = tracker.generateAckRanges(&gap_buf);

    var enc_buf: [128]u8 = undefined;
    const encoded = try ranges.encode(&enc_buf);

    var dec_gap_buf: [16]AckRanges.Gap = undefined;
    const decoded = try AckRanges.decode(encoded, &dec_gap_buf);
    try std.testing.expectEqual(ranges.largest_acked, decoded.largest_acked);
    try std.testing.expectEqual(ranges.first_range, decoded.first_range);
    try std.testing.expectEqual(ranges.gaps.len, decoded.gaps.len);
}
