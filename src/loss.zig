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

    /// Iterate all ACKed offsets and call callback(offset) for each.
    /// Offsets step by max_payload_len (1 slot = 1 packet).
    pub fn iterateAcked(self: *const AckRanges, callback: anytype) void {
        // First range: [largest - first_range*step, largest]
        var offset = self.largest_acked;
        var i: u32 = 0;
        while (i <= self.first_range) : (i += 1) {
            callback.call(offset);
            if (offset < transport.step) return;
            offset -%= transport.step;
        }

        // Additional ranges
        for (self.gaps) |g| {
            // Skip gap (each unit = 1 slot = max_payload_len bytes)
            const gap_bytes = @as(u32, g.gap) *% transport.step;
            if (offset < gap_bytes) return;
            offset -%= gap_bytes;
            // Ack range
            var j: u32 = 0;
            while (j <= g.range) : (j += 1) {
                callback.call(offset);
                if (offset < transport.step) return;
                offset -%= transport.step;
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
        offset: u32 = 0,
        sent_time: i64 = 0,
        size: u32 = 0,
        acked: bool = false,
        retransmit_count: u8 = 0,
        in_use: bool = false,
        delivery_state: congestion.DeliveryState = .{},
        data: [transport.step]u8 = undefined,
        data_len: u16 = 0,
    };

    entries: []Entry,
    head_offset: u32 = 0,
    tail_offset: u32 = 0,

    pub fn init(alloc: std.mem.Allocator) !SendBuffer {
        const entries = try alloc.alloc(Entry, capacity);
        @memset(entries, Entry{});
        return .{ .entries = entries };
    }

    pub fn deinit(self: *SendBuffer, alloc: std.mem.Allocator) void {
        alloc.free(self.entries);
    }

    pub fn idx(offset: u32) usize {
        return (offset / transport.step) % capacity;
    }

    pub fn recordSend(
        self: *SendBuffer,
        offset: u32,
        payload: []const u8,
        now: i64,
        ds: congestion.DeliveryState,
    ) void {
        const i = idx(offset);
        self.entries[i] = .{
            .offset = offset,
            .sent_time = now,
            .size = @intCast(payload.len),
            .acked = false,
            .retransmit_count = 0,
            .in_use = true,
            .delivery_state = ds,
            .data_len = @intCast(payload.len),
        };
        @memcpy(self.entries[i].data[0..payload.len], payload);
        self.tail_offset = offset +% transport.step;
    }

    pub fn markAcked(self: *SendBuffer, offset: u32) ?*const Entry {
        const i = idx(offset);
        const entry = &self.entries[i];
        if (!entry.in_use or entry.offset != offset or entry.acked) return null;
        entry.acked = true;
        return entry;
    }

    pub fn getForRetransmit(self: *SendBuffer, offset: u32) ?*Entry {
        const i = idx(offset);
        const entry = &self.entries[i];
        if (!entry.in_use or entry.offset != offset or entry.acked) return null;
        return entry;
    }

    pub fn getPayload(self: *const SendBuffer, offset: u32) ?[]const u8 {
        const i = idx(offset);
        const entry = &self.entries[i];
        if (!entry.in_use or entry.offset != offset) return null;
        return entry.data[0..entry.data_len];
    }

    /// Find the oldest unACKed packet's sent_time. Returns null if none.
    pub fn oldestUnackedSentTime(self: *const SendBuffer) ?i64 {
        var offset = self.head_offset;
        while (offset != self.tail_offset) : (offset +%= transport.step) {
            const i = idx(offset);
            const entry = &self.entries[i];
            if (entry.in_use and !entry.acked and entry.offset == offset) {
                return entry.sent_time;
            }
        }
        return null;
    }

    /// Find the oldest unACKed packet's offset. Returns null if none.
    pub fn oldestUnackedOffset(self: *const SendBuffer) ?u32 {
        var offset = self.head_offset;
        while (offset != self.tail_offset) : (offset +%= transport.step) {
            const i = idx(offset);
            const entry = &self.entries[i];
            if (entry.in_use and !entry.acked and entry.offset == offset) {
                return offset;
            }
        }
        return null;
    }

    pub fn pruneAcked(self: *SendBuffer) void {
        while (self.head_offset != self.tail_offset) {
            const i = idx(self.head_offset);
            const entry = &self.entries[i];
            if (!entry.in_use or !entry.acked) break;
            entry.in_use = false;
            self.head_offset +%= transport.step;
        }
    }
};

// ---------------------------------------------------------------------------
// Loss Detector (RFC 9002 §6.1 + §6.2)
//
// Architecture follows tquic/quiche: loss detection and PTO are separate
// concerns. detectLosses() is pure §6.1 (packet + time thresholds).
// The caller (serve.zig) manages a dual-mode timer that chooses between
// loss_time and PTO, per §6.2.1 SetLossDetectionTimer.
// ---------------------------------------------------------------------------

/// Timer granularity floor (RFC 9002 §6.1.2). Prevents sub-millisecond
/// loss thresholds on very low RTT paths.
const granularity_ns: i64 = std.time.ns_per_ms;

/// Peer's max ACK delay. Must match ack_delay_ns in remote.zig/lib.zig.
/// Used in PTO calculation (RFC 9002 §6.2.1), NOT in loss detection.
pub const max_ack_delay_ns: i64 = 5 * std.time.ns_per_ms;

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

    /// Detect lost packets per RFC 9002 §6.1.
    ///
    /// Uses two thresholds:
    /// - Packet threshold (§6.1.1): lost if 3 later packets ACKed
    /// - Time threshold (§6.1.2): lost if unACKed for > 9/8 × max(srtt, latest_rtt)
    ///
    /// Returns earliest_loss_time for the loss detection timer, or 0 if none.
    /// max_ack_delay is NOT included here — it belongs in PTO (§6.2.1).
    pub fn detectLosses(
        self: *LossDetector,
        send_buf: *SendBuffer,
        now: i64,
        srtt_ns: i64,
        latest_rtt_ns: i64,
        retransmit_list: *std.ArrayListUnmanaged(u32),
    ) i64 {
        if (!self.has_largest_acked) return 0;

        // RFC 9002 §6.1.2: loss_delay = 9/8 × max(latest_rtt, smoothed_rtt)
        const loss_delay = @max(
            @divFloor(time_threshold_num * @max(srtt_ns, latest_rtt_ns), time_threshold_den),
            granularity_ns,
        );
        var earliest_loss_time: i64 = 0;

        var offset = send_buf.head_offset;
        while (offset != send_buf.tail_offset) : (offset +%= transport.step) {
            const i = SendBuffer.idx(offset);
            const entry = &send_buf.entries[i];
            if (!entry.in_use or entry.acked or entry.offset != offset) continue;

            // Only consider packets genuinely behind largest_acked (wrapping-safe)
            if (!seqGt(self.largest_acked, offset)) continue;

            // Packet threshold: lost if 3 later packets ACKed (in slots)
            if ((self.largest_acked -% offset) / transport.step >= packet_threshold) {
                if (!isInQueue(retransmit_list, offset)) {
                    retransmit_list.appendBounded(offset) catch continue;
                }
                continue;
            }

            // Time threshold
            if (now - entry.sent_time >= loss_delay) {
                if (!isInQueue(retransmit_list, offset)) {
                    retransmit_list.appendBounded(offset) catch continue;
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

    /// Compute PTO duration per RFC 9002 §6.2.1.
    ///
    /// PTO = smoothed_rtt + max(4 × rttvar, granularity) + max_ack_delay
    ///
    /// This is separate from loss detection. PTO fires when loss detection
    /// cannot make progress (no loss_time set), to send probe packets that
    /// elicit ACKs from the peer.
    pub fn computePto(srtt_ns: i64, rttvar_ns: i64, pto_count: u32) i64 {
        const base = srtt_ns + @max(4 * rttvar_ns, granularity_ns) + max_ack_delay_ns;
        // Exponential backoff: base × 2^pto_count (capped at 30 to avoid overflow)
        const shift: u5 = @intCast(@min(pto_count, 30));
        return base *| (@as(i64, 1) << shift);
    }

    fn isInQueue(list: *const std.ArrayListUnmanaged(u32), offset: u32) bool {
        for (list.items) |s| {
            if (s == offset) return true;
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
    // 512-bit bitmap: tracks which of the 512 slots before largest_recv were received
    bitmap: [16]u32 = [1]u32{0} ** 16,

    pub fn onRecv(self: *OutputAckTracker, offset: u32) void {
        if (!self.has_received) {
            self.largest_recv = offset;
            self.has_received = true;
            @memset(&self.bitmap, 0);
            return;
        }

        if (seqGt(offset, self.largest_recv)) {
            // New highest offset — shift bitmap by slot count
            const shift = (offset -% self.largest_recv) / transport.step;
            self.shiftBitmap(shift);
            self.largest_recv = offset;
        } else if (offset == self.largest_recv) {
            // Duplicate of largest — already tracked
            return;
        } else {
            // Old offset — set bit in bitmap
            const diff = (self.largest_recv -% offset) / transport.step;
            if (diff > 0 and diff <= 512) {
                self.setBit(diff - 1);
            }
        }
    }

    pub fn generateAckRanges(self: *const OutputAckTracker, gap_storage: []AckRanges.Gap) AckRanges {
        if (!self.has_received) {
            return .{ .largest_acked = 0, .first_range = 0, .gaps = &[0]AckRanges.Gap{} };
        }

        // Count consecutive acked from largest going backward (in slots)
        var first_range: u16 = 0;
        var pos: u32 = 1;
        while (pos <= 512) : (pos += 1) {
            if (!self.hasBit(pos - 1)) break;
            first_range += 1;
        }

        // Find gap-range pairs (units are slots)
        var num_gaps: usize = 0;
        const max_gaps = @min(gap_storage.len, AckRanges.max_gaps);

        while (pos <= 512 and num_gaps < max_gaps) {
            // Count gap (unacked slots)
            var gap_count: u16 = 0;
            while (pos <= 512 and !self.hasBit(pos - 1)) : (pos += 1) {
                gap_count += 1;
            }
            if (gap_count == 0 or pos > 512) break;

            // Count range (acked slots)
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

test "AckRanges iterate acked offsets" {
    const step = transport.step;
    const gaps = [_]AckRanges.Gap{
        .{ .gap = 2, .range = 1 },
    };
    const ranges = AckRanges{
        .largest_acked = 10 * step,
        .first_range = 2,
        .gaps = &gaps,
    };

    var acked: [32]u32 = undefined;
    var count: usize = 0;

    const Collector = struct {
        acked_buf: *[32]u32,
        count_ptr: *usize,

        pub fn call(self: @This(), offset: u32) void {
            if (self.count_ptr.* < 32) {
                self.acked_buf[self.count_ptr.*] = offset;
                self.count_ptr.* += 1;
            }
        }
    };

    ranges.iterateAcked(Collector{
        .acked_buf = &acked,
        .count_ptr = &count,
    });

    // Expected: 10*s, 9*s, 8*s (first_range=2) + gap=2 (skip 7*s,6*s) + range=1 → 5*s, 4*s
    try std.testing.expectEqual(@as(usize, 5), count);
    try std.testing.expectEqual(@as(u32, 10 * step), acked[0]);
    try std.testing.expectEqual(@as(u32, 9 * step), acked[1]);
    try std.testing.expectEqual(@as(u32, 8 * step), acked[2]);
    try std.testing.expectEqual(@as(u32, 5 * step), acked[3]);
    try std.testing.expectEqual(@as(u32, 4 * step), acked[4]);
}

test "SendBuffer record and ack" {
    const step = transport.step;
    var buf = try SendBuffer.init(std.testing.allocator);
    defer buf.deinit(std.testing.allocator);

    const payload = "hello";
    buf.recordSend(0, payload, 1000, .{});
    buf.recordSend(step, payload, 2000, .{});

    // Mark offset 0 acked
    const entry = buf.markAcked(0);
    try std.testing.expect(entry != null);
    try std.testing.expect(entry.?.acked);

    // Duplicate ack returns null
    try std.testing.expect(buf.markAcked(0) == null);

    // Prune: offset 0 is acked, head advances
    buf.pruneAcked();
    try std.testing.expectEqual(@as(u32, step), buf.head_offset);
}

test "SendBuffer get payload" {
    const step = transport.step;
    var buf = try SendBuffer.init(std.testing.allocator);
    defer buf.deinit(std.testing.allocator);

    buf.recordSend(5 * step, "test data", 1000, .{});
    const payload = buf.getPayload(5 * step);
    try std.testing.expect(payload != null);
    try std.testing.expectEqualStrings("test data", payload.?);

    // Non-existent offset
    try std.testing.expect(buf.getPayload(99 * step) == null);
}

test "LossDetector packet threshold" {
    const step = transport.step;
    var det = LossDetector{};
    var send_buf = try SendBuffer.init(std.testing.allocator);
    defer send_buf.deinit(std.testing.allocator);

    // Record sends for offsets 0..5*step
    for (0..6) |i| {
        const offset: u32 = @intCast(i * step);
        send_buf.recordSend(offset, "x", @intCast((i + 1) * 1000), .{});
    }

    // ACK offset 4*step (slot 4 is 4 slots ahead of slot 0)
    _ = send_buf.markAcked(4 * step);
    det.onAck(4 * step);

    var lost_buf: [64]u32 = undefined;
    var lost = std.ArrayListUnmanaged(u32).initBuffer(&lost_buf);
    _ = det.detectLosses(&send_buf, 100000, 50_000_000, 50_000_000, &lost);

    // Offset 0 is lost (4 slots >= 3 threshold), offset 1*step is also lost (3 slots >= 3)
    // But slot 0: (4*step - 0) / step = 4 >= 3 → lost
    // Slot 1: (4*step - step) / step = 3 >= 3 → lost
    try std.testing.expectEqual(@as(usize, 2), lost.items.len);
    try std.testing.expectEqual(@as(u32, 0), lost.items[0]);
    try std.testing.expectEqual(@as(u32, step), lost.items[1]);
}

test "LossDetector does not declare packets ahead of largest_acked as lost" {
    const step = transport.step;
    var det = LossDetector{};
    var send_buf = try SendBuffer.init(std.testing.allocator);
    defer send_buf.deinit(std.testing.allocator);

    // Send offsets 0..5*step, ACK only offset 2*step
    for (0..6) |i| {
        const offset: u32 = @intCast(i * step);
        send_buf.recordSend(offset, "x", @intCast((i + 1) * 1000), .{});
    }
    _ = send_buf.markAcked(2 * step);
    det.onAck(2 * step);

    var lost_buf: [64]u32 = undefined;
    var lost = std.ArrayListUnmanaged(u32).initBuffer(&lost_buf);
    _ = det.detectLosses(&send_buf, 100000, 50_000_000, 50_000_000, &lost);

    // Only offsets behind largest_acked can be lost.
    // Offsets 3*step, 4*step, 5*step are AHEAD — must NOT be declared lost.
    // Offset 0: (2*step - 0)/step = 2 < 3 → not lost by packet threshold
    // Offset step: (2*step - step)/step = 1 < 3 → not lost
    // (time threshold won't fire at now=100000 with loss_delay ~56ms)
    try std.testing.expectEqual(@as(usize, 0), lost.items.len);
}

test "LossDetector PTO computation" {
    // srtt=50ms, rttvar=10ms, pto_count=0, max_ack_delay=5ms
    // PTO = 50 + max(40, 1) + 5 = 95ms
    const pto = LossDetector.computePto(50_000_000, 10_000_000, 0);
    try std.testing.expectEqual(@as(i64, 95_000_000), pto);

    // With pto_count=1: 95ms * 2 = 190ms
    const pto1 = LossDetector.computePto(50_000_000, 10_000_000, 1);
    try std.testing.expectEqual(@as(i64, 190_000_000), pto1);

    // With pto_count=2: 95ms * 4 = 380ms
    const pto2 = LossDetector.computePto(50_000_000, 10_000_000, 2);
    try std.testing.expectEqual(@as(i64, 380_000_000), pto2);
}

test "OutputAckTracker sequential" {
    const step = transport.step;
    var tracker = OutputAckTracker{};

    // Receive offsets 0, 1100, 2200 in order
    tracker.onRecv(0);
    tracker.onRecv(step);
    tracker.onRecv(2 * step);

    var gap_buf: [16]AckRanges.Gap = undefined;
    const ranges = tracker.generateAckRanges(&gap_buf);
    try std.testing.expectEqual(@as(u32, 2 * step), ranges.largest_acked);
    try std.testing.expectEqual(@as(u16, 2), ranges.first_range); // 3 consecutive slots
    try std.testing.expectEqual(@as(usize, 0), ranges.gaps.len);
}

test "OutputAckTracker with gap" {
    const step = transport.step;
    var tracker = OutputAckTracker{};

    // Receive offsets 0, 1100, 2200, then skip 3300, receive 4400
    tracker.onRecv(0);
    tracker.onRecv(step);
    tracker.onRecv(2 * step);
    tracker.onRecv(4 * step); // gap at 3*step

    var gap_buf: [16]AckRanges.Gap = undefined;
    const ranges = tracker.generateAckRanges(&gap_buf);
    try std.testing.expectEqual(@as(u32, 4 * step), ranges.largest_acked);
    try std.testing.expectEqual(@as(u16, 0), ranges.first_range); // only 4*step is consecutive
    try std.testing.expectEqual(@as(usize, 1), ranges.gaps.len); // gap=1 (slot 3), range for 0,1,2
}

test "OutputAckTracker out of order" {
    const step = transport.step;
    var tracker = OutputAckTracker{};

    tracker.onRecv(0);
    tracker.onRecv(2 * step); // skip step
    tracker.onRecv(step); // fill gap

    var gap_buf: [16]AckRanges.Gap = undefined;
    const ranges = tracker.generateAckRanges(&gap_buf);
    try std.testing.expectEqual(@as(u32, 2 * step), ranges.largest_acked);
    try std.testing.expectEqual(@as(u16, 2), ranges.first_range); // all 3 present
    try std.testing.expectEqual(@as(usize, 0), ranges.gaps.len);
}

test "OutputAckTracker encode roundtrip" {
    const step = transport.step;
    var tracker = OutputAckTracker{};
    for (0..19) |i| {
        if (i != 5 and i != 10) {
            tracker.onRecv(@as(u32, @intCast(i)) * step);
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
