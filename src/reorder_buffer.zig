//! Client-side reorder buffer for the byte-offset output stream and the
//! related stale-gap timeout. Extracted from remote.zig so the in-process
//! reliability test harness (`net_sim.zig`) can exercise the same code that
//! the production client uses.

const std = @import("std");
const transport = @import("transport.zig");

/// Reorder buffer caps for the output byte stream.
pub const reorder_max_bytes: usize = 1 * 1024 * 1024;
pub const reorder_max_fragments: usize = 1024;

const min_stale_us: u64 = 50_000;
const max_stale_us: u64 = 1_000_000;
const default_srtt_us: u64 = 200_000;

pub fn staleGapTimeoutUs(srtt_us: u64) u64 {
    const s: u64 = if (srtt_us == 0) default_srtt_us else srtt_us;
    return std.math.clamp(3 * s, min_stale_us, max_stale_us);
}

pub const Fragment = struct {
    offset_start: u64,
    arrived_us: u64,
    bytes: []u8,
};

pub const ReorderBuffer = struct {
    alloc: std.mem.Allocator,
    fragments: std.ArrayList(Fragment),
    total_bytes: usize = 0,

    pub fn init(alloc: std.mem.Allocator) !ReorderBuffer {
        return .{
            .alloc = alloc,
            .fragments = try std.ArrayList(Fragment).initCapacity(alloc, 16),
        };
    }

    pub fn deinit(self: *ReorderBuffer) void {
        for (self.fragments.items) |f| self.alloc.free(f.bytes);
        self.fragments.deinit(self.alloc);
    }

    pub fn clear(self: *ReorderBuffer) void {
        for (self.fragments.items) |f| self.alloc.free(f.bytes);
        self.fragments.clearRetainingCapacity();
        self.total_bytes = 0;
    }

    pub fn isOverCapacity(self: *const ReorderBuffer) bool {
        return self.total_bytes > reorder_max_bytes or
            self.fragments.items.len > reorder_max_fragments;
    }

    pub fn oldestArrivedUs(self: *const ReorderBuffer) ?u64 {
        var oldest: ?u64 = null;
        for (self.fragments.items) |f| {
            if (oldest == null or f.arrived_us < oldest.?) oldest = f.arrived_us;
        }
        return oldest;
    }

    /// Insert a fragment, keeping the list sorted by offset_start. The
    /// caller has already trimmed any prefix overlapping `next_deliver_offset`.
    pub fn insert(self: *ReorderBuffer, offset_start: u64, data: []const u8, arrived_us: u64) !void {
        if (data.len == 0) return;
        // Skip duplicates that are already fully covered by an existing
        // fragment with the same start offset.
        for (self.fragments.items) |f| {
            if (f.offset_start == offset_start and f.bytes.len >= data.len) return;
        }
        const owned = try self.alloc.dupe(u8, data);
        var idx: usize = 0;
        while (idx < self.fragments.items.len and
            self.fragments.items[idx].offset_start < offset_start) : (idx += 1)
        {}
        try self.fragments.insert(self.alloc, idx, .{
            .offset_start = offset_start,
            .arrived_us = arrived_us,
            .bytes = owned,
        });
        self.total_bytes += owned.len;
    }

    /// Pop the fragment whose offset_start equals `at`, returning its bytes
    /// (caller takes ownership).
    pub fn popAt(self: *ReorderBuffer, at: u64) ?[]u8 {
        var i: usize = 0;
        while (i < self.fragments.items.len) : (i += 1) {
            const f = self.fragments.items[i];
            if (f.offset_start == at) {
                _ = self.fragments.orderedRemove(i);
                self.total_bytes -= f.bytes.len;
                return f.bytes;
            }
            if (f.offset_start > at) return null;
        }
        return null;
    }

    /// Walk fragments from `next_deliver_offset` upward, computing up to
    /// `max_sack_gaps` gap ranges between contiguous fragments and the next
    /// fragment start. Caller passes in the current `highest_contiguous_offset`
    /// (== next_deliver_offset).
    pub fn computeGaps(
        self: *const ReorderBuffer,
        high: u64,
        out: *[transport.max_sack_gaps]transport.SackGap,
    ) u8 {
        var n: u8 = 0;
        var cursor: u64 = high;
        for (self.fragments.items) |f| {
            if (f.offset_start <= cursor) {
                const end = f.offset_start + f.bytes.len;
                if (end > cursor) cursor = end;
                continue;
            }
            const gap_len = f.offset_start - cursor;
            if (gap_len > std.math.maxInt(u32)) break;
            out[n] = .{
                .start_rel = @intCast(cursor - high),
                .len = @intCast(gap_len),
            };
            n += 1;
            if (n >= transport.max_sack_gaps) break;
            cursor = f.offset_start + f.bytes.len;
        }
        return n;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "reorder buffer in-order delivery" {
    var rb = try ReorderBuffer.init(std.testing.allocator);
    defer rb.deinit();

    try rb.insert(0, "hello", 100);
    try std.testing.expectEqual(@as(usize, 1), rb.fragments.items.len);
    const got = rb.popAt(0).?;
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("hello", got);
    try std.testing.expectEqual(@as(usize, 0), rb.total_bytes);
}

test "reorder buffer out-of-order then drain" {
    var rb = try ReorderBuffer.init(std.testing.allocator);
    defer rb.deinit();

    try rb.insert(10, "fffff", 102);
    try rb.insert(5, "ddddd", 101);
    try rb.insert(0, "aaaaa", 100);

    const a = rb.popAt(0).?;
    defer std.testing.allocator.free(a);
    try std.testing.expectEqualStrings("aaaaa", a);
    const b = rb.popAt(5).?;
    defer std.testing.allocator.free(b);
    try std.testing.expectEqualStrings("ddddd", b);
    const c2 = rb.popAt(10).?;
    defer std.testing.allocator.free(c2);
    try std.testing.expectEqualStrings("fffff", c2);
    try std.testing.expectEqual(@as(usize, 0), rb.fragments.items.len);
}

test "reorder buffer computeGaps" {
    var rb = try ReorderBuffer.init(std.testing.allocator);
    defer rb.deinit();
    try rb.insert(110, "0123456789", 0);
    try rb.insert(120, "ABCDE", 0);
    try rb.insert(200, "X", 0);

    var gaps: [transport.max_sack_gaps]transport.SackGap = undefined;
    const n = rb.computeGaps(100, &gaps);
    try std.testing.expectEqual(@as(u8, 2), n);
    try std.testing.expectEqual(@as(u32, 0), gaps[0].start_rel);
    try std.testing.expectEqual(@as(u32, 10), gaps[0].len);
    try std.testing.expectEqual(@as(u32, 25), gaps[1].start_rel);
    try std.testing.expectEqual(@as(u32, 75), gaps[1].len);
}

test "reorder buffer over capacity" {
    var rb = try ReorderBuffer.init(std.testing.allocator);
    defer rb.deinit();
    var i: u64 = 0;
    while (i < reorder_max_fragments + 1) : (i += 1) {
        try rb.insert(i * 10, "x", 0);
    }
    try std.testing.expect(rb.isOverCapacity());
    rb.clear();
    try std.testing.expect(!rb.isOverCapacity());
    try std.testing.expectEqual(@as(usize, 0), rb.fragments.items.len);
}

test "staleGapTimeoutUs clamps to bounds" {
    try std.testing.expectEqual(@as(u64, 50_000), staleGapTimeoutUs(1_000));
    try std.testing.expectEqual(@as(u64, 1_000_000), staleGapTimeoutUs(500_000));
    try std.testing.expectEqual(@as(u64, 300_000), staleGapTimeoutUs(100_000));
    try std.testing.expectEqual(@as(u64, 600_000), staleGapTimeoutUs(0));
}
