const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");
const udp_mod = @import("udp.zig");
const ipc = @import("ipc.zig");
const transport = @import("transport.zig");
const reorder_buffer = @import("reorder_buffer.zig");
const builtin = @import("builtin");

const max_ipc_payload = transport.max_payload_len - @sizeOf(ipc.Header);
const max_stdout_buf = 4 * 1024 * 1024;
const ack_delay_ns = 20 * std.time.ns_per_ms;
const resync_cooldown_ns = 250 * std.time.ns_per_ms;

pub const reorder_max_bytes = reorder_buffer.reorder_max_bytes;
pub const reorder_max_fragments = reorder_buffer.reorder_max_fragments;
pub const staleGapTimeoutUs = reorder_buffer.staleGapTimeoutUs;
pub const Fragment = reorder_buffer.Fragment;
pub const ReorderBuffer = reorder_buffer.ReorderBuffer;

const c = switch (builtin.os.tag) {
    .macos => @cImport({
        @cInclude("sys/ioctl.h");
        @cInclude("termios.h");
        @cInclude("unistd.h");
    }),
    .freebsd => @cImport({
        @cInclude("termios.h");
        @cInclude("unistd.h");
    }),
    else => @cImport({
        @cInclude("sys/ioctl.h");
        @cInclude("termios.h");
        @cInclude("unistd.h");
    }),
};

const log = std.log.scoped(.remote);

pub const RemoteSession = struct {
    host: []const u8,
    port: u16,
    key: crypto.Key,
};

/// Parse a ZMX_CONNECT line: "ZMX_CONNECT udp <host> <port> <base64_key>\n"
pub fn parseConnectLine(line: []const u8) !struct { host: []const u8, port: u16, key: crypto.Key } {
    const trimmed = std.mem.trimRight(u8, line, "\r\n");
    var it = std.mem.splitScalar(u8, trimmed, ' ');

    const prefix = it.next() orelse return error.InvalidConnectLine;
    if (!std.mem.eql(u8, prefix, "ZMX_CONNECT")) return error.InvalidConnectLine;

    const proto = it.next() orelse return error.InvalidConnectLine;
    if (!std.mem.eql(u8, proto, "udp")) return error.UnsupportedProtocol;

    const host = it.next() orelse return error.InvalidConnectLine;

    const port_str = it.next() orelse return error.InvalidConnectLine;
    const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;

    const key_str = it.next() orelse return error.InvalidConnectLine;
    const key = crypto.keyFromBase64(key_str) catch return error.InvalidKey;

    return .{ .host = host, .port = port, .key = key };
}

/// Bootstrap a remote session via SSH: ssh <host> zmosh serve <session>
/// Prepends common user bin dirs to PATH since SSH non-interactive sessions
/// often have a minimal PATH that excludes ~/.local/bin, ~/bin, etc.
pub fn connectRemote(alloc: std.mem.Allocator, host: []const u8, session: []const u8) !RemoteSession {
    const term = posix.getenv("TERM") orelse "xterm-256color";
    const colorterm = posix.getenv("COLORTERM");
    const remote_cmd = if (colorterm) |ct|
        try std.fmt.allocPrint(
            alloc,
            "TERM={s} COLORTERM={s} PATH=\"$PATH:/opt/homebrew/bin:$HOME/bin:$HOME/.local/bin\" zmosh serve {s}",
            .{ term, ct, session },
        )
    else
        try std.fmt.allocPrint(
            alloc,
            "TERM={s} PATH=\"$PATH:/opt/homebrew/bin:$HOME/bin:$HOME/.local/bin\" zmosh serve {s}",
            .{ term, session },
        );
    defer alloc.free(remote_cmd);
    const argv = [_][]const u8{ "ssh", host, "--", remote_cmd };
    var child = std.process.Child.init(&argv, alloc);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Inherit;
    try child.spawn();

    // Read stdout looking for ZMX_CONNECT line
    const stdout = child.stdout.?;
    var buf: [512]u8 = undefined;
    var total: usize = 0;

    while (total < buf.len) {
        const n = stdout.read(buf[total..]) catch |err| {
            log.err("failed to read SSH stdout: {s}", .{@errorName(err)});
            return error.SshReadFailed;
        };
        if (n == 0) break;
        total += n;

        // Check if we have a complete line
        if (std.mem.indexOf(u8, buf[0..total], "\n")) |_| break;
    }

    if (total == 0) {
        _ = child.wait() catch {};
        return error.SshNoOutput;
    }

    const result = parseConnectLine(buf[0..total]) catch |err| {
        log.err("failed to parse connect line: {s}", .{@errorName(err)});
        _ = child.wait() catch {};
        return error.InvalidConnectLine;
    };

    // Close our end of the pipes — we have the connect info.
    // Don't wait for SSH to exit: the remote gateway runs indefinitely.
    // SSH will be killed when we exit or will linger harmlessly.
    if (child.stdin) |f| {
        f.close();
        child.stdin = null;
    }
    if (child.stdout) |f| {
        f.close();
        child.stdout = null;
    }

    const gateway_host = try alloc.dupe(u8, result.host);

    return .{
        .host = gateway_host,
        .port = result.port,
        .key = result.key,
    };
}

var sigwinch_received: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn handleSigwinch(_: i32, _: *const posix.siginfo_t, _: ?*anyopaque) callconv(.c) void {
    sigwinch_received.store(true, .release);
}

fn setupSigwinchHandler() void {
    const act: posix.Sigaction = .{
        .handler = .{ .sigaction = handleSigwinch },
        .mask = posix.sigemptyset(),
        .flags = posix.SA.SIGINFO,
    };
    posix.sigaction(posix.SIG.WINCH, &act, null);
}

fn getTerminalSize() ipc.Resize {
    var ws: c.struct_winsize = undefined;
    if (c.ioctl(posix.STDOUT_FILENO, c.TIOCGWINSZ, &ws) == 0 and ws.ws_row > 0 and ws.ws_col > 0) {
        return .{ .rows = ws.ws_row, .cols = ws.ws_col };
    }
    return .{ .rows = 24, .cols = 80 };
}

/// Detects Kitty keyboard protocol escape sequence for Ctrl+\
fn isKittyCtrlBackslash(buf: []const u8) bool {
    return std.mem.indexOf(u8, buf, "\x1b[92;5u") != null or
        std.mem.indexOf(u8, buf, "\x1b[92;5:1u") != null;
}

fn sendHeartbeat(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_recv: *const transport.RecvState,
    last_ack_send_ns: *i64,
    ack_dirty: *bool,
    now: i64,
    max_byte_offset: u64,
) !void {
    var hb_buf: [8]u8 = undefined;
    const hb_payload = transport.buildHeartbeatPayload(max_byte_offset, &hb_buf);
    var pkt_buf: [1200]u8 = undefined;
    const pkt = try transport.buildUnreliable(
        .heartbeat,
        0,
        reliable_recv.ack(),
        reliable_recv.ackBits(),
        hb_payload,
        &pkt_buf,
    );
    try peer.send(sock, pkt);
    last_ack_send_ns.* = now;
    ack_dirty.* = false;
}

fn sendReliablePayload(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_send: *transport.ReliableSend,
    reliable_recv: *const transport.RecvState,
    channel: transport.Channel,
    payload: []const u8,
    now: i64,
) !void {
    const packet = try reliable_send.buildAndTrack(
        channel,
        payload,
        reliable_recv.ack(),
        reliable_recv.ackBits(),
        now,
    );
    peer.send(sock, packet) catch |err| {
        if (err == error.NoPeerAddress or err == error.WouldBlock) return;
        return err;
    };
}

fn sendIpcReliable(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_send: *transport.ReliableSend,
    reliable_recv: *const transport.RecvState,
    tag: ipc.Tag,
    payload: []const u8,
    now: i64,
) !void {
    if (payload.len <= max_ipc_payload) {
        var buf: [transport.max_payload_len]u8 = undefined;
        const ipc_bytes = transport.buildIpcBytes(tag, payload, &buf);
        try sendReliablePayload(peer, sock, reliable_send, reliable_recv, .reliable_ipc, ipc_bytes, now);
        return;
    }

    var off: usize = 0;
    while (off < payload.len) {
        const end = @min(off + max_ipc_payload, payload.len);
        var buf: [transport.max_payload_len]u8 = undefined;
        const ipc_bytes = transport.buildIpcBytes(tag, payload[off..end], &buf);
        try sendReliablePayload(peer, sock, reliable_send, reliable_recv, .reliable_ipc, ipc_bytes, now);
        off = end;
    }
}

fn requestResync(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_send: *transport.ReliableSend,
    reliable_recv: *const transport.RecvState,
    last_resync_request_ns: *i64,
    now: i64,
) !void {
    if ((now - last_resync_request_ns.*) < resync_cooldown_ns) return;

    var ctrl_buf: [8]u8 = undefined;
    const payload = transport.buildControl(.resync_request, &ctrl_buf);
    try sendReliablePayload(peer, sock, reliable_send, reliable_recv, .control, payload, now);
    last_resync_request_ns.* = now;
}

/// Remote attach: connect to a remote zmx session via UDP.
pub fn remoteAttach(alloc: std.mem.Allocator, session: RemoteSession) !void {
    // Resolve host address — try numeric IP first, fall back to DNS
    const addr = std.net.Address.resolveIp(session.host, session.port) catch blk: {
        const list = try std.net.getAddressList(alloc, session.host, session.port);
        defer list.deinit();
        if (list.addrs.len == 0) return error.HostNotFound;
        break :blk list.addrs[0];
    };

    // Create UDP socket — bind ephemeral port (OS picks)
    const sock_fd = try posix.socket(
        addr.any.family,
        posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC,
        0,
    );
    var udp_sock = udp_mod.UdpSocket{ .fd = sock_fd, .bound_port = 0 };
    defer udp_sock.close();

    // Create peer
    var peer = udp_mod.Peer.init(session.key, .to_server);
    peer.addr = addr;

    var reliable_send = try transport.ReliableSend.init(alloc);
    defer reliable_send.deinit();
    var reliable_recv = transport.RecvState{};

    var reorder = try ReorderBuffer.init(alloc);
    defer reorder.deinit();
    var next_deliver_offset: u64 = 0;

    // Set terminal to raw mode
    var orig_termios: c.termios = undefined;
    _ = c.tcgetattr(posix.STDIN_FILENO, &orig_termios);
    defer {
        _ = c.tcsetattr(posix.STDIN_FILENO, c.TCSAFLUSH, &orig_termios);
        const restore_seq = "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l" ++
            "\x1b[?2004l\x1b[?1004l\x1b[?1049l" ++
            // Restore pre-attach Kitty keyboard protocol mode so Ctrl combos
            // return to legacy encoding in the user's outer shell.
            "\x1b[<u" ++
            "\x1b[?25h";
        _ = posix.write(posix.STDOUT_FILENO, restore_seq) catch {};
    }

    var raw_termios = orig_termios;
    c.cfmakeraw(&raw_termios);
    raw_termios.c_cc[c.VLNEXT] = c._POSIX_VDISABLE;
    raw_termios.c_cc[c.VQUIT] = c._POSIX_VDISABLE;
    raw_termios.c_cc[c.VMIN] = 1;
    raw_termios.c_cc[c.VTIME] = 0;
    _ = c.tcsetattr(posix.STDIN_FILENO, c.TCSANOW, &raw_termios);

    // Clear screen before attaching. We do NOT use the alternate screen
    // (\x1b[?1049h) because it has no scrollback buffer.
    _ = try posix.write(posix.STDOUT_FILENO, "\x1b[2J\x1b[H");

    setupSigwinchHandler();

    // Make stdin non-blocking
    const stdin_flags = try posix.fcntl(posix.STDIN_FILENO, posix.F.GETFL, 0);
    _ = try posix.fcntl(posix.STDIN_FILENO, posix.F.SETFL, stdin_flags | posix.SOCK.NONBLOCK);

    const config = udp_mod.Config{};
    var stdout_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);
    defer stdout_buf.deinit(alloc);
    var was_disconnected = false;
    var session_ended = false;

    var last_ack_send_ns: i64 = @intCast(std.time.nanoTimestamp());
    var ack_dirty = false;
    var last_resync_request_ns: i64 = 0;

    // Output-channel ack tracking. Schedule an output_ack either when 20 ms
    // have passed since the last ack OR when 16 packets received since.
    var unacked_output_count: u32 = 0;
    var last_output_ack_ns: i64 = @intCast(std.time.nanoTimestamp());
    const output_ack_min_interval_ns: i64 = 20 * std.time.ns_per_ms;
    const output_ack_max_unacked: u32 = 16;

    // Send Init message with terminal size (reliable)
    const size = getTerminalSize();
    var init_buf: [64]u8 = undefined;
    const init_ipc = transport.buildIpcBytes(.Init, std.mem.asBytes(&size), &init_buf);
    try sendReliablePayload(&peer, &udp_sock, &reliable_send, &reliable_recv, .reliable_ipc, init_ipc, last_ack_send_ns);

    while (true) {
        const now: i64 = @intCast(std.time.nanoTimestamp());

        // Check SIGWINCH
        if (sigwinch_received.swap(false, .acq_rel)) {
            const new_size = getTerminalSize();
            try sendIpcReliable(&peer, &udp_sock, &reliable_send, &reliable_recv, .Resize, std.mem.asBytes(&new_size), now);
        }

        // Retransmit reliable packets based on adaptive RTO.
        var retransmits = try reliable_send.collectRetransmits(alloc, now, peer.rto_us());
        defer retransmits.deinit(alloc);
        for (retransmits.items) |pkt| {
            peer.send(&udp_sock, pkt) catch {};
        }

        // Compute flow-control window for output bytes: tell the server how
        // many more bytes (above next_deliver_offset) we'll accept before our
        // stdout buffer fills up.
        const stdout_avail = if (stdout_buf.items.len >= max_stdout_buf) 0 else max_stdout_buf - stdout_buf.items.len;
        const reorder_avail = if (reorder.total_bytes >= reorder_max_bytes) 0 else reorder_max_bytes - reorder.total_bytes;
        const credit_bytes: u64 = @intCast(@min(stdout_avail, reorder_avail));
        const max_byte_offset: u64 = next_deliver_offset + credit_bytes;

        // Stale-gap detection: if we've been holding the oldest fragment
        // for longer than the dynamic timeout, escalate to a snapshot resync.
        if (reorder.oldestArrivedUs()) |oldest| {
            const srtt_us: u64 = if (peer.srtt_us) |s| @intCast(@max(@as(i64, 0), s)) else 0;
            const now_us: u64 = @intCast(@divFloor(now, std.time.ns_per_us));
            if (now_us > oldest and (now_us - oldest) > staleGapTimeoutUs(srtt_us)) {
                reorder.clear();
                try requestResync(&peer, &udp_sock, &reliable_send, &reliable_recv, &last_resync_request_ns, now);
            }
        }

        // Output-channel SACK: emit when (a) >=20ms elapsed and unacked > 0,
        // or (b) >=16 packets received since last ack, or (c) we have buffered
        // gaps to report.
        const have_gaps = reorder.fragments.items.len > 0;
        if (unacked_output_count > 0 or have_gaps) {
            const due_by_time = (now - last_output_ack_ns) >= output_ack_min_interval_ns;
            const due_by_count = unacked_output_count >= output_ack_max_unacked;
            if (due_by_time or due_by_count) {
                var gaps: [transport.max_sack_gaps]transport.SackGap = undefined;
                const n = reorder.computeGaps(next_deliver_offset, &gaps);
                var ack_buf: [transport.output_ack_max_encoded_len]u8 = undefined;
                const ack_payload = transport.buildOutputAckPayload(next_deliver_offset, gaps[0..n], &ack_buf);
                var pkt_buf: [128]u8 = undefined;
                const pkt = transport.buildUnreliable(.output_ack, 0, reliable_recv.ack(), reliable_recv.ackBits(), ack_payload, &pkt_buf) catch unreachable;
                peer.send(&udp_sock, pkt) catch {};
                last_output_ack_ns = now;
                unacked_output_count = 0;
            }
        }

        // Ack heartbeat + keepalive heartbeat.
        if (ack_dirty and (now - last_ack_send_ns) >= ack_delay_ns) {
            sendHeartbeat(&peer, &udp_sock, &reliable_recv, &last_ack_send_ns, &ack_dirty, now, max_byte_offset) catch {};
        } else if (peer.shouldSendHeartbeat(now, config)) {
            sendHeartbeat(&peer, &udp_sock, &reliable_recv, &last_ack_send_ns, &ack_dirty, now, max_byte_offset) catch {};
        }

        // State check
        const state = peer.updateState(now, config);
        if (state == .dead) {
            _ = posix.write(posix.STDOUT_FILENO, "\r\nzmx: connection lost permanently\r\n") catch {};
            return;
        }
        if (state == .disconnected and !was_disconnected) {
            _ = posix.write(posix.STDOUT_FILENO, "\x1b7\x1b[999;1H\x1b[2K\x1b[7mzmx: connection lost — waiting to reconnect...\x1b[27m\x1b8") catch {};
            was_disconnected = true;
        } else if (state == .connected and was_disconnected) {
            _ = posix.write(posix.STDOUT_FILENO, "\x1b7\x1b[999;1H\x1b[2K\x1b8") catch {};
            was_disconnected = false;
        }

        // Build poll fds
        var poll_fds: [3]posix.pollfd = undefined;
        var poll_count: usize = 2;
        poll_fds[0] = .{ .fd = posix.STDIN_FILENO, .events = posix.POLL.IN, .revents = 0 };
        poll_fds[1] = .{ .fd = udp_sock.getFd(), .events = posix.POLL.IN, .revents = 0 };
        if (stdout_buf.items.len > 0) {
            poll_fds[2] = .{ .fd = posix.STDOUT_FILENO, .events = posix.POLL.OUT, .revents = 0 };
            poll_count = 3;
        }

        var poll_timeout: i64 = @min(@as(i64, config.heartbeat_interval_ms), 500);
        if (reliable_send.hasPending()) {
            const rto_ms = @divFloor(peer.rto_us(), 1000);
            poll_timeout = @min(poll_timeout, @max(@as(i64, 1), rto_ms));
        }
        if (ack_dirty) poll_timeout = @min(poll_timeout, @as(i64, 20));
        if (unacked_output_count > 0) {
            const next_ack_due_ns = last_output_ack_ns + output_ack_min_interval_ns;
            const remaining_ns = next_ack_due_ns - now;
            const remaining_ms = if (remaining_ns <= 0) 0 else @divFloor(remaining_ns, std.time.ns_per_ms);
            poll_timeout = @min(poll_timeout, remaining_ms);
        }

        _ = posix.poll(poll_fds[0..poll_count], @intCast(poll_timeout)) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };

        // STDIN → reliable IPC over UDP
        if (poll_fds[0].revents & (posix.POLL.IN | posix.POLL.HUP | posix.POLL.ERR) != 0) {
            var input_raw: [4096]u8 = undefined;
            const n_opt: ?usize = posix.read(posix.STDIN_FILENO, &input_raw) catch |err| blk: {
                if (err == error.WouldBlock) break :blk null;
                return err;
            };
            if (n_opt) |n| {
                if (n > 0) {
                    if (input_raw[0] == 0x1C or isKittyCtrlBackslash(input_raw[0..n])) {
                        try sendIpcReliable(&peer, &udp_sock, &reliable_send, &reliable_recv, .Detach, "", now);
                        return;
                    }
                    try sendIpcReliable(&peer, &udp_sock, &reliable_send, &reliable_recv, .Input, input_raw[0..n], now);
                } else {
                    return; // EOF on stdin
                }
            }
        }

        // UDP recv → decode transport packets
        if (poll_fds[1].revents & posix.POLL.IN != 0) {
            while (true) {
                var decrypt_buf: [9000]u8 = undefined;
                const recv_result = try peer.recv(&udp_sock, &decrypt_buf);
                const result = recv_result orelse break;

                const packet = transport.parsePacket(result.data) catch continue;
                reliable_send.ack(packet.ack, packet.ack_bits);

                switch (packet.channel) {
                    .heartbeat => {},
                    .control => {
                        ack_dirty = true;
                        if (reliable_recv.onReliable(packet.seq) != .accept) continue;
                    },
                    .reliable_ipc => {
                        ack_dirty = true;
                        if (reliable_recv.onReliable(packet.seq) != .accept) continue;

                        var offset: usize = 0;
                        while (offset < packet.payload.len) {
                            const remaining = packet.payload[offset..];
                            const msg_len = ipc.expectedLength(remaining) orelse break;
                            if (remaining.len < msg_len) break;

                            const hdr = std.mem.bytesToValue(ipc.Header, remaining[0..@sizeOf(ipc.Header)]);
                            const payload = remaining[@sizeOf(ipc.Header)..msg_len];

                            if (hdr.tag == .Output and payload.len > 0) {
                                if (stdout_buf.items.len + payload.len > max_stdout_buf) {
                                    stdout_buf.clearRetainingCapacity();
                                    try requestResync(&peer, &udp_sock, &reliable_send, &reliable_recv, &last_resync_request_ns, now);
                                } else {
                                    try stdout_buf.appendSlice(alloc, payload);
                                }
                            } else if (@intFromEnum(hdr.tag) == 11) { // SessionEnd
                                session_ended = true;
                            }

                            offset += msg_len;
                        }
                    },
                    .output_ack => {
                        // Server should never send output_ack to client.
                    },
                    .output => {
                        unacked_output_count +%= 1;

                        const start_offset = transport.readOutputOffset(packet.payload) orelse continue;
                        const data_full = packet.payload[transport.output_offset_prefix_len..];
                        if (data_full.len == 0) continue;

                        // Trim any prefix that's already been delivered (handles
                        // overlap with retransmits).
                        var data: []const u8 = data_full;
                        var offset: u64 = start_offset;
                        if (offset < next_deliver_offset) {
                            const skip = next_deliver_offset - offset;
                            if (skip >= data.len) continue;
                            data = data[@intCast(skip)..];
                            offset = next_deliver_offset;
                        }

                        if (offset == next_deliver_offset) {
                            // Deliver immediately, then drain any contiguous
                            // buffered fragments.
                            if (stdout_buf.items.len + data.len > max_stdout_buf) {
                                stdout_buf.clearRetainingCapacity();
                                reorder.clear();
                                try requestResync(&peer, &udp_sock, &reliable_send, &reliable_recv, &last_resync_request_ns, now);
                            } else {
                                try stdout_buf.appendSlice(alloc, data);
                                next_deliver_offset += data.len;
                                while (reorder.popAt(next_deliver_offset)) |buf_bytes| {
                                    defer alloc.free(buf_bytes);
                                    if (stdout_buf.items.len + buf_bytes.len > max_stdout_buf) {
                                        stdout_buf.clearRetainingCapacity();
                                        reorder.clear();
                                        try requestResync(&peer, &udp_sock, &reliable_send, &reliable_recv, &last_resync_request_ns, now);
                                        break;
                                    }
                                    try stdout_buf.appendSlice(alloc, buf_bytes);
                                    next_deliver_offset += buf_bytes.len;
                                }
                            }
                        } else {
                            // Out of order — buffer it.
                            const arrived_us: u64 = @intCast(@divFloor(now, std.time.ns_per_us));
                            try reorder.insert(offset, data, arrived_us);
                            if (reorder.isOverCapacity()) {
                                reorder.clear();
                                try requestResync(&peer, &udp_sock, &reliable_send, &reliable_recv, &last_resync_request_ns, now);
                            }
                        }
                    },
                }
            }
        }

        // Flush stdout
        if (poll_count == 3 and poll_fds[2].revents & posix.POLL.OUT != 0) {
            if (stdout_buf.items.len > 0) {
                const written = posix.write(posix.STDOUT_FILENO, stdout_buf.items) catch |err| blk: {
                    if (err == error.WouldBlock) break :blk 0;
                    return err;
                };
                if (written > 0) {
                    try stdout_buf.replaceRange(alloc, 0, written, &[_]u8{});
                }
            }
        }

        if (session_ended) {
            if (stdout_buf.items.len > 0) {
                _ = posix.write(posix.STDOUT_FILENO, stdout_buf.items) catch {};
            }
            _ = posix.write(posix.STDOUT_FILENO, "\r\nzmx: remote session ended\r\n") catch {};
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseConnectLine valid" {
    const result = try parseConnectLine("ZMX_CONNECT udp 10.0.0.1 60042 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
    try std.testing.expect(result.port == 60042);
    try std.testing.expectEqualStrings("10.0.0.1", result.host);
}

test "parseConnectLine invalid prefix" {
    try std.testing.expectError(error.InvalidConnectLine, parseConnectLine("INVALID udp 60042 key\n"));
}

test "parseConnectLine unsupported protocol" {
    try std.testing.expectError(error.UnsupportedProtocol, parseConnectLine("ZMX_CONNECT tcp 60042 key\n"));
}
