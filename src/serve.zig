const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");
const udp = @import("udp.zig");
const ipc = @import("ipc.zig");
const transport = @import("transport.zig");
const cc_mod = @import("cc.zig");

const log = std.log.scoped(.serve);

const max_ipc_payload = transport.max_payload_len - @sizeOf(ipc.Header);
const max_unix_write_buf = 1024 * 1024;
const max_output_coalesce = 256 * 1024;
const ack_delay_ns = 20 * std.time.ns_per_ms;
const resync_cooldown_ns = 250 * std.time.ns_per_ms;

/// Retransmit ring sizing — 2048 slots × max_payload_len ≈ 2.4 MB per session.
pub const retransmit_ring_slots: usize = 2048;

pub const RetransmitSlot = struct {
    offset_start: u64 = 0,
    length: u32 = 0,
    send_time_us: u64 = 0,
    last_retransmit_us: u64 = 0,
    payload: [transport.max_output_data_len]u8 = undefined,
    in_use: bool = false,
};

var sigterm_received: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn handleSigterm(_: i32, _: *const posix.siginfo_t, _: ?*anyopaque) callconv(.c) void {
    sigterm_received.store(true, .release);
}

fn setupSigtermHandler() void {
    const act: posix.Sigaction = .{
        .handler = .{ .sigaction = handleSigterm },
        .mask = posix.sigemptyset(),
        .flags = posix.SA.SIGINFO,
    };
    posix.sigaction(posix.SIG.TERM, &act, null);
}

/// Resolve the zmx socket directory, following the same logic as main.zig's Cfg.init.
fn resolveSocketDir(alloc: std.mem.Allocator) ![]const u8 {
    if (posix.getenv("ZMX_DIR")) |zmxdir|
        return try alloc.dupe(u8, zmxdir);
    const tmpdir = std.mem.trimRight(u8, posix.getenv("TMPDIR") orelse "/tmp", "/");
    const uid = posix.getuid();
    if (posix.getenv("XDG_RUNTIME_DIR")) |xdg_runtime|
        return try std.fmt.allocPrint(alloc, "{s}/zmx", .{xdg_runtime});
    return try std.fmt.allocPrint(alloc, "{s}/zmx-{d}", .{ tmpdir, uid });
}

/// Connect to the daemon's Unix socket (same as sessionConnect in main.zig).
fn connectUnix(path: []const u8) !i32 {
    var unix_addr = try std.net.Address.initUnix(path);
    const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);
    try posix.connect(fd, &unix_addr.any, unix_addr.getOsSockLen());
    // Make non-blocking for poll loop
    const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
    _ = try posix.fcntl(fd, posix.F.SETFL, flags | posix.SOCK.NONBLOCK);
    return fd;
}

pub const Gateway = struct {
    alloc: std.mem.Allocator,
    udp_sock: udp.UdpSocket,
    unix_fd: i32,
    peer: udp.Peer,
    unix_read_buf: ipc.SocketBuffer,
    unix_write_buf: std.ArrayList(u8),
    output_coalesce_buf: std.ArrayList(u8),

    reliable_send: transport.ReliableSend,
    reliable_recv: transport.RecvState,
    /// Monotonic byte offset of the next byte to send on the output channel.
    next_output_offset: u64,
    /// FIFO ring of recently-sent output payloads, used for retransmission.
    retransmit_ring: []RetransmitSlot,
    retransmit_write: usize,

    config: udp.Config,
    running: bool,

    last_output_flush_ns: i64,
    last_ack_send_ns: i64,
    ack_dirty: bool,

    last_resync_request_ns: i64,
    have_client_size: bool,
    last_resize: ipc.Resize,

    /// Congestion controller for the server->client output path.
    cc: cc_mod.CongestionController,
    /// Absolute us time at which we should retry a pacer-blocked send.
    cc_next_wait_us: u64,

    /// Last max_byte_offset advertised by the client in a heartbeat. Server
    /// must not send output bytes whose end exceeds this value.
    client_max_byte_offset: u64,
    client_max_byte_offset_known: bool,

    pub fn init(
        alloc: std.mem.Allocator,
        session_name: []const u8,
        config: udp.Config,
    ) !Gateway {
        const socket_dir = try resolveSocketDir(alloc);
        defer alloc.free(socket_dir);

        const socket_path = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ socket_dir, session_name });
        defer alloc.free(socket_path);

        // Connect to the daemon's Unix socket
        const unix_fd = connectUnix(socket_path) catch |err| {
            log.err("failed to connect to daemon socket={s} err={s}", .{ socket_path, @errorName(err) });
            return err;
        };
        errdefer posix.close(unix_fd);

        // Bind a UDP socket in the configured port range
        var udp_sock = try udp.UdpSocket.bind(config.port_range_start, config.port_range_end);
        errdefer udp_sock.close();

        // Generate session key
        const key = crypto.generateKey();
        const encoded_key = crypto.keyToBase64(key);

        // Extract server IP from SSH_CONNECTION (set by sshd):
        // format: "<client_ip> <client_port> <server_ip> <server_port>"
        const server_ip = blk: {
            const ssh_conn = posix.getenv("SSH_CONNECTION") orelse break :blk "127.0.0.1";
            var it = std.mem.splitScalar(u8, ssh_conn, ' ');
            _ = it.next(); // client_ip
            _ = it.next(); // client_port
            break :blk it.next() orelse "127.0.0.1";
        };

        // Print bootstrap line for SSH capture
        {
            var out_buf: [256]u8 = undefined;
            const line = std.fmt.bufPrint(&out_buf, "ZMX_CONNECT udp {s} {d} {s}\n", .{ server_ip, udp_sock.bound_port, encoded_key }) catch unreachable;
            _ = try posix.write(posix.STDOUT_FILENO, line);
        }

        // Close stdout so SSH session can terminate
        posix.close(posix.STDOUT_FILENO);

        // Initialize peer (we send to_client, recv to_server from remote client)
        const peer = udp.Peer.init(key, .to_client);

        const unix_read_buf = try ipc.SocketBuffer.init(alloc);
        const unix_write_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);
        const output_coalesce_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);
        const reliable_send = try transport.ReliableSend.init(alloc);

        const now: i64 = @intCast(std.time.nanoTimestamp());

        log.info("gateway started session={s} udp_port={d}", .{ session_name, udp_sock.bound_port });

        var cc: cc_mod.CongestionController = undefined;
        cc.init(@intCast(transport.max_payload_len + 20), nowUs());

        const retransmit_ring = try alloc.alloc(RetransmitSlot, retransmit_ring_slots);
        for (retransmit_ring) |*slot| slot.* = .{};

        return .{
            .alloc = alloc,
            .udp_sock = udp_sock,
            .unix_fd = unix_fd,
            .peer = peer,
            .unix_read_buf = unix_read_buf,
            .unix_write_buf = unix_write_buf,
            .output_coalesce_buf = output_coalesce_buf,
            .reliable_send = reliable_send,
            .reliable_recv = .{},
            .next_output_offset = 0,
            .retransmit_ring = retransmit_ring,
            .retransmit_write = 0,
            .config = config,
            .running = true,
            .last_output_flush_ns = now,
            .last_ack_send_ns = now,
            .ack_dirty = false,
            .last_resync_request_ns = 0,
            .have_client_size = false,
            .last_resize = .{ .rows = 24, .cols = 80 },
            .cc = cc,
            .cc_next_wait_us = 0,
            .client_max_byte_offset = 0,
            .client_max_byte_offset_known = false,
        };
    }

    fn nowUs() u64 {
        return @intCast(@divFloor(std.time.nanoTimestamp(), std.time.ns_per_us));
    }

    pub fn run(self: *Gateway) !void {
        setupSigtermHandler();

        while (self.running) {
            if (sigterm_received.swap(false, .acq_rel)) {
                log.info("SIGTERM received, shutting down gateway", .{});
                break;
            }

            const now: i64 = @intCast(std.time.nanoTimestamp());

            // Check peer state
            const state = self.peer.updateState(now, self.config);
            if (state == .dead) {
                log.info("peer dead (alive timeout), shutting down", .{});
                break;
            }

            try self.flushRetransmits(now);
            try self.flushOutput(now, false);

            if (self.peer.addr != null) {
                if (self.ack_dirty and (now - self.last_ack_send_ns >= ack_delay_ns)) {
                    self.sendHeartbeat(now) catch |err| {
                        if (err != error.NoPeerAddress and err != error.WouldBlock) return err;
                    };
                } else if (self.peer.shouldSendHeartbeat(now, self.config)) {
                    self.sendHeartbeat(now) catch |err| {
                        if (err != error.NoPeerAddress and err != error.WouldBlock) return err;
                    };
                }
            }

            // Build poll fds
            var poll_fds: [2]posix.pollfd = undefined;
            poll_fds[0] = .{ .fd = self.udp_sock.getFd(), .events = posix.POLL.IN, .revents = 0 };

            var unix_events: i16 = posix.POLL.IN;
            if (self.unix_write_buf.items.len > 0) {
                unix_events |= posix.POLL.OUT;
            }
            poll_fds[1] = .{ .fd = self.unix_fd, .events = unix_events, .revents = 0 };

            const poll_timeout = self.computePollTimeoutMs(now);
            _ = posix.poll(&poll_fds, poll_timeout) catch |err| {
                if (err == error.Interrupted) continue;
                return err;
            };

            // Handle incoming UDP datagrams → decrypt → decode transport packet
            if (poll_fds[0].revents & posix.POLL.IN != 0) {
                while (true) {
                    var decrypt_buf: [9000]u8 = undefined;
                    const recv_result = try self.peer.recv(&self.udp_sock, &decrypt_buf);
                    const result = recv_result orelse break;
                    try self.handleTransportPacket(result.data, now);
                }
            }

            // Handle Unix socket read → forward to UDP transport
            if (poll_fds[1].revents & posix.POLL.IN != 0) {
                while (true) {
                    const n = self.unix_read_buf.read(self.unix_fd) catch |err| {
                        if (err == error.WouldBlock) break;
                        log.warn("unix read error: {s}", .{@errorName(err)});
                        self.running = false;
                        break;
                    };
                    if (!self.running) break;
                    if (n == 0) {
                        log.info("daemon closed connection", .{});
                        self.running = false;
                        break;
                    }

                    while (self.unix_read_buf.next()) |msg| {
                        try self.forwardDaemonMessage(msg.header.tag, msg.payload, now);
                    }
                }
            }

            // Flush buffered writes to Unix socket
            if (poll_fds[1].revents & posix.POLL.OUT != 0) {
                if (self.unix_write_buf.items.len > 0) {
                    const written = posix.write(self.unix_fd, self.unix_write_buf.items) catch |err| blk: {
                        if (err == error.WouldBlock) break :blk @as(usize, 0);
                        log.warn("unix write error: {s}", .{@errorName(err)});
                        self.running = false;
                        break :blk @as(usize, 0);
                    };
                    if (written > 0) {
                        self.unix_write_buf.replaceRange(self.alloc, 0, written, &[_]u8{}) catch unreachable;
                    }
                }
            }

            if (poll_fds[1].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                log.info("unix socket closed/error", .{});
                break;
            }
        }

        // Notify client that the session has ended.
        if (self.peer.addr != null) {
            self.sendIpcReliable(@enumFromInt(11), "", @intCast(std.time.nanoTimestamp())) catch |err| { // SessionEnd
                log.debug("failed to send SessionEnd: {s}", .{@errorName(err)});
            };
        }
    }

    fn computePollTimeoutMs(self: *const Gateway, now: i64) i32 {
        var timeout: i64 = @min(@as(i64, self.config.heartbeat_interval_ms), 1000);

        if (self.output_coalesce_buf.items.len > 0) {
            const flush_due = self.last_output_flush_ns + self.outputFlushIntervalNs();
            const remaining_ns = flush_due - now;
            const remaining_ms = if (remaining_ns <= 0) 0 else @divFloor(remaining_ns, std.time.ns_per_ms);
            timeout = @min(timeout, remaining_ms);
        }

        if (self.reliable_send.hasPending()) {
            const rto_ms = @divFloor(self.peer.rto_us(), 1000);
            timeout = @min(timeout, @max(@as(i64, 1), rto_ms));
        }

        if (self.ack_dirty) timeout = @min(timeout, @as(i64, 20));

        // If the pacer wants us to wait, honour that (bounded to >=0).
        if (self.cc_next_wait_us != 0 and self.output_coalesce_buf.items.len > 0) {
            const now_us = nowUs();
            if (self.cc_next_wait_us > now_us) {
                const wait_ms = @divFloor(self.cc_next_wait_us - now_us, 1000) + 1;
                timeout = @min(timeout, @as(i64, @intCast(wait_ms)));
            }
        }

        return @intCast(@max(@as(i64, 0), timeout));
    }

    fn outputFlushIntervalNs(self: *const Gateway) i64 {
        const srtt_us = self.peer.srtt_us orelse 32_000;
        const paced_us = std.math.clamp(@divFloor(srtt_us, 8), @as(i64, 2_000), @as(i64, 8_000));
        return paced_us * std.time.ns_per_us;
    }

    fn sendHeartbeat(self: *Gateway, now: i64) !void {
        // The server's heartbeat doesn't need to advertise a flow-control
        // window — that's the client's job. Send an empty heartbeat.
        var pkt_buf: [1200]u8 = undefined;
        const pkt = try transport.buildUnreliable(
            .heartbeat,
            0,
            self.reliable_recv.ack(),
            self.reliable_recv.ackBits(),
            "",
            &pkt_buf,
        );
        try self.peer.send(&self.udp_sock, pkt);
        self.last_ack_send_ns = now;
        self.ack_dirty = false;
    }

    fn flushRetransmits(self: *Gateway, now: i64) !void {
        var packets = try self.reliable_send.collectRetransmits(self.alloc, now, self.peer.rto_us());
        defer packets.deinit(self.alloc);

        for (packets.items) |packet| {
            self.peer.send(&self.udp_sock, packet) catch |err| {
                if (err == error.NoPeerAddress or err == error.WouldBlock) continue;
                return err;
            };
        }
    }

    /// Send a single output-channel packet carrying `data` starting at
    /// `offset`. Records the chunk in the retransmit ring (unless the call
    /// is itself a retransmit, indicated by `record == false`).
    fn sendOutputChunk(
        self: *Gateway,
        offset: u64,
        data: []const u8,
        now_us: u64,
        record: bool,
    ) !void {
        std.debug.assert(data.len <= transport.max_output_data_len);

        var pkt_buf: [1200]u8 = undefined;
        var payload_buf: [transport.max_payload_len]u8 = undefined;
        transport.writeOutputOffset(payload_buf[0..transport.output_offset_prefix_len], offset);
        @memcpy(payload_buf[transport.output_offset_prefix_len..][0..data.len], data);
        const payload = payload_buf[0 .. transport.output_offset_prefix_len + data.len];

        const pkt = try transport.buildUnreliable(
            .output,
            0,
            self.reliable_recv.ack(),
            self.reliable_recv.ackBits(),
            payload,
            &pkt_buf,
        );
        try self.peer.send(&self.udp_sock, pkt);

        self.cc.onPacketSent(offset, @intCast(data.len), now_us);

        if (record) {
            const idx = self.retransmit_write % retransmit_ring_slots;
            self.retransmit_write += 1;
            const slot = &self.retransmit_ring[idx];
            slot.offset_start = offset;
            slot.length = @intCast(data.len);
            slot.send_time_us = now_us;
            slot.last_retransmit_us = 0;
            @memcpy(slot.payload[0..data.len], data);
            slot.in_use = true;
        }
    }

    fn flushOutput(self: *Gateway, now: i64, force: bool) !void {
        if (self.output_coalesce_buf.items.len == 0) return;
        if (!force and (now - self.last_output_flush_ns) < self.outputFlushIntervalNs()) return;

        if (self.peer.addr == null) {
            self.output_coalesce_buf.clearRetainingCapacity();
            self.last_output_flush_ns = now;
            return;
        }

        var sent_off: usize = 0;
        while (sent_off < self.output_coalesce_buf.items.len) {
            const end = @min(sent_off + transport.max_output_data_len, self.output_coalesce_buf.items.len);
            const chunk = self.output_coalesce_buf.items[sent_off..end];
            const pkt_size: u64 = chunk.len + transport.output_offset_prefix_len + 20;

            const now_us = nowUs();
            // Receiver flow control: stall if the chunk would exceed the
            // client's advertised byte-offset window.
            if (self.client_max_byte_offset_known and
                self.next_output_offset + chunk.len > self.client_max_byte_offset)
            {
                break;
            }
            if (!self.cc.canSend(pkt_size, now_us)) {
                self.cc_next_wait_us = self.cc.nextSendTimeUs(pkt_size, now_us);
                break;
            }

            const offset = self.next_output_offset;
            self.sendOutputChunk(offset, chunk, now_us, true) catch |err| {
                if (err == error.WouldBlock) {
                    log.debug("udp output send would block; dropping stale output and requesting resync", .{});
                    self.output_coalesce_buf.clearRetainingCapacity();
                    try self.requestSnapshot(now);
                    self.last_output_flush_ns = now;
                    return;
                }
                if (err == error.NoPeerAddress) {
                    self.output_coalesce_buf.clearRetainingCapacity();
                    self.last_output_flush_ns = now;
                    return;
                }
                return err;
            };
            self.next_output_offset += chunk.len;
            sent_off = end;
        }

        if (sent_off > 0) {
            self.output_coalesce_buf.replaceRange(self.alloc, 0, sent_off, &[_]u8{}) catch unreachable;
            self.last_output_flush_ns = now;
        }
    }

    fn trackClientResize(self: *Gateway, payload: []const u8) void {
        var offset: usize = 0;
        while (offset < payload.len) {
            const remaining = payload[offset..];
            const msg_len = ipc.expectedLength(remaining) orelse break;
            if (remaining.len < msg_len) break;

            const hdr = std.mem.bytesToValue(ipc.Header, remaining[0..@sizeOf(ipc.Header)]);
            const msg_payload = remaining[@sizeOf(ipc.Header)..msg_len];
            if ((hdr.tag == .Init or hdr.tag == .Resize) and msg_payload.len == @sizeOf(ipc.Resize)) {
                self.last_resize = std.mem.bytesToValue(ipc.Resize, msg_payload);
                self.have_client_size = true;
            }

            offset += msg_len;
        }
    }

    fn appendUnixWrite(self: *Gateway, payload: []const u8) !void {
        if (self.unix_write_buf.items.len + payload.len > max_unix_write_buf) {
            return error.UnixWriteBackpressure;
        }
        try self.unix_write_buf.appendSlice(self.alloc, payload);
    }

    fn requestSnapshot(self: *Gateway, now: i64) !void {
        if ((now - self.last_resync_request_ns) < resync_cooldown_ns) return;
        self.last_resync_request_ns = now;

        const size = if (self.have_client_size) self.last_resize else ipc.Resize{ .rows = 24, .cols = 80 };
        var init_buf: [64]u8 = undefined;
        const init_ipc = transport.buildIpcBytes(.Init, std.mem.asBytes(&size), &init_buf);
        try self.appendUnixWrite(init_ipc);
        log.debug("requested terminal snapshot rows={d} cols={d}", .{ size.rows, size.cols });
    }

    fn handleTransportPacket(self: *Gateway, plaintext: []const u8, now: i64) !void {
        const packet = transport.parsePacket(plaintext) catch |err| {
            log.debug("transport parse failed: {s}", .{@errorName(err)});
            return;
        };

        self.reliable_send.ack(packet.ack, packet.ack_bits);

        const now_us = nowUs();

        switch (packet.channel) {
            .output_ack => {
                if (transport.parseOutputAckPayload(packet.payload)) |oa| {
                    self.applyOutputAck(oa, now_us, now);
                }
                return;
            },
            .heartbeat => {
                if (transport.parseHeartbeatPayload(packet.payload)) |hb| {
                    self.client_max_byte_offset = hb.max_byte_offset;
                    self.client_max_byte_offset_known = true;
                }
            },
            .output => {
                // Client never sends output channel packets.
            },
            .reliable_ipc, .control => {
                self.ack_dirty = true;
                const action = self.reliable_recv.onReliable(packet.seq);
                if (action != .accept) return;

                if (packet.channel == .reliable_ipc) {
                    self.trackClientResize(packet.payload);
                    self.appendUnixWrite(packet.payload) catch |err| {
                        log.warn("unix write buffer overflow: {s}", .{@errorName(err)});
                        self.running = false;
                        return;
                    };
                } else {
                    const ctrl = transport.parseControl(packet.payload) catch return;
                    if (ctrl == .resync_request) {
                        self.requestSnapshot(now) catch |err| {
                            log.warn("failed to queue snapshot request: {s}", .{@errorName(err)});
                            self.running = false;
                        };
                    }
                }
            },
        }
    }

    fn sendReliablePayload(self: *Gateway, channel: transport.Channel, payload: []const u8, now: i64) !void {
        const packet = try self.reliable_send.buildAndTrack(
            channel,
            payload,
            self.reliable_recv.ack(),
            self.reliable_recv.ackBits(),
            now,
        );
        self.peer.send(&self.udp_sock, packet) catch |err| {
            if (err == error.NoPeerAddress or err == error.WouldBlock) return;
            return err;
        };
    }

    fn sendIpcReliable(self: *Gateway, tag: ipc.Tag, payload: []const u8, now: i64) !void {
        if (payload.len <= max_ipc_payload) {
            var buf: [transport.max_payload_len]u8 = undefined;
            const ipc_bytes = transport.buildIpcBytes(tag, payload, &buf);
            try self.sendReliablePayload(.reliable_ipc, ipc_bytes, now);
            return;
        }

        var off: usize = 0;
        while (off < payload.len) {
            const end = @min(off + max_ipc_payload, payload.len);
            var buf: [transport.max_payload_len]u8 = undefined;
            const ipc_bytes = transport.buildIpcBytes(tag, payload[off..end], &buf);
            try self.sendReliablePayload(.reliable_ipc, ipc_bytes, now);
            off = end;
        }
    }

    fn forwardDaemonMessage(self: *Gateway, tag: ipc.Tag, payload: []const u8, now: i64) !void {
        if (tag == .Output) {
            if (self.output_coalesce_buf.items.len + payload.len > max_output_coalesce) {
                log.debug("output coalesce buffer overflow; dropping stale output and requesting snapshot", .{});
                self.output_coalesce_buf.clearRetainingCapacity();
                try self.requestSnapshot(now);
                return;
            }
            try self.output_coalesce_buf.appendSlice(self.alloc, payload);
            if (self.output_coalesce_buf.items.len >= transport.max_payload_len * 4) {
                try self.flushOutput(now, true);
            }
            return;
        }

        try self.flushOutput(now, true);
        try self.sendIpcReliable(tag, payload, now);
    }

    /// Look up a retransmit slot whose stored range overlaps the requested
    /// byte range. Returns null if the range has been evicted.
    fn findRetransmitSlot(self: *Gateway, offset_start: u64) ?*RetransmitSlot {
        for (self.retransmit_ring) |*slot| {
            if (!slot.in_use) continue;
            if (slot.offset_start == offset_start) return slot;
        }
        return null;
    }

    /// Mark every retransmit slot whose stored range lies entirely below
    /// `cutoff` as free. Also feeds those ranges to the congestion controller
    /// as cumulative acks. Returns whether any slot below `cutoff` was missing
    /// (which can happen if a SACK acks a range we never had — should not
    /// occur in practice).
    fn ackContiguousBelow(self: *Gateway, cutoff: u64, now_us: u64) void {
        for (self.retransmit_ring) |*slot| {
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

    /// Apply a decoded SACK from the client. Acks contiguous bytes below
    /// `highest_contiguous_offset`, then for each gap notifies CC of loss
    /// and either retransmits the bytes (if still in the ring) or escalates
    /// to a full snapshot resync (if evicted).
    fn applyOutputAck(self: *Gateway, sack: transport.OutputAckPayload, now_us: u64, now_ns: i64) void {
        self.ackContiguousBelow(sack.highest_contiguous_offset, now_us);

        var i: usize = 0;
        while (i < sack.n_gaps) : (i += 1) {
            const gap = sack.gaps[i];
            if (gap.len == 0) continue;
            const gap_start = sack.highest_contiguous_offset + gap.start_rel;
            // Search the ring for the slot exactly matching this gap. (Server
            // chunking is deterministic so the gap should align to a slot.)
            const slot = self.findRetransmitSlot(gap_start);
            if (slot) |s| {
                self.cc.onLoss(s.offset_start, s.length, now_us);
                const cooldown_us: u64 = blk: {
                    const srtt = self.peer.srtt_us orelse @as(i64, 100_000);
                    const c: u64 = @intCast(@max(srtt, @as(i64, 20_000)));
                    break :blk c;
                };
                if (now_us - s.last_retransmit_us >= cooldown_us) {
                    s.last_retransmit_us = now_us;
                    self.sendOutputChunk(s.offset_start, s.payload[0..s.length], now_us, false) catch {};
                }
            } else {
                // Range has been evicted from the ring — escalate.
                self.cc.onLoss(gap_start, gap.len, now_us);
                self.requestSnapshot(now_ns) catch {};
            }
        }
    }

    pub fn deinit(self: *Gateway) void {
        posix.close(self.unix_fd);
        self.udp_sock.close();
        self.unix_read_buf.deinit();
        self.unix_write_buf.deinit(self.alloc);
        self.output_coalesce_buf.deinit(self.alloc);
        self.reliable_send.deinit();
        self.alloc.free(self.retransmit_ring);
    }
};

/// Entry point for `zmx serve <session>`.
pub fn serveMain(alloc: std.mem.Allocator, session_name: []const u8) !void {
    var gw = try Gateway.init(alloc, session_name, .{});
    defer gw.deinit();
    try gw.run();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "bootstrap output format" {
    const key = crypto.generateKey();
    const encoded = crypto.keyToBase64(key);
    const port: u16 = 60042;
    const host = "10.50.0.102";

    var buf: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, "ZMX_CONNECT udp {s} {d} {s}\n", .{ host, port, encoded });

    // Verify it starts with the expected prefix
    try std.testing.expect(std.mem.startsWith(u8, line, "ZMX_CONNECT udp "));

    // Parse back via remote.parseConnectLine
    const remote = @import("remote.zig");
    const result = try remote.parseConnectLine(line);
    try std.testing.expectEqualStrings("10.50.0.102", result.host);
    try std.testing.expect(result.port == 60042);
    try std.testing.expectEqual(key, result.key);
}

test "resolveSocketDir returns valid path" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const dir = try resolveSocketDir(alloc);
    defer alloc.free(dir);
    try std.testing.expect(dir.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, dir, "zmx") != null);
}
