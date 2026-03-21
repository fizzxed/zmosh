const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");
const udp = @import("udp.zig");
const ipc = @import("ipc.zig");
const transport = @import("transport.zig");
const congestion = @import("congestion.zig");
const loss = @import("loss.zig");

const log = std.log.scoped(.serve);

const max_ipc_payload = transport.max_payload_len - @sizeOf(ipc.Header);
const max_unix_write_buf = 1024 * 1024;
const max_output_coalesce = 2 * 1024 * 1024;
const ack_delay_ns = 20 * std.time.ns_per_ms;
const resync_cooldown_ns = 250 * std.time.ns_per_ms;

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
    pending_output: std.ArrayList(u8),

    reliable_send: transport.ReliableSend,
    reliable_recv: transport.RecvState,
    output_offset: u32,

    // BBR congestion control + pacing
    bbr: congestion.Bbr,
    pacer: congestion.Pacer,
    send_buf: loss.SendBuffer,
    loss_detector: loss.LossDetector,
    retransmit_buf: [64]u32,
    retransmit_queue: std.ArrayListUnmanaged(u32),
    // Dual-mode timer per RFC 9002 §6.2.1 SetLossDetectionTimer:
    // - loss_time > 0: fire at loss_time to run detectLosses (time threshold)
    // - loss_time == 0 && pto_time > 0: fire at pto_time to send probe
    loss_time: i64 = 0, // earliest loss detection time, or 0
    pto_time: i64 = 0, // PTO expiry time, or 0
    pto_count: u32 = 0, // exponential backoff counter (reset on ACK progress)

    // Output-path RTT tracking (separate from Peer's RTT for reliable IPC).
    // Per spec §4.2: RS.rtt = Now() - P.send_time, computed per-packet.
    // Peer's RTT measures heartbeat-to-heartbeat which inflates during idle.
    output_srtt_ns: i64 = 0,
    output_rttvar_ns: i64 = 0,
    output_latest_rtt_ns: i64 = 0,

    // Timestamp of last ACK progress (largest_acked advanced).
    last_ack_progress_ns: i64 = 0,
    prev_largest_acked: u32 = 0,
    has_prev_largest_acked: bool = false,

    config: udp.Config,
    running: bool,

    last_ack_send_ns: i64,
    ack_dirty: bool,

    last_resync_request_ns: i64,
    have_client_size: bool,
    last_resize: ipc.Resize,


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
        const pending_output = try std.ArrayList(u8).initCapacity(alloc, 4096);
        const reliable_send = try transport.ReliableSend.init(alloc);
        const send_buf = try loss.SendBuffer.init(alloc);

        const now: i64 = @intCast(std.time.nanoTimestamp());

        log.info("gateway started session={s} udp_port={d}", .{ session_name, udp_sock.bound_port });

        var gw = Gateway{
            .alloc = alloc,
            .udp_sock = udp_sock,
            .unix_fd = unix_fd,
            .peer = peer,
            .unix_read_buf = unix_read_buf,
            .unix_write_buf = unix_write_buf,
            .pending_output = pending_output,
            .reliable_send = reliable_send,
            .reliable_recv = .{},
            .output_offset = 0,
            .bbr = .{},
            .pacer = .{},
            .send_buf = send_buf,
            .loss_detector = .{},
            .retransmit_buf = undefined,
            .retransmit_queue = undefined,
            .output_srtt_ns = 0,
            .output_rttvar_ns = 0,
            .output_latest_rtt_ns = 0,
            .last_ack_progress_ns = 0,
            .prev_largest_acked = 0,
            .has_prev_largest_acked = false,
            .loss_time = 0,
            .pto_time = 0,
            .pto_count = 0,
            .config = config,
            .running = true,
            .last_ack_send_ns = now,
            .ack_dirty = false,
            .last_resync_request_ns = 0,
            .have_client_size = false,
            .last_resize = .{ .rows = 24, .cols = 80 },
        };
        gw.retransmit_queue = std.ArrayListUnmanaged(u32).initBuffer(&gw.retransmit_buf);
        return gw;
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

            // RFC 9002 §6.2.2 OnLossDetectionTimeout
            if (self.loss_time > 0 and now >= self.loss_time) {
                // Loss timer fired: run loss detection
                self.onLossDetectionTimeout(now);
            } else if (self.pto_time > 0 and now >= self.pto_time) {
                // PTO fired: send probe to elicit ACK
                self.onPtoTimeout(now);
            }

            try self.flushRetransmits(now);
            try self.sendPacedOutput(now);

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

        // Pacer timeout for pending output
        if (self.pending_output.items.len > 0 or self.retransmit_queue.items.len > 0) {
            if (self.bbr.canSend()) {
                const pacer_ms = self.pacer.pollTimeoutMs(now);
                timeout = @min(timeout, @as(i64, pacer_ms));
            }
        }

        // Loss/PTO timer
        const timer = if (self.loss_time > 0) self.loss_time else if (self.pto_time > 0) self.pto_time else @as(i64, 0);
        if (timer > 0) {
            const remaining_ns = timer - now;
            const remaining_ms = if (remaining_ns <= 0) 0 else @divFloor(remaining_ns, std.time.ns_per_ms);
            timeout = @min(timeout, remaining_ms);
        }

        if (self.reliable_send.hasPending()) {
            const rto_ms = @divFloor(self.peer.rto_us(), 1000);
            timeout = @min(timeout, @max(@as(i64, 1), rto_ms));
        }

        if (self.ack_dirty) timeout = @min(timeout, @as(i64, 20));

        return @intCast(@max(@as(i64, 0), timeout));
    }

    fn sendHeartbeat(self: *Gateway, now: i64) !void {
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

    fn sendPacedOutput(self: *Gateway, now: i64) !void {
        if (self.peer.addr == null) {
            self.pending_output.clearRetainingCapacity();
            return;
        }

        while (self.bbr.canSend() and self.pacer.canSend(now)) {
            // Priority 1: retransmissions
            if (self.retransmit_queue.items.len > 0) {
                const offset = self.retransmit_queue.orderedRemove(0);
                const entry = self.send_buf.getForRetransmit(offset) orelse continue;
                const payload = self.send_buf.getPayload(offset) orelse continue;

                var pkt_buf: [1200]u8 = undefined;
                const pkt = try transport.buildUnreliable(
                    .output,
                    offset,
                    self.reliable_recv.ack(),
                    self.reliable_recv.ackBits(),
                    payload,
                    &pkt_buf,
                );

                self.peer.send(&self.udp_sock, pkt) catch |err| {
                    if (err == error.WouldBlock) {
                        // Put it back
                        self.retransmit_queue.insertBounded(0, offset) catch {};
                        return;
                    }
                    if (err == error.NoPeerAddress) return;
                    return err;
                };

                entry.retransmit_count +|= 1;
                entry.sent_time = now;
                // Re-increment inflight: onLoss decremented it, retransmit puts it back
                self.bbr.inflight +|= @as(u32, @intCast(payload.len));
                self.pacer.onSend(now, @intCast(payload.len), self.bbr.pacing_rate);
                continue;
            }

            // Priority 2: new data from pending_output
            if (self.pending_output.items.len == 0) break;

            const end = @min(transport.max_payload_len, self.pending_output.items.len);
            const chunk = self.pending_output.items[0..end];
            const offset = self.output_offset;

            // OnPacketSent: init + snapshot + update inflight (spec §4.1.2.2)
            const ds = self.bbr.onSend(@intCast(chunk.len), now);
            self.send_buf.recordSend(offset, chunk, now, ds);

            var pkt_buf: [1200]u8 = undefined;
            const pkt = try transport.buildUnreliable(
                .output,
                offset,
                self.reliable_recv.ack(),
                self.reliable_recv.ackBits(),
                chunk,
                &pkt_buf,
            );

            self.peer.send(&self.udp_sock, pkt) catch |err| {
                if (err == error.WouldBlock) return;
                if (err == error.NoPeerAddress) {
                    self.pending_output.clearRetainingCapacity();
                    return;
                }
                return err;
            };

            self.pacer.onSend(now, @intCast(chunk.len), self.bbr.pacing_rate);
            self.output_offset +%= transport.step;

            // Remove sent data from pending buffer
            self.pending_output.replaceRange(self.alloc, 0, end, &[_]u8{}) catch unreachable;
        }

        // If both queues are empty, mark app-limited
        if (self.pending_output.items.len == 0 and self.retransmit_queue.items.len == 0) {
            self.bbr.setAppLimited();
        }
    }

    fn processOutputAcks(self: *Gateway, payload: []const u8, now: i64) void {
        var gap_buf: [loss.AckRanges.max_gaps]loss.AckRanges.Gap = undefined;
        const ranges = loss.AckRanges.decode(payload, &gap_buf) catch return;

        self.loss_detector.onAck(ranges.largest_acked);

        // Track ACK progress and reset PTO backoff
        if (!self.has_prev_largest_acked or ranges.largest_acked != self.prev_largest_acked) {
            self.last_ack_progress_ns = now;
            self.prev_largest_acked = ranges.largest_acked;
            self.has_prev_largest_acked = true;
            self.pto_count = 0; // Reset PTO backoff on ACK progress
        }

        // Begin batched ACK event (spec §5.2.3: BBRUpdateOnACK runs once)
        self.bbr.beginAck();

        // Track whether any packet in the retransmit queue was ACKed (spurious loss)
        var spurious_detected = false;

        // Process ACKed offsets
        const Ctx = struct {
            gw: *Gateway,
            now_ns: i64,
            spurious: *bool,
        };
        const ctx = Ctx{ .gw = self, .now_ns = now, .spurious = &spurious_detected };
        const Handler = struct {
            ctx_inner: Ctx,

            pub fn call(handler: @This(), offset: u32) void {
                const gw = handler.ctx_inner.gw;
                const n = handler.ctx_inner.now_ns;

                // Spurious loss detection: if this offset is in the retransmit queue
                // (declared lost) but arrives ACKed, the loss was spurious.
                for (gw.retransmit_queue.items, 0..) |roffset, idx| {
                    if (roffset == offset) {
                        _ = gw.retransmit_queue.orderedRemove(idx);
                        handler.ctx_inner.spurious.* = true;
                        break;
                    }
                }

                const entry = gw.send_buf.markAcked(offset) orelse return;

                // RTT: Karn's algorithm -- only use non-retransmitted packets.
                if (entry.retransmit_count == 0) {
                    const rtt_ns = n - entry.sent_time;
                    if (rtt_ns > 0) {
                        gw.updateOutputRtt(rtt_ns);
                    }
                }

                // Per spec §4.1.2.3: accumulate delivery info per-packet,
                // run model+control update once in endAck.
                gw.bbr.onAckPacket(.{
                    .size = entry.size,
                    .sent_time = entry.sent_time,
                    .delivery_state = entry.delivery_state,
                    .rtt_ns = if (entry.retransmit_count == 0) n - entry.sent_time else 0,
                }, entry.retransmit_count > 0);
            }
        };

        ranges.iterateAcked(Handler{ .ctx_inner = ctx });

        // Finalize ACK event: compute rate sample and run model+control once
        self.bbr.endAck(now);

        // Handle spurious loss detection (spec §5.5.11.2)
        if (spurious_detected) {
            self.bbr.handleSpuriousLossDetection();
        }

        // Loss detection -- uses Gateway's output-path SRTT (not Peer's)
        const srtt_ns: i64 = if (self.output_srtt_ns > 0) self.output_srtt_ns else 100 * std.time.ns_per_ms;
        const latest = if (self.output_latest_rtt_ns > 0) self.output_latest_rtt_ns else srtt_ns;
        const prev_queue_len = self.retransmit_queue.items.len;
        self.loss_time = self.loss_detector.detectLosses(&self.send_buf, now, srtt_ns, latest, &self.retransmit_queue);

        // Only notify BBR about NEWLY detected losses (not already-queued ones)
        for (self.retransmit_queue.items[prev_queue_len..]) |lost_offset| {
            if (self.send_buf.getForRetransmit(lost_offset)) |entry| {
                // RS.lost = C.lost - P.lost (cumulative lost since this packet was sent)
                const rs_lost = self.bbr.total_lost -| entry.delivery_state.lost;
                self.bbr.onLoss(lost_offset, entry.size, rs_lost + entry.size, entry.delivery_state.tx_in_flight, entry.delivery_state.is_app_limited);
            }
        }

        self.setLossDetectionTimer(now);
        self.send_buf.pruneAcked();
    }

    /// Update output-path RTT estimate (RFC 6298 EWMA, separate from Peer).
    fn updateOutputRtt(self: *Gateway, rtt_ns: i64) void {
        self.output_latest_rtt_ns = rtt_ns;
        if (self.output_srtt_ns > 0) {
            const diff = if (self.output_srtt_ns > rtt_ns) self.output_srtt_ns - rtt_ns else rtt_ns - self.output_srtt_ns;
            self.output_rttvar_ns = @divFloor(3 * self.output_rttvar_ns, 4) + @divFloor(diff, 4);
            self.output_srtt_ns = @divFloor(7 * self.output_srtt_ns, 8) + @divFloor(rtt_ns, 8);
        } else {
            self.output_srtt_ns = rtt_ns;
            self.output_rttvar_ns = @divFloor(rtt_ns, 2);
        }
    }

    /// RFC 9002 §6.2.1 SetLossDetectionTimer.
    /// Dual-mode: if loss_time is set, use it. Otherwise compute PTO.
    fn setLossDetectionTimer(self: *Gateway, now: i64) void {
        _ = now;
        // If loss_time is set, that takes priority
        if (self.loss_time > 0) {
            self.pto_time = 0;
            return;
        }

        // If no unacked packets, disable timer
        if (self.send_buf.oldestUnackedSentTime() == null) {
            self.loss_time = 0;
            self.pto_time = 0;
            return;
        }

        // Compute PTO
        const srtt_ns: i64 = if (self.output_srtt_ns > 0) self.output_srtt_ns else 100 * std.time.ns_per_ms;
        const rttvar = if (self.output_rttvar_ns > 0) self.output_rttvar_ns else @divFloor(srtt_ns, 2);
        const pto_dur = loss.LossDetector.computePto(srtt_ns, rttvar, self.pto_count);

        // PTO fires relative to the most recent ack-eliciting send
        const last_sent = self.send_buf.oldestUnackedSentTime() orelse return;
        self.pto_time = last_sent + pto_dur;
    }

    /// RFC 9002 §6.2.2 OnLossDetectionTimeout (loss timer mode).
    /// Called when loss_time fires to run time-based loss detection.
    fn onLossDetectionTimeout(self: *Gateway, now: i64) void {
        const srtt_ns: i64 = if (self.output_srtt_ns > 0) self.output_srtt_ns else 100 * std.time.ns_per_ms;
        const latest = if (self.output_latest_rtt_ns > 0) self.output_latest_rtt_ns else srtt_ns;
        const prev_queue_len = self.retransmit_queue.items.len;
        self.loss_time = self.loss_detector.detectLosses(&self.send_buf, now, srtt_ns, latest, &self.retransmit_queue);

        for (self.retransmit_queue.items[prev_queue_len..]) |lost_offset| {
            if (self.send_buf.getForRetransmit(lost_offset)) |entry| {
                const rs_lost = self.bbr.total_lost -| entry.delivery_state.lost;
                self.bbr.onLoss(lost_offset, entry.size, rs_lost + entry.size, entry.delivery_state.tx_in_flight, entry.delivery_state.is_app_limited);
            }
        }

        self.setLossDetectionTimer(now);
    }

    /// RFC 9002 §6.2.4 OnLossDetectionTimeout (PTO mode).
    /// Retransmit the oldest unACKed packet as a probe to elicit ACKs.
    fn onPtoTimeout(self: *Gateway, now: i64) void {
        const probe_offset = self.send_buf.oldestUnackedOffset() orelse return;

        // Queue for retransmission if not already queued
        for (self.retransmit_queue.items) |s| {
            if (s == probe_offset) break; // already queued
        } else {
            self.retransmit_queue.appendBounded(probe_offset) catch {};
        }

        self.pto_count += 1;
        self.setLossDetectionTimer(now);
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

        switch (packet.channel) {
            .heartbeat => {
                if (packet.payload.len > 0) {
                    self.processOutputAcks(packet.payload, now);
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
            if (self.pending_output.items.len + payload.len > max_output_coalesce) {
                log.debug("output pending overflow buf={d} payload={d}; requesting snapshot", .{ self.pending_output.items.len, payload.len });
                self.pending_output.clearRetainingCapacity();
                try self.requestSnapshot(now);
                return;
            }
            try self.pending_output.appendSlice(self.alloc, payload);
            return;
        }

        try self.sendIpcReliable(tag, payload, now);
    }

    /// Test-only constructor: takes pre-created sockets, no daemon/SSH.
    pub fn initForTest(
        alloc: std.mem.Allocator,
        udp_sock: udp.UdpSocket,
        unix_fd: i32,
        key: crypto.Key,
    ) !Gateway {
        const unix_read_buf = try ipc.SocketBuffer.init(alloc);
        const unix_write_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);
        const pending_output = try std.ArrayList(u8).initCapacity(alloc, 4096);
        const reliable_send = try transport.ReliableSend.init(alloc);
        const send_buf = try loss.SendBuffer.init(alloc);
        const now: i64 = @intCast(std.time.nanoTimestamp());

        var gw = Gateway{
            .alloc = alloc,
            .udp_sock = udp_sock,
            .unix_fd = unix_fd,
            .peer = udp.Peer.init(key, .to_client),
            .unix_read_buf = unix_read_buf,
            .unix_write_buf = unix_write_buf,
            .pending_output = pending_output,
            .reliable_send = reliable_send,
            .reliable_recv = .{},
            .output_offset = 0,
            .bbr = .{},
            .pacer = .{},
            .send_buf = send_buf,
            .loss_detector = .{},
            .retransmit_buf = undefined,
            .retransmit_queue = undefined,
            .output_srtt_ns = 0,
            .output_rttvar_ns = 0,
            .output_latest_rtt_ns = 0,
            .last_ack_progress_ns = 0,
            .prev_largest_acked = 0,
            .has_prev_largest_acked = false,
            .loss_time = 0,
            .pto_time = 0,
            .pto_count = 0,
            .config = .{},
            .running = true,
            .last_ack_send_ns = now,
            .ack_dirty = false,
            .last_resync_request_ns = 0,
            .have_client_size = false,
            .last_resize = .{ .rows = 24, .cols = 80 },
        };
        gw.retransmit_queue = std.ArrayListUnmanaged(u32).initBuffer(&gw.retransmit_buf);
        return gw;
    }

    pub fn deinit(self: *Gateway) void {
        posix.close(self.unix_fd);
        self.udp_sock.close();
        self.unix_read_buf.deinit();
        self.unix_write_buf.deinit(self.alloc);
        self.pending_output.deinit(self.alloc);
        self.send_buf.deinit(self.alloc);
        self.reliable_send.deinit();
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

// ---------------------------------------------------------------------------
// Integration test: BBR pacing + selective retransmit over loopback UDP
// ---------------------------------------------------------------------------

/// Bind a non-blocking IPv4 UDP socket on loopback for testing.
fn testBindLoopback(port_start: u16, port_end: u16) !udp.UdpSocket {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);
    var port = port_start;
    while (port < port_end) : (port += 1) {
        const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
        posix.bind(fd, &addr.any, addr.getOsSockLen()) catch continue;
        return .{ .fd = fd, .bound_port = port };
    }
    posix.close(fd);
    return error.AddressInUse;
}

test "integration: BBR paced output delivery with simulated loss" {
    const alloc = std.testing.allocator;
    const key = crypto.generateKey();

    // Create a socketpair for the "daemon" side
    const pair = try posix.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0);
    const daemon_write_fd = pair[0]; // we write daemon output here
    const gateway_read_fd = pair[1]; // gateway reads from here
    defer posix.close(daemon_write_fd);

    // Create UDP sockets for server and client
    var server_udp = try testBindLoopback(61100, 61200);
    defer server_udp.close();
    var client_udp = try testBindLoopback(61200, 61300);
    defer client_udp.close();

    // Initialize gateway with test constructor
    var gw = try Gateway.initForTest(alloc, server_udp, gateway_read_fd, key);
    defer gw.deinit();

    // Set the gateway's peer address to the client
    gw.peer.addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, client_udp.bound_port);

    // Initialize client-side state
    var client_peer = udp.Peer.init(key, .to_server);
    client_peer.addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, server_udp.bound_port);
    var output_recv = transport.OutputRecvState{};
    var output_ack_tracker = loss.OutputAckTracker{};
    var received_data = try std.ArrayList(u8).initCapacity(alloc, 64 * 1024);
    defer received_data.deinit(alloc);

    // Generate test data: 32KB of recognizable pattern
    const test_data_len = 32 * 1024;
    var test_data: [test_data_len]u8 = undefined;
    for (&test_data, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    // Write test data as daemon Output IPC messages into the socketpair
    {
        var offset: usize = 0;
        while (offset < test_data_len) {
            const chunk_end = @min(offset + 512, test_data_len);
            const chunk = test_data[offset..chunk_end];
            var msg_buf: [1024]u8 = undefined;
            const msg = transport.buildIpcBytes(.Output, chunk, &msg_buf);
            _ = posix.write(daemon_write_fd, msg) catch break;
            offset = chunk_end;
        }
    }

    // Simple PRNG for simulating packet loss
    var drop_rng: u64 = 0xdeadbeef12345678;
    const drop_pct: u64 = 10; // 10% simulated loss

    // Run server/client exchange loop
    var iterations: u32 = 0;
    const max_iterations: u32 = 5000;

    while (iterations < max_iterations) : (iterations += 1) {
        const now: i64 = @intCast(std.time.nanoTimestamp());

        // --- SERVER SIDE ---

        // Read daemon data into gateway
        while (gw.unix_read_buf.read(gw.unix_fd) catch |err| blk: {
            if (err == error.WouldBlock) break :blk @as(usize, 0);
            break :blk @as(usize, 0);
        } > 0) {}
        while (gw.unix_read_buf.next()) |msg| {
            gw.forwardDaemonMessage(msg.header.tag, msg.payload, now) catch {};
        }

        // Loss/PTO timer
        if (gw.loss_time > 0 and now >= gw.loss_time) {
            gw.onLossDetectionTimeout(now);
        } else if (gw.pto_time > 0 and now >= gw.pto_time) {
            gw.onPtoTimeout(now);
        }

        // Send paced output
        gw.sendPacedOutput(now) catch {};

        // --- CLIENT SIDE ---

        // Receive UDP packets (with simulated loss)
        while (true) {
            var decrypt_buf: [9000]u8 = undefined;
            const recv_result = client_peer.recv(&client_udp, &decrypt_buf) catch break;
            const result = recv_result orelse break;

            // Simulate packet loss
            drop_rng ^= drop_rng << 13;
            drop_rng ^= drop_rng >> 7;
            drop_rng ^= drop_rng << 17;
            if (drop_rng % 100 < drop_pct) continue; // drop this packet

            const packet = transport.parsePacket(result.data) catch continue;

            if (packet.channel == .output) {
                switch (output_recv.onPacket(packet.seq, packet.payload)) {
                    .delivered => {
                        output_ack_tracker.onRecv(packet.seq);
                        const deliveries = output_recv.deliverSlice();
                        for (1..deliveries.len()) |di| {
                            output_ack_tracker.onRecv(output_recv.deliver_start +% @as(u32, @intCast(di)) *% transport.step);
                        }
                        for (0..deliveries.len()) |i| {
                            const p = deliveries.get(i);
                            if (p.len > 0) {
                                try received_data.appendSlice(alloc, p);
                            }
                        }
                    },
                    .buffered => {
                        output_ack_tracker.onRecv(packet.seq);
                    },
                    .gap_resync, .duplicate, .stale => {},
                }
            }
        }

        // Client sends ACK heartbeat back to server
        if (output_ack_tracker.has_received) {
            var gap_buf: [loss.AckRanges.max_gaps]loss.AckRanges.Gap = undefined;
            const ranges = output_ack_tracker.generateAckRanges(&gap_buf);
            var ack_payload_buf: [128]u8 = undefined;
            const ack_payload = ranges.encode(&ack_payload_buf) catch "";
            var pkt_buf: [1200]u8 = undefined;
            const pkt = transport.buildUnreliable(.heartbeat, 0, 0, 0, ack_payload, &pkt_buf) catch continue;
            client_peer.send(&client_udp, pkt) catch {};
        }

        // Server receives client heartbeats
        while (true) {
            var decrypt_buf: [9000]u8 = undefined;
            const recv_result = gw.peer.recv(&gw.udp_sock, &decrypt_buf) catch break;
            const result = recv_result orelse break;
            gw.handleTransportPacket(result.data, now) catch {};
        }

        // Check if all data delivered
        if (received_data.items.len >= test_data_len) break;

        // Check if server is done sending and no pending data
        if (gw.pending_output.items.len == 0 and
            gw.retransmit_queue.items.len == 0 and
            received_data.items.len >= test_data_len) break;
    }

    // Verify all data was received correctly
    try std.testing.expect(received_data.items.len >= test_data_len);
    try std.testing.expectEqualSlices(u8, &test_data, received_data.items[0..test_data_len]);

    // Verify BBR moved past startup
    try std.testing.expect(gw.bbr.pacing_rate > 0);
}
