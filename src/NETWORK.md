# zmosh Network Layer Architecture

The network layer enables remote terminal sessions over encrypted UDP with auto-reconnect. It sits between the client terminal and the daemon's unix socket, bridging them via a gateway process.

```
Client (macOS/Linux)          Server (Linux)
┌──────────────┐              ┌──────────────┐         ┌────────┐
│  remote.zig  │◄─encrypted──►│  serve.zig   │◄─unix──►│ daemon │
│  (or lib.zig)│   UDP/1200   │  (gateway)   │  socket  │ (pty)  │
└──────────────┘              └──────────────┘         └────────┘
```

## Files

| File | Role |
|------|------|
| `transport.zig` | Packet format, header encode/decode, output reorder buffer, reliable send |
| `congestion.zig` | BBR v3 congestion control, delivery rate estimation, pacer |
| `loss.zig` | Send buffer, QUIC-style loss detection (RFC 9002), ACK range codec, output ACK tracker |
| `serve.zig` | Server-side gateway: bridges UDP ↔ daemon unix socket |
| `remote.zig` | Client-side remote attach: terminal ↔ UDP |
| `lib.zig` | C API client (same protocol as remote.zig, callback-driven) |
| `udp.zig` | UDP socket management, peer state, encryption (XChaCha20-Poly1305) |
| `crypto.zig` | Key generation, encrypt/decrypt wrappers |

## Wire Format

Every UDP datagram is encrypted with XChaCha20-Poly1305. The plaintext is a 20-byte header followed by optional payload:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   version=2   |   channel     |         reserved              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         seq / offset                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           ack                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         ack_bits                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        payload_len            |          reserved             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Channels

| Channel | Direction | Delivery | Description |
|---------|-----------|----------|-------------|
| `heartbeat` (0) | Bidirectional | Unreliable | Keepalive + output ACK ranges + flow control window |
| `reliable_ipc` (1) | Bidirectional | Reliable (seq/ack) | IPC messages: Init, Input, Resize, Detach, SessionEnd |
| `output` (2) | Server → Client | Unreliable + reorder buffer | Terminal output (PTY data) |
| `control` (3) | Client → Server | Reliable | Resync requests |

### Byte-Offset Addressing

The output channel uses byte offsets instead of sequence numbers. The `seq` header field carries the byte offset into the output stream. Each packet advances by `max_payload_len` (1100 bytes) regardless of actual payload size, enabling O(1) slot arithmetic:

```
slot_index = (offset / 1100) % window_size
```

This aligns with QUIC stream semantics (RFC 9000 §2.2) — since zmosh has a single unidirectional output stream, the byte offset serves as both packet identity and stream position.

## Congestion Control: BBR v3

Implementation follows [draft-ietf-ccwg-bbr-05](https://datatracker.ietf.org/doc/html/draft-ietf-ccwg-bbr-05) with adaptations for bursty terminal traffic.

### State Machine

```
Startup → Drain → ProbeBW (cycles: DOWN/CRUISE/REFILL/UP) → ProbeRTT → ProbeBW
```

### Key Parameters

| Parameter | Spec Value | zmosh Value | Rationale |
|-----------|-----------|-------------|-----------|
| `min_cwnd` | 4 × SMSS (4800 B) | Same | Spec value; flow control + backpressure handle bursts |
| `send_quantum` | `pacing_rate × 1ms` | N/A | Replaced by credit-based pacer (see below) |
| `packet_threshold` | 3 | 3 | Per RFC 9002 §6.1.1 |
| `time_threshold` | 9/8 | 9/8 | Per RFC 9002 §6.1.2 |
| `startup_pacing_gain` | 2.77 (4·ln2) | 2.77 | Per spec §2.4 |
| `startup_cwnd_gain` | 2.0 | 2.0 | Per spec §2.5 |
| `drain_pacing_gain` | 1/cwnd_gain = 0.5 | 0.5 | Per spec §2.4 |

### Delivery Rate Estimation

Per spec §4.1.1.2.4:

```
delivery_rate = data_acked / max(ack_elapsed, send_elapsed)
```

This is equivalent to `min(send_rate, ack_rate)` since both share `data_acked` as the numerator. The `max(elapsed)` approach naturally handles bursty terminal traffic — `ack_elapsed` (spanning the RTT) dominates during bursts, giving a bandwidth estimate that reflects actual link capacity rather than application burstiness.

A 1ms floor prevents degenerate rate estimates before the first RTT sample.

### Terminal-Specific Adaptations

1. **No ProbeRTT during Startup** — BBR would enter ProbeRTT 5 seconds after connection start, before bandwidth estimation stabilizes. Terminal sessions often have idle periods during startup (waiting for shell prompt) that look like ProbeRTT triggers.

2. **ProbeRTT suppression during bursts** — ProbeRTT crushes cwnd to min_cwnd (4800 bytes), which at typical RTTs causes ~500ms stalls when output is pending. The gateway sets `suppress_probe_rtt` when `pending_output > cwnd`, deferring ProbeRTT until the burst drains.

3. **Flow-control pauses mark app-limited** — When the flow control window blocks sending, BBR must know the pause is receiver-imposed, not a bandwidth limit. Without this, BBR collapses its bandwidth estimate during pauses.

4. **Idle-to-burst bandwidth probe** — BBR's ProbeBW waits 2-3 seconds between bandwidth probes. When terminal traffic transitions from idle to a large burst (e.g., image preview), the gateway triggers an early REFILL→UP probe cycle so BBR discovers the link's capacity within 1-2 RTTs instead of waiting seconds.

5. **Startup inflight cap** — Before the client's first flow control window arrives, inflight is capped to `initial_cwnd` (12 KB). Without this, Startup's 2.77× pacing gain blasts hundreds of KB before the client can advertise its capacity.

## Pacer

Credit-based leaky bucket, inspired by [picoquic's pacing.c](https://github.com/private-octopus/picoquic/blob/master/picoquic/pacing.c).

### Why not burst-based pacing?

The BBR spec (§5.6.3) uses `send_quantum` — a burst budget granted per timer tick. The application sends the entire quantum back-to-back, then sleeps. This works for TCP where the kernel paces individual segments at hardware-level granularity. For user-space UDP, the entire burst hits router queues simultaneously, causing packet loss on real network paths. We measured loss correlating with burst size: zero loss below ~8 packets per burst, 5%+ above ~10 packets.

### Credit-based approach

Instead of granting a burst and sending all packets at once, the pacer maintains a nanosecond credit bucket:

- **Refill**: credits accumulate based on elapsed wall-clock time
- **Cost**: each packet costs `packet_size × 1e9 / pacing_rate` nanoseconds
- **Gate**: `canSend()` checks credit ≥ cost before *every* `sendto()` call
- **Deduct**: `onSend()` subtracts the packet's cost after sending

This gates individual packets, not bursts. If the send loop is fast (~10μs per iteration), packets are naturally spaced at `packet_time` intervals — e.g., ~73μs apart at 15 MB/s. No sub-millisecond timer precision required; the wall clock refills credit between iterations.

### Bucket capacity

`bucket_max = packet_time × 10` (10 packets). This controls the maximum burst after idle — enough for the initial bandwidth probe without overwhelming router queues. After idle, the bucket fills to max. The first 10 packets send immediately; subsequent packets are paced.

### Interaction with BBR

BBR and the pacer are orthogonal but cooperative:
- **BBR** decides the pacing rate (`bw × gain`) and the congestion window (cwnd)
- **The pacer** enforces the pacing rate by gating individual packet sends
- **The send loop** checks both: `bbr.canSend()` (inflight < cwnd) AND `pacer.canSend()` (credit available)
- BBR updates `pacing_rate` on each ACK; the pacer reads it on each `onSend()`

### Special states

- **Idle restart**: fill bucket to max (10 packets of immediate burst)
- **Loss**: drain bucket to zero (stop bursting during recovery)
- **Poll timeout**: `(packet_time - bucket) / 1e6` ms until next send

## Loss Detection (RFC 9002)

### Packet Threshold (§6.1.1)

A packet is declared lost if 3 or more later packets have been acknowledged:

```
(largest_acked - offset) / step >= 3
```

Guard: only packets genuinely behind `largest_acked` are candidates (wrapping-safe comparison prevents false positives from packets ahead of the ACK frontier).

### Time Threshold (§6.1.2)

```
loss_delay = max(9/8 × max(srtt, latest_rtt), 1ms)
```

### PTO (§6.2)

PTO probes bypass cwnd — they must be sent regardless of congestion state to elicit ACKs and prevent deadlocks.

The PTO timer is armed after sending new data into an idle path (all prior packets acked). Without this, packets would never trigger PTO if the ACK is lost.

### Inflight Tracking

Retransmits do **not** increment inflight. `onLoss` already decremented inflight for the lost packet. Re-incrementing on retransmit causes drift: if `markAcked` returns null (original already acked), `onAckPacket` never decrements, and inflight grows unboundedly until it exceeds cwnd permanently.

## Flow Control

The client advertises `max_offset` (u32, big-endian) appended to each heartbeat payload. The server stops sending new data when `output_offset` reaches `client_max_offset`.

```
recv_window = min(max_stdout_buf - stdout_buf.len, reorder_window_bytes)
max_offset  = next_offset + recv_window
```

This provides end-to-end backpressure adapted to the terminal's actual rendering speed. When Ghostty is busy rendering a large Kitty image, `stdout_buf` fills, `recv_window` shrinks, `max_offset` stops advancing, and the server pauses automatically.

### Heartbeat Payload Format

```
[AckRanges (7 + 4*num_gaps bytes)][max_offset: u32 BE][cumulative_ack: u32 BE]
```

The `cumulative_ack` field (client's `next_offset`) tells the server that everything below this offset has been delivered. This is analogous to TCP's cumulative ACK. It prevents deadlocks when heavy loss creates more gaps than the 16-gap ACK range encoding can represent — without it, old acked packets fall outside the ACK window and the server retransmits them forever while the flow control window is closed.

## Output Reorder Buffer

256-slot circular buffer indexed by `(offset / step) % 256`. Handles:

- **In-order**: deliver immediately + any consecutive buffered packets
- **Out-of-order**: buffer in slot, deliver when gap is filled
- **Duplicate**: within window → ignore; beyond window → stale
- **Stale**: old retransmit far behind `next_offset` → silently drop
- **Gap resync**: packet 256+ slots ahead → clear buffer, request terminal snapshot

The stale detection uses wrapping-aware comparison to distinguish old retransmits (behind `next_offset`) from genuine gaps (ahead). Without this, old retransmits would trigger false gap resyncs, destroying terminal state.

## UDP Socket Buffers

Both sides request 2 MB socket buffers (`SO_RCVBUF`/`SO_SNDBUF`). The kernel may clamp to `rmem_max`/`wmem_max`. This is defense-in-depth — the flow control window is the primary mechanism preventing receiver overflow.

## Client ACK Policy

QUIC-style (RFC 9000 §13.2):
- ACK every 4 output packets (packet threshold)
- ACK within 1ms if threshold not reached (delay timeout)
- ACK immediately on out-of-order reception (fast loss detection)

The client's `ack_delay` (1ms) can be shorter than the server's `max_ack_delay` (5ms) in the PTO calculation. The server's value is a worst-case assumption; the client sending faster is always safe.

## ACK Range Encoding

QUIC-style ACK ranges encoded in heartbeat payloads:

```
largest_acked: u32 (4 bytes)
first_range:   u16 (2 bytes) — consecutive slots before largest
num_gaps:      u8  (1 byte)
gaps:          [num_gaps × {gap: u16, range: u16}]
```

Gap and range values are in **slots** (1 slot = 1100 bytes of offset space). The client tracks received offsets in a 512-bit bitmap and generates ACK ranges from it.

## References

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) — QUIC Transport Protocol
- [RFC 9002](https://datatracker.ietf.org/doc/rfc9002/) — QUIC Loss Detection and Congestion Control
- [draft-ietf-ccwg-bbr-05](https://datatracker.ietf.org/doc/html/draft-ietf-ccwg-bbr-05) — BBR v3
- [draft-cheng-iccrg-delivery-rate-estimation-02](https://datatracker.ietf.org/doc/html/draft-cheng-iccrg-delivery-rate-estimation-02) — Delivery Rate Estimation
