# Multi-terminal multiplexing (design sketch)

Status: idea, not implemented.

## Motivation

A single zmosh session today carries one PTY. For a "native remote
terminal experience" beyond what `ssh + tmux` can offer, we'd want one
session to multiplex N independent terminals (think tmux panes/windows,
but the multiplexing lives in zmosh's encrypted UDP transport rather
than in a local tmux process).

What it buys over `ssh + tmux`:

- New terminals open instantly (no per-terminal SSH handshake).
- One credential exchange and one roaming event cover all terminals.
- Server-side persistence for every terminal in the session.
- Bulk output in one terminal doesn't block interactive work in another
  — provided we solve head-of-line blocking properly.

## The core problem: head-of-line blocking

zmosh's output channel is currently one reliable byte stream. If we
naively interleaved N terminals into that stream, a lost packet
belonging to terminal A would stall delivery of *every subsequent
byte*, including bytes destined for terminals B and C, until the
retransmit arrives. Exactly the problem HTTP/2 hit over TCP.

Example:

- Terminal A: `cat big_file` at 10 MB/s.
- Terminal B: editor, mostly idle.
- Terminal C: `tail -f` on a log.

Lose one packet on A's stream. Client holds everything after it in
the reorder buffer until the retransmit arrives ~1 RTT later. If any
of those held bytes are for B or C, the user sees a visible pause on
terminals that have nothing to do with the loss.

The fix is **per-stream reliability**: each terminal gets its own
reorder buffer, its own retransmit tracking, and its own flow-control
window. Loss on A stalls A only.

## Why not adopt QUIC-style frames

The natural question is "shouldn't we just use QUIC frames, which
solve this by design?". No — QUIC frames are over-engineered for
zmosh's use case. The only frame benefit we'd actually use is the
ability to put data from multiple streams into one packet, and that's
a marginal bandwidth optimization, not a correctness thing.

Specifically, zmosh does not need:

- Heterogeneous frame types (STREAM + ACK + MAX_DATA + PING) in one
  packet — our control channels are already separate packets.
- Frame-level retransmission with repackaging — our retransmit model
  is "resend the same bytes at the same offset."
- PMTU-driven frame splitting — we use a fixed MTU.
- Frame-level priorities — channel-level priority is enough.

Adopting frames would be ~1000+ lines of new infrastructure (parser,
scheduler, per-frame retry queues) to gain a tiny bandwidth win.

## Proposed design: `(stream_id, byte_offset)` keyed reliability

Extend the current byte-stream design with a stream dimension. Every
reliability primitive that today is keyed by `offset` becomes keyed by
`(stream_id, offset)`.

### Wire format changes (output channel only)

Today's output payload prefix:

    [8-byte u64 start_offset] [payload bytes]

Multi-terminal version:

    [2-byte stream_id] [8-byte u64 start_offset] [payload bytes]

10 bytes of prefix instead of 8 — ~1% overhead at MTU. 65 536 stream
IDs covers any realistic session.

`OutputAckPayload` gains a stream dimension: it carries a list of
per-stream SACKs, each `{stream_id, highest_contiguous_offset, gaps}`.
Variable-length but bounded by the number of streams with in-flight
gaps. Quiet streams don't take space.

### Server-side state (`serve.zig`)

- `Gateway.streams: HashMap(StreamId, StreamState)` where `StreamState`
  holds `next_output_offset`, per-stream retransmit ring, per-stream
  flow-control bookkeeping.
- `next_output_offset` is per-stream — each terminal has its own byte
  sequence.
- Retransmit ring: either one ring per stream, or a single combined
  ring with `stream_id` added to `RetransmitSlot`. Single combined
  ring is cheaper memory-wise (one big buffer instead of N small
  ones) and more efficient under uneven load.
- Daemon-side protocol: each stream corresponds to a separate PTY
  child with its own `ghostty-vt` state, spawned via an extended
  `Init` IPC message that carries a `stream_id`.

### Client-side state (`remote.zig`)

- `streams: HashMap(StreamId, StreamState)` where each holds its own
  `ReorderBuffer` and `next_deliver_offset`.
- UI layer presents the streams however the user configured — tabs,
  splits, an internal pane manager. Out of scope for the transport.
- Flow control: advertise a `max_byte_offset` per stream in the
  heartbeat. Total heartbeat size stays small if most streams are
  quiet.

### Congestion control stays shared

CC is a property of the network path, not the application. One link
between client and server means one BDP, one loss rate, one RTT, one
C4 instance. The cwnd budget is shared across all streams — which
means we need a scheduler that decides whose bytes go in the next
MTU-sized packet when multiple streams have data queued.

Scheduler options, simplest to most sophisticated:

1. Round-robin by stream_id.
2. Weighted round-robin with a per-stream priority (foreground terminal
   gets more).
3. Deficit round-robin (DRR) — actual bandwidth fairness.
4. Recent-activity bias — stream the user last typed into gets
   priority.

Start with (1) or (2); revisit if profiling shows it matters.

### Stream lifecycle

New wire messages on the control channel:

- `STREAM_OPEN(stream_id, rows, cols, command)` — client → server.
- `STREAM_CLOSE(stream_id)` — either direction.
- `STREAM_RESIZE(stream_id, rows, cols)` — client → server.

Stream IDs are allocated by the client, monotonic per session.
Server accepts any unused ID. Closed IDs are not reused until the
session ends (avoids in-flight-byte ambiguity during the drain
window).

### Per-stream resync

Today, resync is a single `requestSnapshot` → daemon serializes its
ghostty-vt state → bytes flow back as output. In the multi-terminal
future, resync becomes per-stream: one terminal can need a resync
while others keep streaming normally. The `resync_request` control
message grows a `stream_id` field.

## What changes, what doesn't

### Changes

- Transport wire format v3 for output/output_ack (add stream_id
  prefix and per-stream SACK list).
- `src/reorder_buffer.zig` — unchanged; instantiated once per stream.
- `src/cc.zig` — unchanged; still shared across streams.
- `src/pacer.zig` — unchanged; one pacer per session.
- `src/c4.zig` — unchanged; C4 sees the whole link.
- `src/serve.zig` — gains a stream table, stream scheduler, extended
  daemon IPC for multi-PTY.
- `src/remote.zig` — gains a stream table, per-stream reorder buffers,
  a per-stream flow-control advertiser, a UI layer (or hook for one).
- `main.zig` / daemon — Extended to spawn and track multiple child
  PTYs per session, each with its own ghostty-vt state.

### Doesn't change

- Encryption (XChaCha20-Poly1305, nonce scheme).
- Heartbeat / roaming / peer liveness.
- Reliable_ipc channel semantics.
- Resync fallback behavior (just gains a stream_id).
- C4 / pacer / CC ring sizing.

## Estimated scope

Probably 2000–3000 lines of diff. The heavy lifting is in serve.zig
(stream table, scheduler, multi-PTY IPC) and main.zig (daemon gains
multi-PTY support — each stream is effectively its own current-style
Daemon child). Reliability state is mostly "multiply what we have by
N using a hash map."

## When to actually build this

When there's a concrete user workflow that head-of-line blocking
hurts. "Run a `find` in one pane while editing in another, over a
500 ms RTT link, and the editor stays responsive" is the obvious
acceptance test.

## Non-goals

- Per-stream congestion control. One path, one C4.
- QUIC wire compatibility.
- Stream prioritization beyond a simple scheduler.
- Byte-level backpressure across streams — flow control is per-stream
  windows, not a single shared window.

## Forward compatibility

Nothing in the current codebase precludes this extension. The wire
format is versioned; the reorder buffer and retransmit ring are
clean types that can gain a stream_id field without rewriting their
internals. The single-stream design today is effectively
"multi-stream with N=1."
