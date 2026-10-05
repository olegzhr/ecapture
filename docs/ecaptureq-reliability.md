# eCaptureQ delivery and TLS endpoint binding

## Problem and behavior

The previous hub used an unbuffered broadcast channel and a nonblocking send.
Events were silently lost whenever the broadcaster was busy. This could remove
HTTP response chunks or connection metadata before they reached a collector.
Separate connect perf records could also arrive after TLS plaintext, allowing a
collector to associate a reused process FD with an earlier connection.

Broadcast admission now uses a bounded FIFO and copies caller-owned buffers.
An idle/busy hub can retain a short burst. On overload the newest message is
rejected with an error, rather than reporting a successful write. A subscriber
that exceeds its own queue budget is disconnected and its pending buffers are
discarded: continuing a partially lost HTTP stream would be misleading. Other
subscribers continue independently. Heartbeats use the sole socket writer and
cannot deadlock by enqueueing to that writer's own queue.

OpenSSL probes snapshot the current socket endpoints from the process FD table
at entry to SSL_read/SSL_write. The snapshot travels with that operation's
plaintext in a 48-byte extension to the existing perf event. The eCaptureQ
protobuf Event now preserves PID, UUID, direction and source/destination
addresses/ports alongside the existing text wrapper. Separate OpenSSL lifecycle
records are suppressed for this structured destination so delayed metadata
cannot overwrite the collector's newer FD binding. Plain text/file output
continues to use the original formatter.

If a TLS snapshot is unavailable, structured eCaptureQ delivery returns an
error and increments MissingEndpoints. It does not send an ambiguous TLS record
that a collector could bind to stale endpoints. This can happen for unsupported
FD/BIO types, failed kernel reads or descriptors outside the snapshot bound.
The decoder can read legacy perf events, but legacy assets have no endpoint
extension: rebuild the Go binary **and** its OpenSSL eBPF assets together.

## Limits and diagnostics

| Resource | Limit |
| --- | --- |
| Encoded broadcast message | 4 MiB |
| Broadcast queue | 1024 messages / 8 MiB |
| Per-subscriber queue | 1024 messages / 8 MiB |
| Subscribers | 64 |
| Startup log history | 128 messages / 1 MiB |
| Socket write deadline | 5 seconds per message |

History is synchronized with registration. New subscribers receive the bounded
history window once; live logs are broadcast immediately instead of being
withheld until the history fills. Messages target the subscribers present at
admission, preventing pending live logs from duplicating a joining client's
history. Close stops the listener and hub, disconnects subscribers and waits for
their handlers. Normal listener closure is successful, not a CLI startup error.
The server lives across probe reloads and closes when runProbe returns.

Server.Stats() reports Accepted, QueueFull, Oversized, NoSubscribers, SlowClients,
WriteErrors, ShutdownDropped, MissingEndpoints and SubscriberDropped, plus
current queued bytes and subscribers. Rejections/slow subscribers emit a
rate-limited warning; shutdown logs the complete local snapshot. Accepted means
local admission, **not remote acknowledgement**. These counters do not measure
eBPF/perf losses, collector-side losses, or TCP acknowledgement of application
records. Queues are volatile; shutdown may discard pending messages. There is
no persistent retry, reconnect replay, or exactly-once delivery guarantee.

## Reproduction

Build on Linux as described in AGENTS.md, with matching generated assets:

```sh
make all
go test -race -tags dynamic,ebpfassets ./...
```

An opt-in local live capture test is included in pkg/ecaptureq/tls_e2e_test.go.
It requires Linux root with eBPF/perf permission, curl linked to OpenSSL 3,
the library at /usr/lib/x86_64-linux-gnu/libssl.so.3, and a production binary.
UID 424242 is reserved for its disposable curl clients. The test uses only a
local HTTPS server, with separate header/body writes, and the direct eCaptureQ
WebSocket transport. It verifies complete requests/responses, exact endpoints,
keep-alive, three new connections reusing the same FD, and clean process exit.

```sh
sudo env ECAPTUREQ_E2E_BINARY="$PWD/bin/ecapture" \
  go test -race -count=1 -tags dynamic,ebpfassets \
  -run '^TestLocalTLSCapture$' -v ./pkg/ecaptureq
```

## Validation on 2026-10-05

Linux/amd64, WSL2 kernel 5.15.167.4, Ubuntu 22.04, Go 1.26.8, Clang 14,
OpenSSL 3.0.2 and curl 7.81:

- All CO-RE eBPF modules compiled and the production Go binary linked with assets.
- The complete Go test suite passed with race detection. Existing tests were
  made independent of installed mysqld, public GitHub availability and CRLF
  source checkouts; their production behavior was not relaxed.
- Queue, byte/count overflow, slow-subscriber isolation, missing snapshots,
  buffer ownership, structured adapter, IPv4/IPv6 perf decoding, FD reuse,
  legacy ABI reset, log history, reconnect and close races passed.
- Live direct TLS test: 3/3 complete transactions on one keep-alive connection;
  3/3 on new connections with FD 5 reused three times. Capture exited cleanly.
- The existing external ecapture_lab also passed direct eCaptureQ → production
  Altprobe: 3/3 OCSF records for keep-alive and 3/3 for separate connections,
  including complete JSON bodies, exact client/server IPs and ports and unique
  UIDs. No writer-relay workaround was used. Final separate-connection run
  reported zero local transport losses and zero missing endpoint snapshots.

Live validation covers OpenSSL 3 on Linux/amd64 with IPv4. IPv6 decoder coverage
is a unit test; ARM/Android, non-CO-RE live loading, other TLS libraries,
mid-connection HTTP/2 decoding and sustained overload throughput were not
established by this run.
