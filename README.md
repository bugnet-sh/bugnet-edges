# bugnet-edges

The public Go binaries of the Bugnet sandbox router's data plane. They face the internet, hold no
provider keys and reach sandboxes only through the `bugnet-run` gate on port 29417. Each one calls
`router-api` over Connect with its own bearer token.

The binaries are `bugnet-edge` (also run as `bugnet-secrets`), `bugnet-ssh`, `bugnet-egress` and
`bugnet-certs`. They share the libraries under `internal`.

## Layout

| Path | What it holds |
| --- | --- |
| `internal/proxyproto` | Listeners that take only trusted sources opening with a PROXY v2 header |
| `internal/tlsconf` | One TLS config that picks the certificate and ALPN list by SNI |
| `internal/settings` | Strict TOML settings files, byte sizes and durations |
| `internal/routerclient` | Bearer-token HTTP clients for router-api's Connect services |
| `internal/metrics` | Counters and gauges in the Prometheus text format, with no client library |
| `internal/strangers` | Limits on clients without a valid token, per client address |
| `internal/pace` | Per-placement pace each way, under one total cap per process |
| `internal/usage` | Byte counts sent to the router, and the bytes left it answers |
| `internal/events` | The router's event stream, resumed from its cursor |
| `internal/lease` | One context per placement that ends at its deadline, end or spent budget |

## Listeners

HAProxy opens every connection to a backend with a PROXY v2 header. `internal/proxyproto` takes
the client's address from it.

- A connection from a source outside the trusted prefixes closes before `Accept` returns it.
- A trusted connection without a v2 header, or with a v1 header, closes at its first read or
  write. That holds for `io.Copy` too, so a raw TCP relay cannot use it.
- A trusted connection whose header does not arrive within 10 s closes the same way.
- Each listener sets `SO_REUSEPORT`, so a new version binds beside the old one during a deploy.

## TLS

`internal/tlsconf` picks a certificate and an ALPN list by SNI. An unknown SNI fails the handshake,
and so does a client below TLS 1.2.

- With ACME on, each exact name gets its own certificate from autocert by TLS-ALPN-01, kept in the
  state directory. The wildcard comes from the `fullchain.pem` and `key.pem` that `bugnet-certs`
  writes. The edge checks their modification times every minute and loads a new pair without a
  restart.
- With ACME off, one static pair serves every name, the wildcard too. Unit tests and the live
  stack's local mode use it with a self-signed certificate.
- An exact name or the wildcard suffix with an empty label, `*`, `:`, `/` or a space is refused at
  start. Write the suffix as `preview.bugnet.sh`, not `.preview.bugnet.sh` or `*.preview.bugnet.sh`.

## Calling the router

`internal/routerclient` gives two `*http.Client`s for the Connect clients from `bugnet-proto`. Both
send the caller's token only to the router URL and never follow a redirect.

| Client | Protocol | Used for |
| --- | --- | --- |
| `New` | h2c to an `http://` router, else h2 or HTTP/1.1 over TLS | Every call but transfers |
| `PerCall` | HTTP/1.1, one connection per call | Transfers, so one stalled stalls no other |

## Traffic

These libraries count, limit and cut each placement's traffic. The edge, the SSH gateway and the
egress proxy share them.

### Strangers

A `strangers.Guard` applies the token failure rule to one route.

- Each client address may send a set number of tokens a minute that fail to resolve, 20 in the
  edge's settings. The next one marks the address for 10 minutes, counted from the last failure
  past the limit.
- A marked address gets 429 for unknown tokens. At most one of its tokens a second goes to the
  router, so a valid token from behind a shared NAT still works.
- A token that failed is remembered by its SHA-256 for 10 seconds and never asked again in that
  time.
- An IPv4-mapped address counts as its IPv4 address.

A `strangers.PerIP` allows a number of requests a minute per address, for the secrets and hooks
routes. A limit of 0 turns it off.

Both forget an address once its count is back to full and its mark has run out. Each holds at most
200,000 addresses, and the guard at most 100,000 failed tokens. A full table sweeps at most once a
second. Between sweeps, one arbitrary entry gives way to each new one.

### Pace

A `pace.Pacer` gives each placement a lane with one limiter each way, burst 64 KiB.

- Reads and writes move in pieces of at most 64 KiB. Each piece waits on the lane, then on the
  process's total cap, so busy placements take turns.
- A new lane has no pace of its own until `SetRate`. A rate of 0 means the same. So the caller
  sets the starting pace from the resolve's `bytes_per_second` when it makes the lease, and each
  usage answer's pace after that.
- `pace.New(0)` has no total cap.
- `Drop` forgets a placement's lane and ends the reads and writes waiting on it.

### Usage

A `usage.Reporter` sends each placement's bytes to the router every interval (5 s), or at once
when one placement has built up the threshold (8 MiB).

- The router answers the bytes left and, for the edge and the SSH gateway, the pace. `OnAnswer`
  hands both on, less the bytes counted since the report went out.
- Between answers the reporter counts the bytes left down itself. When that reaches zero it calls
  `OnAnswer` with zero at once, even while the router is down.
- A failed report keeps its bytes for the next one. While the router is down, reports go once an
  interval, not at every threshold.
- `SetRemaining` sets the bytes left from a resolve, a lease check or an event. The lease table's
  `OnState` gives it each one.
- An answer to a report sent before the last `SetRemaining` keeps that newer figure.
- `Drop` forgets a placement's figure. Its unsent bytes still go out, and answers about it change
  nothing until the next `SetRemaining`.
- A threshold of 0 turns threshold reports off.
- When `Run` stops, it sends what is left once.

### Events

An `events.Watcher` keeps one `Watch*Events` stream open.

- It hands each event on in order and resumes from the last cursor after a break.
- A `Resync` event, or a reconnect that had no cursor to resume from, asks for a lease check.
- It reports the stream down at once, and back once the stream has stayed open a second or
  delivered a message.
- Reconnects back off from 250 ms to 10 s, a quarter either way, and start over once a stream
  was up.

### Leases

A `lease.Table` holds one lease per placement. A lease is a context with a timer at the paid
deadline. Requests, transfers, connections and tunnels run under its children.

| What happens | The lease |
| --- | --- |
| The deadline timer fires | Asks the router once (2 s), ends with `expired` unless it moved |
| A check leaves the placement out | Ends with `ended` |
| A check, a move or a put says 0 bytes left | Ends with `budget` |
| A check names a held preview as revoked | Ends only that preview's children, with `revoked` |
| A check answers another secrets version | Calls `OnVersion` once per change |

- Checks run every 60 s, and every 30 s while the event stream is down. `EdgeCheck` sends the
  held previews with `CheckEdgeLeases`. `EgressCheck` reads each secrets version from
  `CheckEgressLeases`.
- Each check gets 10 s, so a hung one never holds up the next.
- A late answer, to a check sent before the lease last changed, does not overwrite the newer state.
  So it never undoes an extension. Its ends and revocations still apply, since they only cut.
- `OnState` hands on every state a lease takes, from a put, a move or a check. The edge passes the
  bytes left to its usage reporter there.
- `Apply` acts on one event: `PlacementEnded`, `DeadlineMoved`, `PreviewRevoked`, the binary's
  own `BudgetSpent` kind and `Resync`.
- `lease.Reason(ctx)` gives the reason a lease or child context ended with.

## Settings

Each binary reads one TOML file through `internal/settings`. Loading fails, naming the line and
the key, when:

- a key names no setting, or differs from one only in case (`Drain` for `drain`);
- a key or table is set twice;
- a value has the wrong kind, or does not fit, such as `drain = 5` or `300` for an 8-bit number.

Errors never quote a value. A line that is not valid TOML is named by its line alone.

| Type | Written as | Range |
| --- | --- | --- |
| `settings.Bytes` | Bytes, `KiB`, `MiB` or `GiB`, such as `65536` or `"64KiB"` | 0 to 1 TiB |
| `settings.Duration` | Go's form, such as `"30s"`, `"5m"` or `"1h30m"` | 0 or more |

A size in plain bytes may be bare or quoted, so `65536` and `"65536"` are the same.

Secrets never go in these files. They come from the environment.

## Prerequisites

- Go 1.27
- `golangci-lint` 2
- `bugnet-proto` checked out next to this repository. `go.mod` points at it with a `replace` line
  until it is published.
- `go.work` at the workspace root lists this module. Outside that workspace, or before it lists
  this module, set `GOWORK=off` on every `go`, `make` and `golangci-lint` command.

The edges never reach Postgres or Valkey, so the tests need neither.

## Tests

```sh
make test
make lint
```
