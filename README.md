# bugnet-edges

The public Go binaries of the Bugnet sandbox router's data plane. They face the internet, hold no
provider keys and reach sandboxes only through the `bugnet-run` gate on port 29417. Each one calls
`router-api` over Connect with its own bearer token.

The binaries are `bugnet-edge` (also run as `bugnet-secrets`), `bugnet-ssh`, `bugnet-egress` and
`bugnet-certs`. They share the libraries under `internal`.

## Layout

| Path | What it holds |
| --- | --- |
| `cmd/bugnet-edge` | The HTTP edge, and with `--role secrets` the secrets route |
| `cmd/bugnet-certs` | Renews the preview wildcards by DNS-01 and checks every served certificate |
| `internal/edge` | Both roles' settings, listeners, host routing, HSTS and drain |
| `internal/pages` | The edge's own HTML pages and the transfer route's JSON errors |
| `internal/certs` | `bugnet-certs`' settings, renewal, writing by rename and the expiry alert |
| `internal/certmetric` | `edge_cert_days_left` and `edge_cert_issued` for any TLS config |
| `example` | Each settings file at its defaults, with the production names |
| `internal/proxyproto` | Listeners that take only trusted sources opening with a PROXY v2 header |
| `internal/reuseport` | Plain listeners with `SO_REUSEPORT` |
| `internal/hostname` | The router's rule for a host name in the settings |
| `internal/tlsconf` | One TLS config that picks the certificate and ALPN list by SNI |
| `internal/settings` | Strict TOML settings files, byte sizes and durations |
| `internal/routerclient` | Bearer-token HTTP clients for router-api's Connect services |
| `internal/metrics` | Counters and gauges in the Prometheus text format, with no client library |
| `internal/strangers` | Limits on clients without a valid token, per client address |
| `internal/pace` | Per-placement pace each way, under one total cap per process |
| `internal/usage` | Byte counts sent to the router, and the bytes left it answers |
| `internal/events` | The router's event stream, resumed from its cursor |
| `internal/lease` | One context per placement that ends at its deadline, end or spent budget |
| `internal/x402` | `[x402]` settings, refusals, headers, paths, 402s, bodies, cache, caps, events |
| `internal/x402/x402test` | A test CA in the `mtls init --dev` layout and a fake Payments signer |
| `internal/fakeseller` | The fake x402 seller of XS 11.2 and an in-memory settler |

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

## bugnet-edge

`bugnet-edge -config FILE [--role edge|secrets]` reads its settings from FILE and its secrets
from the environment. On SIGTERM or SIGINT it drains and exits. A second signal kills it at once.

| Role | Settings | Secrets | Ports |
| --- | --- | --- | --- |
| `edge` | `example/edge.toml` | `BUGNET_EDGE_TOKEN`, `BUGNET_HOOK_PATH_SECRET` | 8443, 80, 9101 |
| `secrets` | `example/secrets-route.toml` | `BUGNET_SECRETS_TOKEN` | 8445, 9104 |

`edge` is the default role.

`.env.example` lists every secret with an empty value.

### Listeners

| Listener | Serves |
| --- | --- |
| `tls_listen_addr` | TLS for the role's names, behind HAProxy, PROXY v2 first |
| `redirect_listen_addr` | Edge only. `301` to the same URL on `https://`. Empty turns it off |
| `metrics_listen_addr` | `/healthz`, `/readyz` (503 while draining) and `/metrics` |

Every listener sets `SO_REUSEPORT`, so a new version binds beside the old one during a deploy.
The redirect answers only host names with a dot, never an IP address, and carries no HSTS, since
browsers ignore HSTS over plain HTTP.

### Hosts

The edge routes by the `Host` header. Anything else gets the 404 page.

| Host | Paths | Handler |
| --- | --- | --- |
| `<id>.<preview_domain>` | Everything | Previews. `<id>` is 16 characters of `a-z` and `2-7` |
| `<preview_domain>` | `/` only | The landing page with the abuse contact |
| `<transfer_host>` | `/<token>` and `/<token>/<name>` | Transfers |
| `<hooks_host>` | `POST /hooks/<provider>/<secret>` | Hooks. `<provider>` is 1 to 16 of `a-z0-9` |

- A route without a handler yet serves the 404 page. Later tasks plug in previews, transfers and
  hooks through `edge.Deps`.
- A request whose `Host` belongs to another route than its TLS name gets 421, so the browser
  opens its own connection. That keeps transfers on HTTP/1.1 and within their per-address
  connection limit. Previews may share a connection, since one wildcard covers them all.
- The secrets role serves only `host`.

### Responses

- Every TLS answer carries `Strict-Transport-Security: max-age=31536000`. Any other value a
  handler or an upstream sets is replaced.
- Server settings: `ReadHeaderTimeout` 10 s (the TLS handshake too), `IdleTimeout` 2 min, no read
  or write timeout, `MaxHeaderBytes` 64 KiB on the edge and `max_header_bytes` on the secrets
  route, HTTP/2 `max_concurrent_streams` (128). Extended CONNECT stays off, so WebSockets
  always arrive over HTTP/1.1.
- `internal/pages` writes DP 8.6's pages. They are small static HTML with `Cache-Control:
  no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` and a CSP of
  `default-src 'none'`. They never name a provider. Transfer errors are JSON,
  `{"error": "<code>", "message": "..."}`.
- net/http's own messages reach the log at warn level, and a handler's panic at error level. The
  noise any stranger can cause, such as a failed TLS handshake or a bad HTTP/2 preface or frame,
  logs at debug level.

### Drain

On a stop signal the process answers 503 on `/readyz`, stops accepting, and lets open requests
finish. Connections a handler hijacked, such as WebSockets, may stay open up to `drain` (5
minutes on the edge, 1 minute on the secrets route). Then everything left is closed. With
nothing open, the process exits at once.

### Certificates

At start the edge asks autocert once, in the background, for every exact name. That issues a
missing certificate and starts autocert's renewal timer. Two gauges on `/metrics` show the
state of each name:

| Metric | Value |
| --- | --- |
| `edge_cert_days_left{name}` | Whole days to expiry, for the wildcard and each issued name |
| `edge_cert_issued{name}` | 1 once the name has a certificate, 0 once its request at start failed |

## bugnet-certs

`bugnet-certs -config FILE` runs from a systemd timer twice a day and exits. Its settings are
`example/certs.toml`. Its environment holds only the DNS provider's variables.

Each run:

1. checks that every variable in `dns_env` is set, naming a missing one and never a value;
2. renews each certificate in `[[certificates]]` that is missing or due, by DNS-01 through the
   lego provider `dns_provider`. It judges `fullchain.pem` and `key.pem` together, so a pair whose
   `key.pem` is missing or is not the chain's key is renewed at once, with a warning naming the
   certificate. A certificate is due once the CA's ARI window starts, or at two thirds of its life
   when the CA gives no window. A failed window lookup logs a warning naming the certificate and
   falls back to two thirds. A renewal names the certificate it replaces
   (ARI). When the CA refuses the new order for that field, as malformed, unauthorized or in
   conflict, it orders once more without it. A failed validation is never retried in the same
   run, so one bad run spends one validation;
3. writes `fullchain.pem` and `key.pem` by rename, mode 0640, in the group of their directory.
   Give that directory the edge's group and the setgid bit, so the edge can read the files, as
   `install -d -o bugnet-certs -g bugnet-edge -m 2750 DIR` does. Without the bit, a user outside
   that group cannot hand the files to it, and the run fails with an error naming the bit. A
   chain and key that do not match are never written;
4. reads `edge_cert_days_left` and `edge_cert_issued` from each address in `cert_metrics`.

It exits 1, with an error log naming the certificate, when a renewal fails, a pair still lacks
its key, a certificate has fewer than `alert_days` (14) days left, a name was never issued, or a
metrics address does not answer after 3 tries. So `systemctl --failed` shows it. Otherwise it
exits 0.

The ACME account key and registration live under `state_dir`, one directory per ACME directory
URL, so runs never register a new account and staging never mixes with production. Switching
`dns_provider` to any lego provider, with its variables in `dns_env`, changes no code.

### The dev wildcard on the Mac

Before the production deploy, the edges run on the Mac behind the VPS (DP 15.6). The dev
wildcard `*.preview.dev.<domain>` comes from `bugnet-certs` on the VPS, into
`/var/lib/bugnet-certs/preview-dev/` (bugnet-router's `deploy/vps/front.sh` sets it up). Copy the
pair to the Mac with:

```sh
make dev-certs VPS=<user>@<host> [VPS_SSH_PORT=<port>]
```

- It copies `fullchain.pem` and `key.pem` with one `scp` over the admin SSH, into
  `~/.local/state/bugnet-dev/preview-dev/`, which is outside every repository. The directory is
  0700 and both files 0600. `DEV_CERTS_DIR=<dir>` copies elsewhere.
- `VPS_SSH_PORT` is 2222 by default, admin SSH's port under DP question 1 (a). Under (b) it is 22.
- `<user>` must be the admin user `front.sh` ran as with sudo, since the directory belongs to
  that user's group. Anyone else cannot read `key.pem`.
- The DNS token never leaves the VPS. Run it again after each renewal. The dev edge's
  `[acme] wildcard_dir` points at the directory and picks the new pair up within a minute.

## Calling the router

`internal/routerclient` gives two `*http.Client`s for the Connect clients from `bugnet-proto`. Both
send the caller's token only to the router URL and never follow a redirect.

| Client | Protocol | Used for |
| --- | --- | --- |
| `New` | h2c to an `http://` router, else h2 or HTTP/1.1 over TLS | Every call but transfers |
| `PerCall` | HTTP/1.1, one connection per call | Transfers, so one stalled stalls no other |

## Calling Payments

`x402.Signer` calls Payments' `X402SignerService` (XS 6.10) for egress, over mutual TLS.

| Part | Rule |
| --- | --- |
| Connection | TLS 1.3 only, HTTP/2, no environment proxy, no redirect and no trace header |
| Payments' certificate | Checked against `payments_ca_file` with the name `payments_server_name` |
| Egress's certificate | `payments_client_cert_file`, sent through `GetClientCertificate` |
| Egress's key | Read once at start from `$CREDENTIALS_DIRECTORY/<payments_client_key_credential>` |
| `Reserve` | One `ReserveAndSign` under `payments_timeout`, never retried |
| `Report` | Queued, then sent by `Run` with up to 3 retries after 0.5, 1 and 2 s |
| `ReportClean` | Sent at once, ahead of the queue, waiting at most `clean_report_wait` |
| `Reload` | Reads both files again, keeps the key, and keeps the old files' copy on any error |
| `Run` | Drains the queue and logs the expiry line |

- `Reserve` fails closed. An answer that is neither a `Refused` nor a `Signed` with a payment id,
  a payload, a `payment_ref` and an amount is an error, so egress pays nothing with it.
- The queue holds `report_queue` reports, waiting or in flight. A full queue drops the new report
  with one log line. A report that fails 4 times is dropped with one log line.
- Payments' `FailedPrecondition` (`REF_CONFLICT`) and `InvalidArgument` are final. Each is logged
  once and never retried, so Payments' `x402_ref_conflict` alarm fires once for one fault.
- A missing or unreadable file, a file with no PEM certificate or key, or a certificate for
  another key fails `NewSigner`. The error names the setting, never the path or the key.
- No log line holds a payload, a `ref`, a `payTo`, a target or an error message Payments sent.
  A line names an `ErrorInfo` reason only when it is upper case, digits and `_`, up to 64.
- `Reserve` logs no line when its caller gave up first. A `payments_timeout` deadline is logged.
- After `Reload`, each new call goes through a new transport, so it makes a handshake with the
  new files, even while other calls keep a connection busy. Calls in flight end on the old
  connections, which close after 90 s with no call.
- From 30 days before egress's certificate expires, `Run` logs one error line a day. It names the
  file and the days left.

## Unpaid use and the host rate

`x402.Counters` keep each placement's unpaid use per x402 host (XS 6.8). `x402.HostRate` holds
the unpaid requests a minute per host across placements, the founder's pick (b) of 2026-11-07.

| Part | Rule |
| --- | --- |
| `Over` | True once a host's unpaid requests or bytes reach the placement's cap |
| `AddBytes` | Counts bytes as they flow and says when the byte cap is reached |
| `CountsRequest` | Reached the seller and ended unpaid, and no limit of Bugnet's own refused it |
| `Merge` | On each resolve, the larger of the own count and `unpaid_used` plus unsent deltas |
| `RunReports` | Sends deltas through `ReportEgressUsage` every interval, with `usage` empty |
| `Admit` | Passes the floor's requests, then others only while the host's bucket holds a token |
| `Ended` | Spends one token when the answer started and the end is not `paid` or `uncertain` |

- A report that fails or gets no answer within one interval goes out again with the next one.
  When the context ends, `RunReports` sends what is left once.
- A report still waiting for the router's answer counts as unsent in `Merge`, since
  `unpaid_used` may not hold it yet. When it does, the count is high by that one report.
- `Drop` forgets a placement once its last deltas reached the router.
- The bucket holds `custom_host_requests_per_minute` and refills over a minute. Paid and
  uncertain ends never spend from it. A cached resend spends one at `Admit` and none at its end.
- An empty bucket goes into debt, at most one minute's refill. So once an attacker stops,
  requests past the floor pass again within about a minute.
- The floor is `host_rate_floor_per_placement` requests a minute per placement and host, counted
  from the placement's first request to the host.
- Past windows and full buckets are forgotten once a minute.

## x402 events

`x402.Events` queues one row per x402 request for each placement and sends them through the
router's `AppendX402Events` (XS 6.14). The interval is `event_flush_interval`.

| Part | Rule |
| --- | --- |
| `Shape` | Puts a row in XS 8.1's shape, as the table below says |
| `Add` | Queues a copy with `count` 1, a `ref` when it has none, and `at` now when it has none |
| `RefusedHost` | Queues a `refused_host` row for a failed handshake on a placement with services |
| `SetServices` | Gives `RefusedHost` its check that a placement has x402 services |
| `Run` | Sends each interval, at 50 unsent rows, at each minute's close and once at the end |
| `EventsSend` | Builds the sender from the router's `EgressService` client |

`Shape` keeps these fields:

| Field | Kept when |
| --- | --- |
| `method` | It is 1 to 10 capital letters, else `OTHER`. Empty on `refused_host` |
| `path` | The target passed XS 6.7, never on `path_refused` or `upgrade_refused`. Cut to 80 |
| `host` | It is visible ASCII. Cut to 253 |
| `asked_micros`, `asset`, `network`, `scheme`, `x402_version` | The offer is exact USDC on Solana |
| `pay_to` | The offer is exact USDC on Solana and it decodes to 32 bytes |

Folding:

- A row can involve money when its status is `paid`, `uncertain` or `payment_failed`, or its
  amount is above 0. Such a row is never folded.
- Every other row folds per placement by host, `service_id`, status and reason, within the UTC
  minute of its `at`. The first call of a minute is queued at once with `count` 1. The later
  calls become one row with their `count`, summed bytes, the newest `at` and the second call's
  other fields, queued when the minute closes.
- A call whose minute already closed is queued at once, and its later calls at the next flush.
- `RefusedHost` lower-cases the name and keeps it when it is only `a-z`, `0-9`, `.` and `-`, cut
  to 63. Each placement keeps 10 names a minute. Other names, and names past 10, fold into one
  row a minute with an empty host, queued when the minute closes.
- When `Run` ends it queues every open window and sends each queue once, within one interval.

Sending:

- A batch holds at most 50 rows of one placement, money rows first.
- A send gets one interval. A failed send keeps every `ref`, so the router stores a row once.
- A row that cannot involve money is sent again 3 times, then dropped. A money row is sent
  again for 5 minutes from its first failure, then dropped.
- `InvalidArgument` drops the whole batch at once. Rows the router names in `rejected` are
  dropped and never sent again.
- A send cut by the end of `Run` counts no try. Its rows go out with the last flush.
- Each row gets one log line when the router takes it, rejects it, or it is dropped. The line
  holds a hash of the placement id (`PlacementHash`), the host, method, status, reason, amount,
  bytes and count. A drop adds why, and the error code when a send failed. Never the path,
  `ref`, `payment_ref`, `pay_to`, `service_id` or a payment value.

## The fake x402 seller

`fakeseller.New` serves the fake seller of XS 11.2 as an `http.Handler`. Egress tests run it in
process. The path prefix picks the mode. A `Settler` completes each payment: `fakeseller.InMemory`
takes the fixed test format of the fake Payments in `x402test` and needs no chain.

| Prefix | First send | Paid retry |
| --- | --- | --- |
| `/ok/`, `/cents/`, `/cent/` | 402 at $0.001, $0.02 or $0.01 | Settles, 200 with `success: true` |
| `/bait/` | 402 at $10 | As `/ok/` |
| `/switch/` | 402 with a new made-up `payTo` each time | As `/ok/` |
| `/splits/` | 402 with `extra.splits` | As `/ok/` |
| `/upfront/` | 402 with `extra.paymentFlow` `upfront` | As `/ok/` |
| `/ata/` | 402 with `extra.ataCreationRequired` | As `/ok/` |
| `/upto/`, `/escrow/` | 402 in that scheme | As `/ok/` |
| `/feepayer-bugnet/` | 402 naming `BugnetFeePayer` as fee payer | As `/ok/` |
| `/memo/`, `/memo-long/<n>/` | 402 with a memo of 32 bytes, or of `n` from 33 to 256 | As `/ok/` |
| `/hints/` | 402 with a blockhash hint and `lastValidBlockHeight` 1 | As `/ok/` |
| `/late/` | 402 | 200 with `success: false`, settles `Late` later |
| `/lie/` | 402 | 200 with `success: true` and a made-up transaction, never settles |
| `/silent/` | 402 | Settles, 200 with no `PAYMENT-RESPONSE` |
| `/settle500/`, `/settle429/` | 402 | Settles, then 500 or 429 |
| `/settle500-wait/`, `/settle429-wait/` | 402 | As their bases, with `Retry-After: 15` |
| `/reject/` | 402 | A new 402 |
| `/slow/` | 402 | Waits `Slow`, settles, then 200, settling even when the caller left |
| `/stall/` | 402 after `Stall` | As `/ok/` |
| `/pid/` | 402 offering `payment-identifier` | As `/ok/`, a repeat answered from its cache |
| `/echo/` | 402 | As `/ok/`, request headers echoed as `Echo-<name>` and in the body |
| `/redirect/` | 402 | Settles, then a 302 to `RedirectTo` |
| `/post400/` | 400 to a POST with an empty body, else 402 | As `/ok/` |
| `/v1only/` | 402 with only an x402 v1 body | The same 402 |
| `/base/` | 402 offering only `eip155:8453` | As `/ok/` |
| `/free/` | 200 | None |
| `/hold/<seconds>/` | 200 after `seconds` times `Second`, 1 to 300, no byte before | None |
| `/sse/` | One event every `SSEEvery` for `SSEFor`, each flushed at once | None |

- Prices the XS 11.2 table does not name are $0.01. Every 402 is x402 v2 with one `accepts`
  entry, exact USDC on Solana with `extra.feePayer`, unless the mode says otherwise.
- The 402 comes before the seller reads the body, as x402 middleware does. Only `/post400/`
  reads it first. A paid answer reads it and gives its length and SHA-256.
- A payment passes when its `accepted` equals an entry the seller offered on that prefix. A
  payload seen before gets a new 402, except on `/pid/`. So does a failed settle, except on
  `/slow/`, which answers 200 with `success: false`. A `Settler` names that `errorReason` with
  `SettleError`, else it is `unexpected_settle_error`.
- `/echo/`'s body gives `PAYMENT-SIGNATURE` only as its SHA-256, so no payload reaches a body.
- With `TestToken` set, `GET /__test/payloads` and `GET /__test/settled` list the payloads
  received and the signatures settled, for that bearer token only. Without it they are 404.
  A payload is listed only when it decodes as x402 v2. Each value of a header is listed apart.
- The seller keeps at most 1,024 payloads seen, `/pid/` answers and entries in each list,
  forgetting the oldest. It takes no `PAYMENT-SIGNATURE` value over 16 KiB as a payment.

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
- A limit of 0 marks no address. Failed tokens are still remembered.

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
- `down` runs outside the watcher's lock, so it may call `Cursor`. It can run alongside `on`,
  from the timer that marks a silent stream back.
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

Each binary reads one TOML file through `internal/settings`. `example/` holds each file at its
defaults. Host names have no default, so each deployment sets them. Loading fails, naming the
line and the key, when:

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
- `bugnet-certs` links every lego DNS provider, so its first build takes a few minutes.

The edges never reach Postgres or Valkey, so the tests need neither.

## Tests

```sh
make test
make lint
```
