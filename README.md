# bugnet-edges

The public Go binaries of the Bugnet sandbox router's data plane. They face the internet, hold no
provider keys and reach sandboxes only through the `bugnet-run` gate on port 29417. Each one calls
`router-api` over Connect with its own bearer token.

The binaries are `bugnet-edge` (also run as `bugnet-secrets` and `bugnet-sessions`), `bugnet-ssh`,
`bugnet-egress` and `bugnet-certs`. They share the libraries under `internal`. `x402-fake-seller` is
a test seller for local and mainnet test runs, never deployed with them.

## Layout

| Path | What it holds |
| --- | --- |
| `cmd/bugnet-edge` | The HTTP edge, and with `--role secrets` or `--role sessions` that route |
| `cmd/bugnet-certs` | Renews the preview wildcards by DNS-01 and checks every served certificate |
| `cmd/x402-fake-seller` | The fake x402 seller over TLS, settling to a chain or a facilitator |
| `internal/edge` | Every role's settings, listeners, host routing, HSTS and drain |
| `internal/sessionsroute` | The session page, its record and delete calls, and its live view |
| `internal/edge/transfer` | The transfer route, uploads and downloads relayed through the router |
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
| `internal/traffic` | One process's leases, events, usage and pace, wired together |
| `internal/x402` | `[x402]` settings, refusals, headers, paths, 402s, bodies, cache, caps, events |
| `internal/x402/x402test` | A test CA in the `mtls init --dev` layout and a fake Payments signer |
| `internal/fakeseller` | The fake x402 seller of XS 11.2 and its settlers |

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

`bugnet-edge -config FILE [--role edge|secrets|sessions]` reads its settings from FILE and its
secrets from the environment. On SIGTERM or SIGINT it drains and exits. A second signal kills it at
once.

| Role | Settings | Secrets | Ports |
| --- | --- | --- | --- |
| `edge` | `example/edge.toml` | `BUGNET_EDGE_TOKEN`, `BUGNET_HOOK_PATH_SECRET` | 8443, 80, 9101 |
| `secrets` | `example/secrets-route.toml` | `BUGNET_SECRETS_TOKEN` | 8445, 9104 |
| `sessions` | `example/sessions.toml` | `BUGNET_SESSIONS_TOKEN` | 8448, 9105 |

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

- A route without a handler yet serves the 404 page. Transfers are served. Later tasks plug in
  previews and hooks through `edge.Deps`.
- A request whose `Host` belongs to another route than its TLS name gets 421, so the browser
  opens its own connection. That keeps transfers on HTTP/1.1 and within their per-address
  connection limit. Previews may share a connection, since one wildcard covers them all.
- The secrets and sessions roles each serve only their `host`.

### Responses

- Every TLS answer carries `Strict-Transport-Security: max-age=31536000`. Any other value a
  handler or an upstream sets is replaced.
- Server settings: `ReadHeaderTimeout` 10 s (the TLS handshake too), `IdleTimeout` 2 min, no read or
  write timeout, `MaxHeaderBytes` 64 KiB on the edge, `max_header_bytes` on the secrets route and
  twice `max_header_bytes` on the sessions route (which answers past it itself), HTTP/2
  `max_concurrent_streams` (128). Extended CONNECT stays off, so WebSockets always arrive over
  HTTP/1.1.
- `internal/pages` writes DP 8.6's pages. They are small static HTML with `Cache-Control:
  no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` and a CSP of
  `default-src 'none'`. They never name a provider. Transfer errors are JSON,
  `{"error": "<code>", "message": "..."}`.
- net/http's own messages reach the log at warn level, and a handler's panic at error level. The
  noise any stranger can cause, such as a failed TLS handshake or a bad HTTP/2 preface or frame,
  logs at debug level.

### Transfers

`internal/edge/transfer` serves `https://<transfer_host>/<token>` (DP 8.3). A `/<name>` after the
token is ignored. `PUT` uploads, `GET` downloads and `HEAD` describes a download without claiming
it. Errors are JSON, `{"error": "<code>", "message": "..."}`.

Before the router is asked:

| Check | Answer |
| --- | --- |
| The address holds `max_connections_per_ip` (16) connections already | 429 `rate_limited` |
| Another method | 405 `method`, with `Allow: GET, HEAD, PUT` |
| `Content-Range` on `PUT` | 400 `content_range` |
| Not `bnx_` and 43 base64url characters, or failed in the last 10 s | 404 `token_unknown` |
| The address is marked and asked the router within 1 s | 429 `rate_limited`, `Retry-After: 1` |

- A token the router does not know counts against the address. Past `token_failures_per_minute`
  (20) the address is marked for 10 minutes, and its unknown tokens get 429 with
  `Retry-After: 600`. A token that resolves always works.
- `OpenTransfer` runs on the shared router connection. Each `ReadTransfer` and `WriteTransfer`
  gets its own HTTP/1.1 connection, so a stalled transfer stalls no other.
- Every answer carries `Connection: close`, so each connection holds one request, and the
  requests an address has in flight are its open connections.
- The placement's lease holds each transfer. The lease's end, a spent budget or `max_duration`
  (30 minutes from the open) cuts it at once. A blocked read or write on the client returns then
  too. The lease ends at the placement deadline and follows each extension, so an extension
  during a transfer moves its end.
- A transfer cut that way before its answer gets 429 `budget_spent` for a spent budget, 408
  `too_long` at `max_duration`, and 410 `sandbox_ended` otherwise. A hard stop already passed
  at the open answers the same.
- The router ends its own streams for idleness, a stalled provider call or its hard stop with
  `DeadlineExceeded`. Within 2 s of a hard stop that gets the same answer as the edge's own cut,
  and otherwise 503 `unavailable`, without a warning in the log.

Uploads:

- `OpenTransfer` runs before the body is read, so with `Expect: 100-continue` a bad, used or
  expired token is refused before the file is sent.
- A `Content-Length` other than the URL's size gets 413 when larger and 400 when smaller, before
  the body is read. Its claim is freed first, with a write the router refuses for its size, so a
  corrected retry works at once. A chunked body must total the size exactly, the same two
  answers otherwise. A size of 0 takes `Content-Length: 0` or an empty chunked body.
- The first message to the router carries the transfer id and lease, then the body follows in
  messages of up to `chunk` (256 KiB). A read that comes back short is sent at once, so a slow
  client still shows progress to the router.
- Only a body of exactly the size ends with a clean close, which lets the router commit. Every
  other end cancels the stream, so the router aborts. The answer is 200 with
  `{"path": "...", "size": N, "sha256": "<hex>"}`.
- A client that moves nothing for `idle_timeout` (60 s), or leaves, has its connection cut.

Downloads:

| Request | Answer |
| --- | --- |
| No `Range`, several ranges, another unit or a bad one | 200, the whole file |
| `bytes=a-`, `bytes=a-b` or `bytes=-n` within the file | 206 with `Content-Range` |
| A range starting at or past the end | 416 `range`, `Content-Range: bytes */<size>` |
| `If-Range` with another validator | 200, the whole file |

- Every answer carries `Content-Length`, the strong `ETag`, `Accept-Ranges: bytes`,
  `Content-Type: application/octet-stream`, `nosniff`, `Content-Security-Policy: sandbox;
  default-src 'none'`, `no-store`, `no-referrer`, `Content-Disposition: attachment` with the
  file name less its control characters, and `X-Bugnet-Sha256` when the URL was made with
  `want_sha256`.
- The last data message waits for the router's `verified`. On any other end the connection is
  cut, so `curl` sees a short transfer and `curl -C -` resumes, never a mixed file. A router
  refusal before the first byte is answered as JSON instead.
- A refused range frees its claim at once, with a read the router refuses.

Bytes count after TLS, toward the sandbox for uploads and from it for downloads, paced by the
placement's lane. Logs name a transfer only by the first 8 hex characters of its token's SHA-256,
never the token or the path.

### The sessions route

`--role sessions` serves the session page at `sessions.bugnet.sh` (session-page.md 7) and calls
`SessionPageService` with `BUGNET_SESSIONS_TOKEN`. It holds no root key: the router checks each
key.

| Method and path | Answer |
| --- | --- |
| `GET /s/<id>` | The bundle's `index.html` for any id of 16 `a-z2-7`, never looked up |
| `GET /assets/<name>` | The bundle's `.js`, `.css`, `.svg` and `.woff2` (`font/woff2`) files |
| `GET /robots.txt` | `Disallow: /` |
| `POST /v1/s/<id>`, `{"k"}` | `GetSessionRecord`: 200 with the record, the snapshot or expired |
| `DELETE /v1/s/<id>`, `{"k"}` | `DeleteSessionRecord`: 204, and the record's live streams end |
| `POST /v1/s/<id>/jobs/<seq>/live`, `{"k","cursor"}` | `WatchSessionJob` as server-sent events |
| Anything else | 404 with no body |

- **The bundle** is `page_dir`'s `index.html`, `headers.txt` and `assets/`, read once at start,
  so a new page needs a restart. Every answer carries `headers.txt`'s headers. A bundle stops the
  role at start unless they hold a CSP, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`
  and `X-Content-Type-Options: nosniff`, or if they set a cookie or a content header. Text files
  go gzipped to a client that accepts it.
- **The 200 body** is built around the router's bytes, never parsed:
  `{"state":"ended","record":<record_json>}`, `{"state":"running","snapshot":<live_json>}` or
  `{"state":"expired"}`.
- **Page calls** need `Content-Type: application/json`, `Origin` equal to `https://<host>` and
  `Sec-Fetch-Site: same-origin`, else 403. `Cookie` is never read. A body over 1 KiB is 413.
- **An unknown id and a wrong key** both get 404 with no body. The pair is cached as unknown for
  10 s, so a wrong key never blocks the id's right key.
- **Limits** (SP 7.4): `requests_per_minute` page calls per client address; past
  `key_failures_per_minute` wrong keys an address is marked 10 minutes, as for transfers; past
  `id_failures_per_minute` wrong keys for one id, the addresses that sent it a wrong key share
  one router call a second for it, and every other address is never held by it. An IPv6 client
  counts by its /64. A pair the router accepted skips the wrong key limits for 10 minutes, so a
  right key is never blocked. A malformed key counts against its address only.
- **Deadlines**: 10 s to read a page call's body (408 past it), and 10 s for a record or delete
  call to the router (503 past it).
- **Live streams**: `out`, `skip`, `exit` and `end` events, an `id:` line only with a cursor,
  `: keepalive` every 15 s, a 30 s deadline on each write, and `live_per_ip` and `live_max`
  streams. A stream counts toward its record's `live_per_record` only once the router took its
  key, so a wrong key gets 404 whether the record is full or not. A NotFound for a key the
  router took before (a placement not ready or ended) never counts as a wrong key. Each stream
  has its own HTTP/1.1 connection to the router. On a stop signal the streams end without an
  `end` event and the page resumes them.
- **Headers** past `max_header_bytes` get a 431 page that says to clear the `bugnet.sh` cookies.
- **Logs** name a call by its route, status and the first 8 hex characters of the id's
  SHA-256, never the body, the key or the link. Strangers' calls log at debug level.

### Drain

On a stop signal the process answers 503 on `/readyz`, stops accepting, and lets open requests
finish. Connections a handler hijacked, such as WebSockets, may stay open up to `drain` (5 minutes
on the edge, 1 minute on the secrets and sessions routes). Then everything left is closed. With
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
- Payments' `FailedPrecondition` (`REF_CONFLICT`), `InvalidArgument` and `NotFound` are final.
  Each is logged once and never retried, so Payments' `x402_ref_conflict` alarm fires once for
  one fault. `NotFound` is an unknown `payment_id`, which no retry can find, since Payments
  stores the row before it answers `Signed`.
- `Reserve` accepts a `Signed` whose `payment_ref` differs from the request's `ref`, since a
  resend carries its first row's ref.
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

`path` never holds a query. It ends before its first `?`.

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
- A flush sends to at most 8 placements at once, and all its sends share one interval. Every
  flush but the last starts a batch only while a quarter of the interval is left, so each send
  gets at least that long. Rows a flush had no time to start wait for the next flush with no try
  counted.
- A failed send keeps every `ref`, so the router stores a row once.
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

### Settlers

- `fakeseller.InMemory()` takes the fixed test format, with no chain.
- `fakeseller.SelfSettle(rpcURL, feePayer, payToTokenAccount)` signs the fee payer's slot and
  sends the transaction with `sendTransaction`, in base64.
- `fakeseller.Facilitator(url)` posts to an x402 facilitator's `/verify`, then to its `/settle`.

`SelfSettle` acts as its own facilitator (XS 11.2). It reads a legacy or version 0 message and
refuses, before it signs anything:

- an entry other than `exact` on Solana mainnet;
- an address lookup table, whose accounts only the chain knows;
- a first key other than the fee payer's, or another signer's signature that fails;
- the fee payer in any instruction, as an account or as the program;
- any token instruction but one Tokenkeg `TransferChecked`;
- a compute unit limit above 400,000 or a price above 5,000,000 micro-lamports, the
  facilitator's caps, a malformed one, or a price with no limit, so a payer cannot spend the fee
  payer's SOL on priority fees;
- a transfer of another amount, with decimals other than 6, of a mint other than USDC, or to an
  account other than `payToTokenAccount`.

Each refusal is a `SettleError` named as x402's SVM facilitator names it, so the payer gets a new
402. The token account is a setting, so the seller never derives an ATA. It sends each message
once, and a second payload carrying it gets `duplicate_settlement`. A failed send frees the
message for another try. A JSON-RPC error is `invalid_exact_svm_transaction_failed`.

`Facilitator` posts `{x402Version: 2, paymentPayload, paymentRequirements}` to both paths, the
payload as the payer sent it and the requirements as its `accepted` entry. It settles only after
`isValid: true`. An answer of `isValid: false` or `success: false` passes on its reason, at any
HTTP status. An answer with neither field, or a settle with no 64-byte transaction signature, is
`unexpected_settle_error`.

### The binary

`x402-fake-seller -config FILE` serves `fakeseller.New` over TLS. `make build` writes
`bin/x402-fake-seller`, and `example/x402-fake-seller.toml` holds every setting at its default.

- TLS comes from `tls_cert_file` and `tls_key_file`, or from Let's Encrypt for `acme_hosts` by
  TLS-ALPN-01 on `listen`, with the account and certificates in `acme_dir`. One of the two must
  be set, never both.
- `settle = "self"` uses `SelfSettle` with `chain_url` and `pay_to_token_account`.
  `settle = "facilitator"` uses `Facilitator` with `facilitator_url`, and the seller then holds
  no key.
- `fee_payer`'s key comes only from the variable `fee_payer_key_env` names,
  `TESTSELLER_FEE_PAYER_KEY` by default, the name Payments' `keys testseller` writes. It is 64
  bytes in base58 or a JSON byte array, as Payments writes keys, and its public half must be
  `fee_payer`. A key in the file is an unknown setting. A missing variable stops the start and
  names `fee_payer_key_env`. No message quotes the key.
- The test API opens when the variable `test_token_env` names is set, `TESTSELLER_TEST_TOKEN` by
  default.
- `late`, `slow` and `stall` set the mode delays, and `redirect_to` where `/redirect/` points.
- The server reads headers for at most 10 s and has no read or write timeout, so a 150 s
  `/hold/`, a 3-minute `/sse/` and a slow upload are never cut.
- It logs the address it serves on, and server errors at warn, such as a failed TLS handshake
  with the client's address. It never logs a payment, a header or a body.

### The test transfer and the facilitator goldens

`internal/fakeseller/testdata/payments-transfer.json` is a seller payment that bugnet-payments'
own `buildSellerPayment` and `signSellerPayment` made, with the fee payer's slot empty. Run
`node testdata/payments-transfer.mjs <bugnet-payments directory>` in `internal/fakeseller` to
make it again. Its keys come from public labels: each is the Ed25519 key whose seed is the
SHA-256 of `bugnet fakeseller test <label>`, for the labels `fee payer`, `allowance`, `pay to`
and `blockhash`. None of them is a secret.

`testdata/facilitator-verify.json` and `testdata/facilitator-settle.json` are the bodies
`Facilitator` posts for that payment at `/ok/x`. The mainnet test seller's facilitator replays
them. `go test ./internal/fakeseller -run TestFacilitatorOrder -update` writes them again.

## Traffic

These libraries count, limit and cut each placement's traffic. The edge, the SSH gateway and the
egress proxy share them.

### Strangers

A `strangers.Guard` applies the token failure rule to one route.

- Each client address may send a set number of tokens a minute that fail to resolve, 20 in the
  edge's settings. The next one marks the address for 10 minutes, counted from the last failure
  past the limit.
- A marked address gets 429 for unknown tokens. At most one of its tokens a second goes to the
  router, so a valid token from behind a shared NAT still works. The others get 429 with
  `Retry-After: 1`.
- A token that failed is remembered by its SHA-256 for 10 seconds and never asked again in that
  time.
- An IPv4-mapped address counts as its IPv4 address.
- A limit of 0 marks no address. Failed tokens are still remembered.

A `strangers.PerIP` allows a number of requests a minute per address, for the secrets and hooks
routes. A limit of 0 turns it off.

A `strangers.Conns` caps the connections each address holds open at once, 16 on the transfer
route, where every answer closes its connection. `Acquire` takes a slot and hands back its release, which is safe to call twice. An address
with nothing open is forgotten at once.

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
- An answer to a report sent before the last `SetRemaining` keeps that newer figure, even when a
  `Drop` came between. One sequence for the whole process orders them, never one per placement.
- `Drop` forgets a placement's figure. Its unsent bytes still go out, and answers about it change
  nothing until the next `SetRemaining`. Bytes counted after a `Drop` and before the next
  `SetRemaining` never call `OnAnswer`, so they never cut on a figure the reporter lacks.
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
- One sequence orders every put, move and check sent. An answer applies only when its check was
  sent after the lease's state was last set, so the answer sent last wins, whatever order the
  answers arrive in. A late answer never undoes an extension. Its ends and revocations still
  apply, since they only cut.
- A deadline check whose later deadline lost to a newer state with a passed deadline asks the
  router again at once, rather than ending the lease or leaving it without a timer.
- `OnState` hands on every state a lease takes, from a put, a move or a check. The edge passes the
  bytes left to its usage reporter there.
- `Apply` acts on one event: `PlacementEnded`, `DeadlineMoved`, `PreviewRevoked`, the binary's
  own `BudgetSpent` kind and `Resync`.
- `lease.Reason(ctx)` gives the reason a lease or child context ended with.

### Wiring

A `traffic.Traffic` holds one process's lease table, usage reporter, pacer and event watcher,
wired as below. `traffic.Edge` builds it on `EdgeService`. The SSH gateway and the egress proxy
build theirs with `traffic.New` and their own calls and budget kind.

- Each event goes to `Apply`. `Resync` asks for a lease check, and the stream's state switches
  the checks between 60 s and 30 s.
- Every state a lease takes gives the reporter its bytes left.
- A usage answer of 0 ends the lease with `budget`. A pace above 0 repaces the placement's lane.
- `Hold` moves the placement's live lease, or makes one and paces its lane from the router's
  `bytes_per_second`. When that lease ends, its lane and its usage figure are dropped, unless a
  new lease for the placement exists by then.
- Failed checks, reports and stream opens are logged at warn level. The libraries never log.
- `Run` stops once its context ends, after one last usage report.

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
