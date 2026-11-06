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

## Calling the router

`internal/routerclient` gives two `*http.Client`s for the Connect clients from `bugnet-proto`. Both
send the caller's token only to the router URL and never follow a redirect.

| Client | Protocol | Used for |
| --- | --- | --- |
| `New` | h2c to an `http://` router, else h2 or HTTP/1.1 over TLS | Every call but transfers |
| `PerCall` | HTTP/1.1, one connection per call | Transfers, so one stalled stalls no other |

## Settings

Each binary reads one TOML file through `internal/settings`. Loading fails, naming the line and
the key, when:

- a key names no setting, or differs from one only in case (`Drain` for `drain`);
- a key or table is set twice;
- a value has the wrong kind, or does not fit, such as `drain = 5` or `300` for an 8-bit number.

Errors never quote a value. A line that is not valid TOML is named by its line alone.

| Type | Written as | Range |
| --- | --- | --- |
| `settings.Bytes` | Bytes, `KiB`, `MiB` or `GiB`, such as `"65536"` or `"64KiB"` | 0 to 1 TiB |
| `settings.Duration` | Go's form, such as `"30s"`, `"5m"` or `"1h30m"` | 0 or more |

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
