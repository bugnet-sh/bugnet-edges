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
