# Development

## Supported toolchain

- Go 1.26.5
- GNU Make or a compatible `make`
- Git for history-aware secret scanning

The application currently uses only the Go standard library. Security tools
are invoked at pinned versions through `go run`, so they do not become runtime
dependencies.

## Encryption boundary

`internal/encryption` implements the versioned AES-256-GCM Envelope and the
`KekProvider` port. The package uses only Go standard-library cryptography and
does not log, persist, authorize, or expose plaintext through HTTP.

The canonical AAD and provider contracts are documented in the
[Encryption Boundary](security/encryption-boundary.md). The deterministic
provider is declared only in `_test.go`; Application builds cannot select it.
There is no Production provider, Database adapter, or runtime wiring yet.

## Local startup

Laf Secrets requires an explicit runtime mode. Development binds to loopback
by default:

```sh
export LAFSECRETS_RUNTIME_MODE=development
make run
```

`LAFSECRETS_HTTP_ADDRESS` may override `127.0.0.1:8080` with a valid
`host:port` value.

Unknown `LAFSECRETS_*` variables, malformed values, duplicate values, unknown
runtime modes, and port `0` fail startup. Rejected configuration values are
not copied into errors.

Production mode is intentionally unavailable in this slice. Startup with
`LAFSECRETS_RUNTIME_MODE=production` fails until the required storage,
identity, audit, and production `KekProvider` dependencies exist and their
separate approval gates are resolved. There is no bypass flag.

## Quality commands

<!-- markdownlint-disable MD013 -->

| Command | Purpose |
| --- | --- |
| `make format` | Format Go source. |
| `make lint` | Check formatting and run `go vet` for normal and integration builds. |
| `make test-unit` | Run unit tests with the race detector. |
| `make test-integration` | Run integration-tagged tests with the race detector. |
| `make audit` | Verify modules and run `govulncheck` against source and tests. |
| `make scan-secrets` | Scan the current worktree with Gitleaks and redact findings. |
| `make scan-secrets-history` | Scan all Git history available in the checkout. |
| `make check` | Run lint, tests, dependency audit, and worktree secret scan. |
| `make ci` | Run all checks, including the Git history scan. |

<!-- markdownlint-enable MD013 -->

`make scan-secrets-history` requires a real Git checkout. CI uses a full-depth
checkout so the history scan is not silently partial. The command first runs
the same full-history `git log` operation independently; this makes a Git
failure visible instead of trusting a scanner success code after an aborted
history read.

## Operational probes

The server exposes unversioned operational probes. They are not part of the
public REST product contract.

<!-- markdownlint-disable MD013 -->

| Path | Healthy | Unhealthy | Body |
| --- | --- | --- | --- |
| `/livez` | `204 No Content` | Not applicable while the HTTP process responds | Empty |
| `/readyz` | `204 No Content` | `503 Service Unavailable` | Empty |

<!-- markdownlint-enable MD013 -->

Both probes support `GET` and `HEAD`, set `Cache-Control: no-store`, and expose
no dependency names, configuration, build metadata, or sensitive state.
Readiness starts false, becomes true only after the listener is established,
and returns to false before graceful shutdown.

The service has no storage or Production key-provider adapter. Production
remains blocked so readiness cannot falsely claim Production capability.
Later required dependencies must participate in readiness before Production
startup can be enabled.

## CI security boundary

The GitHub Actions workflow:

- uses read-only repository permissions;
- does not use `pull_request_target`;
- does not persist checkout credentials;
- pins actions to full commit SHAs;
- applies a job timeout; and
- runs the same `make ci` command available to developers.
