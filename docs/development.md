# 개발 가이드

## 지원 Toolchain

- Go 1.26.5
- GNU Make 또는 호환되는 `make`
- history-aware Secret scan을 위한 Git

Service는 Go standard library와 Human Identity Boundary에 필요한 고정 버전의
`go-oidc`, `go-jose` dependency를 사용합니다. Security tool은 runtime
dependency가 되지 않도록 고정 버전을 `go run`으로 실행합니다.

Windows에서는 GitHub Actions와 동일한 Linux command·Race Detector 동작을
재현하기 위해 WSL2 사용을 권장합니다. 검증 환경이 Race Detector를 지원하지
않으면 `-race`를 제거하지 말고 WSL2 또는 GitHub Actions에서 실행합니다.

## 현재 개발자 인터페이스

현재 외부에서 사용할 수 있는 Product API, CLI, Dashboard는 없습니다.
`internal/*` package는 Application 내부 구현이며 external SDK나 stable Public
API로 import하는 용도가 아닙니다.

현재 제공하는 실행 가능한 interface는 다음 두 가지입니다.

1. 각 Security Boundary의 contract test
2. Development process의 `/livez`·`/readyz` operational probe

따라서 Encryption, Service Token, RBAC를 확인하려면 아래 package test를
실행해야 합니다. Development Server를 실행해도 이 기능을 HTTP로 직접 호출할
수는 없습니다.

## 처음 검증하기

```sh
git clone https://github.com/laflabs-inc/lafwall.git
cd lafwall
go version
make test
```

`go version`은 `go1.26.5`여야 합니다. `make test`는 Race Detector가 활성화된
unit·integration test를 실행합니다. 모든 command가 exit code `0`으로 끝나면
성공입니다.

Repository 변경을 제출하기 전에는 CI와 동일한 전체 Gate를 실행합니다.

```sh
make ci
```

첫 실행은 고정 버전의 `govulncheck`와 Gitleaks를 내려받으므로 Network 연결이
필요합니다. `make ci`는 전체 Git history를 읽으므로 source archive가 아닌
full Git checkout에서 실행해야 합니다.

## Boundary별 검증

<!-- markdownlint-disable MD013 -->

| 목적 | 명령 | 핵심 검증 |
| --- | --- | --- |
| Envelope Encryption | `go test -race -count=1 -v ./internal/encryption` | Known-answer, tamper, wrong context, fresh DEK·nonce, redaction |
| Human Identity | `go test -race -count=1 -v ./internal/identity` | Signature, issuer, audience, time, nonce, duplicate claim, redaction |
| Service Token | `go test -race -count=1 -v ./internal/servicetoken` | Entropy, verifier, Tenant scope, expiry, revocation, one-time reveal |
| Authorization | `go test -race -count=1 -cover -v ./internal/authorization` | 5×19 matrix, scope isolation, Service Principal, grant·revoke, last admin |
| Operational lifecycle | `go test -race -tags=integration -run '^TestIntegration' -count=1 -v ./...` | Listener readiness와 graceful shutdown |

<!-- markdownlint-enable MD013 -->

이 test에 사용하는 key, token, identity는 deterministic fake 또는 synthetic
test data입니다. 실제 Secret이나 운영 credential을 test input으로 사용하지
않습니다.

## Encryption Boundary

`internal/encryption`은 versioned AES-256-GCM Envelope과 `KekProvider` port를
구현합니다. 이 package는 Go standard library의 cryptography만 사용하며
plaintext를 log·persist·authorize하거나 HTTP로 노출하지 않습니다.

Canonical AAD와 provider 계약은
[Encryption Boundary](security/encryption-boundary.md)에 정의되어 있습니다.
Deterministic provider는 `_test.go`에만 선언되므로 Application build에서
선택할 수 없습니다. Production provider, Database adapter, runtime wiring은
아직 존재하지 않습니다.

## Human Identity Boundary

`internal/identity`는 명시적으로 설정된 하나의 HTTPS issuer가 서명한 OIDC
ID Token을 검증하고 immutable `(issuer, subject)` claim을 내부 Human
Principal에 mapping합니다. 정확히 하나의 audience와 명시적인 asymmetric
signing algorithm allowlist를 요구합니다. Email과 기타 profile claim은
identity proof가 아닙니다.

Race detector가 활성화된 unit test는 signature, issuer, audience,
authorized party, expiry, issued-at, not-before, duplicate claim, subject,
size, nonce 거부를 검증합니다. 모든 Authentication failure는 sanitize되며
raw token이나 claim value를 포함하지 않습니다.

전체 계약과 보류된 provider 요구 사항은
[Human Identity Boundary](security/human-identity-boundary.md)에 정의되어
있습니다. Remote JWKS adapter, Laf ID Production configuration, HTTP
Authentication wiring, session, Database principal mapping은 아직 없습니다.
Production startup은 계속 차단됩니다.

## Service Token Boundary

`internal/servicetoken`은 Workload용 opaque credential을 발급하고 exact Tenant
scope·authoritative lifecycle state에 대해 인증합니다. 매 발급마다
`crypto/rand.Reader`로 128-bit public ID와 256-bit secret을 생성합니다.
Persistent `Record`에는 plaintext credential 대신 domain-separated SHA-256
verifier만 남기며 candidate는 constant-time으로 비교합니다.

Unit Test는 fresh entropy, canonical format, one-time reveal boundary,
wrong-secret·wrong-tenant·expiry·revocation 거부, immutable last-used metadata,
formatting redaction, sanitized failure를 검증합니다. Deterministic entropy는
`_test.go`에서만 주입할 수 있습니다.

전체 계약과 보류된 storage·concurrency 요구 사항은
[Service Token Boundary](security/service-token-boundary.md)에 정의되어
있습니다. Database persistence, HTTP Authentication, Audit transaction,
Authorization wiring은 아직 연결되지 않았습니다. Service Principal은 Tenant
scope만 증명하며 authoritative Role Assignment와 별도의 Authorization
decision 없이는 어떤 resource action도 허용하지 않습니다. Production startup은
계속 차단됩니다.

## Authorization Boundary

`internal/authorization`은 승인된 다섯 고정 Role, 19개 Permission,
Tenant→Project→Environment 하향 scope를 pure Domain Policy로 구현합니다.
모든 operation은 authenticated Principal, exact action, authoritative lookup으로
resolve한 target, 최신 Assignment snapshot을 요구합니다.

Policy는 unknown·malformed·cross-tenant·archived·insufficient state를 하나의
sanitized denial로 거부하고 routine formatting에서 Principal·Scope·Assignment·
Target metadata를 redact합니다. Service Principal은 `secret_editor`와
`secret_accessor`만 받을 수 있고 Admin·Editor·Auditor는 Secret plaintext를
read할 수 없습니다.

전체 계약과 보류된 storage·Audit 요구 사항은
[Authorization Boundary](security/authorization-boundary.md)에 정의되어
있습니다. Database Adapter, initial administrator bootstrap, atomic Audit
transaction, HTTP wiring은 아직 없으며 Production startup은 계속 차단됩니다.

## Local 실행

Laf Secrets는 명시적인 runtime mode를 요구합니다. Development mode의 기본
listen address는 loopback입니다.

첫 번째 Terminal에서 실행합니다.

```sh
export LAFSECRETS_RUNTIME_MODE=development
make run
```

`LAFSECRETS_HTTP_ADDRESS`에 유효한 `host:port` 값을 지정하면 기본값
`127.0.0.1:8080`을 변경할 수 있습니다.

두 번째 Terminal에서 확인합니다.

```sh
curl -i http://127.0.0.1:8080/livez
curl -i http://127.0.0.1:8080/readyz
```

정상 상태에서는 두 요청 모두 body 없이 `204 No Content`를 반환합니다. 이
Smoke Test는 HTTP process와 readiness lifecycle만 확인하며 Secret CRUD,
Encryption, Authentication, Authorization의 end-to-end 사용법은 아닙니다.

알 수 없는 `LAFSECRETS_*` 변수, 잘못된 값, 중복 값, 알 수 없는 runtime
mode, port `0`은 startup을 실패시킵니다. 거부된 configuration value는
error에 복사하지 않습니다.

Production mode는 현재 의도적으로 사용할 수 없습니다.
`LAFSECRETS_RUNTIME_MODE=production`으로 시작하면 필요한 storage, identity,
audit, Production `KekProvider` dependency가 존재하고 각 approval gate가
해결될 때까지 실패합니다. 이를 우회하는 flag는 없습니다.

## 품질 검사 명령

<!-- markdownlint-disable MD013 -->

| 명령 | 목적 |
| --- | --- |
| `make format` | Go source를 format합니다. |
| `make lint` | Format을 검사하고 일반·integration build에 `go vet`을 실행합니다. |
| `make test-unit` | Race detector를 활성화해 unit test를 실행합니다. |
| `make test-integration` | Race detector를 활성화해 integration-tagged test를 실행합니다. |
| `make audit` | Module을 검증하고 source·test에 `govulncheck`를 실행합니다. |
| `make scan-secrets` | 현재 worktree를 Gitleaks로 검사하고 finding을 redact합니다. |
| `make scan-secrets-history` | checkout에서 확인 가능한 전체 Git history를 검사합니다. |
| `make check` | Lint, test, dependency audit, worktree Secret scan을 실행합니다. |
| `make ci` | Git history scan을 포함한 모든 검사를 실행합니다. |

<!-- markdownlint-enable MD013 -->

`make scan-secrets-history`는 실제 Git checkout을 요구합니다. CI는 history
scan이 일부만 실행된 채 성공하지 않도록 full-depth checkout을 사용합니다.
또한 scanner가 중단된 history read를 성공으로 판단하는 상황을 막기 위해,
같은 full-history `git log` operation을 먼저 독립적으로 실행합니다.

## Operational Probe

Server는 version이 없는 operational probe를 제공합니다. 이 endpoint들은
public REST product contract에 포함되지 않습니다.

<!-- markdownlint-disable MD013 -->

| 경로 | 정상 | 비정상 | Body |
| --- | --- | --- | --- |
| `/livez` | `204 No Content` | HTTP process가 응답하는 동안 해당 없음 | 비어 있음 |
| `/readyz` | `204 No Content` | `503 Service Unavailable` | 비어 있음 |

<!-- markdownlint-enable MD013 -->

두 probe는 `GET`과 `HEAD`를 지원하고 `Cache-Control: no-store`를 설정합니다.
Dependency 이름, configuration, build metadata, 민감한 상태는 노출하지
않습니다. Readiness는 false로 시작하고 listener가 준비된 뒤에만 true가
되며 graceful shutdown 전에 다시 false가 됩니다.

Service에는 아직 storage나 Production key-provider adapter가 없습니다.
따라서 readiness가 Production capability를 잘못 표시하지 않도록 Production
startup은 차단된 상태입니다. 이후 추가되는 필수 dependency는 Production
startup을 허용하기 전에 readiness에 포함해야 합니다.

## CI Security Boundary

GitHub Actions workflow는 다음 조건을 지킵니다.

- Repository permission을 read-only로 제한합니다.
- `pull_request_target`을 사용하지 않습니다.
- Checkout credential을 저장하지 않습니다.
- Action을 full commit SHA로 고정합니다.
- Job timeout을 설정합니다.
- 개발자가 실행할 수 있는 것과 동일한 `make ci` 명령을 실행합니다.
