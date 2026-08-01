# Encryption Boundary

상태: **Implemented Baseline(구현된 기준선)**

구현일: 2026-07-31

이 문서는 Roadmap Slice 1.2의 구현 계약을 기록합니다. Production KMS를
선택하거나 Database schema를 정의하거나 API contract를 공개하지 않고,
승인된 [Security Invariants](security-invariants.md)를 적용합니다.

## 책임

`internal/encryption` Package는 다음 책임을 가집니다.

- 모든 Encryption operation마다 `crypto/rand`로 fresh 256-bit DEK를
  생성합니다.
- Go standard library의 AES-256-GCM 구현으로 plaintext를 encrypt합니다.
- 모든 Envelope에 fresh 96-bit GCM nonce를 생성합니다.
- Immutable Secret Version context를 canonical AAD로 authenticate합니다.
- DEK wrap·unwrap을 `KekProvider`에 위임합니다.
- Ciphertext·key metadata만 포함하는 versioned Envelope을 반환합니다.
- 직접 관리하는 plaintext DEK buffer를 사용 후 clear합니다.
- Provider detail·민감한 value가 없는 sanitized error를 반환합니다.

이 Package는 storage, logging, telemetry, HTTP, Production provider에
의존하지 않습니다. Principal에게 value encrypt·reveal 권한이 있는지는
결정하지 않습니다. Authorization은 Application Use Case의 책임입니다.

## Canonical AAD Version 1

AAD Version 1은 정확히 다음 순서의 byte sequence입니다.

1. 고정 byte `LAFSECRETS`, zero byte, `SECRET-VERSION`, zero byte
2. Unsigned 16-bit big-endian AAD format version
3. Unsigned 16-bit big-endian Envelope format version
4. Tenant ID, Project ID, Environment ID, Secret ID, Secret Version ID 각각의
   unsigned 32-bit big-endian UTF-8 byte length와 해당 byte
5. Unsigned 64-bit big-endian Secret Version sequence

모든 identifier는 비어 있지 않은 valid UTF-8이어야 하며 sequence는 1부터
시작합니다. Length prefix는 모호한 concatenation을 방지합니다. 고정 Domain은
이 AAD를 현재·향후의 다른 cryptographic use와 분리합니다.

순서, encoding, Domain, 의미를 변경하려면 새로운 AAD format version,
compatibility test, 승인된 Migration·forward-recovery plan이 필요합니다.
기존 Ciphertext를 암묵적으로 재해석해서는 안 됩니다.

## Envelope Format Version 1

Envelope은 다음 field를 함께 persist합니다.

- Envelope format version
- AAD format version
- Data Encryption algorithm identifier(`AES-256-GCM`)
- Key Wrapping algorithm identifier
- External KEK reference
- 96-bit nonce
- GCM Authentication Tag를 포함한 Ciphertext
- Opaque Wrapped DEK

Decryption은 provider에 key unwrap을 요청하기 전에 unknown version·algorithm,
incomplete metadata, malformed nonce, GCM tag보다 짧은 Ciphertext를
거부합니다. Authentication failure와 잘못된 resource context에서는
plaintext를 반환하지 않습니다.

Ciphertext·Wrapped DEK를 포함한 Envelope field는 민감정보로 유지하며
Metadata operation에서 log·expose하지 않습니다.

## `KekProvider` Contract

Production provider는 다음 조건을 충족해야 합니다.

- KEK authority를 Laf Secrets Database 외부에 둡니다.
- 검토된 provider SDK·established library를 사용합니다.
- Plaintext DEK를 export, persist, retain, log하지 않습니다.
- Opaque Wrapped Key byte, stable KEK reference, algorithm identifier를
  반환합니다.
- Unknown·mismatched KEK reference와 wrapping algorithm을 거부합니다.
- Unwrap 시 caller-owned 32-byte DEK buffer를 반환합니다.
- Concurrent use에 안전하고 Context cancellation을 준수합니다.
- Error에 민감한 value를 포함하지 않습니다.
- Plaintext·local-key fallback 없이 fail-closed 처리합니다.

Encryption Service는 Envelope을 만들기 전에 provider output을 copy하고,
unwrapped key buffer를 clear하며, provider failure를 sanitize합니다. Provider가
plaintext DEK 자체를 Wrapped Key로 반환하면 거부합니다.

Test에서 사용하는 deterministic provider는 `_test.go`에만 존재합니다.
Stateful·memory-only이며 Application build에서는 사용할 수 없습니다.
Production startup이 아직 허용되지 않으므로 test·local provider를 실수로
선택할 수 없습니다.

## 검증 증거

Unit test는 다음 항목을 검증합니다.

- 고정 AES-256-GCM·canonical AAD known-answer vector
- 성공적인 round trip
- 반복 operation에서 서로 다른 DEK·nonce
- Tampered Ciphertext, nonce, Wrapped DEK
- 잘못된 Tenant, Project, Environment, Secret, Version ID, sequence
- Unknown Envelope version·algorithm
- Invalid Binding·provider output
- Provider, random source, cancellation failure
- Sanitized error
- Envelope field에 plaintext·unwrapped DEK가 없음
- Service가 직접 관리하는 DEK buffer clear

CI는 race detector, `go vet`, `govulncheck`, Gitleaks worktree·full-history
scan과 함께 이 test를 실행합니다.

## Security 영향·잔여 위험

이 Boundary는 KEK custody를 분리하고 Ciphertext를 immutable Domain context에
묶어 Database disclosure·Ciphertext substitution을 완화합니다. Plaintext를
실제로 처리하는 동안 Application Process 전체가 침해되는 상황까지 보호한다고
주장하지 않습니다.

Go·standard library는 Application code가 확실하게 지울 수 없는 internal key
schedule·plaintext copy를 만들 수 있습니다. 구현은 명시적인 copy를
최소화하고 소유한 buffer를 clear하지만 보장된 memory erasure를 주장하지
않습니다. Confidential Computing·HSM Integration은 MVP 범위 밖입니다.

Production startup 전까지 Production provider 선택, provider별 outage policy,
Database Envelope schema, backup behavior, key rotation procedure를 별도
approval gate로 유지합니다.
