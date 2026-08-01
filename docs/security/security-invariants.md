# Security Invariants

상태: **Accepted Baseline(승인된 기준선)**

승인일: 2026-07-30

이 Invariant는 Repository에서 가장 우선하는 계약입니다. 하나라도 변경하면
Security Policy Change로 간주하며 명시적인 승인과 문서화된 Security
Review가 필요합니다.

## Cryptography·Key Custody

1. Cryptographic primitive는 검토된 established library에서 제공합니다.
   Laf Secrets는 AES, GCM, random generation, hashing, signature primitive를
   직접 구현하지 않습니다.
2. 모든 Secret Version은 새로 생성한 256-bit Data Encryption Key(DEK)를
   사용합니다.
3. Secret plaintext는 cryptographically secure random source가 생성한
   unique 96-bit nonce와 AES-256-GCM으로 encrypt합니다.
4. Authenticated Additional Data(AAD)는 canonical·versioned encoding을
   사용하며 최소한 다음 항목을 묶습니다.
   - Tenant ID
   - Project ID
   - Environment ID
   - Logical Secret ID
   - Secret Version ID·sequence
   - Encryption format version
5. 승인된 `KekProvider`를 통해 Key Encryption Key(KEK)로 DEK를 wrap합니다.
   Plaintext DEK는 persist하지 않습니다.
6. Production KEK는 Application Database 외부에 저장하고 Laf Secrets를 통해
   export할 수 없게 합니다.
7. Ciphertext, nonce, Wrapped DEK, KEK reference, AAD format version,
   algorithm identifier는 persist합니다. Plaintext·unwrapped DEK는
   persist하지 않습니다.
8. Authentication tag failure, context mismatch, malformed Envelope, unknown
   algorithm, key-provider error는 fail-closed 처리합니다.
9. Key·Encryption format 변경에는 명시적인 versioning과 검증된 Migration을
   사용합니다. 기존 Ciphertext를 암묵적으로 재해석하지 않습니다.

## Plaintext Handling

1. Secret value는 명시적인 value operation에서만 입력·반환합니다.
2. Metadata list, Version history, search, Audit, error, metric, trace, health
   endpoint에는 plaintext나 reversible derivative를 포함하지 않습니다.
3. Process memory에서 plaintext의 수명과 copy를 최소화합니다. Use Case에
   필요한 component만 plaintext를 받습니다.
4. Plaintext를 포함하는 HTTP response는 cache할 수 없으며 server, proxy,
   browser, observability capture에 포함하지 않습니다.
5. Secret value를 URL path, query string, CLI process argument 등 일상적으로
   기록되는 channel로 받지 않습니다.

## Authentication·Token

1. Human Identity는 email이 아닌 승인된 OIDC issuer와 immutable
   `(issuer, subject)`를 사용합니다.
2. Signature, issuer, audience, expiry, not-before, allowed algorithm 검증은
   필수입니다.
3. Service Token은 entropy가 높은 opaque credential이며 plaintext는 한 번만
   표시합니다.
4. Database에는 credential 자체가 아닌 token identifier, non-reversible
   verifier, scope, status, expiry, operational metadata를 저장합니다.
5. Secret comparison boundary에서 token을 constant-time으로 검증합니다.
6. Expired, revoked, malformed, unknown credential은 어느 validation step에서
   실패했는지 노출하지 않고 거부합니다.

## Authorization·Tenant Isolation

1. Authorization은 deny-by-default입니다.
2. 모든 Use Case는 민감한 작업 전에 Principal, action, Tenant, target
   resource를 authorize합니다.
3. Resource identifier 자체는 access 권한을 부여하지 않습니다.
4. Storage query가 cross-tenant access를 구조적으로 제한하며 negative
   integration test가 이를 검증합니다.
5. 승인된 Permission Model에 명시되지 않으면 Administrative role은 Secret
   plaintext access를 암시하지 않습니다.
6. Application·Migration Database role은 least privilege를 따릅니다.

## Versioning·Deletion

1. Secret Version은 생성 후 immutable입니다.
2. Secret value update는 transaction 안에서 새 Version을 생성합니다.
3. Version sequence allocation은 concurrency-safe하며 logical Secret 안에서
   unique합니다.
4. 기본 deletion은 복구할 수 있어야 합니다. Archive·soft-delete된 resource는
   일반 read·reveal path로 접근할 수 없습니다.
5. 영구 파기는 별도로 승인된 Policy·Audit trail을 요구합니다.

## Auditability

1. Security-relevant read·write·denied operation, token lifecycle event, role
   change, administrative action은 structured Audit Event를 생성합니다.
2. 성공한 state change와 필수 Audit Event는 atomic하게 commit합니다.
3. Audit Record에는 stable actor, action, resource, Tenant, outcome, time,
   request correlation, 안전한 context field를 포함합니다.
4. Audit Record에는 Secret value, credential, raw Authorization header,
   Wrapped Key, 민감한 request body를 포함하지 않습니다.
5. Application code는 일반 runtime permission으로 Audit Event를 update·delete할
   수 없습니다.
6. Audit delivery·persistence failure는 Security-sensitive operation에 대해
   승인된 fail-closed policy를 따릅니다.

## Operational Safety

1. Test key provider, insecure default, incomplete Authentication
   configuration, unknown Security mode가 선택되면 Production startup을
   실패시킵니다.
2. Backup은 encrypt하고 민감정보로 취급합니다. Restore test로 Tenant
   isolation·key-provider dependency를 검증합니다.
3. Log·telemetry는 best-effort redaction만 사용하지 않고 allowlisted field를
   사용합니다.
4. Rate, size, pagination, concurrency limit은 명시적이며 안전하게 실패합니다.
5. 필수 storage·key-provider dependency가 request를 안전하게 처리할 수
   없으면 readiness는 성공을 표시하지 않습니다.
