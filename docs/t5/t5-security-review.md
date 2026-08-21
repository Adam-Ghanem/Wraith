# T5 Security Review

## Threat and Control Review

| Threat | T5 control | Verification |
|---|---|---|
| Untrusted caller claims an outbound capability | Registry has unique operation ownership and validates the capability ID. | Unit test rejects duplicate ownership and unknown capabilities. |
| Caller forges or reuses derived trust | T4 trust is validated with project, scope, task, assessment, campaign, and time bindings. | Regression test rejects a forged fingerprint and cross-project operation. |
| Destination carries credentials | Secret-like destination, project, or budget fields are checked before target parsing. | Regression test expects `ErrCredentialMaterial` for a user-info URL. |
| Scope decision is skipped | Required capabilities invoke the T2 outbound target gateway. | Missing scope authority denies the operation. |
| Audit infrastructure is unavailable | Audit sink is mandatory and failure prevents R3 delegation. | Recording transport test proves zero dispatches on audit failure. |
| Write or credential-bearing request is delegated | Client accepts only GET/HEAD with no body, authorization, or cookie headers. | Client contract is unit-tested and statically guarded. |
| Gateway grows a second transport boundary | Package import guard forbids network and subprocess packages. | `check-t5-outbound-gateway.sh` runs in CI. |

## Audit Record

Every permitted gateway operation appends a T3 `authorization_lifecycle` event with reason code `t5_gateway_allowed`, project, authorization ID, scope reference, and operation time. The gateway treats a failed append as a denial. The returned audit fingerprint is part of the in-memory decision so callers can relate a permitted operation to its recorded authorization event without returning raw credential material.

## Explicit Limitations

T5 is not a general network monitor and it is not a claim that all historical request code is already centralized. It covers only the two listed R15 read operations. It does not provide DNS pinning, redirect processing, credential storage, automatic scope expansion, traffic interception, exploit execution, background scheduling, or new scanner capabilities. Redirect behavior remains under existing R3 and owner-specific controls; the T5 capability currently does not declare independent redirect permission.
