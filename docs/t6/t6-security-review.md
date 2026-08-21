# T6 Security Review

| Security invariant | T6 control | Evidence |
|---|---|---|
| No supported target-web dispatch bypasses T5 | R15 remains T5-mediated; legacy roots deny before dispatch | Root-dispatch regression tests and T6 static guard. |
| No provider bypass | `scan` returns provider block before phase-2 enumerator setup | T6 CLI regression and source inventory. |
| No subprocess bypass | `scan --use-nmap` and `scan --use-nuclei` return subprocess block first | T6 CLI regression and source inventory. |
| No credentials enter the T5 read seam | Auth testing remains blocked; T5 rejects request bodies and credential headers | Existing T5 contract and T6 classification. |
| Local dry-run remains non-executing | Root gate permits dry-run only for local command validation; underlying commands retain dry-run contracts | Existing dry-run CLI tests plus T6 root-gate tests. |
| Cross-project, expiry, revocation, forged trust, scope, budget, rate, concurrency, cancellation, and audit failures | Maintained by the existing T1/T2/T3/T4/T5/R3/R10.5 authorities on supported R15 dispatch | Existing T5 and assessment/campaign regression coverage remains mandatory. |
| New unreviewed direct engine construction | Exact production CLI R3-constructor set is checked in CI | `check-t6-central-egress-adoption.sh`. |

T6 does not claim that static source checks replace runtime authority checks. Static enforcement prevents architectural drift; T1 through T5 and R3 still decide whether a supported operation may dispatch. The root denials are intentionally conservative and do not send a request, resolve DNS, open a socket, read a provider key, or launch a subprocess.

## Non-Claims

T6 does not add a scanner, new client, resolver, socket abstraction, proxy, worker, scheduler, provider credential store, or subprocess adapter. It does not make legacy libraries safe for arbitrary external embedding. It only closes the repository’s audited production CLI entry points and preserves the existing explicitly central R15 path.
