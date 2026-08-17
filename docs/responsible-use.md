# Wraith Responsible Use Policy

**Status:** Active for the implemented Phase 1–5 feature set; review this policy before every run.

**Document owner:** Wraith project

**Applies to:** Wraith Phase 1 local-network discovery; Phases 2–4 authorized domain and web-surface workflows; and Phase 5 local export-fixture and static-dashboard workflows.

**Normative terms:** The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** state requirements for authorized use and implementation. **MUST NOT** is an absolute prohibition.

## 1. Policy statement

Wraith is an authorization-bound asset inventory and reconnaissance support tool. Phase 1 is narrowly bounded local IPv4 discovery. Phases 2–4 add authorized domain, HTTP/content, JavaScript, and optional subprocess enrichment workflows. Phase 5 adds a local export fixture and a static dashboard. Wraith is not an exploitation tool, credential-testing tool, internet-wide scanning service, security guarantee, or an unattended scanning platform.

Use of Wraith is permitted only when every target, domain, network, web origin, fixture, and output recipient is owned by the operator or covered by explicit, current authorization from the owner. Local network visibility, technical reachability, employment access, Wi-Fi access, possession of an IP address, a public hostname, a DNS record, a browser response, or a search result does not by itself establish authorization.

The operator is responsible for confirming permission, selecting the correct scope, protecting output, using only features that the authorization covers, and stopping the run if scope or authorization becomes uncertain.

## 2. Authorized-use requirement

Before each run, the operator **MUST** have a reasonable, documented basis to conclude that the intended targets and planned activity are authorized. The authorization should identify the owner or responsible organization, the network/CIDR and/or domain scope, the systems or target population, the permitted activities, the authorization period, and operational restrictions such as maintenance windows, rate limits, authentication boundaries, excluded paths, tooling restrictions, and output handling.

| Authorization condition | Required action |
| --- | --- |
| The operator owns or administers the complete intended scope and the activity is permitted by applicable policy | The operator may proceed only within the documented phase-specific controls. |
| A third party owns any intended target, domain, origin, tenant, network, or application | Obtain explicit authorization covering each planned Wraith activity before proceeding. |
| Authorization excludes discovery, probing, content access, JavaScript analysis, Nmap, Nuclei, particular hosts, paths, time periods, or output recipients | Do not perform the excluded activity. Narrow the run or do not proceed. |
| Authorization is expired, ambiguous, verbal without a reliable record, or unavailable | Treat authorization as unconfirmed and fail closed. |
| A discovered target, redirect, hostname, virtual host, IP address, or web page falls outside the documented scope | Do not follow, scan, crawl, or enrich it. Record the omission where appropriate. |

Wraith **MUST NOT** be used to test whether an owner notices scanning, to discover systems for later unauthorized access, or to create evidence of permission from the fact that a packet, DNS record, HTTP response, or banner was received.

## 3. Phase-specific permitted activity

| Phase | Permitted activity when expressly authorized | Additional boundary |
| --- | --- | --- |
| 1 | One explicitly selected local IPv4 interface and explicitly selected local IPv4 CIDR; bounded ARP discovery; TCP connect checks on the curated top-100 TCP list; limited read-only service metadata. | No public IP, external network, arbitrary port, credential, state-changing, or unbounded activity. |
| 2 | Authorized domain-subdomain enumeration, DNS resolution, and bounded HTTP probing, with local storage and history comparison. | The operator must authorize the domain and any reachable in-scope targets; Wraith must not turn response data into a license to expand scope. |
| 3 | Authorized bounded content-path discovery and JavaScript analysis associated with the approved web scope. | Access only the approved web scope and treat returned content, scripts, endpoints, URLs, and possible secrets as sensitive untrusted data. |
| 4 | Optional Nmap and/or Nuclei enrichment through explicitly selected flags and separately authorized subprocess use. | Neither binary is required or implicitly enabled. The operator must approve each tool, its own configuration, and its network effects. |
| 5 | Export of authorized local findings into local fixtures and offline use of the static React dashboard. | The dashboard has no backend or remote network API; fixture data must stay within the authorized audience. |

## 4. Prohibited use

The following uses are prohibited, even when an operator can technically reach the target.

| Prohibited use | Explanation |
| --- | --- |
| Unauthorized discovery, probing, crawling, or enrichment | Do not scan networks, hosts, tenants, guest systems, domains, web paths, customers, neighbors, or third parties without explicit authorization. |
| Internet-wide, public-target, or cloud-range scanning | Do not use Wraith to enumerate or probe public ranges, arbitrary domains, cloud-wide ranges, externally routed networks, or unapproved tenants. |
| Exploitation or attack enablement | Do not deliver exploits, execute commands, alter state, gain persistence, evade detection, or prepare an unauthorized intrusion. |
| Credential testing | Do not guess, spray, reuse, validate, or test passwords, keys, tokens, default credentials, sessions, or other authentication material. |
| Scope expansion through discovery output | Do not follow an unapproved redirect, DNS result, JavaScript endpoint, discovered virtual host, page link, Nmap target, or Nuclei result into a new target scope. |
| Sensitive-content collection or disclosure | Do not intentionally collect, publish, sell, or share credentials, private records, protected resources, or sensitive scan output outside the approved audience. |
| Misrepresenting output | Do not label partial observations as a penetration test, vulnerability assessment, compliance certification, clean bill of health, or proof of exploitability. |
| Unattended or externally integrated operation | Do not use Wraith as a scheduler, daemon, event-triggered scanner, remote API, telemetry service, output-export service, or a vehicle for unreviewed third-party data sources. Existing Phase 2 enumeration sources remain subject to their documented authorization and data-handling limits. |

The exclusions are functional boundaries, not suggestions. A wrapper, plugin, shell command, remote service, or operator workflow that causes a prohibited activity remains prohibited even if the activity is not implemented inside Wraith itself.

## 5. Fail-closed operator rules

The operator **MUST** stop before network activity when the selected interface, local IPv4 address, CIDR, domain scope, target authorization, tool authorization, resource limits, or output destination is missing, invalid, ambiguous, or inconsistent. The operator **MUST NOT** try a nearby range, use a default interface without confirming it, follow a route or redirect outside scope, infer permission from public availability, or continue after a boundary violation.

The operator **MUST** treat hostnames, redirects, banners, service responses, imported target lists, JavaScript, configuration values, and tool output as untrusted data. They **MUST NOT** allow network-provided text to redefine the target boundary, activate a new protocol, add ports, invoke another tool, or create authorization. If an encountered target cannot be confirmed as in scope, the operator **MUST** omit it and report the reason.

If Wraith reports a fail-closed condition, incomplete run, authorization problem, output failure, optional-tool skip, or unsupported test limitation, the operator **MUST** preserve that status in subsequent communication. They **MUST NOT** relabel incomplete observations as a clean result or imply that untested hosts, ports, paths, sources, or vulnerabilities were verified.

## 6. Phase-specific safeguards

### Phase 1 — local discovery

The operator must explicitly select the local interface and IPv4 CIDR, ensure both match the authorization, and limit activity to bounded ARP, the curated top-100 TCP list, and conservative read-only metadata. A capability or permission error for ARP is a stop-and-remediate signal, not permission to bypass operating-system controls.

### Phase 2 — domain and HTTP workflow

Subdomain enumeration, DNS resolution, and HTTP probing can reveal third-party hosting, shared infrastructure, takeover candidates, redirects, or unrelated destinations. The operator must define the allowed domain and web-origin scope before running, avoid SSRF-like pivoting through supplied URLs or redirects, and not treat a resolved IP or external response as an authorized target by default. Storage output may contain operationally sensitive names, headers, and timestamps and must be protected accordingly.

### Phase 3 — content discovery and JavaScript analysis

Content discovery and JavaScript analysis must remain bounded to approved origins and paths. Wraith output can surface strings that resemble credentials, tokens, internal URLs, or implementation details. Such output is a detection signal, not a guarantee that the value is real, active, exploitable, or safe to disclose. Operators must redact, minimize, securely store, and report possible secrets through the owner's approved handling process; they must not validate them by attempting authentication or reuse.

### Phase 4 — optional Nmap and Nuclei enrichment

`--use-nmap` and `--use-nuclei` are opt-in subprocess actions. Before using either, the operator must have explicit authorization for that specific tool and its effect, confirm the executable and version being invoked, understand tool-specific flags/templates, and observe applicable rate, scheduling, and privilege limits. The absence, skip, or failure of either optional binary does not establish that a target is clean or that no vulnerability exists.

### Phase 5 — export fixtures and static dashboard

The export-fixtures command and dashboard are local, read-only presentation workflows, not an authorization bypass. Operators must export only data they may handle, use fixtures from authorized local scans, retain data only as allowed, and ensure the static dashboard is not served or shared with an unapproved audience. The dashboard does not contact a remote service, scan targets, authenticate users, or validate the truth of fixture contents.

## 7. Safe operating practices

Authorized operators should perform runs during an approved maintenance or testing window, coordinate with the asset owner, and use the least aggressive settings that satisfy the stated inventory purpose. They should avoid sensitive or operationally fragile environments unless the owner expressly approves the activity and limits. They should monitor for unexpected impact and stop immediately if the activity causes instability, alarms, service degradation, or other harm.

The operator should keep a record of the authorization, selected scope, Wraith version, phase/feature flags, source and tool versions, run time, scope version, port-list version, input provenance, output recipient, and any deviations or failures. They should store terminal results, JSON, databases, and fixtures according to the owner's data-handling requirements and restrict access because they may reveal operational details.

## 8. What Wraith output does not prove

| Phase | Output does **not** prove |
| --- | --- |
| 1 | That a non-responsive host is absent; that a timeout proves a service is absent; that a successful connection/banner means a service is secure, authorized, current, or vulnerable; or that the network is safe. |
| 2 | That all subdomains were found; that DNS/HTTP reachability establishes ownership or authorization; that a historical change is malicious; or that all assets and technologies are complete. |
| 3 | That all paths or scripts were discovered; that a string is a valid secret; that a discovered endpoint is authorized to assess; or that content findings establish vulnerability or exploitability. |
| 4 | That Nmap/Nuclei output is comprehensive, accurate, exploitable, or a substitute for an authorized vulnerability assessment; that an optional-tool skip or error means no issue exists. |
| 5 | That fixture data is current, complete, authentic, secure to share, or a complete representation of a target's attack surface. |

## 9. Incident and unexpected-impact response

If the operator discovers that a target was not authorized, the selected scope was wrong, a redirect/pivot left scope, or the run exceeded approval, they **MUST** stop immediately, preserve relevant logs and authorization records, notify the appropriate owner or security contact, and follow the organization's incident and disclosure process. They **MUST NOT** continue scanning to gather more evidence, attempt remediation through Wraith, or conceal the scope error.

If activity appears to cause service disruption or other harm, the operator **MUST** stop, notify the affected owner through the agreed channel, and document observed time, scope, settings, optional tools, and impact. Any later investigation or validation **MUST** be separately authorized and must not assume that an earlier Wraith permission extends to new actions.

## 10. Governance and scope changes

Any proposal to add exploitation, credential testing, remote APIs, external data exfiltration, new external data sources, unattended execution, scheduling, scanner fleets, public-target scanning, automated authorization inference, or broader scanning capability requires separate review and an explicit policy update. No operator, configuration file, wrapper, test fixture, deployment environment, or Phase 5 dashboard may silently broaden the approved scope. When a requirement is unclear, pause and seek written clarification or authorization rather than infer permission.

## 11. Operator checklist

Before starting, the operator must be able to answer “yes” to all of the following.

| Check | Required answer |
| --- | --- |
| I own the targets or have explicit, current authorization for the exact planned phase and feature flags. | Yes |
| I have verified the selected interface/CIDR or domain/origin/path scope matches that authorization. | Yes |
| I have separately approved optional Nmap/Nuclei use, if I intend to select either flag. | Yes or not applicable |
| I will not follow output-derived scope expansion, test credentials, exploit, or expose sensitive data. | Yes |
| I understand that results are incomplete observations rather than an assurance or vulnerability finding. | Yes |
| I know how to stop the run and whom to contact if scope, authorization, or service impact becomes uncertain. | Yes |

If any answer is “no” or “not sure,” do not run Wraith.

## References

This is the project's normative responsible-use policy. It intentionally relies on no external factual authority. Tool and privilege behavior is documented in [`support-matrix.md`](support-matrix.md); release and disclosure process limits are documented in [`release-process.md`](release-process.md) and [`SECURITY.md`](../SECURITY.md).
