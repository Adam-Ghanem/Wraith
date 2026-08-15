# Wraith Responsible Use Policy

**Status:** Frozen for Phase 1

**Document owner:** Wraith project

**Applies to:** Wraith Phase 1 local-network discovery

**Normative terms:** The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** state requirements for authorized use and implementation. **MUST NOT** is an absolute prohibition.

## 1. Policy statement

Wraith Phase 1 is a narrowly bounded tool for authorized, local IPv4 network inventory. It is designed to help an operator identify reachable devices and expose limited service metadata on a specifically selected local interface and CIDR. It is not a general reconnaissance platform, vulnerability scanner, exploitation tool, credential-testing tool, or internet-scanning service.

Use of Wraith is permitted only when every target is owned by the operator or is covered by explicit, current authorization from the owner. Local network visibility, technical reachability, employment access, Wi-Fi access, or possession of an IP address does not by itself establish authorization to discover or probe a target.

The operator is responsible for confirming permission, selecting the correct local interface and CIDR, staying within the frozen Phase 1 boundary, protecting output, and stopping the run if scope or authorization becomes uncertain.

## 2. Authorized-use requirement

Before each run, the operator MUST have a reasonable, documented basis to conclude that the selected local IPv4 network and all targets within the intended scope are authorized for bounded ARP discovery, TCP connect checks on the curated top-100 TCP list, and limited read-only service metadata collection.

Authorization SHOULD identify the owner or responsible organization, the network or CIDR covered, the systems or target population covered, the permitted activity, the start and end of the authorization period, and any operational restrictions such as maintenance windows, rate limits, or excluded hosts. If the authorization is narrower than the selected CIDR, the operator MUST reduce the target scope or refrain from running Wraith.

| Authorization condition | Required action |
| --- | --- |
| The operator owns or administers the entire selected network and the activity is permitted by applicable policy | The operator may proceed, subject to all Phase 1 limits. |
| A third party owns some or all of the selected network | Obtain explicit authorization covering the intended discovery and probing before proceeding. |
| Authorization excludes discovery, service probing, particular hosts, or the selected time | Do not run against the excluded scope; narrow the run or do not proceed. |
| Authorization is expired, ambiguous, verbal without a reliable record, or unavailable | Treat authorization as unconfirmed and fail closed. |
| The selected CIDR contains unknown, guest, shared, or third-party systems | Do not scan those systems unless the authorization expressly covers them. |

Wraith MUST NOT be used to test whether a network owner notices scanning, to discover systems for later unauthorized access, or to create evidence of “permission” from the fact that packets received a response.

## 3. Permitted Phase 1 activity

Authorized operation is limited to one explicitly selected local IPv4 interface and its explicitly selected local IPv4 CIDR. Within that boundary, the operator may perform bounded ARP discovery, followed by bounded TCP connect checks against the versioned curated top-100 TCP port list. The operator may collect limited read-only service metadata when it is exposed through a conservative, bounded interaction that does not require credentials or change state.

Results may be rendered to the terminal and serialized as JSON for local, authorized use. Output should identify the selected interface and CIDR, the scope and port-list versions, timestamps, observed outcomes, errors, omissions, and testing limitations so that a reader cannot mistake the result for an unrestricted or complete security assessment.

## 4. Prohibited use

The following uses are prohibited under this policy, even when an operator can technically reach the target:

| Prohibited use | Explanation |
| --- | --- |
| Public-target or internet scanning | Do not scan public IP addresses, internet hosts, externally routed ranges, cloud-wide ranges, or any network outside the selected local IPv4 CIDR. |
| Unauthorized discovery | Do not scan networks, hosts, tenants, guests, neighbors, customers, or third parties without explicit authorization. |
| Exploitation or attack enablement | Do not use Wraith to deliver exploits, execute commands, alter state, gain persistence, evade detection, or prepare an unauthorized intrusion. |
| Credential testing | Do not guess, spray, reuse, validate, or test passwords, keys, tokens, default credentials, or other authentication material. |
| Nmap or Nuclei operation | Do not invoke, wrap, embed, or substitute Nmap or Nuclei within a Phase 1 run. |
| Web reconnaissance | Do not crawl websites, enumerate URLs, directories, endpoints, forms, or web content. |
| Vulnerability correlation | Do not turn Phase 1 output into CVE matches, exploitability conclusions, risk scores, or remediation claims. |
| Unbounded probing | Do not replace the curated top-100 TCP list, bounded ARP process, or read-only metadata rules with arbitrary ports, protocols, retries, rates, or payloads. |
| Data exfiltration or enrichment | Do not send results to external APIs, cloud services, telemetry systems, remote databases, or third-party enrichment services. |
| Persistence and unattended execution | Do not use Phase 1 for scheduled scans, daemons, background jobs, event-triggered scans, or other unattended activity. |
| Privacy-invasive collection | Do not seek sensitive content, credentials, personal records, protected resources, or data beyond the limited service metadata expressly permitted. |

The exclusions are functional boundaries, not suggestions. A wrapper, plugin, shell command, remote service, or operator workflow that causes a prohibited activity remains prohibited even if the activity is not implemented inside Wraith itself.

## 5. Fail-closed operator rules

The operator MUST stop before network activity when the selected interface, local IPv4 address, CIDR, target authorization, port-list version, or resource limits are missing, invalid, ambiguous, or inconsistent. The operator MUST NOT “try a nearby range,” use a default interface without confirming it, follow a route outside the CIDR, or continue after a boundary violation.

The operator MUST treat hostnames, redirects, banners, service responses, imported target lists, and configuration values as untrusted data. They MUST NOT allow network-provided text to redefine the target boundary, activate a new protocol, add ports, invoke another tool, or create authorization. If an encountered target cannot be confirmed as within the selected authorized CIDR, the operator MUST omit it and report the reason.

If Wraith reports a fail-closed condition, an incomplete run, an authorization problem, an output failure, or an unsupported test limitation, the operator MUST preserve that status in any subsequent communication. They MUST NOT relabel incomplete observations as a clean result or imply that untested hosts and ports were verified.

## 6. Safe operating practices

Authorized operators SHOULD perform runs during an approved maintenance or testing window, coordinate with the network owner, and use the least aggressive settings that satisfy the inventory purpose. They SHOULD avoid sensitive or operationally fragile environments unless the owner has expressly approved the activity and its limits. They SHOULD monitor for unexpected impact and stop immediately if the activity causes instability, alarms, service degradation, or other harm.

The operator SHOULD keep a record of the authorization, selected interface and CIDR, run time, Wraith version, scope version, curated port-list version, and any deviations or failures. They SHOULD store JSON and terminal results according to the owner’s data-handling requirements and restrict access because service metadata may reveal operational details.

Wraith output MUST be treated as potentially sensitive operational information. Operators MUST NOT publish, sell, or share results outside the authorized audience without the owner’s permission. They MUST redact or securely delete results when the authorization or retention period requires it.

## 7. Interpretation of results

Wraith observations are limited and may be incomplete. An ARP non-response does not prove that a host is absent; a TCP timeout or filtered result does not prove that a service is absent; and a successful connection or banner does not prove that a service is secure, authorized, current, or vulnerable. A Phase 1 run MUST NOT be represented as a penetration test, vulnerability assessment, compliance certification, or assurance that a network is safe.

The operator MUST communicate material limitations, including VLAN or routing boundaries, wireless isolation, host firewalls, proxy ARP, sleeping systems, rate limiting, transient connectivity, incomplete port coverage, metadata truncation, and any fail-closed omissions. When a security conclusion is needed, the owner should use a separately authorized assessment process designed for that purpose.

## 8. Incident and unexpected-impact response

If the operator discovers that a target was not authorized, the selected interface or CIDR was wrong, or the run exceeded the approved boundary, they MUST stop the run immediately, preserve relevant logs and authorization records, notify the appropriate owner or security contact, and follow the organization’s incident and disclosure procedures. They MUST NOT continue scanning to gather more evidence, attempt remediation through Wraith, or conceal the scope error.

If the activity appears to cause service disruption or other harm, the operator MUST stop the activity, notify the affected owner through the agreed channel, and document the observed time, scope, settings, and impact. Any later investigation or validation MUST be separately authorized and must not assume that Phase 1 permissions extend to new actions.

## 9. Governance and scope changes

This policy is part of the frozen Phase 1 boundary. Any proposal to add public-target scanning, exploitation, credential testing, Nmap, Nuclei, web reconnaissance, vulnerability correlation, a database, a dashboard, scheduling, external APIs, additional protocols, broader address families, or unattended execution requires a separately reviewed phase and an explicit policy update.

No operator, configuration file, wrapper, test fixture, or deployment environment may silently broaden Phase 1. When a requirement is unclear, the correct policy decision is to pause and seek written clarification or authorization rather than infer permission.

## 10. Operator checklist

Before starting, the operator MUST be able to answer “yes” to all of the following:

- I own the targets or have explicit, current authorization covering the selected network and the planned Phase 1 activity.
- I have explicitly selected the correct local IPv4 interface and CIDR, and I have verified that they match the authorization.
- The run will remain within that CIDR and will use only bounded ARP, TCP connect checks on the curated top-100 list, and limited read-only service metadata.
- I will not use public-target scanning, exploitation, credential testing, Nmap, Nuclei, web reconnaissance, vulnerability correlation, a database, a dashboard, scheduling, or external APIs.
- I understand that the results are partial observations, not a vulnerability assessment or security guarantee.
- I know how to stop the run and who to contact if authorization, scope, or service impact becomes uncertain.

If any answer is “no” or “not sure,” do not run Wraith.

## References

This is an internal Wraith responsible-use policy. It intentionally relies on no external factual source; the authorization and operating requirements are defined above.
