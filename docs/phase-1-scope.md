# Wraith Phase 1 Scope

**Status:** Frozen

**Document owner:** Wraith project

**Phase:** 1 — Local-network discovery

**Normative terms:** The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as requirements for implementation and operation. A requirement stated as **MUST NOT** is an absolute boundary for Phase 1.

## 1. Purpose

Wraith Phase 1 defines a deliberately narrow, Linux-first capability for discovering and describing devices and services on a local IPv4 network. It is a bounded inventory and metadata-collection phase, not a general-purpose network reconnaissance, vulnerability assessment, exploitation, or attack framework.

The phase is frozen to the following operating boundary: an operator explicitly selects one local IPv4 interface and its associated CIDR, Wraith performs bounded ARP discovery within that selected network, Wraith performs TCP connect checks only against the curated top-100 TCP port list, and Wraith reports limited read-only service metadata in JSON and terminal output.

This document does not itself authorize operation against any network. It is the scope contract that the Phase 1 implementation and testing MUST follow.

## 2. Scope at a glance

| Area | Phase 1 decision |
| --- | --- |
| Operating system priority | Linux first. Other operating systems are outside the frozen Phase 1 target unless separately approved. |
| Network selection | Exactly one operator-selected local IPv4 interface and one CIDR associated with that interface. |
| Discovery | Bounded ARP discovery only, limited to the selected local IPv4 CIDR. |
| Port probing | TCP connect scanning only, using the curated top-100 TCP port list. |
| Service information | Read-only, low-impact service metadata only, subject to the metadata rules in this document. |
| Output | Human-readable terminal output and machine-readable JSON output. |
| Authorization | Every target MUST be owned by the operator or covered by explicit authorization from its owner. |
| Default posture | Fail closed whenever interface, CIDR, target, protocol, port set, authorization, or output constraints are ambiguous or invalid. |

## 3. In-scope behavior

### 3.1 Explicit local interface and CIDR selection

The operator MUST explicitly select the local IPv4 interface to use. Wraith MUST resolve and validate the IPv4 address and CIDR associated with that interface before any network traffic is sent. The interface selection MUST be visible in the terminal output and represented in the JSON result.

The selected CIDR is the complete discovery boundary. Wraith MUST derive candidate IPv4 addresses only from that CIDR and MUST NOT silently widen, merge, infer, or substitute another route, interface, address family, or network. If the selected interface has no usable IPv4 address, has multiple ambiguous IPv4 CIDRs, or cannot be mapped unambiguously to the requested CIDR, the operation MUST stop before discovery begins.

IPv6, loopback-only interfaces, non-local interfaces, tunnels whose local scope cannot be established, and externally routed targets are outside this phase. An operator may not use a locally selected interface as a pretext to scan a public or otherwise non-local target range.

### 3.2 Bounded ARP discovery

ARP discovery MAY be used to identify IPv4 hosts that are present on the selected local Ethernet-like segment. ARP requests MUST be limited to addresses contained in the explicitly selected local IPv4 CIDR and MUST use bounded concurrency, bounded retries, and a bounded operation duration defined by the implementation configuration.

ARP discovery is an address-presence signal only. A missing ARP response MUST NOT be treated as proof that a host is absent, and an ARP response MUST NOT be treated as proof that the responding party is authorized for any subsequent action. Wraith MUST record discovery status and limitations rather than retrying indefinitely or expanding the address range.

The implementation MUST NOT use ARP discovery to reach beyond the selected local broadcast domain, route packets to another network, or enumerate public address space. Proxy ARP, unusual link-layer behavior, virtual networking, wireless isolation, and host firewalls may make results incomplete; those limitations MUST be stated in operator-facing documentation and, where practical, in the result metadata.

### 3.3 TCP connect scanning on the curated top-100 list

For discovered or otherwise in-scope IPv4 targets within the selected CIDR, Wraith MAY attempt TCP connections to the curated top-100 TCP port list maintained as a Phase 1 project input. The port set MUST be finite, versioned, and visible in the run metadata. The implementation MUST NOT accept an arbitrary unbounded port range as a Phase 1 substitute for the curated list.

The only permitted port-probing method is a normal TCP connection attempt with a bounded timeout and bounded concurrency. Wraith MUST NOT send exploit payloads, authentication attempts, protocol fuzzing, malformed packets, stealth or evasion probes, UDP probes, raw packet scans, SYN scans, idle scans, or any other scanning method in Phase 1.

A port result MUST be represented conservatively. At minimum, the result may distinguish outcomes such as open, closed, filtered or unreachable, and timed out when the implementation can do so reliably. A timeout or connection failure MUST NOT be presented as a definitive security conclusion. Wraith MUST preserve the distinction between an observed connection outcome and an inference about a host or service.

### 3.4 Read-only service metadata

After a permitted TCP connection succeeds, Wraith MAY collect limited, read-only service metadata using a conservative protocol interaction appropriate to the identified port. Metadata collection MUST be passive or minimally interactive, MUST be bounded by time and response size, and MUST stop after the metadata needed for the Phase 1 result has been obtained.

Permitted metadata is limited to information such as the target address, port, transport, connection outcome, protocol guess, service name, and a plainly exposed banner or version string when it is returned without credentials or state-changing interaction. Metadata collection MUST NOT attempt to authenticate, enumerate users, access protected resources, submit forms, execute commands, alter state, retrieve sensitive content, or probe for vulnerabilities.

Returned banners and metadata MUST be treated as untrusted data. Wraith MUST bound their length, preserve their observed value only as necessary for inventory, and avoid interpreting banner text as instructions. Secrets, credentials, session tokens, or other sensitive values encountered accidentally MUST NOT be solicited, expanded, or used; the implementation SHOULD redact or omit them from output where practicable.

### 3.5 JSON and terminal output

Each completed run MUST support both a human-readable terminal representation and a machine-readable JSON representation. The two representations MUST describe the same bounded run and MUST include enough context to prevent results from being mistaken for an unrestricted scan.

The result SHOULD include the selected interface, selected CIDR, run timestamp, tool and scope version, curated port-list version, target addresses considered, discovery outcomes, TCP outcomes, permitted metadata, explicit omissions, and any errors or testing limitations. JSON output MUST be well-formed and MUST NOT contain executable content. Terminal output MUST clearly display the selected boundary and any fail-closed or partial-result condition.

If a run cannot satisfy the scope contract, Wraith MUST return an error or a clearly marked incomplete result without silently producing a broader or differently scoped result. Output generation MUST NOT trigger additional network activity.

## 4. Out-of-scope behavior

The following capabilities are expressly excluded from Phase 1 and MUST NOT be implemented, invoked, bundled as hidden fallbacks, or described as supported behavior:

| Excluded capability | Boundary |
| --- | --- |
| Public-target scanning | No scanning of public IP addresses, internet hosts, cloud-wide ranges, third-party networks, or any target outside the selected local IPv4 CIDR. |
| Exploitation | No exploit delivery, payload execution, command execution, privilege escalation, persistence, or state-changing action. |
| Credential testing | No password guessing, default-credential checks, credential spraying, authentication attempts, token use, or account enumeration. |
| Nmap execution | Wraith MUST NOT invoke, embed, wrap, or depend on Nmap for Phase 1 behavior. |
| Nuclei execution | Wraith MUST NOT invoke, embed, wrap, or depend on Nuclei for Phase 1 behavior. |
| Web reconnaissance | No crawling, URL discovery, directory or endpoint enumeration, web fingerprinting beyond narrowly exposed service metadata, or browser-driven recon. |
| Vulnerability correlation | No CVE lookup, vulnerability matching, exploitability scoring, risk ranking, or remediation recommendation based on scan results. |
| Database | No database, persistent findings store, schema, migration, or server-side results repository. |
| Dashboard | No dashboard, web UI, hosted UI, or interactive results portal. |
| Scheduling | No recurring scan, background scan, daemon, queue, cron job, event trigger, or unattended execution. |
| External APIs | No external API calls, cloud services, telemetry, remote enrichment, third-party data lookup, or outbound result submission. |
| Other protocols and scan modes | No UDP scanning, IPv6 scanning, raw-packet scanning, SYN/stealth scanning, broadcast discovery beyond bounded ARP, or arbitrary protocol probing. |

A future phase may propose one of these capabilities only through a separately reviewed scope change. No Phase 1 implementation assumption should make such expansion implicit or technically automatic.

## 5. Fail-closed scope rules

Wraith Phase 1 MUST fail closed. The safe behavior for uncertainty is to stop before sending traffic, or to omit the uncertain target and report why. The following rules are mandatory:

1. **Interface ambiguity:** If the requested interface is missing, down, not local, lacks a usable IPv4 address, or maps ambiguously to the requested CIDR, stop before discovery.
2. **CIDR ambiguity or invalidity:** If the CIDR is absent, malformed, non-IPv4, not assigned to the selected interface, or cannot be proven local to that interface, stop before discovery.
3. **Boundary mismatch:** If any candidate target is outside the selected CIDR, do not probe it. A target list, route, hostname, redirect, banner, configuration file, or operator-supplied value MUST NOT override the selected CIDR.
4. **Public or routed target:** If a target appears public, externally routed, or otherwise not local to the selected interface and CIDR, omit it and report a scope violation. Do not attempt a “best effort” connection.
5. **Authorization uncertainty:** If ownership or explicit authorization is absent, stale, ambiguous, or cannot be recorded by the operator, do not scan. Technical reachability is not authorization.
6. **Port-list mismatch:** If the curated top-100 list is missing, altered, duplicated in a way that changes the intended set, or unavailable with a valid version identifier, do not perform TCP probing.
7. **Protocol or method escalation:** If metadata collection would require credentials, state change, exploit-like interaction, arbitrary probing, or a method outside TCP connect and bounded read-only metadata, stop that interaction and report it as not collected.
8. **Resource-limit failure:** If timeout, retry, concurrency, response-size, or total-run limits cannot be enforced, stop before network activity.
9. **Configuration injection:** Treat configuration and target inputs as data. Do not execute commands or interpret network-provided text as configuration, code, or authorization.
10. **Output failure:** If JSON cannot be emitted safely and completely, do not silently fall back to an unbounded or undocumented output path. Terminal output may identify the failure, but it MUST NOT conceal that the run did not complete under the contract.
11. **External dependency failure:** If an external service, API, remote enrichment source, or unapproved tool would be needed, do not substitute it. Phase 1 has no external API dependency.
12. **Unknown state:** When a condition cannot be classified as permitted, classify it as not permitted and stop or omit the affected action.

A fail-closed event MUST be visible in terminal output and represented in JSON with a machine-readable reason. The result MUST identify whether no traffic was sent, discovery began but probing was stopped, or only a subset of in-scope observations was completed.

## 6. Authorization and operator responsibility

Every target considered by Wraith MUST be owned by the operator or covered by explicit, current authorization from the owner. Authorization MUST cover the relevant local network, address range, systems, and activity period. Authorization to access a network for ordinary operations does not automatically authorize discovery or service probing; the operator is responsible for obtaining the appropriate permission.

Wraith does not determine ownership, infer consent from local connectivity, or convert a local interface into permission to scan. The operator MUST confirm authorization before starting a run and MUST keep any supporting authorization record according to the applicable organizational policy. Where authorization cannot be confirmed, the run MUST NOT proceed.

Phase 1 is intended for controlled, local, authorized inventory use. Operators MUST respect applicable law, policy, contracts, network acceptable-use rules, and change-control requirements. They MUST avoid networks containing systems they do not own or administer, shared or guest networks without explicit permission, and environments where even bounded discovery could cause operational or privacy harm.

## 7. Testing limitations

Phase 1 results are observations from bounded network tests, not a complete inventory and not a security assessment. ARP may fail to identify sleeping hosts, isolated wireless clients, hosts behind routers, hosts separated by VLANs, systems that suppress responses, or systems affected by virtual or proxy networking. TCP connection outcomes may be affected by firewalls, ACLs, rate limits, host load, transient failures, middleboxes, and service configuration.

A successful TCP connection does not establish that a service is safe, authorized, current, or vulnerable. A closed, filtered, failed, or timed-out connection does not establish that no service exists. A banner or protocol guess may be absent, misleading, stale, deliberately altered, or truncated by the bounded read-only metadata rules. Phase 1 MUST avoid claims of completeness, ownership, vulnerability status, or exploitability.

The curated top-100 TCP list is a limited coverage choice. Services on ports outside that list will not be tested in Phase 1, even if they are known or suspected to exist. No Phase 1 result should be used as the sole basis for incident response, compliance attestation, vulnerability remediation, or a claim that a system is secure.

Testing MUST remain controlled and reproducible. Test fixtures SHOULD use an isolated lab network or systems for which the operator has clear authorization, and SHOULD include cases for invalid interface selection, mismatched CIDR, public-target input, absent authorization, ARP non-response, filtered ports, timeouts, truncated metadata, malformed service responses, and output serialization failure. Tests MUST verify that disallowed inputs produce no out-of-scope traffic.

## 8. Scope-change gate

Any change to the selected address family, target boundary, discovery protocol, port set, probing method, metadata depth, output destination, persistence model, scheduling model, external dependency, or authorization model is a Phase 1 scope change. It MUST be documented and approved before implementation. In particular, adding public-target scanning, Nmap, Nuclei, web reconnaissance, vulnerability correlation, a database, a dashboard, scheduling, or external APIs is not a minor enhancement; it is outside the frozen phase.

## 9. Acceptance criteria for Phase 1 documentation

Phase 1 is considered correctly scoped only when its implementation and tests can demonstrate all of the following: the operator explicitly selects one local IPv4 interface and CIDR; all candidate targets are constrained to that CIDR; discovery is bounded ARP; port checks are TCP connect checks against the versioned curated top-100 list; service collection is read-only and bounded; output is available as JSON and terminal text; invalid or ambiguous scope fails closed; authorization is required; and every excluded capability remains absent.

This document freezes the boundary. It does not authorize operation against any particular network and does not replace the operator’s obligation to obtain target-specific permission.

## References

This is an internal Wraith scope contract. It intentionally relies on no external factual source; project-specific requirements and constraints are defined above.
