# T2 Scope Model

T2 introduces `internal/scope` as the one **authoritative decision model** for project target boundaries. It consumes a T1 authorization record by reference and preserves R1 as the existing policy-owner adapter during migration; it does not perform transport, DNS, or execution.

The model normalizes only explicit HTTP(S) targets, strips fragments, rejects credentials and ambiguous encodings, and evaluates typed host/IP/CIDR/scheme/port/path rules. Allow rules establish positive membership, deny rules override every allow match, and an authorization must exactly bind the project, scope version/reference, and canonical scope fingerprint.

R3 remains the transport owner. Its redirect and resolver paths supply each redirect target or resolved IP to the same authority decision; no initial authorization is inherited by a later destination.
