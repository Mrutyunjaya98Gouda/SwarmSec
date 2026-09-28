# SwarmSec — Stated Simplifications & Design Notes

This file documents deliberate simplifications made during implementation. Each is a conscious
trade-off, not an oversight — recorded here so reviewers and future work can see exactly what
was scoped out and why.

## Sprint 1

### Single registrar signing key (not 2-of-3 threshold)

The design doc calls for internal 2-of-3 threshold signing per registrar. For this build, the
registrar uses a single Ed25519 signing key. Threshold signing is deferred — it's a well-understood
technique (proactive secret sharing) that doesn't affect the rest of the architecture.

### Pre-seeded allowlist (not real KYC vetting)

Registration is gated by a pre-seeded allowlist of org identifiers rather than a real vetting
process. This is a defensible simplification for demo purposes — the registration gate's purpose
(preventing unvetted pseudonyms) is demonstrated without building actual identity verification.

### JSON-lines log storage (not a database)

The transparency log is stored as a JSON-lines file. Sufficient for demo scale; a production
deployment would use an append-only database or a Merkle tree.

### No credential revocation propagation protocol

The signed revocation primitive exists (the registrar can re-sign a credential with status
"revoked"), but there is no protocol yet for propagating revocation status to peers in real time.
Peers must query the registrar to check current status. A gossip-based revocation propagation
mechanism is future work.

## Sprint 3

### Fixed-Parameter Trust Scoring Formula

Trust scoring is computed locally by each node using a fixed, deterministic formula based purely on corroboration.

**Formula Definition:**
1. Base score for a newly seen indicator from a single source = 0 (Displays as UNCONFIRMED).
2. For each additional report (corroboration) of the exact same indicator from a *distinct pseudonym*:
   - If the new report shares the exact same `external_references[0].url` (feed source) as any previous report, it is flagged as `not_independent`. Its corroboration weight is `0.0`.
   - If it is independent, its weight depends on the indicator's specificity (entropy):
     - High-entropy (e.g., file hashes like `file:hashes.'SHA-256'`): Weight = `1.0`.
     - Medium-entropy (e.g., specific URLs or malware families): Weight = `0.8`.
     - Low-entropy (e.g., generic IPs like `ipv4-addr:value`): Weight = `0.5`.
3. Total `local_corroboration_score` = Sum of independent weights.

This ensures that generic claims require more independent observers to reach high trust rankings than highly specific, hard-to-guess claims.
