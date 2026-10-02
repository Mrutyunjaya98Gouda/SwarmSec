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

## Sprint 4

### Feedback Pipeline

Feedback uses STIX 2.1 Opinion objects (`StixOpinion`) with `opinion` field values from
`strongly-agree | agree | neutral | disagree | strongly-disagree`. Feedback goes through the
same signed, rate-limited gossip pipeline as indicator reports — it is not a separate channel.

### Correlated-Evidence Down-Weighting Formula

Three signals are combined to detect coordinated feedback from clustered pseudonyms:

1. **Repeat endorsement penalty**: If a giver endorses the same target multiple times,
   penalty = `(endorsements_to_target - 1) / (total_endorsements - 1)`.
2. **Mutual endorsement amplification**: If the target also endorses the giver (bidirectional edge),
   the repeat penalty is amplified. Even a single mutual endorsement contributes a weak signal (0.1).
3. **Cluster density penalty**: For each of the giver's other endorsement targets, check if they
   *also* endorse the same target. The ratio of such mutual endorsers to total other targets gives
   the cluster density. Contribution = `cluster_density * 0.5`.

Final weight = `max(0.0, 1.0 - repeat_penalty - mutual_amplification - cluster_penalty)`.

### Dense Cluster Attack Results

The dense cluster scenario (4 pseudonyms, each endorsing every other's indicator) is **caught and
down-weighted**. The cluster density signal detects that all of a giver's endorsees also endorse
each other — a strong indicator of coordinated behavior.

### Staggered Cluster Attack Results — Honest Assessment

The staggered variant (~50% endorsement coverage, staggered timing, camouflage endorsements to
non-cluster indicators) is **not reliably detected** by the current fixed-parameter formula. With
sparse coverage and decoy endorsements diluting the concentration ratio, the cluster density metric
does not reach the threshold needed to trigger down-weighting.

This is a documented, honest limitation. Potential improvements for future work:
- Time-window velocity analysis (detecting bursts of endorsements within short periods)
- Graph community detection algorithms (Louvain, label propagation)
- Endorsement entropy scoring (low-diversity endorsement patterns even when sparse)

### False-Positive Assessment

**Legitimate closely-connected pseudonyms** (e.g., partner CERTs who collaborate through a side
channel) are **not flagged** as long as their endorsement patterns are diverse — i.e., they endorse
indicators from many different pseudonyms, not just each other.

**Known limitation**: Two pseudonyms that exclusively and repeatedly endorse *only each other* and
nobody else will be down-weighted. This is structurally indistinguishable from a two-node colluding
cluster. The system cannot differentiate exclusive mutual endorsement from collusion without
external context. This is a conscious trade-off: accepting a false-positive on exclusively mutual
endorsers in exchange for reliably catching dense coordinated clusters.

## Sprint 5

### Advisory Output and Human Decision Gating

Per `AGENTS.md`, SwarmSec is strictly advisory: it ranks and annotates local corroboration, but
never makes automated block/allow containment decisions.

All CLI commands (`query`, `feed`, `submit`, `feedback`) and terminal dashboard screens terminate with
or prominently display the mandatory operational disclaimer:
> "ADVISORY ONLY: SwarmSec computes local corroboration scores and trust rankings.
> This output is NOT an automated block/allow decision; a human analyst must make that call."

### Terminal Live Dashboard (`swarmsec.cli.dashboard`)

Built with `rich`:
- **Header**: Active node status, connected peers count, total indicators, and total gossiped messages.
- **Ranked Feed Table**: Displays indicators ranked descending by `local_corroboration_score`, independent sources count, and clear flags.
- **Credentialed Collusion Resistance Alert**: Dynamically triggers when the correlated-evidence down-weighting formula reduces scores, detailing the affected pattern, report count, and feedback count.
- **Operational Advisory Footer**: Persistent disclaimer banner.

### End-to-End Demonstration (`scripts/demo_end_to_end.sh`)

An automated bash harness that executes the entire end-to-end lifecycle on isolated daemons:
1. **Stage 1 (Clean single source)**: Org A reports an indicator; status displays `UNCONFIRMED` (score 0.00).
2. **Stage 2 (Independent corroboration)**: Org B and Org C report the same indicator; score advances to 2.00, status displays `CONFIRMED`, and status remains `CLEAN`.
3. **Stage 3 (Dense-cluster attack)**: 4 colluding pseudonyms densely cross-endorse; correlated-evidence down-weighting triggers (`TRIGGERED`), and the terminal dashboard displays the active collusion alert panel.

**Definition of Done Verification**:
The end-to-end script was run with 3 consecutive iterations (`./scripts/demo_end_to_end.sh 3`), completing all stages with zero manual intervention.


