# SwarmSec — Agent Instructions

SwarmSec is a permissioned peer-to-peer CTI exchange where a registrar verifies organizations and
issues signed pseudonymous credentials. Participants exchange signed STIX 2.1 sightings; each
receiver computes an explainable, local, correlation-aware trust ranking. Architecture: centralized
identity plane, decentralized data-sharing and scoring plane. Full design: `docs/DESIGN.md`. Full
schedule: `docs/DEVELOPMENT_PLAN.md`.

## Build & test
- Python 3.11+, venv at `.venv`; `pip install -r requirements.txt`
- `pytest -v` before considering any task done
- Never commit anything matching `*.key`, `*keystore*`, `.env` — confirm `.gitignore` covers this
  before the first commit of any session

## Hard constraints — these were each proposed and deliberately rejected. If a step seems to call
## for one of these, stop and ask rather than adding it back:
- **No blockchain, no smart contracts, no staking/slashing.** Trust is computed locally by each
  receiving node from corroboration and feedback signals only.
- **No blind signatures.** The registrar knows the org-to-pseudonym mapping and signs credentials
  with ordinary Ed25519. Deliberate, documented trade-off — not an oversight to "fix."
- **One registrar, one community for this build.** Multiple registrar constellations are explicitly
  out of scope; cross-registrar deduplication is unsolved, don't build toward it.
- **One trust-scoring model, not an ensemble.** Published, fixed-parameter formula — auditable and
  reproducible, never randomized per node.
- **No contribution-gated visibility.** Every node holds the full gossiped history; don't build a
  feature that pretends otherwise.
- **STIX 2.1 in a constrained profile** (Indicator, Sighting, Observed-Data-lite, Identity,
  Marking-Definition for TLP CLEAR/GREEN only — no AMBER/RED). CTI content and the SwarmSec
  transport envelope (credential ID, sequence number, timestamp, message ID, signature) are separate
  objects, never merged into one payload.
- **Canonicalize before signing, always** — RFC 8785 JSON Canonicalization on the envelope before
  Ed25519 signing. Not optional; skipping it produces bugs that look fine until two serializations
  of the same object fail to verify against each other.

## Terminology
"Credentialed collusion resistance," not "Sybil resistance." "Local corroboration score" or "trust
ranking," not "confidence." "Correlated-evidence down-weighting," not "collusion detection."

## Working style
Plan before executing anything spanning more than one module, and stop for review before writing
code once you have. Write each test alongside the code it covers, not after. If something in
`docs/DESIGN.md` turns out wrong or intractable while building it, say so explicitly and explain why
— don't silently deviate.

