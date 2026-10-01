# SwarmSec development plan

Canonical copy of this document. Historical research alternatives in [DESIGN.md](DESIGN.md)
that contradict `AGENTS.md` are **not** in scope for the current build.

Sprint 2 remains **libp2p/GossipSub** for inter-node dissemination. HTTP is the local control
plane (registrar API, node query/ingest), not a substitute for GossipSub.

---

Sprint 1 — Registration & credentials (sprint-1-registration)

Read AGENTS.md before starting. Work on branch sprint-1-registration. Do not touch main. Do not
proceed to Sprint 2 until this is reviewed.

Task: registration and credential issuance.

- Ed25519 keypair generation for pseudonym identities (org-side).
- A single registrar service (FastAPI) that: accepts a registration request, records the real-world
  identity against the chosen pseudonym public key internally (this mapping is intentional per
  AGENTS.md — do not try to blind it), and signs a credential for that key with an ordinary Ed25519
  registrar signing key. One registrar key for this build — no threshold signing yet; note that
  simplification explicitly in NOTES.md rather than silently building single-key and calling it done.
- A minimal signed status mechanism: each credential carries a status ("active"/"revoked") and an
  expiry/freshness field, and the registrar can re-sign an updated status. Doesn't need a full
  revocation propagation protocol yet — just prove the primitive exists and is signed, not asserted.
- A hash-chained append-only log of every credential issued, canonicalized per Sprint 0's scheme
  before hashing. Its job is proving the registrar isn't showing different views to different
  observers — not proving vetting was correct, which no outside observer can evaluate anyway.
- Reuse Sprint 0's canonicalization + signing code directly. Do not reimplement it.

Definition of done: an org can register, receive a credential any peer can independently verify
against the registrar's public key, and the credential's entry is present and checkable in the log.
Unit tests for the registrar logic and the log's append-only property specifically. Push, open for
review, do not merge yourself.

Sprint 2 — Gossip & message pipeline (sprint-2-gossip)

Read AGENTS.md before starting. Work on branch sprint-2-gossip. Do not touch main. Do not proceed to
Sprint 3 until this is reviewed.

Task: gossip propagation and the real message format.

- 3+ node containers (Docker Compose) gossiping over libp2p/GossipSub, building on Sprint 0's spike.
- Message format: a constrained STIX 2.1 object (Indicator or Sighting — pick the minimal one that
  covers "org reports this IoC") as the CTI content, wrapped in a separate SwarmSec envelope
  (credential ID, sequence number, timestamp, message ID, signature) per AGENTS.md — two distinct
  objects, never merged into one payload.
- Attach a TLP marking to every report: CLEAR or GREEN only. Do not implement AMBER or RED.
- Canonicalize the envelope (Sprint 0's scheme) before signing every message.
- Peer-side verification before relay: valid signature, valid non-revoked credential (check Sprint
  1's status field), valid rate ticket. Drop anything failing any of these at the first hop.
- Per-epoch rate ticket enforcement: refuse to relay a pseudonym's (N+1)th message in an epoch.
- A report queried before it has independent corroboration displays as
  `UNCONFIRMED — single source, awaiting corroboration`, not a score.

Definition of done: a signed report from one node produces a verified message visible on the other
nodes within about a second, correctly showing UNCONFIRMED. Write a specific test for each of the
three rejection cases (bad signature, revoked credential, exhausted ticket) — provably dropped, not
just assumed dropped. Push, open for review, do not merge.

Sprint 3 — Trust scoring & corroboration (sprint-3-scoring)

Read AGENTS.md before starting. Work on branch sprint-3-scoring. Do not touch main. Do not proceed
to Sprint 4 until this is reviewed.

Task: the trust-scoring model and corroboration.

- One scoring model — a published, fixed-parameter formula, not an ensemble, never randomized per
  node. Write the formula down explicitly in code comments and NOTES.md before implementing it.
- Corroboration matching: exact/near-exact only (same hash, same IP, same specific TTP identifier),
  not fuzzy similarity. Weight a match by how improbable it would be by chance — a specific,
  high-entropy detail counts more than something generic like "this IP is bad."
- A basic independence check: if two reports appear to restate the same public feed rather than
  reflecting separate first-hand observation, flag this rather than silently counting it as two
  independent corroborations. Doesn't need to be sophisticated — needs to exist and be visible.
- Call the output "local corroboration score" or "trust ranking" per AGENTS.md, never "confidence."

Definition of done: corroborating reports from independent nodes visibly move the score in a way
you can explain line-by-line from the formula. A test demonstrating the "same feed, not independent"
case gets flagged rather than scored as genuine corroboration. Push, open for review, do not merge.

Sprint 4 — Feedback & correlated-evidence down-weighting (sprint-4-feedback) — the most important sprint in the build; if it slips, let everything downstream wait rather than moving on around it

Read AGENTS.md before starting. Work on branch sprint-4-feedback. Do not touch main. Do not proceed
to Sprint 5 until this is reviewed.

Task: feedback and correlated-evidence down-weighting.

- Feedback submission: same signed, rate-limited pipeline as reports.
- Reuse Sprint 3's independence-checking against feedback-givers: if feedback for a pseudonym
  disproportionately comes from a small, mutually-clustered set of other pseudonyms, down-weight it.
- Build two attack scripts, not one:
  1. spawn_dense_cluster.sh — several pseudonyms rapidly, densely endorsing each other. Call this
     exactly what it is in comments and docs — not "Sybil resistance" or "collusion detection," see
     AGENTS.md terminology.
  2. spawn_staggered_cluster.sh — same underlying collusion, staggered timing, sparser mutual
     endorsement — closer to what a patient adversary would actually do. Build this even if it's
     less likely to trigger detection as cleanly, and report exactly what it does or doesn't catch.
- Also test a false-positive case: a small set of legitimate, genuinely closely-connected pseudonyms
  (e.g., partner CERTs corroborating through a side channel). Confirm this doesn't get flagged the
  same way, or document clearly if it does — that's a real finding either way, not something to hide.

Definition of done: the dense-cluster script gets caught and down-weighted. The staggered variant's
actual result — caught, partially caught, or missed — is documented honestly, not glossed over. The
false-positive test result is documented the same way. Push, open for review, do not merge.

Sprint 5 — Advisory output & dashboard (sprint-5-interface)

Read AGENTS.md before starting. Work on branch sprint-5-interface. Do not touch main. Do not proceed
to Sprint 6 until this is reviewed.

Task: advisory-only output and the live dashboard.

- CLI output: ranked, annotated, explicitly advisory — every output ends with a clear statement that
  this is not a block/allow decision, a human makes that call.
- A live dashboard (terminal-based `rich`, or a minimal web view if ahead of schedule) showing the
  score update in real time, and clearly flagging when correlated-evidence down-weighting triggers.
- Wire this into a runnable end-to-end script: a clean report, corroboration arriving, then the
  dense-cluster attack from Sprint 4, so the full sequence can actually be demonstrated.

Definition of done: running that script produces the sequence live, three times in a row, with no
manual intervention between stages. Push, open for review, do not merge.

Sprint 6 — Evaluation harness (sprint-6-evaluation)

Read AGENTS.md before starting. Work on branch sprint-6-evaluation. Do not touch main.

Task, if Sprints 1-5 landed on schedule: the evaluation harness, not new features — this is what
makes the project a defensible research claim rather than just a working demo.

- Baselines: a simple quorum/majority-vote scheme, and a conventional source-reputation-only scheme
  (no corroboration or independence checking at all).
- Metrics: false-acceptance rate for poisoned indicators, and time-to-acceptance for legitimate ones
  — proving detection doesn't come at the cost of delaying real reports.
- Run all three (SwarmSec, quorum, plain reputation) against both Sprint 4 attack scenarios and
  report the comparison honestly, including anywhere SwarmSec doesn't clearly win.

If behind schedule instead: skip this sprint's build work and spend the week on the report, which
should already be running in parallel since Sprint 1. No definition of done in the usual sense —
report what got measured and what it actually showed, including any unflattering result.

Sprint 7 — Rehearsal (no branch — this one's yours, not the agent's)

Record a video of the Sprint 5 end-to-end sequence succeeding, as the jury-demo backup. Run the full
presentation on a timer at least twice. Have the Sprint 4 staggered-cluster result and the Sprint 6
comparison numbers ready as direct answers — both are honest, specific things you're likely to be
asked about.
