# SwarmSec — Complete Project Document

A decentralized, peer-to-peer threat-intelligence sharing system, designed to solve a specific failure in
how the security industry shares information today: organizations that detect an attack are often
reluctant to disclose it, for fear of reputational damage, which lets the same infrastructure and
techniques get reused against the next victim. This is the complete, final record of the project —
architecture, the decisions made and rejected along the way, the development plan, and the jury
presentation — consolidated into one document.

**Contents:** Overview · The Problem · Why Existing Solutions Fall Short · Core Design Insight ·
Architecture · Threat Lifecycle · Design Evolution · Gap-Closing Table · What's Actually Novel ·
What's Still Genuinely Open · Final Pre-Build Review · Technology Stack · Development Plan ·
Jury Presentation & Demo Script · Final Pre-Jury Checklist

---

## The Problem

When a company gets hit, the fastest way to protect everyone else is to share what they saw — but
admitting a breach costs reputation, so most organizations sit on it, and the same attack infrastructure
gets reused against the next victim.

## Why Existing Solutions Fall Short

- **MISP** already does anonymized, trust-group threat-intel sharing, for free, at real scale. It solves
  *sharing*. It doesn't solve the *fear* — visibility is still scoped to who's in your trust group, and
  there's no portable, cross-organization reputation that survives without exposing who you are.
- **PolySwarm** already does blockchain-based staking on threat verdicts, live since 2018. It works
  *because* file/malware verdicts are sandbox-checkable — there's an actual ground truth to slash against.
  Most IoCs (a suspicious IP, a TTP pattern) aren't independently checkable that way by a stranger. That's
  the specific gap SwarmSec targets.

## Core Design Insight

Reputation and anonymity were treated as the same goal in the earliest version of this design, and they're
not. **Anonymity** means no two of your actions are ever linkable to each other. **Reputation** requires
the opposite — a persistent identity you can track over time. Trying to build the second on top of the
first is close to a category error, and it's why the original design broke.

**Pseudonymity** is the actual target: persistent and linkable to itself, but never linked to real-world
identity. That single distinction is the load-bearing idea in this whole system — reputation can only be
built on it, and almost every other design contradiction in earlier versions traces back to not having made
this distinction explicitly.

True anonymity (unlinkable even across your own actions) still has a place — as an optional, explicitly
reputation-free mode for rare one-off disclosures — but it's the exception, not the default.

---

## Architecture

```
+--------------------------------------------------------------------+
|                          SWARMSEC NETWORK                          |
|                                                                      |
|   +------------+      +------------+      +------------+           |
|   |   Node A   |      |   Node B   |      |   Node C   |           |
|   |            |<---->|            |<---->|            |           |
|   | pseudonym  |      | pseudonym  |      | pseudonym  |           |
|   | keypair    |      | keypair    |      | keypair    |           |
|   | (Ed25519)  |      | (Ed25519)  |      | (Ed25519)  |           |
|   |            |      |            |      |            |           |
|   | gossip     | GossipSub / libp2p, no chain in this path         |
|   |            |      |            |      |            |           |
|   | 3-model    |      | 3-model    |      | 3-model    |           |
|   | LOCAL trust|      | LOCAL trust|      | LOCAL trust|           |
|   | scorer     |      | scorer     |      | scorer     |           |
|   | (randomized|      | (randomized|      | (randomized|           |
|   |  params —  |      |  params —  |      |  params —  |           |
|   |  no two    |      |  no two    |      |  no two    |           |
|   |  nodes must|      |  nodes must|      |  nodes must|           |
|   |  agree)    |      |  agree)    |      |  agree)    |           |
|   +------------+      +------------+      +------------+           |
+--------------------------------------------------------------------+
                              |
              rare: one-time registration + periodic transparency log
                              v
   +----------------------------------------------------------------+
   |     REGISTRAR CONSTELLATION(S)  (consumers pick which to trust)  |
   |  - internal 2-of-3 threshold signing per registrar (HSM-backed) |
   |  - vets an org's real-world legitimacy ONCE                    |
   |  - blind-signs that org's chosen pseudonym key                 |
   |  - EVERY issued credential published to a public, append-only, |
   |    hash-chained transparency log — misissuance is mechanically |
   |    detectable by anyone, not adjudicated by a governance vote  |
   +----------------------------------------------------------------+
                              |
                              v   (Phase 3, optional)
   +----------------------------------------------------------------+
   |     CHECKPOINT ANCHOR  (tiny contract, cheap L2)                 |
   |     stores only: date + log root + registrar signatures         |
   |     no staking. no slashing. no per-IoC voting.                 |
   +----------------------------------------------------------------+
```

### Registration & registrar integrity

Rather than fortifying a single K-of-N consortium with economic stake, SwarmSec hardens the registrar layer
three ways:

1. **Internal threshold signing per registrar.** Each registrar's signing authority is itself a 2-of-3
   threshold key, held by separate officers or HSMs. A single compromised laptop or leaked credential can
   no longer issue fraudulent credentials on its own.
2. **Public transparency log.** Every credential a registrar issues is published to a public, hash-chained
   append-only log, the same principle Certificate Transparency uses to catch CA misissuance in the real
   world. Misissuance becomes mechanically visible rather than something a token-holder vote has to be
   trusted to punish after the fact.
3. **Multiple independent, competing constellations.** Different registrar constellations can operate in
   parallel (a CERT-run one, an ISAC-run one, a university-consortium one). Consuming orgs choose which
   constellation(s) they trust — the same trust model browsers use for root CAs.

### Gossip layer

py-libp2p + GossipSub. Every report carries `{payload, timestamp, pseudonym signature, registrar credential
proof, rate ticket}`, broadcast the moment it's signed. No blockchain call sits in this path. Peers verify
locally and drop invalid messages at the first hop.

### Rate limiting

Per-epoch signed quota per pseudonym; peers refuse to relay message N+1. An optional fully-anonymous burner
mode (one-time blind-signed tokens, or RLN for a more sophisticated version) exists for rare disclosures and
stays Phase 3.

### Trust layer: multi-model scoring

Each node runs three independent scoring models over incoming reports — a decayed-weighted average, a
Bayesian model, and an EigenTrust-style propagation model — and randomizes its own model parameters
(corroboration window, decay rate) within a bounded range at initialization. This prevents the shipped
default algorithm from becoming a single, study-able, global target.

```
> swarmsec-node query --ioc "1.2.3.4"

IoC: 1.2.3.4
- Trust Score (Model A - Decayed Weighted Avg): 75
- Trust Score (Model B - Bayesian):              72
- Trust Score (Model C - EigenTrust-style):       74
Confidence: HIGH (models agree)
```

```
IoC: 1.2.3.4
- Trust Score (Model A - Decayed Weighted Avg): 85
- Trust Score (Model B - Bayesian):              25   <-- flagged
Confidence: UNCERTAIN (models disagree — treat as ambiguous, not high-confidence either way)
```

This hardens the *aggregation* step. It does not defend against fabricated *evidence* — three models run
over the same Sybil-poisoned corroboration data will often just agree with each other on garbage. That's
what feedback independence is for.

### Trust layer: cold-start handling

A report below the corroboration/feedback threshold — including a genuinely novel, first-to-report threat,
from a new or an established pseudonym — gets a distinct status rather than a low score:

```
IoC: 203.0.113.44
Status: UNCONFIRMED — single source, awaiting corroboration
Confidence: LOW (not enough independent reports yet)
```

Corroboration determines *confidence*, not *visibility*. Scoring an unconfirmed report the same as one
that's actively distrusted would bury the reports that matter most: the first one in.

### Trust layer: feedback independence

An attacker with several vetted pseudonyms could submit a false report from one and "confirm" it with fake
positive feedback from the others. Fixed with four mechanisms, none of which rely on trusting a signature
over an unverifiable claim:

- **Reuse corroboration clustering on feedback-givers.** If feedback for a pseudonym disproportionately
  comes from a small, tightly-clustered set of other pseudonyms — especially ones that also corroborate
  each other elsewhere — it's automatically down-weighted. The same graph analysis already built for
  corroboration, pointed at a second target.
- **Vesting, with retroactive revocation.** Reputation gained from feedback accrues over weeks, not
  instantly, and is clawed back if the feedback-giver is later identified as part of a Sybil cluster.
- **External cross-correlation.** Feedback that independently correlates with public threat-intel sources
  outside the network's control (abuse.ch, community VirusTotal signals) is weighted higher.
- **Specificity weighting.** Agreement on a high-entropy, hard-to-guess detail (a specific hash, an unusual
  URI path, a TLS fingerprint) counts far more than agreement on a low-entropy claim ("this IP is bad").

**Explicitly rejected: "Proof-of-Impact" via signed firewall/EDR logs.** A signature only authenticates
that a log was produced by whoever chose to produce it — it says nothing about whether the underlying
threat claim was true, and a Sybil ring can trivially generate valid-looking logs on infrastructure it
controls for a claim that was never real. It also leaks real detection telemetry into a gossiped feed.

### Trust layer: report staleness vs. falseness

A correct report can become outdated as infrastructure rotates, without ever having been wrong. Reports
carry an explicit validity window, decoupled entirely from the accuracy/trust score — the same reason STIX
indicators carry a validity period.

### Registrar-level revocation: scope

Credential revocation is triggered *only* by cryptographically provable protocol violations — proven
rate-limit abuse, or a registrar disputing a credential it issued. Suspicion arising from local
trust-scoring or feedback-clustering never triggers revocation; it only ever affects that pseudonym's score
at the nodes that observed it. This keeps "no global truth" actually true.

### Hard rule: advisory only

SwarmSec's output is always a ranked, evidence-annotated candidate list for a human analyst or an existing
SOAR/SIEM pipeline. It never auto-touches a firewall or EDR.

### Incentive layer: contribution-gated visibility

Feed access is tiered by a rolling contribution score: active contributors get full real-time access with
full corroboration detail; pure consumers get delayed and/or summary-only access. A direct response to the
underlying game being an N-player public-goods problem rather than a simple two-party Prisoner's Dilemma —
see **What's Still Genuinely Open** for what this does and doesn't solve.

### Settlement layer

If used at all, blockchain touches only a once-daily anchor of the transparency log's root hash, via one
small, low-complexity contract. No staking, no slashing, no per-IoC voting.

---

## Threat Lifecycle

1. **Submission** — org signs a report with its pseudonym key, attaches its current rate ticket.
2. **Local signing** — no network call, no chain touched.
3. **Gossip broadcast** — immediate, over libp2p/GossipSub.
4. **Peer reception** — verify signature + registrar credential + ticket validity locally; relay if valid,
   drop if not.
5. **Continuous scoring** — each node runs all three trust models over incoming reports and feedback,
   applying corroboration clustering, feedback-independence weighting, and specificity weighting. No voting
   round, no consensus deadline.
6. **Human/SOAR triage** — an analyst reviews the ranked, annotated, multi-model candidates (with
   disagreement flagged) and decides whether to act. Access to full detail is gated by the consumer's own
   contribution tier.
7. **Decoupled transparency logging / checkpointing** — registrar credential issuance is continuously
   logged publicly; an optional daily on-chain anchor is fully decoupled from the live sharing network.

---

## Design Evolution: What Changed, and What Was Rejected

SwarmSec went through a full redesign before reaching this version, plus two proposed hardening measures
that were argued out rather than adopted. Recording that here isn't just a changelog — it's the strongest
evidence in this document that the final choices were reasoned into place, not assumed.

**From the original design to this one:**
- The original tried to build reputation on top of full anonymity — close to a category error. This
  version's core reframe is pseudonymity as the default.
- The original put every threat report through an on-chain vote before it counted as verified. This
  version removes the chain from the hot path entirely.
- The original's Sybil resistance was Proof-of-Stake, which defends against generic profit-motivated spam
  but not a targeted, well-resourced adversary who can simply buy tokens. This version gates registration
  on real-world vetting instead of capital.
- The original auto-updated firewalls and EDR systems off decentralized consensus. This version makes
  advisory-only, human-decides-always a hard rule.

**Proposed mid-course and explicitly rejected:**
- **Registrar staking, slashing, and DAO governance** — proposed to harden the registrar layer against
  compromise. Rejected: it reintroduces the exact gas-scaling and governance-capture risk this design was
  built to avoid, and it selects registrars by capital rather than trustworthiness — a well-resourced
  adversary clears a large bond more easily than a legitimate, mission-driven CERT does. Replaced with
  internal threshold signing, a public transparency log, and competing constellations.
- **"Proof-of-Impact" via signed firewall/EDR logs** — proposed to make feedback harder to fake. Rejected:
  a signature authenticates who produced a log, not whether the claim was true, and a Sybil ring can
  generate valid logs for false claims on infrastructure it controls. Replaced with feedback-giver
  clustering, vesting with retroactive revocation, external cross-correlation, and specificity weighting.

---

## Gap-Closing Table

| # | Issue | How it's closed |
|---|---|---|
| 1 | Core mechanism already exists (PolySwarm) / MISP dominates | Differentiated on purpose: handles non-independently-verifiable IoCs via corroboration + feedback rather than sandbox-checkable verdicts; portable cryptographic identity rather than a platform account. |
| 2 | Undefined "local analysis" / verification gap | Corroboration + outcome feedback, mechanically computed, never a claimed global truth. |
| 3 | On-chain vote per IoC vs. real-time need; gas scales with volume | Chain fully off the hot path; only a once-daily, volume-independent anchor if used at all. |
| 4 | Anonymity vs. reputation contradiction | Pseudonymity (linkable to self, not to real identity) is the default and carries reputation; true anonymity is opt-in and explicitly reputation-free. |
| 5 | PoS Sybil-resistance ignores a motivated/targeted adversary | Real-world vetting gate, not capital; corroboration requires independent registrants. |
| 6 | Auto-updating firewalls/EDR off pseudonymous consensus | Explicitly banned — output is always advisory. |
| 7 | "Decentralized" doesn't survive contract deployment/governance | On-chain footprint minimized to a trivial anchor contract; the only registrar-side "governance" is public transparency + internal threshold signing, not a token vote. |
| 8 | Registrar compromise or collusion | Internal 2-of-3 threshold signing per registrar; public transparency log makes misissuance mechanically detectable; multiple competing constellations avoid a single global authority. |
| 9 | Default scoring algorithm becomes a single, study-able target | Three independent models with randomized per-node parameters; disagreement surfaced as a confidence signal. |
| 10 | Sybils faking positive feedback to inflate their own reputation | Feedback-giver clustering analysis, vesting with retroactive revocation, external cross-correlation, specificity weighting. |
| 11 | Free-riding on shared intel without contributing | Contribution-gated visibility tiers (partial fix — see What's Still Genuinely Open). |
| 12 | Cold-start: novel, first-to-report threats have no corroboration or feedback history yet | Reports below threshold get a distinct `UNCONFIRMED` status rather than a low score — stays visible to the analyst instead of being buried. |
| 13 | Undefined trigger for pseudonym/credential revocation | Scoped to only cryptographically provable protocol violations; local suspicion never triggers global revocation, only local score effects. |
| 14 | Reports can go stale (infrastructure rotates) without ever having been false | Explicit validity window on reports, decoupled from the accuracy/trust score. |

---

## What's Actually Novel

None of the individual primitives are novel. The contribution is the specific composition aimed at the gap
neither MISP nor PolySwarm covers, plus — if a genuine research angle is wanted — an empirical comparison
of the three trust-scoring models under simulated adversarial injection, which is a real, original, gettable
result.

---

## What's Still Genuinely Open

- **This is an N-player public-goods game, not a two-party Prisoner's Dilemma.** The benefit is
  non-excludable and non-rival. Reputation makes cooperation a *sustainable equilibrium* in the repeated
  version of the game — it does not make defection-forever stop being a valid equilibrium too.
  Contribution-gated visibility raises the cost of pure free-riding but doesn't eliminate it; real
  communities that work (MISP instances, ISACs) bootstrap past this with a critical mass of non-strategic
  or mandated early contributors, not through mechanism design alone.
- **Multi-model scoring hardens aggregation, not evidence.** Three models run over Sybil-poisoned input
  will often agree with each other on the poison. Feedback independence and specificity weighting are the
  actual defense against fabricated evidence, and they raise cost rather than eliminate the risk.
- **A patient, well-funded adversary willing to stand up multiple genuinely real front organizations over
  months, pass real vetting on each, and deploy real shared infrastructure to make specificity-matches
  legitimate, still gets through.** This isn't unique to SwarmSec — it's the unresolved edge of every
  reputation system that exists, including Wikipedia's sockpuppet detection and app-store review fraud. The
  honest claim is that this raises the cost of that attack substantially, not that it closes it.
- **Registrar vetting strictness is a real, unresolved trade-off, not a solved parameter.** Stricter vetting
  means stronger Sybil resistance and a smaller, harder-to-bootstrap network; looser vetting means the
  reverse. Competing constellations give consumers a choice of trade-off, but that's a mitigation, not a
  resolution — no single setting is correct.

---

## Final Pre-Build Review

A last review pass before implementation started surfaced three gaps, now fixed above and reflected in the
architecture section, plus two smaller operational notes.

**Operational notes (documented, not deeply engineered for the capstone):**
- Threshold-signing key rotation: registrars need a defined resharing process for when an officer leaves or
  a share is lost. Standard proactive secret-sharing techniques apply; worth a paragraph in the report
  rather than full implementation.
- Corroboration matching function: "overlapping IoCs/TTPs" needs a concretely decided matcher before that
  work starts. Start with exact/near-exact matching (same hash, same IP, same specific TTP identifier) —
  simpler to build and harder to game than fuzzy similarity matching, which is left as stated future work.

**Checked and holds up:** query-side privacy. Because gossip means every node already holds a local copy of
everything broadcast to it, querying never requires asking a peer "have you seen X" — there's no
query-pattern leak the way a DHT-lookup design would have. Worth preserving as a standing design principle:
never introduce an on-demand "ask a peer for X by name" lookup later without re-checking this holds.

---

## Technology Stack

- **P2P:** Python 3.11+, py-libp2p, GossipSub
- **Crypto:** `cryptography` (Ed25519 signing), an RSA or Schnorr blind-signature implementation for
  credential issuance, simple hash-chained log for the transparency layer
- **Registrar service:** FastAPI, internal 2-of-3 threshold signing
- **Trust scoring:** plain Python; worth prototyping the model comparison if taking the research angle
- **CLI:** click
- **Phase 3 only:** Solidity (one small contract), Hardhat, web3.py, testnet/L2; RLN tooling from the
  Waku/Vac ecosystem
- **Orchestration:** Docker, Docker Compose

---

## Development Plan

This plan sequences the build by actual technical dependency, not by the Phase 1/2/3 grouping used
elsewhere in this document — the sections above describe *what* to build, this describes *in what order*
and *why*.

**Scope correction:** feedback-independence clustering could look like optional hardening at a glance, but
the demo's Act 3 — the scripted Sybil cluster getting caught live — does not exist without it. It is
core, non-negotiable scope, sequenced immediately after corroboration matching since it reuses that same
clustering machinery. Multi-model scoring stays genuinely optional — the demo reads fine off a single score
climbing and getting flagged.

**Planning assumptions:** solo build, 12 weeks total, one semester's worth of part-time effort, no prior
hands-on experience assumed with blind signatures or libp2p specifically. If actual runway is shorter, see
Compressed Timeline below before starting — don't just chop weeks off the end, the ordering changes too.

### Roadmap Overview

| Sprint | Weeks | Focus | Milestone |
|---|---|---|---|
| 0 | 1 | Spikes: blind signatures, libp2p | Two ugly standalone proofs-of-concept working |
| 1 | 2–3 | Registration & credentials | Register a pseudonym, get back a verifiable credential |
| 2 | 4–5 | Gossip & message pipeline | Act 1 of the demo works for real |
| 3 | 6–7 | Trust scoring — corroboration | Act 2 of the demo works for real |
| 4 | 8–9 | Feedback + independence clustering | **Act 3 works — the thesis, demonstrated** |
| 5 | 10 | Advisory output + dashboard | Full demo script runs end-to-end, 3x clean |
| 6 | 11 | Stretch hardening + write-up | Report skeleton done; extra Phase 2 items if ahead |
| 7 | 12 | Rehearsal + buffer | Jury-ready |

### Sprint-by-Sprint

**Sprint 0 (Week 1) — De-risk the unknowns first.** Spike the two components most likely to blow the
schedule if harder than expected: a minimal blind-signature implementation running standalone (blind, sign,
unblind, verify, nothing else), and two local processes exchanging one message over py-libp2p + GossipSub.
Neither needs to be pretty — the only goal is confirming both are tractable before scheduling depends on it.

**Sprint 1 (Weeks 2–3) — Registration & credentials.** Ed25519 pseudonym keypair generation, signing,
verification. Registrar service (FastAPI): a vetting step — a pre-seeded allowlist is a reasonable,
defensible simplification for demo purposes rather than real KYC — and blind-signed credential issuance.
2-of-3 internal threshold signing (fallback: single-key registrar, documented as a stated simplification if
this is eating the schedule). Hash-chained public credential log — genuinely simple, don't overbuild it.
*Milestone:* an org can register and receive a credential that any peer can independently verify.

**Sprint 2 (Weeks 4–5) — Gossip & message pipeline.** 3+ node containers gossiping over libp2p/GossipSub.
Message format: payload + pseudonym signature + credential proof + rate ticket. Peer-side verification
before relay; invalid messages dropped at the first hop. Rate-ticket enforcement. A minimal status rule
pulled forward from Sprint 3: any report below the corroboration threshold displays as `UNCONFIRMED —
single source, awaiting corroboration` rather than a bare score — the one sliver of the trust layer Act 1
needs before Sprint 3's actual scoring models exist. *Milestone:* `swarmsec-node submit` from one node
produces a signed, verified message visible via `swarmsec-node query` on the other two within about a
second, correctly showing `UNCONFIRMED` rather than a score. Act 1, for real.

**Sprint 3 (Weeks 6–7) — Trust scoring: corroboration.** The decayed-weighted-average scoring model (the
one model that's core scope — the other two are Sprint 6 if there's time). Corroboration matching: detect
overlapping IoCs/TTPs across recent reports within a time window. *Milestone:* corroborating reports from
independent nodes visibly move the score and flip confidence to HIGH. Act 2, working.

**Sprint 4 (Weeks 8–9) — Feedback + independence clustering (core, not optional).** Feedback submission,
same signed/rate-limited pipeline as reports. Reuse Sprint 3's clustering logic against feedback-givers.
Build `spawn_sybil_cluster.sh` — the actual attack script the demo fires live. *Milestone, the most
important one in this plan:* run the Sybil cluster script, watch the raw score tick up and then get flagged
and pulled back down. If this slips, everything downstream should wait for it — there is no version of the
presentation that works without this.

**Sprint 5 (Week 10) — Advisory output + dashboard.** CLI output formatting: ranked, annotated, explicitly
advisory-only. The `rich`-based live terminal dashboard. Wire the whole thing into the exact sequence in the
demo script below. *Milestone:* the full demo script runs start to finish, live, three times in a row, with
no manual intervention between acts.

**Sprint 6 (Week 11) — Stretch hardening + write-up.** If on schedule, pick up to two more Phase 2 items —
multi-model scoring first (the demo already references it), external cross-correlation against abuse.ch
second (easy to narrate to a jury). If not ahead, skip build work and use the week for the write-up.
Report work should already be running in parallel since Sprint 1 — this week is where it's consolidated,
not started.

**Sprint 7 (Week 12) — Rehearsal + buffer.** Record the backup demo video. Full timed run-throughs — don't
skip this because the system "works," rehearsal is about the presenter, not the code. Red-team the Sybil
resistance a different way than the scripted attack before a juror finds the gap live. Buffer for whatever
slipped. Something will have.

### What's Core vs. What's Cuttable

If time runs out, cut in this order — never the reverse:

1. **Cut first:** everything in Phase 3 (competing registrar constellations, the checkpoint-anchor contract,
   RLN burner mode). Already scoped as design-and-document-only.
2. **Cut second:** multi-model scoring. Demo falls back to one model's number — corroboration still
   visibly works.
3. **Cut third:** the rest of Phase 2 hardening beyond core feedback-independence — vesting/retroactive
   revocation, external cross-correlation, specificity weighting, contribution-gated visibility. Core
   clustering-based down-weighting stands on its own without them.
4. **Cut last, only if truly desperate:** dashboard polish. Fall back to well-formatted, narrated CLI
   output — this weakens the demo's visual impact the most, so it's the last thing to give up.

**Never cut:** pseudonym signing, registrar credentialing (even simplified to single-key), the gossip
pipeline, corroboration matching, feedback-independence clustering, advisory-only output. Losing any one of
these means there's no working demo and no demonstrated thesis — just a design document.

### Testing & Validation

- **Unit test the crypto first, separately from everything else.** Blind signatures and Ed25519 signing are
  the one place a silent bug is worse than a crash.
- **One scripted integration test** covering submit → gossip → verify → score, asserting expected results
  at each step, run after every pipeline change instead of manually re-running the full demo by hand.
- **Red-team yourself before the jury does.** Try breaking Sybil resistance a different way than the
  scripted attack — fewer colluding pseudonyms, staggered submissions, a single high-reputation pseudonym
  instead of a fresh cluster. Catches real gaps early, and gives a confident answer if a juror proposes a
  variant live.

### Documentation Track (parallel, starting Sprint 1 — not after)

- **Introduction / Problem statement** — write now, doesn't depend on code existing.
- **Related work** — largely done already; the PolySwarm/MISP research above slots straight in.
- **Design chapter** — the Architecture and Design Evolution sections above are most of this already; the
  explicitly rejected mechanisms make strong "alternatives considered" material.
- **Implementation chapter** — write incrementally as each sprint milestone lands.
- **Evaluation** — draft during Sprints 5–6, once there's a working system and a red-team pass to report on.
- **Limitations / future work** — What's Still Genuinely Open above, plus anything cut per the descope
  order, slots straight in here.

### Compressed Timeline (meaningfully less than 12 weeks)

Don't just delete weeks from the end — the ordering changes too: fold Sprint 0's spikes into Sprint 1;
simplify the registrar to single-key signing from the start; merge Sprints 3 and 4 since Sprint 4's
milestone is non-negotiable and shouldn't be exposed to a schedule slip; drop multi-model scoring and most
Phase 2 hardening by default rather than as an if-time-allows stretch; protect rehearsal time even more than
the full schedule does — a working system nobody has rehearsed presenting is a worse outcome than a smaller
system delivered with confidence.

---

## Jury Presentation & Live Demo Script

Built around a ~10-minute slot (talk + demo, before Q&A). If the actual slot is shorter or longer, cut or
expand the talk below first — the demo should stay close to full length regardless, since it's the part
that actually proves the thesis.

### The Talk (~6 minutes before the demo)

Timing and delivery cues for presenting the material already laid out above:

1. **The problem (30–40 sec)** — open on the failure mode, not the tech. 2–3 sentences.
2. **Why existing tools don't solve it (60–75 sec)** — name MISP and PolySwarm specifically; this is what
   signals real literature review to a jury.
3. **The core insight (60–90 sec) — the centerpiece, slow down here** — state the pseudonymity/anonymity
   reframe plainly. Worth naming as the contribution, not just a technical detail.
4. **Architecture, at a glance (60–90 sec) — one diagram, don't re-explain the whole doc** — hit four
   things only: registration, gossip with no chain in the path, local trust scoring, advisory-only output.
   Save the transparency log, the three scoring models, and feedback clustering for Q&A, where they land
   better anyway.
5. **Hand off to the demo** — one line: "Rather than describe how it resists a poisoning attempt, let me
   show you one happening live."

### The Live Demo (~3–4 minutes)

**Setup (before being called up, not while the jury watches):** `docker compose up -d` to bring up the
registrar and three node containers in advance; confirm all healthy, dashboard idle. Have the backup video
cued up and ready to alt-tab to.

**Act 1 — Clean submission (30–45 sec)**
```
$ swarmsec-node submit --as org-a --ioc "203.0.113.44" --type c2-server
```
Narrate: "Org A just signed and broadcast this with its pseudonym key — no blockchain call, no waiting."
Point at propagation to org-b and org-c within roughly a second. Query it explicitly:
```
$ swarmsec-node query --ioc "203.0.113.44"

IoC: 203.0.113.44
Status: UNCONFIRMED — single source, awaiting corroboration
Confidence: LOW (not enough independent reports yet)
```
Say explicitly: "Notice it's marked *unconfirmed*, not distrusted — those are deliberately different
states. A brand-new report is exactly what corroboration hasn't caught up to yet, and scoring that the same
as something we actively distrust would bury the reports that matter most: the first one in." Don't rush
this beat — it's a real design decision, not connective tissue.

**Act 2 — Corroboration (45–60 sec)**
```
$ swarmsec-node submit --as org-b --ioc "203.0.113.44" --type c2-server
$ swarmsec-node submit --as org-d --ioc "203.0.113.44" --ttp "same-C2-infra"
```
Narrate: "Two independent, separately-vetted orgs are now pointing at the same infrastructure." Point at
the score climbing across the dashboard's three models, confidence flipping to HIGH. Query explicitly:
```
$ swarmsec-node query --ioc "203.0.113.44"

IoC: 203.0.113.44
- Trust Score (Decayed Weighted Avg): 78
- Trust Score (Bayesian):             74
- Trust Score (EigenTrust-style):     76
Confidence: HIGH (models agree)
```

**Act 3 — The attack, live (90–120 sec, THE beat — rehearse until the script isn't needed)**
```
$ ./demo/spawn_sybil_cluster.sh --count 4 --target "198.51.100.7" --claim malicious
```
Fires a burst of pre-scripted pseudonyms submitting a false report plus fake corroborating feedback on each
other. Narrate: "These four pseudonyms passed registration, so nothing stops them from posting — watch what
happens next." Let the raw score tick up for a second, then it should flag:
```
IoC: 198.51.100.7
⚠ SYBIL CLUSTER DETECTED — feedback from 4 pseudonyms shows high mutual clustering,
  down-weighting applied.
Confidence: UNCERTAIN — treat as unverified, do not act on this alone.
```
Say explicitly: "This isn't a blocklist catching a known-bad actor — it's noticing that the *feedback
itself* is coming from a suspiciously tight cluster, and discounting it automatically." This sentence does
the real work of the demo; don't rush it.

**Close (15–20 sec):** Query the first IoC again to show it's still confidently flagged, contrast with the
second sitting at UNCERTAIN: "Either way, this is as far as the system goes on its own — it hands a ranked,
annotated list to an analyst. It never touches a firewall itself."

**If it breaks live:** "Let me switch to a recorded run of exactly this," calmly, no apology spiral. A jury
remembers composure, not five seconds of a stalled container.

### Q&A Prep Sheet

Answer in 1–2 sentences first, elaborate only if pressed — don't front-load full depth unprompted.

**"Isn't this just MISP?"** MISP solves sharing. It doesn't solve the fear that stops sharing in the first
place — no portable, cross-org pseudonymous reputation that survives without exposing who you are.

**"PolySwarm already does staking on threat intel — what's different?"** PolySwarm's stake-and-slash works
because malware verdicts are sandbox-checkable ground truth. Most IoCs aren't independently verifiable that
way by a stranger — solved here with corroboration and outcome feedback instead of pretending to verify
what can't be verified.

**"Why even use blockchain if you're avoiding it everywhere else?"** Deliberately minimized to a once-daily,
low-stakes checkpoint anchor of the registrar's credential log — the one thing blockchain is actually good
for here — fully decoupled from the live network, so it never touches cost or latency for report-sharing.

**"How do you stop Sybil attacks?"** Registration requires real-world vetting, not capital. Corroboration
requires independent registrants; feedback is clustering-analyzed the same way. Honest follow-up: this
raises the cost of the attack substantially, it doesn't reduce it to zero against a sufficiently patient,
well-resourced adversary — no reputation system fully closes that.

**"What if a registrar itself is compromised or malicious?"** Each registrar's signing authority is a
2-of-3 threshold key, so one compromised credential can't issue fraudulent credentials alone. Every issued
credential is published to a public log. Multiple independent constellations can operate; consuming orgs
choose which they trust, the same way browsers choose root CAs.

**"Who decides to revoke a participant?"** Only cryptographically provable protocol violations do — proven
rate-limit abuse, or a registrar disputing a credential it issued. Local suspicion never triggers global
revocation; it only affects that pseudonym's score at the nodes that noticed.

**"Doesn't corroboration-based trust miss the first report of something brand new?"** That's exactly why a
fresh report shows as `UNCONFIRMED` instead of a low score — as seen in Act 1. Corroboration determines
confidence, not visibility.

**"Does this solve the free-rider / prisoner's dilemma problem?"** No — say that plainly. It's an N-player
public-goods game, not a two-party dilemma. Reputation converts a one-shot game into a repeated one where
cooperation becomes a sustainable equilibrium, not the only one. Visibility tiering raises the cost of
free-riding but every working system in this space bootstraps past this with early non-strategic
contributors, not through mechanism design alone.

**"If none of the individual pieces are new, what's your actual contribution?"** The composition, aimed at
a specific unaddressed gap — pseudonymous, accountable sharing for claims that can't be independently
verified the way a malware sample can.

**"How would this perform at real scale?"** GossipSub-style propagation is proven at large scale elsewhere
in production. Be honest that this build is a capstone-scale demonstration, not a stress-tested deployment.

### Delivery Notes

- Don't read slides. If speaking word-for-word off a slide, cut the slide's text down until that's
  impossible.
- Don't try to explain the full architecture document — the talk hits four ideas; the rest is here for
  anyone who asks afterward.
- Time against a real clock at least twice before the day. By the third rehearsal, the script above should
  not be needed.
- When a hard question lands, pause a beat before answering. Composure reads as more confident than a
  rushed response.

---

## Final Pre-Jury Checklist

- Demo script runs live, unattended between acts, 3+ times in a row.
- Backup video recorded and instantly accessible.
- Red-team pass completed and its result ready as a talking point if asked.
- Report finalized, not still being edited the morning of.
