# SwarmSec

> Decentralized, pseudonymous threat-intelligence sharing — corroboration-based trust instead of blockchain consensus, so orgs can report without exposure.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-in%20development-yellow.svg)]()

## The problem

Security teams that get hit first are often the last to say so. Disclosing an attack costs
reputation, so the details — the infrastructure, the technique, the indicators — frequently never
leave the org that found them, and the same attack gets reused against the next victim. SwarmSec is
a peer-to-peer network for sharing that information without forcing a choice between staying silent
and staking your organization's name on every report.

## Why not MISP or PolySwarm?

**[MISP](https://www.misp-project.org/)** already does free, community-run threat-intel sharing at
real scale — but visibility is scoped to trust groups, and there's no portable reputation that
survives without exposing who you are.

**[PolySwarm](https://polyswarm.io/)** already does blockchain-based staking on threat verdicts —
but it works because malware verdicts are sandbox-checkable ground truth. Most indicators of
compromise (a suspicious IP, a TTP) aren't independently verifiable that way by a stranger.

SwarmSec targets that gap: pseudonymous, accountable sharing for the kind of intel neither approach
fully covers.

## How it works

```
+--------------------------------------------------------------------+
|                          SWARMSEC NETWORK                          |
|                                                                    |
|   +------------+      +------------+      +------------+       |
|   |   Node A   |      |   Node B   |      |   Node C   |       |
|   |            |<---->|            |<---->|            |       |
|   | pseudonym  |      | pseudonym  |      | pseudonym  |       |
|   | keypair    |      | keypair    |      | keypair    |       |
|   | (Ed25519)  |      | (Ed25519)  |      | (Ed25519)  |       |
|   |            |      |            |      |            |       |
|   | gossip     | HTTP relay (or GossipSub in future)           |
|   |            |      |            |      |            |       |
|   | LOCAL trust|      | LOCAL trust|      | LOCAL trust|       |
|   | scorer     |      | scorer     |      | scorer     |       |
|   | (fixed     |      | (fixed     |      | (fixed     |       |
|   |  params)   |      |  params)   |      |  params)   |       |
|   +------------+      +------------+      +------------+       |
+--------------------------------------------------------------------+
                               |
        rare: one-time registration + periodic transparency log
                               v
    +----------------------------------------------------------------+
    |     REGISTRAR CONSTELLATION(S)  (consumers pick which to trust)|
    |  - internal 2-of-3 threshold signing per registrar (HSM-backed)|
    |  - vets an org's real-world legitimacy ONCE                    |
    |  - blind-signs that org's chosen pseudonym key                 |
    |  - EVERY issued credential published to a public, append-only, |
    |    hash-chained transparency log — misissuance is mechanically |
    |    detectable by anyone, not adjudicated by a governance vote  |
    +----------------------------------------------------------------+
                               |
                     (Phase 3, optional)
                               v 
    +----------------------------------------------------------------+
    |     CHECKPOINT ANCHOR  (tiny contract, cheap L2)               |
    |     stores only: date + log root + registrar signatures        |
    |     no staking. no slashing. no per-IoC voting.                |
    +----------------------------------------------------------------+
```

- **Pseudonymous, not anonymous.** Every org gets a persistent identity that's never linked to who
  they are, but *is* linkable to itself — which is what lets reputation build at all.
- **Gossip, not blockchain, for propagation.** Reports broadcast over HTTP or libp2p/GossipSub 
  the moment they're signed. No chain, no vote, no gas cost, no delay.
- **Corroboration and feedback, not a global vote, for trust.** Every node scores incoming reports
  locally, across three independent models, informed by corroboration and outcome feedback over
  time — never a single "verified" flag nobody can audit.
- **Advisory only.** SwarmSec ranks and annotates. It never touches a firewall or EDR — a human
  always decides.
- **Blockchain, if used at all, for one narrow thing.** A once-daily, low-stakes anchor of the
  registrar's public credential log — the one place a tamper-evident ledger is actually the right
  tool.

Full architecture, every rejected alternative and why, and the complete threat model:
[`SwarmSec-Design.md`](SwarmSec-Design.md).

## Status

This is a capstone project that's been through multiple hardening passes — a full architecture
redesign, several proposed mechanisms deliberately rejected with the reasoning kept, and a
pre-implementation review. **Nothing here is built or deployed yet.** Implementation is starting now
against a 12-week sprint plan.

**Roadmap:**
- [ ] Phase 1 — core: gossip layer, pseudonymous registration, single-model trust scoring, advisory CLI
- [ ] Phase 2 — hardening: multi-model scoring, feedback-independence clustering, contribution-gated visibility
- [ ] Phase 3 — stretch: competing registrar constellations, on-chain checkpoint anchor, anonymous burner mode

Full sprint-by-sprint breakdown: [`SwarmSec-Development.md`](SwarmSec-Development.md).

## Planned usage

*(Design target — implementation in progress, not yet functional.)*

```bash
# Generate your pseudonym identity and register with a registrar
swarmsec-node init
swarmsec-node register --registrar <constellation>

# Report and query indicators
swarmsec-node submit --ioc "203.0.113.44" --type c2-server
swarmsec-node query --ioc "203.0.113.44"

# Live feed of network activity
swarmsec-node feed

# Export your trusted feed for existing SIEM/SOAR tooling
swarmsec-node export --format stix
```

## Security

SwarmSec is a research and capstone project. The cryptography has not been professionally audited,
and no deployment should trust it with real organizational reputations yet — see
[`SwarmSec-Design.md`](SwarmSec-Design.md) for an explicit accounting of what's hardened, what's a documented
trade-off, and what's still genuinely open. Found a real issue? Please open an issue or reach out
directly rather than a public PR with exploit details — good habit to start early, even at this
stage.

## Built with

Python · FastAPI · Ed25519 · RFC 8785 JSON Canonicalization · Docker Compose

## License

[Apache 2.0](LICENSE) — its explicit patent grant fits a project that expects multiple independent
registrar constellations and forks to exist, and it's the norm for comparable security
infrastructure. MIT is a fine, simpler alternative if you'd rather keep it minimal.
