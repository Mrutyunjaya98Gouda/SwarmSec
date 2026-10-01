# SwarmSec

A permissioned peer-to-peer cyber threat intelligence (CTI) exchange where a registrar verifies
organizations and issues signed pseudonymous credentials. Participants exchange signed STIX 2.1
sightings; each receiver computes an explainable, local, correlation-aware trust ranking.

**Current branch status (Sprint 1):** registrar, credentials, transparency log, and CLI for
keygen/register/verify. Gossip, scoring, and the dashboard land on later sprint branches.

## Architecture

- **Centralized identity plane**: a single registrar verifies organizations and issues Ed25519-signed
  pseudonymous credentials, recorded in a public hash-chained transparency log.
- **Decentralized data-sharing and scoring plane** (later sprints): nodes gossip signed STIX 2.1
  reports over libp2p/GossipSub. Each node independently computes a local corroboration score using a
  published, fixed-parameter formula.

## Setup

```bash
# Python 3.11+ required
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
# Generate a pseudonym keypair (writes pseudonym.key / pseudonym.pub)
swarmsec-node keygen --out ./keys/

# Start the registrar (optional persistence)
export SWARMSEC_REGISTRAR_KEY_FILE=./data/registrar.pem
export SWARMSEC_LOG_FILE=./data/registrar.jsonl
PYTHONPATH=src uvicorn swarmsec.registrar.app:app --port 8000

# Register with the registrar
swarmsec-node register --registrar http://localhost:8000 --identity org-a --key ./keys/pseudonym.pub
```

Private keys are never returned by the registrar. Peers fetch `GET /credential/{id}` and verify
the registrar signature with `GET /pubkey`.

## Testing

```bash
PYTHONPATH=src pytest -v
```

## Documentation

- [Design Document](docs/DESIGN.md)
- [Development Plan](docs/DEVELOPMENT_PLAN.md)
- [Stated Simplifications](NOTES.md)
