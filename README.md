# SwarmSec

A permissioned peer-to-peer cyber threat intelligence (CTI) exchange where a registrar verifies
organizations and issues signed pseudonymous credentials. Participants exchange signed STIX 2.1
sightings; each receiver computes an explainable, local, correlation-aware trust ranking.

## Architecture

- **Centralized identity plane**: a single registrar verifies organizations and issues Ed25519-signed
  pseudonymous credentials, recorded in a public hash-chained transparency log.
- **Decentralized data-sharing and scoring plane**: nodes gossip signed STIX 2.1 reports over
  libp2p/GossipSub. Each node independently computes a local corroboration score using a published,
  fixed-parameter formula.

## Setup

```bash
# Python 3.11+ required
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Generate a pseudonym keypair
swarmsec keygen --out ./keys/

# Start the registrar
uvicorn swarmsec.registrar.app:app --port 8000

# Register with the registrar
swarmsec register --registrar http://localhost:8000 --identity org-a --key ./keys/pubkey.pem
```

## Testing

```bash
pytest -v
```

## Documentation

- [Design Document](docs/DESIGN.md)
- [Development Plan](docs/DEVELOPMENT_PLAN.md)
- [Stated Simplifications](NOTES.md)
