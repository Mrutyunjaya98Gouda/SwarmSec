# SwarmSec

**Permissioned Peer-to-Peer Cyber Threat Intelligence (CTI) Exchange**

A production-grade, decentralized CTI platform where a central registrar verifies organizations and issues signed pseudonymous credentials. Participants exchange signed STIX 2.1 sightings, and each receiver computes an explainable, local, correlation-aware trust ranking.

---

## Features

- 🔐 **Centralized Identity Plane**: A single registrar issues Ed25519-signed pseudonymous credentials.
- 🌐 **Decentralized Data-Sharing**: Nodes gossip signed STIX 2.1 reports over libp2p/GossipSub.
- 🧮 **Local Corroboration Scoring**: Independent trust computation using a published, fixed-parameter formula.
- 🛡️ **Sybil & Collusion Resistance**: Advanced evidence down-weighting for mutual endorsement clusters.
- 📄 **Transparency Log**: Public, hash-chained, append-only log of all issued credentials.
- 📊 **Real-time Analytics**: Live terminal dashboard to track trust score updates and flagged overlap.

---

## Technology Stack

- **Backend / CLI**: Python 3.11+
- **API Framework**: FastAPI + Uvicorn
- **CLI Framework**: Click + Rich
- **Data Schemas**: Pydantic (STIX 2.1 constraints)
- **Cryptography**: Ed25519 (`cryptography`), RFC 8785 JSON Canonicalization (`jcs`)

---

## Installation

### Prerequisites
- Python 3.11+
- [pipx](https://pipx.pypa.io/stable/) (Recommended for global CLI installation)

### Global Installation (Recommended)

To install SwarmSec globally as a command-line tool without polluting your system Python:

```bash
# Clone the repository
git clone https://github.com/Mrutyunjaya98Gouda/SwarmSec.git
cd SwarmSec

# Install globally using pipx
pipx install .
```

### Local Development Setup

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

---

## Usage

Once installed, the `swarmsec` CLI is available globally.

1. **Generate a pseudonym keypair**:
   ```bash
   swarmsec keygen --out ./keys/
   ```
2. **Start the registrar** (in a separate terminal):
   ```bash
   uvicorn swarmsec.registrar.app:app --port 8000
   ```
3. **Register with the registrar**:
   ```bash
   swarmsec register --registrar http://localhost:8000 --identity org-a --key ./keys/pubkey.pem
   ```
4. **Launch Live Dashboard**:
   ```bash
   swarmsec dashboard
   ```

---

## Deployment

### Docker Deployment (Recommended)

This project includes a Dockerfile and `docker-compose.yml` for multi-node deployment.

1. **Build the Image**
   ```bash
   docker-compose build
   ```

2. **Run the Cluster**
   ```bash
   docker-compose up -d
   ```
   This will spin up the Registrar service and 3 independent peer nodes.

---

## CI/CD Pipeline

This project uses GitHub Actions for continuous integration:
- **Build Verification**: Automatically sets up Python and installs dependencies.
- **Tests**: Runs the comprehensive unit and integration test suite (`pytest`) on all PRs and pushes to main/sprint branches.

---

## Documentation

- [Design Document](docs/DESIGN.md)
- [Development Plan](docs/DEVELOPMENT_PLAN.md)
- [Stated Simplifications](NOTES.md)

---

## License

This project is licensed under the MIT License.

---

**SwarmSec v0.1.0** - © 2026 Permissioned P2P CTI Exchange
