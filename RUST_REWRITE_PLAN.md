# SwarmSec v2.0: Rust Rewrite Plan

This document outlines the architectural roadmap for migrating the SwarmSec Python prototype (v1.0) to a production-grade, enterprise-scale Rust implementation (v2.0).

## Why Rewrite in Rust?
While the Python implementation successfully proved the distributed trust scoring logic and the overall cryptographic architecture, transitioning to Rust provides:
1. **Absolute Performance**: Zero garbage collection overhead, allowing for massive P2P network throughput (thousands of STIX 2.1 indicators processed per second).
2. **Ironclad Security**: Memory safety guarantees at compile-time (no buffer overflows or data races) which is strictly required for production cybersecurity software.
3. **P2P Dominance**: `rust-libp2p` is the industry standard for high-performance decentralized networks (used by Polkadot and Substrate).

## The v2.0 Tech Stack
- **Networking**: `rust-libp2p` (GossipSub for intelligence routing, Noise for transport encryption).
- **Cryptography**: `ed25519-dalek` (high speed, side-channel resistant) and `sha2`.
- **Database**: `sqlx` + `sqlite` (for high-performance, asynchronous local graph storage).
- **API & Web**: `axum` (extremely fast routing to serve local WebSockets and REST APIs).
- **Serialization**: `serde` + `serde_json` (custom canonicalization to match RFC 8785).

## Migration Phases

### Phase 1: Core Primitives & Cryptography
- Port the RFC 8785 JSON canonicalization logic to Rust.
- Implement the Ed25519 signing and verification wrappers.
- Define the `stix2` payload models using `serde`.

### Phase 2: The Local Trust Graph
- Set up an embedded SQLite database using `sqlx`.
- Translate the Python trust-scoring formula (entropy weighting, diverse endorser calculations) into a Rust service.

### Phase 3: P2P Networking
- Initialize a `libp2p` Swarm with GossipSub.
- Implement peer discovery and message validation (drop invalid signatures or revoked credentials at the network edge before they hit the database).

### Phase 4: Integration & Dashboard
- Embed the React/Vite web dashboard directly into the Rust binary using `rust-embed`.
- Expose WebSocket endpoints via `axum` to push real-time STIX feeds to the frontend.

## End Goal
A single, statically compiled binary (`swarmsec-node`) that security analysts can run anywhere. Upon execution, it seamlessly connects to the P2P swarm, validates threat intelligence silently in the background, and serves a beautiful React dashboard on `localhost:8080`.
