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

### Registrar key and log persistence

Set `SWARMSEC_REGISTRAR_KEY_FILE` to a PEM path and `SWARMSEC_LOG_FILE` to a JSON-lines path
so the demo registrar keeps the same signing key and credential log across restarts. If those
variables are unset, the process generates an ephemeral key and an in-memory log: previously
issued credentials will **not** verify after restart. This is intentional demo behavior.

### Transparency log stores the full signed credential

Each log payload is `{record_type, record}` where `record` includes `registrar_signature`.
Peers still verify with `verify_credential()` against `/pubkey`; they must not treat unsigned
log fields as authoritative.

### Ed25519 public-key validation

Registration requires strict base64 that decodes to exactly 32 bytes and constructs an
Ed25519 public key. The cryptography library accepts any 32-byte string as an Ed25519 public
key, so length-32 random bytes are issued; shorter or non-base64 values are rejected.


### No credential revocation propagation protocol

The signed revocation primitive exists (the registrar can re-sign a credential with status
"revoked"), but there is no protocol yet for propagating revocation status to peers in real time.
Peers must query the registrar to check current status. A gossip-based revocation propagation
mechanism is future work.
