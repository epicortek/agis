# AgIS Test Vectors

Deterministic offline test vectors for the AgIS v0.2.2 reference implementation.

Each vector is a self-contained set of input files and a manifest JSON that freezes the expected output. Run all vectors from `packages/agis-sdk-ts` with `npm run test:vectors`.

## Vector Index

| Vector | Description |
|---|---|
| **001** — Agent Card canonical hash | Canonicalizes a valid Agent Card using RFC 8785 JCS and computes its SHA-256 fingerprint. |
| **001-skeleton** — Skeleton Agent Card canonical hash | Same canonicalization applied to a skeleton Agent Card with placeholder key material, proving the scheme is deterministic before real keys exist. |
| **002** — JWK Thumbprint | Computes the RFC 7638 JWK Thumbprint of the test Ed25519 public key and verifies it matches the Agent Card. |
| **003** — DNS TXT Binding | Parses and validates an `agis=` DNS TXT record, verifying the agent identifier, card URL, JWK Thumbprint, and card hash fields. |
| **004** — Agent Card JWS Signature | Signs the canonical Agent Card with the test Ed25519 private key using compact JWS and verifies the signature. |
| **004-negative** — Agent Card tampering | Verifies that a tampered Agent Card (field changed in memory) fails signature verification. |
| **005** — Agent Status / Revocation | Validates both an active and a revoked agent status document. |
| **005-negative** — Invalid status documents | Rejects status documents with wrong agent ID, invalid status values, missing `revoked_at`, invalid TTL, or missing `updated_at`. |
| **006** — Offline composite identity verification | Combines DNS binding, Agent Card hash, JWK Thumbprint, card signature, and status into a single end-to-end identity verification result. |
| **006-negative** — Invalid identity verification cases | Rejects identity verification when any component (DNS hash, DNS JKT, agent ID, signature, status) is wrong. |
| **007** — Content-Digest | Computes the `sha-256` Content-Digest header for a JSON request body and verifies it round-trips correctly. |
| **007-negative** — Invalid Content-Digest cases | Rejects mismatched digests, empty digests, unsupported algorithms, and malformed format strings. |
| **008** — HTTP Message Signature | Signs an HTTP request over a fixed set of covered components using Ed25519 and produces a `Signature-Input` / `Signature` header pair. |
| **008-negative** — Invalid HTTP signature cases | Rejects missing signature input, corrupted signature bytes, wrong algorithm, and missing covered components. |
| **009** — Offline signed request verification | End-to-end offline verification combining identity verification, Content-Digest, and HTTP Message Signature checks. |
| **009-negative** — Invalid signed request cases | Rejects requests with failed identity, invalid Content-Digest, or invalid HTTP signature. |
| **010** — Freshness and replay protection | Verifies that a signed request is within the freshness window and that its nonce has not been seen before. |
| **010-negative** — Invalid freshness/replay cases | Rejects stale requests, future-dated requests, missing nonces in high-assurance mode, and replayed nonces. |
| **011** — Single delegation token | Signs an AgIS delegation token (compact JWS) and verifies all claims including issuer, subject, audience, scope, and expiry. |
| **011-negative** — Invalid delegation token cases | Rejects expired tokens, not-yet-valid tokens, wrong audience/subject, missing scopes, tampered signatures, and missing `jti`. |
| **012** — Delegated signed request | Offline verification of an HTTP request signed by an acting agent carrying a single `AgIS-Delegation` token from an issuing agent. |
| **012-negative** — Invalid delegated request cases | Rejects requests with missing delegation header, wrong acting agent, wrong audience, scope not granted, expired delegation, tampered delegation, or changed body. |
| **013** — Delegation chain signed request | Offline verification of an HTTP request signed by a final acting agent carrying an `AgIS-Delegation-Chain` header with two tokens, validating chain linkage, scope narrowing, and request integrity. |
| **013-negative** — Invalid delegation chain request cases | Rejects reversed chain order, wrong final agent, scope escalation, required scope not met, expired downstream token, tampered chain header, and changed body. |

## Directory Structure

```
test-vectors/
  agent-card/
    valid-agent-card.json
    valid-agent-card.manifest.json
    signed-agent-card.json
    skeleton-agent-card.json
    skeleton-agent-card.manifest.json
  dns/
    example.com.agis.txt
    dns-binding.manifest.json
  keys/
    ed25519-test-private.jwk.json   ← TEST MATERIAL ONLY, never use in production
    ed25519-test-public.jwk.json
  requests/
    valid-request-body.json
    valid-content-digest.manifest.json
    valid-signed-request.manifest.json
    valid-high-assurance-signed-request.manifest.json
    delegated-signed-request.manifest.json
    delegated-chain-signed-request.manifest.json
  delegation/
    valid-delegation-payload.json
    valid-delegation-token.manifest.json
    valid-delegation-payload-2.json
    valid-delegation-chain.manifest.json
  verification/
    valid-composite-verification.manifest.json
```
