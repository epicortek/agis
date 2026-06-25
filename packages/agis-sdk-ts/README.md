# AgIS SDK for TypeScript

AgIS is a DNS-backed identity and verification profile for agents on the existing web.

This package is the reference TypeScript implementation of AgIS v0.2.2. It ships deterministic offline test vectors for every component of the protocol and exposes a stable set of verification functions.

## What this SDK supports

- **Agent Card canonicalization and SHA-256 hashing** — RFC 8785 JSON Canonicalization Scheme applied to Agent Cards, producing a stable fingerprint.
- **RFC 7638 JWK Thumbprint** — canonical public key identifier for Ed25519 keys.
- **DNS TXT binding parsing and validation** — parse and validate `agis=` DNS TXT records that bind an agent identifier to an Agent Card URL and JWK Thumbprint.
- **Agent Card JWS signing and verification** — sign and verify Agent Cards using EdDSA (Ed25519) via compact JWS.
- **Agent Status and revocation validation** — validate agent status documents including revocation state and TTL.
- **Offline composite identity verification** — end-to-end identity check combining DNS binding, Agent Card hash, JWK Thumbprint, card signature, and status.
- **Content-Digest generation and verification** — `sha-256` Content-Digest header per RFC 9530.
- **AgIS HTTP Message Signature profile** — sign and verify HTTP requests using a subset of RFC 9421, covering `agis-agent`, `@method`, `@target-uri`, `content-digest`, and `date`.
- **Freshness and replay protection** — validate request age against a configurable clock-skew window and detect replayed nonces using an in-memory cache.
- **Single delegation token** — sign and verify AgIS delegation tokens (compact JWS) carrying issuer, subject, audience, scope, and time constraints.
- **Delegated signed request verification** — offline verification of an HTTP request signed by an acting agent, carrying a single `AgIS-Delegation` token from an issuing agent.
- **Two-token delegation chain verification** — offline verification of a delegation chain where a root issuer delegates to an intermediate agent, which re-delegates to a final acting agent, with scope narrowing enforced.

## Limitation

This is an **offline reference SDK and test-vector implementation**. It does not yet perform:

- Live DNS lookup
- Live HTTP fetching
- Resolver API calls
- DNSSEC validation
- Persistent replay-cache storage across restarts

## Install

```bash
npm install
```

## Test

```bash
npm run test:vectors
npm run typecheck
```

## Build

```bash
npm run build
```

## Usage

```ts
import {
  verifyAgisRequestOffline,
  InMemoryReplayCache,
} from "@epicortek/agis-sdk-ts";
```

See `src/test-vector-*.ts` for complete working examples of each protocol component.

## Authorship and stewardship

AgIS was created and initially architected by Rizk Ayoub.

This TypeScript SDK and reference implementation are maintained under the EPICORTEK project namespace.

## Security note

The test keys in `test-vectors/keys/` are **public deterministic test material** generated for offline vector verification only. They must never be used in production.
