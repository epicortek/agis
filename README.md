# AgIS — Agent Identity System

AgIS is a DNS-backed identity and verification profile for AI and software agents on the existing web.

## Why AgIS exists

Existing web identity infrastructure (TLS, OAuth, DNS) was designed for humans and services. AI agents are increasingly making requests on behalf of users and other systems, but there is no standard way for a receiving service to answer: "Who sent this request, under what authority, and can I verify that offline?"

AgIS extends the existing web infrastructure to answer those questions without introducing new infrastructure. An agent publishes a DNS TXT record that binds its identifier to a signed Agent Card. Requests are signed with the agent's Ed25519 key. Delegation tokens carry scoped authority from one agent to another. A verifier can check everything offline from the DNS record and Agent Card alone.

## What AgIS verifies

1. **Agent identity** — that a given `agent://domain/name` identifier is bound to a specific public key via DNS TXT record and a signed Agent Card.
2. **Request authenticity** — that an HTTP request was signed by the agent claiming to have sent it.
3. **Request freshness** — that the request is recent and not replayed.
4. **Delegation** — that an acting agent holds a signed, scoped, time-limited token from an issuing agent, and that the token has not been tampered with.
5. **Delegation chains** — that authority flows in order through multiple agents, with scope narrowing enforced at each link.

## Current implementation status

AgIS v0.2.2 is currently implemented as an offline TypeScript reference SDK with deterministic test vectors.

| Component | Status |
|---|---|
| Agent Card canonicalization (RFC 8785) | Implemented |
| JWK Thumbprint (RFC 7638) | Implemented |
| DNS TXT binding | Implemented |
| Agent Card JWS signing + verification | Implemented |
| Agent Status + revocation | Implemented |
| Offline composite identity verification | Implemented |
| Content-Digest (RFC 9530) | Implemented |
| HTTP Message Signature profile (RFC 9421 subset) | Implemented |
| Request freshness + replay protection | Implemented |
| Single delegation token | Implemented |
| Delegated signed request verification | Implemented |
| Two-token delegation chain | Implemented |
| Live DNS lookup | Not yet |
| Live HTTP fetching | Not yet |
| DNSSEC validation | Not yet |
| Persistent replay cache | Not yet |
| Delegation chains longer than 2 | Not yet |

## Release readiness

Before tagging or publishing a pre-release:

```bash
npm run verify:release
npm run publish:dry-run
npm run release:audit
npm run release:check
```

These commands do not publish packages. They only build, test, pack, smoke-test, and run npm publish dry-runs. The release audit checks package names, version consistency, attribution files, stale package references, and release-blocking hygiene issues.

## Package smoke test

Before publishing or tagging a release, run:

```bash
npm run verify:release
```

This builds the SDK and CLI, runs all vectors, creates local package tarballs with `npm pack`, installs them into a temporary test project, verifies SDK import, and runs basic CLI commands from the packaged CLI.

## Build and verification

From the repository root:

```bash
npm run build         # build SDK then CLI
npm run typecheck     # type-check SDK and CLI
npm run test:vectors  # run all offline test vectors
npm run verify        # build + typecheck + test:vectors in sequence
```

The SDK must be built before the CLI because the CLI imports the built SDK output.

## Test vectors

The `test-vectors/` directory contains deterministic offline test fixtures for every protocol component. See [`test-vectors/README.md`](test-vectors/README.md) for the full index.

Run all vectors:

```bash
npm run test:vectors
```

## Repository structure

```
agis/
  test-vectors/
    agent-card/       Agent Card JSON fixtures
    dns/              DNS TXT binding test records
    keys/             Deterministic Ed25519 test keypair
    requests/         HTTP request body + Content-Digest + signed request manifests
    delegation/       Delegation token payloads and manifests
    verification/     Composite verification manifests
  packages/
    agis-sdk-ts/      TypeScript reference SDK
      src/            Implementation modules and test-vector runner scripts
    agis-cli/         Offline CLI tools for local AgIS verification and test-vector inspection
      src/            CLI source (thin wrapper over agis-sdk-ts)
```

## Security model

- Agent identity is rooted in DNS. An attacker who can modify DNS records for a domain can forge an agent identity for that domain.
- Signatures use Ed25519. Signature verification is deterministic and offline.
- Delegation tokens are compact JWS. Their validity depends on the issuer's key not being compromised.
- Replay protection uses an in-memory nonce cache, which is not persistent across restarts. Production deployments must use a durable cache.
- The test keypair in `test-vectors/keys/` is public and must never be used in production.

## What is not implemented yet

- Live DNS lookup and DNSSEC validation
- Live Agent Card and status fetching
- Resolver API
- OAuth/OIDC integration
- Delegation chains longer than two tokens
- Persistent replay cache
- Key rotation protocol

## Project stewardship

AgIS — Agent Identity System was created and initially architected by Rizk Ayoub.

The reference implementation, SDK, CLI, and deterministic test vectors are maintained under the EPICORTEK project namespace.

- Creator and initial architect: Rizk Ayoub
- Specification editor: Rizk Ayoub
- Project steward: EPICORTEK Technologies Inc.

## License

Apache-2.0
