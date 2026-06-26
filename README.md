# AgIS — ANS-Compatible Agent Verification and Governance Toolkit

AgIS is a TypeScript toolkit that evaluates agent identity signals and produces operational trust decisions for applications, MCP servers, API gateways, and enterprise workflows.

> **AgIS is not a replacement for Agent Name Service (ANS).**
> AgIS is not a competing global naming service.
> AgIS is not endorsed by the Linux Foundation or the ANS project.
> AgIS is a verification, policy, and enforcement layer that sits above identity signals — including signals that ANS and similar systems may provide.

## What AgIS is

ANS and similar ecosystem-level services provide agent naming, discovery, and identity data. AgIS consumes that evidence and turns it into clear, deterministic operational decisions:

- **Allow** requests from trusted active agents.
- **Deny** requests from revoked, suspended, or compromised agents.
- **Review** requests from unknown or deprecated agents before execution.

AgIS helps applications and infrastructure answer: *"Should I trust this agent request right now, under what conditions, and can I prove it offline?"*

## Status decision policy

| Agent Status  | Decision | Reason Code            |
|---------------|----------|------------------------|
| `active`      | allow    | `AGENT_ACTIVE`         |
| `revoked`     | deny     | `AGENT_REVOKED`        |
| `suspended`   | deny     | `AGENT_SUSPENDED`      |
| `compromised` | deny     | `AGENT_COMPROMISED`    |
| `unknown`     | review   | `AGENT_STATUS_UNKNOWN` |
| `deprecated`  | review   | `AGENT_DEPRECATED`     |

`unknown` and `deprecated` produce `review`, not `allow`. Applications may configure a stricter policy that converts `review` to `deny`.

## Quick example

### A. Agent Card

```json
{
  "agent_id": "agent://example.com/support-agent",
  "issuer": "epicortek.com",
  "issued_at": "2026-06-01T00:00:00Z",
  "public_keys": [
    {
      "id": "key-1",
      "public_key_jwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
      }
    }
  ]
}
```

### B. Signed Request

```http
POST /mcp/tool HTTP/1.1
Host: api.example.com
Agis-Agent: agent://example.com/support-agent
Agis-Signature: <base64url-encoded-sig>
Agis-Timestamp: 2026-06-01T12:00:00Z
Content-Digest: sha-256=:base64digest:
```

### C. Verification Result

Active agent — allow:

```json
{
  "decision": "allow",
  "active": true,
  "revoked": false,
  "reasonCode": "AGENT_ACTIVE",
  "trustLevel": 4,
  "checks": {
    "dnsBinding": true,
    "agentCardHash": true,
    "jwkThumbprint": true,
    "agentCardSignature": true,
    "status": true
  }
}
```

Unknown status — review (never allow):

```json
{
  "decision": "review",
  "active": false,
  "revoked": false,
  "reasonCode": "AGENT_STATUS_UNKNOWN",
  "trustLevel": 4
}
```

## What AgIS verifies

1. **Agent identity** — that an `agent://domain/name` identifier is bound to a specific public key via a DNS TXT record and a signed Agent Card.
2. **Request authenticity** — that an HTTP request was signed by the agent that claims to have sent it.
3. **Request freshness** — that the request is recent and not replayed.
4. **Agent status** — that the agent's lifecycle status permits the request (active = allow, revoked/suspended/compromised = deny, unknown/deprecated = review).
5. **Delegation** — that an acting agent holds a signed, scoped, time-limited delegation token from a principal agent.
6. **Delegation chains** — that authority flows in order through multiple agents, with scope narrowing enforced at each link.

## ANS compatibility

ANS provides ecosystem-level agent naming, discovery, and identity evidence. AgIS can consume ANS-style identity evidence and apply local verification and governance policy.

See [`docs/ANS_COMPATIBILITY.md`](docs/ANS_COMPATIBILITY.md) for a detailed mapping table and non-goals.

## Current implementation status

AgIS v0.3.0-alpha.3 is implemented as an offline TypeScript reference SDK with deterministic test vectors.

| Component | Status |
|---|---|
| Agent Card canonicalization (RFC 8785) | Implemented |
| JWK Thumbprint (RFC 7638) | Implemented |
| DNS TXT binding | Implemented |
| Agent Card JWS signing + verification | Implemented |
| Agent Status + status decision policy | Implemented |
| Signed status document (EdDSA/JWS) | Implemented (alpha) |
| Offline composite identity verification | Implemented |
| Content-Digest (RFC 9530) | Implemented |
| HTTP Message Signature profile (RFC 9421 subset) | Implemented |
| Request freshness + replay protection | Implemented |
| Single delegation token | Implemented |
| Delegated signed request verification | Implemented |
| Two-token delegation chain | Implemented |
| Experimental JSON Schemas | Implemented |
| Signed status document for live fetching | Designed; live fetching not yet implemented |
| Live DNS lookup | Not yet |
| Live HTTP fetching | Not yet |
| DNSSEC validation | Not yet |
| Persistent replay cache | Not yet |
| Delegation chains longer than 2 | Not yet |

## Build and verification

```bash
npm run build         # build SDK then CLI
npm run typecheck     # type-check SDK and CLI
npm run test:vectors  # run all offline test vectors
npm run test:schemas  # validate schema files
npm run verify        # build + typecheck + test:vectors + test:schemas
```

## Release readiness

```bash
npm run verify:release
npm run publish:dry-run
npm run release:audit
npm run release:check
```

These commands do not publish packages. They build, test, pack, smoke-test, and run `npm publish` dry-runs. The release audit checks package names, version consistency, attribution files, and release hygiene.

## Test vectors

The `test-vectors/` directory contains deterministic offline test fixtures for every protocol component. See [`test-vectors/README.md`](test-vectors/README.md) for the full index.

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
    status/           Agent status documents (active, revoked, suspended, compromised, unknown, deprecated)
    verification/     Composite verification manifests
  schemas/            Experimental JSON Schemas for AgIS data structures
  docs/               Specifications, compatibility notes, and IETF Internet-Draft
  packages/
    agis-sdk-ts/      TypeScript reference SDK
    agis-cli/         Offline CLI tools for local AgIS verification
```

## Security model

- Agent identity is rooted in DNS. An attacker who can modify DNS records for a domain can forge an agent identity for that domain.
- Signatures use Ed25519. Signature verification is deterministic and offline.
- Delegation tokens are compact JWS. Their validity depends on the issuer's key not being compromised.
- Replay protection uses an in-memory nonce cache, which is not persistent across restarts. Production deployments must use a durable cache.
- The test keypair in `test-vectors/keys/` is public and must never be used in production.

## Non-goals

- AgIS does not replace ANS or operate a global agent namespace.
- AgIS does not provide live DNS lookups or DNSSEC validation (not yet implemented).
- AgIS does not claim Linux Foundation endorsement.
- AgIS does not provide production DNSSEC validation yet.

## Project stewardship

AgIS was created and initially architected by Rizk Ayoub.

The reference implementation, SDK, CLI, and deterministic test vectors are maintained under the EPICORTEK project namespace.

- Creator and initial architect: Rizk Ayoub
- Specification editor: Rizk Ayoub
- Project steward: EPICORTEK Technologies Inc.

## License

Apache-2.0
