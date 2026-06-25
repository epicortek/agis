# AgIS CLI

The AgIS CLI provides offline command-line tools for working with AgIS test vectors and local verification files.

This CLI is a thin wrapper over the [`@epicortek/agis-sdk-ts`](../agis-sdk-ts) TypeScript SDK. All operations are fully offline.

## Install

```bash
cd packages/agis-cli
npm install
npm run build
```

The SDK must be built first:

```bash
cd packages/agis-sdk-ts
npm run build
```

## Commands

### Agent Card hash

Canonicalize an Agent Card (RFC 8785) and print its SHA-256 fingerprint:

```bash
node dist/index.js card hash \
  --card ../../test-vectors/agent-card/valid-agent-card.json
```

### JWK Thumbprint

Compute the RFC 7638 JWK Thumbprint of an Ed25519 public key:

```bash
node dist/index.js jwk thumbprint \
  --jwk ../../test-vectors/keys/ed25519-test-public.jwk.json
```

### DNS TXT binding parse

Parse an `agis=` DNS TXT record and print the fields as JSON:

```bash
node dist/index.js dns parse \
  --txt ../../test-vectors/dns/valid-dns-binding.txt
```

### Content-Digest

Compute the `sha-256` Content-Digest header for a request body:

```bash
node dist/index.js digest body \
  --body ../../test-vectors/requests/valid-request-body.json
```

### Agent Status validate

Validate an Agent Status document against an expected agent ID:

```bash
node dist/index.js status validate \
  --status ../../test-vectors/status/active-status.json \
  --agent agent://example.com/support-agent
```

### Offline identity verification

Run full offline composite identity verification (DNS + Agent Card + Status):

```bash
node dist/index.js verify identity \
  --dns ../../test-vectors/dns/valid-dns-binding.txt \
  --card ../../test-vectors/agent-card/signed-agent-card.json \
  --status ../../test-vectors/status/active-status.json
```

### Delegation token verify

Verify a delegation token from a test vector manifest:

```bash
node dist/index.js delegation verify \
  --token-manifest ../../test-vectors/delegation/valid-delegation-token.manifest.json \
  --public-jwk ../../test-vectors/keys/ed25519-test-public.jwk.json
```

### Run test vectors

Run the full AgIS SDK test vector suite:

```bash
node dist/index.js test-vectors
```

## Build and type check

```bash
npm run build       # compile TypeScript to dist/
npm run typecheck   # type-check only, no output
npm run dev         # run from source with tsx (requires built SDK dist/)
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Validation failed or runtime error |

## Limitation

This CLI does not perform live DNS lookup, live HTTP fetching, resolver API calls, DNSSEC validation, or persistent replay-cache storage. All operations read local files only.

## Authorship and stewardship

AgIS was created and initially architected by Rizk Ayoub.

This CLI is maintained under the EPICORTEK project namespace as an offline tool for local AgIS verification.
