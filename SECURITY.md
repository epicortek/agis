# Security Policy

## Supported versions

| Version | Status |
|---------|--------|
| `0.3.0-alpha.x` | Experimental / pre-release. Active development. Not recommended for production use. |
| `0.2.2-alpha.x` | Previous experimental. No further security patches planned. |

No production-stable release has been made yet. Breaking changes may occur in any pre-release version.

## Reporting a vulnerability

To report a security vulnerability in this project, email:

**security@epicortek.com**

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a minimal proof-of-concept.
- The affected component (SDK, CLI, test vector, delegation logic, signing/verification).
- The version or commit you tested against.

We will acknowledge receipt within 5 business days and provide an estimated timeline for a fix.

Do not open a public GitHub issue for security vulnerabilities until a fix has been coordinated.

## Scope

The following are **in scope** for security reports:

- `packages/agis-sdk-ts` — offline SDK for AgIS verification
- `packages/agis-cli` — CLI wrapper over the SDK
- Test vector data under `test-vectors/` (correctness of deterministic values)
- Delegation token logic (signing, verification, chain validation)
- HTTP Message Signature verification logic
- Agent Card canonicalization and signing/verification logic

## Out of scope

The following are **not in scope**:

- Production deployments not maintained by this project.
- Modified forks of this repository.
- Misuse of test keys (see note below).
- Issues in third-party dependencies not introduced by this project.
- Social engineering attacks.

## Important: test keys are public

The key material under `test-vectors/keys/` consists of **deterministic test-only key pairs**. They are intentionally published as part of the test-vector suite.

**These keys must never be used in production.** They offer no security. Any system that relies on these keys for real authentication is misconfigured.

If you discover that test keys have been used in a production system, that is a misconfiguration of that system, not a vulnerability in this project.
