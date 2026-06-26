# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.3.0-alpha.1] - 2026-06-26

### Security

- Fixed release hygiene: added `.npmrc` to `.gitignore` to prevent accidental token leakage.
- Fixed schema/signature type mismatch: `schemas/agent-card.schema.json` now accepts both `"JWS"` and `"jws"` for alpha compatibility.
- Added explicit EdDSA algorithm allowlist in `agentCardSignature.ts` and `delegationToken.ts` via `algorithms: ["EdDSA"]` in jose `compactVerify`.
- Added protected-header validation in `verifyAgentCardSignature`: `alg` must be `"EdDSA"`, `kid` in protected header must match `sig.key_id`.
- Hardened delegated request signer-key binding in `verifyDelegatedRequestOffline` and `verifyDelegationChainRequestOffline`: signing key is now resolved from the delegation subject's/final subject's verified public keys. Direct `requestSignerPublicJwk` usage is deprecated and adds a warning.
- Refactored replay protection to a two-phase check/commit API (`checkReplayProtection` / `commitReplayProtection`). Nonces are no longer consumed by rejected or invalid requests.
- Updated `SECURITY.md` to list `0.3.0-alpha.x` as the current experimental release.

### Added

- `checkReplayProtection()` and `commitReplayProtection()` exported from `replayProtection.ts`.
- `actingSubjectPublicKeys` option on `verifyDelegatedRequestOffline` (preferred over deprecated `requestSignerPublicJwk`).
- `finalSubjectPublicKeys` option on `verifyDelegationChainRequestOffline` (preferred over deprecated `requestSignerPublicJwk`).
- `checks.signatureKeyBound` field in delegated and chain request verification results.
- New error codes: `DELEGATED_REQUEST_SIGNATURE_KEY_NOT_FOUND`, `DELEGATED_REQUEST_SIGNER_KEY_NOT_BOUND_TO_SUBJECT`, `DELEGATION_CHAIN_REQUEST_SIGNATURE_KEY_NOT_FOUND`, `DELEGATION_CHAIN_REQUEST_SIGNER_KEY_NOT_BOUND_TO_FINAL_SUBJECT`.
- Test Vector 015-negative: delegated request rejected when signed with attacker key.
- Test Vector 016-negative: chain delegation request rejected when signed with attacker key.
- Test Vector 017-negative: replay nonce not burned when HTTP signature is invalid.
- Attacker test keypair in `test-vectors/keys/ed25519-attacker-{private,public}.jwk.json`.

## [0.3.0-alpha.0] - 2026-06-26

### Changed

- Repositioned AgIS as an ANS-compatible verification and governance toolkit — not a replacement for or competitor to Agent Name Service.
- Fixed agent status decision policy: `active`→allow, `revoked`/`suspended`/`compromised`→deny, `unknown`/`deprecated`→review.
- `unknown` and `deprecated` now produce `review` instead of falling through to `allow` or `deny` based on mode.
- Added `statusDecision` and `reasonCode` fields to `AgisAgentStatusValidationResult` and `AgisOfflineVerificationResult`.
- Added `active` field to `AgisAgentStatusValidationResult` (true only when status is `active`).

### Added

- New status test vectors: `suspended-status.json`, `compromised-status.json`, `unknown-status.json`, `deprecated-status.json`.
- New verification manifests for all six status values, each with `reasonCode`.
- Test Vector 014: complete status decision policy coverage for all six status values.
- Experimental JSON Schemas for Agent Card, Status Document, and Delegation Token (`schemas/`).
- `test:schemas` script to validate schema files.
- `docs/ANS_COMPATIBILITY.md`: mapping table and non-goals for AgIS/ANS relationship.
- `docs/SITE_MESSAGE.md`: website positioning copy.
- `reasonCode` field added to existing verification manifests for `active` and `revoked`.

## [0.2.2-alpha.1] - 2026-06-23

### Added

- Offline TypeScript SDK for AgIS v0.2.2.
- Agent Card canonicalization and SHA-256 hashing.
- RFC 7638 JWK thumbprint support.
- DNS TXT binding parsing and validation.
- Agent Card JWS signing and verification.
- Agent status and revocation validation.
- Offline composite identity verification.
- Content-Digest generation and verification.
- AgIS HTTP Message Signature test profile.
- Freshness and replay protection.
- Single delegation token verification.
- Delegated signed request verification.
- Two-token delegation chain verification.
- Offline CLI for local AgIS verification.
- Deterministic test vectors and negative cases.
- Root build/typecheck/test orchestration.
- Package smoke test.
- GitHub Actions CI.
