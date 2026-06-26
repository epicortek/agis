# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
