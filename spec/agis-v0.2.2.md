# AgIS v0.2.2 Specification

## Agent Identity System

**Status:** Final Pre-Implementation Draft
**Version:** 0.2.2
**Category:** Agent Identity, Web Security, API Security, AI Agent Interoperability

---

## Abstract

AgIS — Agent Identity System — defines a DNS-backed identity and verification profile for software agents and AI agents.

AgIS enables websites, APIs, MCP servers, developer platforms, enterprise gateways, automation platforms, and autonomous workflow systems to verify an agent’s identity, domain ownership, public keys, status, revocation state, delegated authority, and signed requests using existing web standards.

AgIS does not define a new internet, a new DNS system, a new authorization framework, a new transport protocol, or a proprietary signing scheme. It is designed as a profile over existing web infrastructure and security standards, including DNS, HTTPS, `.well-known`, JSON, JWK, JWS, JSON Canonicalization Scheme, HTTP Message Signatures, HTTP Digest Fields, Problem Details for HTTP APIs, optional DID:web mapping, OAuth/OIDC compatibility, DPoP compatibility, and MCP compatibility.

An AgIS identity is expressed as a domain-backed Agent ID:

```text
agent://example.com/support-agent
agent://vendor.example/invoice-reader
agent://api.example/research-worker
```

The domain portion of the Agent ID acts as the root of administrative control. A verifier can use DNS records, an Agent Card, public keys, signatures, status endpoints, revocation information, delegation tokens, and optional resolver services to determine whether an agent identity is technically valid and whether requests attributed to that agent should be trusted under local policy.

---

## 1. Status of This Document

This document is a final pre-implementation draft specification.

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in uppercase.

This specification is intended to be implementable without reliance on a single centralized provider. Hosted resolvers, dashboards, trust networks, verification pages, key management services, and commercial implementations MAY be built on top of AgIS, but the base protocol MUST remain independently verifiable.

This draft is considered design-frozen for implementation experiments. Changes after this version SHOULD be limited to interoperability findings, security corrections, test-vector corrections, and clarifications required by implementation feedback.

---

## 2. Design Goals

AgIS is designed to provide:

1. A stable identity format for agents.
2. A DNS-backed method for proving domain control over an agent identity.
3. A public Agent Card format for publishing agent metadata.
4. Public key discovery for verifying agent signatures.
5. A deterministic canonicalization model for Agent Card hashing and signing.
6. A standard request-signing profile based on HTTP Message Signatures.
7. Explicit status and revocation mechanisms.
8. Fast revocation support through short-lived status checks and revocation feeds.
9. Delegation support for orchestrator-agent and sub-agent workflows.
10. Standardized HTTP error responses using Problem Details.
11. Compatibility with existing websites, APIs, MCP servers, OAuth/OIDC systems, DPoP, and optional DID:web.
12. A verification model that works both with hosted resolvers and independent local verification.
13. A gradual trust-level model that supports low-friction adoption and high-assurance deployments.
14. A set of operational verification modes that allow deployments to choose appropriate strictness.
15. A conformance model for publishers, verifiers, resolvers, SDKs, and reference implementations.
16. Reference test vectors for canonicalization, hashing, signatures, delegation, and error handling.

---

## 3. Non-Goals

AgIS does not attempt to:

1. Replace DNS.
2. Replace HTTPS.
3. Replace OAuth or OIDC.
4. Replace MCP.
5. Replace DID.
6. Replace API keys in all use cases.
7. Replace enterprise IAM.
8. Create a blockchain-based identity system.
9. Create a universal agent marketplace.
10. Define global reputation scoring.
11. Define moral, legal, or behavioral trustworthiness.
12. Proxy all agent traffic.
13. Prove the internal reasoning process of an AI model.
14. Prove that a specific model generated a specific output unless the activity is separately signed, instrumented, and verifiable.
15. Define universal authorization policy for all receiving systems.

AgIS identifies and verifies agents. Authorization decisions remain the responsibility of the receiving system.

---

## 4. Terminology

### 4.1 Agent

A software entity capable of acting semi-autonomously or autonomously on behalf of a user, organization, workflow, application, service, or another agent.

An agent MAY be powered by a language model, a rules engine, an automation system, a workflow orchestrator, a service account, or a hybrid architecture.

### 4.2 Agent ID

A URI identifying an agent under a domain-controlled namespace.

Example:

```text
agent://example.com/support-agent
```

### 4.3 HTTPS Equivalent Identifier

An HTTPS-based representation of an AgIS Agent ID for environments that restrict or reject custom URI schemes.

Example:

```text
https://example.com/.well-known/agis/id/support-agent
```

### 4.4 Agent Card

A public JSON document describing an agent’s identity, owner, public keys, capabilities, endpoints, status metadata, cache preferences, delegation support, and optional interoperability metadata.

### 4.5 DNS Binding

A DNS TXT record that binds an Agent ID to an Agent Card URL, public key thumbprint, and optionally an Agent Card hash.

### 4.6 Verifier

A system that receives an Agent ID or signed agent request and evaluates whether the agent identity, signature, status, key state, and delegation state are valid.

### 4.7 Resolver

A service, library, gateway, or local component that resolves an Agent ID into verified metadata by checking DNS records, fetching the Agent Card, validating hashes, validating keys, validating signatures, and checking status.

### 4.8 Delegation

A signed authorization by which one agent grants another agent limited authority to act within specific scope, time, audience, and depth constraints.

### 4.9 Delegation Chain

An ordered sequence of delegation tokens representing authority flow from an issuer agent to an acting agent through zero or more intermediate agents.

### 4.10 Trust Level

A technical assurance level describing the strength of verification evidence available for an agent identity.

Trust levels do not represent moral trustworthiness, safety, correctness, legal compliance, or model reliability.

### 4.11 Verification Mode

An operational policy mode that determines whether verification mismatches produce warnings, temporary failures, or hard failures.

### 4.12 High-Assurance Operation

A request, action, workflow, or verification context where identity failure, replay, key compromise, delegation misuse, or stale revocation data may cause significant security, operational, legal, financial, or safety impact.

---

## 5. AgIS Identity Model

### 5.1 Agent ID Format

The canonical AgIS Agent ID format is:

```text
agent://{domain}/{agent-name}
```

Where:

```text
scheme      = agent
domain      = valid DNS domain name
agent-name  = URL-safe agent name
```

Valid examples:

```text
agent://example.com/support-agent
agent://vendor.example/invoice-reader
agent://api.example/research-worker
```

Invalid examples:

```text
agent://support-agent
agent://example/support-agent
agent://example.com/
agent://example.com/My Agent
agent://example.com/../../admin
```

### 5.2 Agent Name Requirements

The `agent-name` component:

1. MUST be non-empty.
2. MUST be lowercase.
3. MUST be URL-safe.
4. MUST NOT contain path traversal sequences.
5. SHOULD be stable over time.
6. MUST NOT contain secrets.
7. SHOULD identify a software agent, not a human user.

### 5.3 URI Scheme Status

The `agent://` scheme is used by AgIS as an identifier scheme.

Until formally registered, implementations SHOULD treat `agent://` values as structured identifiers, not as browser-navigable URLs.

Systems MAY provide clickable user interface affordances that resolve an Agent ID through an AgIS resolver, verification page, local verifier, or HTTPS equivalent identifier.

### 5.4 HTTPS Equivalent Identifier

Implementations MUST support the canonical `agent://` Agent ID format.

Implementations SHOULD support an HTTPS equivalent identifier for environments that restrict or reject custom URI schemes.

The RECOMMENDED HTTPS equivalent form is:

```text
https://{domain}/.well-known/agis/id/{agent-name}
```

Example:

```text
https://example.com/.well-known/agis/id/support-agent
```

The HTTPS equivalent identifier SHOULD resolve through an HTTP 301, 302, 303, or 307 redirect to the Agent Card.

If a JSON descriptor is returned instead of a redirect, it:

1. MUST be served over HTTPS.
2. MUST contain the canonical Agent ID.
3. MUST contain the Agent Card URL.
4. SHOULD be treated only as discovery metadata.
5. MUST NOT replace DNS Binding validation.
6. MUST NOT replace Agent Card signature validation.
7. MUST NOT replace key thumbprint validation.
8. MUST NOT be treated as an independent trust anchor.

Example JSON descriptor:

```json
{
  "agis_version": "0.2.2",
  "agent_id": "agent://example.com/support-agent",
  "agent_card": "https://example.com/.well-known/agis/agents/support-agent.json"
}
```

The HTTPS equivalent identifier MUST NOT replace the canonical Agent ID inside signatures unless the signing profile explicitly declares that HTTPS identifiers are being used.

---

## 6. DNS Binding

### 6.1 Purpose

The DNS Binding proves that the owner or administrator of a domain has authorized an agent identity and has bound that identity to an Agent Card and public key material.

This prevents an Agent Card from being trusted solely because it is self-signed.

### 6.2 DNS TXT Record Name

For an Agent ID:

```text
agent://example.com/support-agent
```

The RECOMMENDED DNS TXT record name is:

```text
_agis.support-agent.example.com
```

General form:

```text
_agis.{agent-name}.{domain}
```

### 6.3 DNS TXT Record Value

The DNS TXT record MUST use semicolon-separated key-value pairs.

Minimum form:

```text
agis=0.2.2; agent=agent://example.com/support-agent; card=https://example.com/.well-known/agis/agents/support-agent.json
```

Recommended form:

```text
agis=0.2.2; agent=agent://example.com/support-agent; card=https://example.com/.well-known/agis/agents/support-agent.json; jkt=SHA256_JWK_THUMBPRINT; card_sha256=SHA256_AGENT_CARD
```

### 6.4 Required Fields

The following fields are REQUIRED:

```text
agis
agent
card
```

The `agis` field identifies the AgIS version.

The `agent` field MUST match the Agent ID being resolved.

The `card` field MUST be an HTTPS URL pointing to the Agent Card.

### 6.5 Recommended Fields

The following fields are RECOMMENDED:

```text
jkt
card_sha256
```

The `jkt` field contains the SHA-256 JWK thumbprint of the active signing key or a valid currently accepted key.

The `card_sha256` field contains the SHA-256 hash of the canonical Agent Card payload, as defined in Section 7.7.

### 6.6 Key Rotation Fields

Implementations MAY include key rotation metadata:

```text
jkt_active=NEW_THUMBPRINT
jkt_next=NEXT_THUMBPRINT
jkt_retiring=OLD_THUMBPRINT
rotation=planned
rotation_grace_until=2026-06-24T00:00:00Z
```

If key rotation fields are present, verifiers SHOULD apply the operational verification mode defined in Section 14.

### 6.7 DNSSEC

DNSSEC validation is OPTIONAL for low-friction adoption.

DNSSEC or an equivalent transparency proof SHOULD be required for high-assurance deployments.

A verifier MAY reduce the trust level of an agent if DNSSEC is unavailable.

---

## 7. Agent Card

### 7.1 Agent Card Location

The default Agent Card location is:

```text
https://{domain}/.well-known/agis/agents/{agent-name}.json
```

Example:

```text
https://example.com/.well-known/agis/agents/support-agent.json
```

### 7.2 Media Type

The RECOMMENDED media type is:

```text
application/agis+json
```

Until formally registered, implementations MAY serve Agent Cards as:

```text
application/json
```

### 7.3 Minimum Agent Card

An Agent Card MUST include:

```json
{
  "agis_version": "0.2.2",
  "agent_id": "agent://example.com/support-agent",
  "name": "support-agent",
  "owner": {
    "name": "Example Organization",
    "domain": "example.com"
  },
  "status": "active",
  "public_keys": [
    {
      "id": "key-2026-01",
      "type": "OKP",
      "crv": "Ed25519",
      "use": "sig",
      "alg": "EdDSA",
      "jwk_thumbprint": "SHA256_JWK_THUMBPRINT",
      "public_key_jwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "BASE64URL_PUBLIC_KEY"
      },
      "status": "active",
      "created_at": "2026-06-23T00:00:00Z"
    }
  ],
  "capabilities": [
    "signed_requests",
    "agent_identity"
  ],
  "endpoints": {
    "status": "https://example.com/.well-known/agis/agents/support-agent/status.json",
    "jwks": "https://example.com/.well-known/agis/agents/support-agent/jwks.json"
  },
  "cache": {
    "agent_card_ttl_seconds": 86400,
    "status_ttl_seconds": 60
  },
  "issued_at": "2026-06-23T00:00:00Z",
  "updated_at": "2026-06-23T00:00:00Z",
  "signature": {
    "type": "jws",
    "alg": "EdDSA",
    "key_id": "key-2026-01",
    "value": "JWS_SIGNATURE"
  }
}
```

### 7.4 Public Keys

The `public_keys` array MUST contain at least one public key.

Each key MUST include:

```text
id
type
use
public_key_jwk
status
```

Each key SHOULD include:

```text
alg
crv
jwk_thumbprint
created_at
expires_at
```

Ed25519 with EdDSA is RECOMMENDED for AgIS v0.2.2 interoperability.

Implementations MAY support additional algorithms such as ECDSA P-256 or ECDSA P-384, provided that:

1. The algorithm is explicitly declared in the Agent Card.
2. The key material is represented in a standard JWK-compatible form.
3. The algorithm is supported by the verifier.
4. The algorithm is covered by implementation test vectors.
5. The deployment policy permits the algorithm.

Supported key statuses:

```text
active
next
rotating
retiring
revoked
compromised
expired
```

### 7.5 Key Bloat Control

The Agent Card SHOULD contain only keys that are operationally relevant for current verification.

The Agent Card SHOULD contain keys with one of the following statuses:

```text
active
next
rotating
retiring
```

Keys with the following statuses SHOULD be removed from the Agent Card after the relevant operational window:

```text
revoked
compromised
expired
```

Historical keys MAY be published through the JWKS endpoint or a historical key archive if needed for audit verification.

The JWKS endpoint MAY contain a longer key history than the Agent Card.

Historical keys MUST include explicit status metadata if published.

### 7.6 Capabilities

The `capabilities` field is an array of machine-readable capability identifiers.

AgIS does not define a universal capability registry in v0.2.2.

Capability values SHOULD be stable strings and SHOULD NOT reveal sensitive internal architecture.

Examples:

```text
signed_requests
agent_identity
mcp_client
mcp_server
workflow_orchestrator
code_assistant
data_retrieval
```

### 7.7 Agent Card Canonical Hash

If `card_sha256` is used in DNS, it MUST be computed over the canonical Agent Card payload.

To avoid circular hashing:

1. The `signature` field MUST be excluded from the canonical hash payload.
2. Canonicalization MUST use RFC 8785 JSON Canonicalization Scheme.
3. The result MUST be hashed using SHA-256.
4. The resulting hash SHOULD be encoded as lowercase hex or base64url.
5. The encoding used SHOULD be declared by implementation policy or test vectors.

Verifiers MUST apply the same RFC 8785 canonicalization rules when validating `card_sha256`.

If canonicalization fails, the verifier MUST treat the Agent Card as invalid for hash and signature validation purposes.

### 7.8 Agent Card Signature

The Agent Card SHOULD be signed.

The signature MUST cover the canonical Agent Card payload excluding the `signature` field.

The signature SHOULD use JWS with EdDSA over Ed25519.

The signing key MUST correspond to one of the public keys declared in the Agent Card and bound by DNS through `jkt`, `jkt_active`, or equivalent key rotation metadata.

### 7.9 Optional DID:web Alias

An Agent Card MAY include a DID:web alias:

```json
{
  "did": "did:web:example.com:agis:agents:support-agent"
}
```

AgIS does not require DID adoption.

If DID:web is used, it SHOULD describe the same agent identity, public keys, and service endpoints in a compatible manner.

---

## 8. Agent Status and Revocation

### 8.1 Status Endpoint

The Agent Card MUST reference a status endpoint.

Default location:

```text
https://{domain}/.well-known/agis/agents/{agent-name}/status.json
```

### 8.2 Status Values

Allowed status values:

```text
active
revoked
suspended
deprecated
compromised
unknown
```

### 8.3 Active Status Response

```json
{
  "agent_id": "agent://example.com/support-agent",
  "status": "active",
  "updated_at": "2026-06-23T00:00:00Z",
  "cache": {
    "ttl_seconds": 60
  }
}
```

### 8.4 Revoked Status Response

```json
{
  "agent_id": "agent://example.com/support-agent",
  "status": "revoked",
  "reason": "key_compromise",
  "revoked_at": "2026-07-02T10:00:00Z",
  "updated_at": "2026-07-02T10:00:00Z",
  "cache": {
    "ttl_seconds": 30
  }
}
```

### 8.5 Cache-Control Requirements

The Agent Card MAY be cached for longer periods.

Recommended Agent Card caching:

```http
Cache-Control: max-age=86400
```

Status endpoints SHOULD use short TTLs.

Recommended normal status caching:

```http
Cache-Control: max-age=60, must-revalidate
```

Recommended high-assurance status caching:

```http
Cache-Control: max-age=15, must-revalidate
```

### 8.6 Revocation Behavior

A revoked agent MUST continue to resolve.

A resolver MUST NOT treat a revoked agent as nonexistent.

A resolver SHOULD return:

```text
agent found
identity existed
status revoked
reason if available
revoked_at if available
```

This preserves auditability.

### 8.7 Revocation Feed

High-assurance deployments SHOULD support a revocation feed.

An Agent Card MAY include:

```json
{
  "endpoints": {
    "revocation_feed": "https://example.com/.well-known/agis/revocations.json"
  }
}
```

A revocation feed SHOULD be signed and SHOULD support incremental updates.

---

## 9. HTTP Request Signing

### 9.1 Design Decision

AgIS v0.2.2 MUST NOT define a custom HTTP signature format.

AgIS request signing MUST use HTTP Message Signatures.

AgIS MAY define a profile that specifies which components are required.

### 9.2 Required Identity Header

An agent request SHOULD include:

```http
AgIS-Agent: agent://example.com/support-agent
```

The `AgIS-Agent` header is an identity hint and MUST be included in the signed components if present.

The `AgIS-Agent` header MUST NOT be modified by proxies, gateways, middleware, or application frameworks after the signature is created.

### 9.3 Content Digest

When a request contains a body, the sender SHOULD include `Content-Digest`.

The `Content-Digest` field SHOULD be computed according to RFC 9530.

For signed requests with a body, `content-digest` SHOULD be included in the HTTP Message Signature covered components.

High-assurance verifiers SHOULD reject signed requests with bodies if `Content-Digest` is missing.

### 9.4 Recommended Signed Components

A signed AgIS request SHOULD cover:

```text
agis-agent
@method
@target-uri
content-digest
date
```

Example:

```http
AgIS-Agent: agent://example.com/support-agent
Date: Tue, 23 Jun 2026 18:30:00 GMT
Content-Digest: sha-256=:BASE64_DIGEST:
Signature-Input: agis=("agis-agent" "@method" "@target-uri" "content-digest" "date");created=1782249000;keyid="key-2026-01";alg="ed25519"
Signature: agis=:BASE64_SIGNATURE:
```

### 9.5 Verification Steps

A verifier MUST:

1. Extract the `AgIS-Agent` header.
2. Parse the Agent ID.
3. Resolve the agent identity.
4. Retrieve the public key matching `keyid`.
5. Verify the HTTP Message Signature.
6. Verify `Content-Digest` if a request body is present.
7. Check request freshness using `Date` or signature metadata.
8. Apply replay protection if nonce, request ID, or equivalent mechanism is used.
9. Check agent status.
10. Check key status.
11. Check delegation if present.
12. Apply local authorization policy.

### 9.6 Replay Protection

AgIS implementations SHOULD support replay protection using one or more of:

```text
Date freshness
Nonce
Request ID
Short-lived delegation tokens
OAuth/DPoP proof-of-possession where applicable
```

Recommended request freshness windows:

```text
Normal requests: 300 seconds
High-risk requests: 60 seconds
```

High-assurance verifiers MUST require replay protection stronger than `Date` freshness alone, such as a nonce, request ID, DPoP proof, one-time-use challenge, or equivalent mechanism.

---

## 10. Signing Profiles

HTTP infrastructure often includes gateways, reverse proxies, URL rewriting, and load balancers.

AgIS defines signing profiles to reduce operational failure.

### 10.1 Public URL Profile

The Public URL Profile signs the public URL as seen by the client.

Recommended signed components:

```text
agis-agent
@method
@target-uri
content-digest
date
```

This profile is appropriate when the verifier receives the same URL that the agent signed.

### 10.2 Gateway Verification Profile

In this profile, an API gateway verifies the AgIS signature at the edge.

After verification, the gateway MAY forward trusted internal assertions to backend services.

Example internal headers:

```http
X-AgIS-Verified-Agent: agent://example.com/support-agent
X-AgIS-Verification-Result: valid
```

Internal verification headers MUST only be trusted from authenticated, controlled gateway infrastructure.

Backend services MUST NOT trust these headers from public clients.

### 10.3 Path/Authority Profile

For systems where internal URLs are rewritten but host/path semantics are preserved, implementations MAY sign:

```text
agis-agent
@method
host or authority
path
content-digest
date
```

Deployments using this profile MUST document exactly which components are signed.

### 10.4 Proxy Requirements

Systems that modify signed components will cause signature verification failure.

AgIS deployment guides MUST document how to configure common gateways and load balancers so that signed components are preserved or verified at the edge.

---

## 11. Delegation

### 11.1 Purpose

Delegation allows one agent to authorize another agent to act within limited scope.

Example:

```text
agent://example.com/orchestrator
delegates to
agent://example.com/worker-1
```

### 11.2 Delegation Token

A delegation token is a signed object.

Minimum fields:

```json
{
  "type": "agis-delegation",
  "version": "0.2.2",
  "issuer": "agent://example.com/orchestrator",
  "subject": "agent://example.com/worker-1",
  "audience": "https://api.service.example",
  "scope": [
    "read:resource",
    "write:result"
  ],
  "constraints": {
    "allowed_resources": [
      "resource:123"
    ],
    "max_duration_seconds": 900,
    "max_delegation_depth": 1
  },
  "issued_at": "2026-06-23T18:00:00Z",
  "expires_at": "2026-06-23T18:15:00Z",
  "jti": "deleg_123",
  "signature": {
    "type": "jws",
    "alg": "EdDSA",
    "key_id": "key-2026-01",
    "value": "JWS_SIGNATURE"
  }
}
```

### 11.3 Delegation Verification

A verifier MUST check:

1. Issuer identity is valid.
2. Issuer status is active.
3. Issuer key is active.
4. Issuer signature is valid.
5. Subject identity is valid.
6. Subject status is active.
7. Token is not expired.
8. Audience matches the receiving service.
9. Scope is sufficient.
10. Scope is not excessive under local policy.
11. Delegation depth is allowed.
12. Token is not revoked if revocation checking is required.

### 11.4 Delegation Revocation

Delegation tokens SHOULD be short-lived.

Recommended maximum lifetime:

```text
Normal delegation: 900 seconds
High-risk delegation: 60 seconds or less
```

Agents supporting delegation SHOULD publish a delegation revocation endpoint:

```json
{
  "delegation": {
    "supports_delegation": true,
    "delegation_revocation_endpoint": "https://example.com/.well-known/agis/agents/orchestrator/delegation-revocations.json"
  }
}
```

High-risk receivers SHOULD check delegation revocation synchronously before accepting delegated authority.

High-assurance verifiers MUST perform delegation revocation checks when a `delegation_revocation_endpoint` is declared.

### 11.5 Delegation Headers

A request MAY include a single delegation token using:

```http
AgIS-Delegation: BASE64URL_JWS_TOKEN
```

A request MAY include a delegation chain using:

```http
AgIS-Delegation-Chain: BASE64URL_JWS_TOKEN_1,BASE64URL_JWS_TOKEN_2
```

If `AgIS-Delegation` or `AgIS-Delegation-Chain` is present, the corresponding header MUST be included in the HTTP Message Signature covered components.

Example:

```http
AgIS-Agent: agent://example.com/worker-1
AgIS-Delegation-Chain: TOKEN_1,TOKEN_2
Date: Tue, 23 Jun 2026 18:30:00 GMT
Content-Digest: sha-256=:BASE64_DIGEST:
Signature-Input: agis=("agis-agent" "agis-delegation-chain" "@method" "@target-uri" "content-digest" "date");created=1782249000;keyid="key-2026-02";alg="ed25519"
Signature: agis=:BASE64_SIGNATURE:
```

### 11.6 Delegation Chain Order

Delegation chains MUST be ordered from original authority to acting agent.

Example order:

```text
orchestrator-token,worker-token
```

A verifier MUST reject a delegation chain if:

1. The order is invalid.
2. The issuer of a token does not match the expected previous subject.
3. The chain exceeds the allowed delegation depth.
4. Any token is expired.
5. Any token is revoked when revocation checking is required.
6. Any audience does not match the receiving service.
7. Any scope exceeds local policy.

### 11.7 Delegation Chain Size

Delegation chains carried in HTTP headers SHOULD be kept short.

Deployments MUST account for header size limits enforced by web servers, reverse proxies, gateways, and load balancers.

For long or complex delegation chains, implementations MAY carry the delegation chain inside the signed request body, provided that:

1. The body is covered by `Content-Digest`.
2. The relevant request components are covered by HTTP Message Signatures.
3. The receiving service explicitly supports body-carried delegation chains.
4. Local policy permits body-carried delegation chains.

---

## 12. Trust Levels

AgIS defines technical assurance levels.

### Level 0 — Self-Declared

The Agent ID is provided, but no proof is available.

### Level 1 — Domain-Proven

DNS TXT binding exists.

Agent Card exists.

Agent ID matches.

### Level 2 — Key-Bound

DNS binds the Agent Card and/or key thumbprint.

Public key matches DNS binding.

### Level 3 — Signed

Agent Card signature is valid.

Agent can sign requests using HTTP Message Signatures.

### Level 4 — Revocation-Aware

Status endpoint is valid.

Short TTL is enforced.

Revocation checks are available.

### Level 5 — High Assurance

DNSSEC or equivalent transparency proof is available.

Organization verification is available.

Signed requests are required.

Delegation is controlled.

Revocation feed is available.

Agent-signed activity records are supported.

Replay protection stronger than `Date` freshness alone is required.

### 12.1 Trust Level Interpretation

Trust levels are technical assurance levels.

They do not mean that an agent is safe, ethical, correct, compliant, or appropriate for all uses.

Receiving systems MUST still apply local policy.

---

## 13. Standard Error Responses

### 13.1 Problem Details

AgIS HTTP APIs SHOULD use Problem Details for HTTP APIs as defined by RFC 9457.

Responses SHOULD use:

```http
Content-Type: application/problem+json
```

### 13.2 Problem Detail Object

An AgIS problem detail response SHOULD include:

```json
{
  "type": "https://agis.example/problems/key-thumbprint-mismatch",
  "title": "Key thumbprint mismatch",
  "status": 400,
  "detail": "The public key thumbprint in the Agent Card does not match the DNS binding.",
  "instance": "agent://example.com/support-agent",
  "agis_code": "KEY_THUMBPRINT_MISMATCH",
  "trust_level": 1
}
```

### 13.3 Recommended AgIS Error Codes

Implementations SHOULD support stable machine-readable error codes.

Recommended codes:

```text
AGENT_ID_INVALID
HTTPS_EQUIVALENT_ID_INVALID
DNS_RECORD_MISSING
DNS_RECORD_INVALID
DNSSEC_UNAVAILABLE
AGENT_CARD_UNAVAILABLE
AGENT_CARD_INVALID
AGENT_CARD_HASH_MISMATCH
JCS_CANONICALIZATION_FAILED
KEY_THUMBPRINT_MISSING
KEY_THUMBPRINT_MISMATCH
KEY_REVOKED
KEY_COMPROMISED
KEY_EXPIRED
SIGNATURE_MISSING
SIGNATURE_INVALID
CONTENT_DIGEST_MISSING
CONTENT_DIGEST_INVALID
STATUS_UNAVAILABLE
STATUS_REVOKED
STATUS_SUSPENDED
STATUS_COMPROMISED
REVOCATION_FEED_UNAVAILABLE
DELEGATION_MISSING
DELEGATION_INVALID
DELEGATION_EXPIRED
DELEGATION_REVOKED
DELEGATION_AUDIENCE_MISMATCH
DELEGATION_SCOPE_EXCEEDED
DELEGATION_CHAIN_INVALID
DELEGATION_CHAIN_TOO_LARGE
REPLAY_DETECTED
REQUEST_TOO_OLD
VERIFICATION_MODE_FAILURE
UNSUPPORTED_ALGORITHM
```

### 13.4 Error Disclosure

Error responses SHOULD be useful for debugging but MUST NOT disclose secrets, private keys, internal tokens, sensitive infrastructure details, or confidential incident information.

### 13.5 Canonicalization Errors

`JCS_CANONICALIZATION_FAILED` indicates that the Agent Card could not be canonicalized according to RFC 8785.

This may indicate invalid JSON, unsupported numeric representations, incompatible JSON structures, or implementation defects.

A verifier MUST NOT proceed with Agent Card hash validation or Agent Card signature validation if canonicalization fails.

---

## 14. Verification Modes

AgIS supports operational verification modes.

### 14.1 Advisory Mode

Used for development, experimentation, and low-risk integrations.

Mismatches MAY produce warnings instead of hard failures.

### 14.2 Balanced Mode

Recommended default mode.

Minor operational mismatches MAY produce warnings if key rotation or migration is explicitly declared.

Critical mismatches MUST fail.

### 14.3 Strict Mode

Any mismatch in DNS binding, key thumbprint, Agent Card hash, signature, status, or revocation state MUST fail.

### 14.4 High-Assurance Mode

High-Assurance Mode SHOULD require:

```text
DNSSEC or equivalent transparency proof
valid Agent Card
valid key thumbprint
valid Agent Card hash
valid signature
active status
short status TTL
revocation feed availability
no unplanned key mismatch
controlled delegation
replay protection stronger than Date freshness alone
```

### 14.5 Example Failure Handling

| Condition                                    | Advisory | Balanced                                    | Strict                    | High-Assurance      |
| -------------------------------------------- | -------- | ------------------------------------------- | ------------------------- | ------------------- |
| Missing DNS TXT                              | Warning  | Fail                                        | Fail                      | Fail                |
| Agent Card hash mismatch                     | Warning  | Warning if planned rotation, otherwise fail | Fail                      | Fail                |
| Key thumbprint mismatch                      | Warning  | Fail unless planned rotation                | Fail                      | Fail                |
| Status endpoint unavailable                  | Warning  | Warning or temporary fail by policy         | Fail                      | Fail                |
| Revocation feed unavailable                  | Warning  | Warning                                     | Warning or fail by policy | Fail                |
| DNSSEC unavailable                           | Allowed  | Allowed                                     | Allowed with warning      | Fail or lower trust |
| Delegation revocation endpoint unavailable   | Warning  | Warning or fail by policy                   | Fail for high-risk        | Fail                |
| Replay protection weaker than Date freshness | Allowed  | Warning                                     | Warning or fail by policy | Fail                |

---

## 15. Key Management and Rotation

### 15.1 Key States

AgIS recognizes the following key states:

```text
next
active
rotating
retiring
revoked
compromised
expired
```

### 15.2 Planned Rotation Process

A safe key rotation SHOULD follow this sequence:

1. Generate the next key.
2. Publish the next public key in the Agent Card with status `next`.
3. Publish the next key thumbprint in DNS as `jkt_next` or equivalent rotation metadata.
4. Wait at least one DNS TTL.
5. Begin signing with the next key.
6. Mark the previous key as `retiring`.
7. Continue accepting the retiring key during the grace period.
8. Mark the old key as `expired` or `revoked` after the grace period.

### 15.3 Rotation Metadata Example

```json
{
  "key_rotation": {
    "mode": "planned",
    "started_at": "2026-06-23T00:00:00Z",
    "grace_until": "2026-06-24T00:00:00Z"
  }
}
```

DNS rotation example:

```text
agis=0.2.2; agent=agent://example.com/support-agent; card=https://example.com/.well-known/agis/agents/support-agent.json; jkt_active=NEW_THUMBPRINT; jkt_retiring=OLD_THUMBPRINT; rotation=planned
```

### 15.4 Emergency Rotation

If a key is compromised:

1. Mark the key as `compromised`.
2. Update the status endpoint if the whole agent identity is affected.
3. Publish a revocation feed entry.
4. Publish a new key if available.
5. Update DNS binding.
6. Reduce trust level until verification stabilizes.

High-assurance verifiers SHOULD fail requests signed by compromised keys immediately.

---

## 16. Server-Side Discovery

### 16.1 Purpose

A server MAY advertise AgIS support before receiving signed agent requests.

Server-side discovery is OPTIONAL.

### 16.2 Link Header Discovery

A server MAY advertise an AgIS metadata document using an HTTP `Link` header.

Example:

```http
Link: <https://api.service.example/.well-known/agis/server.json>; rel="agis-server-metadata"
```

### 16.3 Server Metadata Document

An AgIS server metadata document MAY include:

```json
{
  "agis_version": "0.2.2",
  "supported": true,
  "required_signing_profiles": [
    "public-url",
    "gateway-verification"
  ],
  "required_components": [
    "agis-agent",
    "@method",
    "@target-uri",
    "content-digest",
    "date"
  ],
  "high_assurance": false,
  "max_delegation_depth": 1,
  "max_request_age_seconds": 300
}
```

Server metadata is discovery information only.

Server metadata MUST NOT replace local policy, signature verification, DNS Binding validation, Agent Card validation, status checking, or delegation validation.

---

## 17. Resolver API

### 17.1 Resolve Agent

Request:

```http
GET /api/resolve?agent=agent://example.com/support-agent
```

Response:

```json
{
  "agent_id": "agent://example.com/support-agent",
  "verified": true,
  "trust_level": 4,
  "verification": {
    "domain_proof": "valid",
    "dnssec": "not_available",
    "agent_card": "valid",
    "card_hash": "valid",
    "key_thumbprint": "valid",
    "signature": "valid",
    "status": "active",
    "revocation": "not_revoked"
  },
  "owner": {
    "name": "Example Organization",
    "domain": "example.com"
  },
  "public_keys": [
    {
      "id": "key-2026-01",
      "type": "OKP",
      "crv": "Ed25519",
      "use": "sig",
      "status": "active"
    }
  ],
  "capabilities": [
    "signed_requests",
    "agent_identity"
  ],
  "cache": {
    "status_ttl_seconds": 60,
    "resolver_cache_ttl_seconds": 60
  },
  "resolved_at": "2026-06-23T18:45:00Z"
}
```

### 17.2 Verify Request

A resolver MAY provide request verification assistance.

Request:

```http
POST /api/verify-request
```

The request body SHOULD include:

```json
{
  "agent_id": "agent://example.com/support-agent",
  "method": "POST",
  "url": "https://api.service.example/action",
  "headers": {
    "AgIS-Agent": "agent://example.com/support-agent",
    "Date": "Tue, 23 Jun 2026 18:30:00 GMT",
    "Content-Digest": "sha-256=:BASE64_DIGEST:",
    "Signature-Input": "agis=(\"agis-agent\" \"@method\" \"@target-uri\" \"content-digest\" \"date\");created=1782249000;keyid=\"key-2026-01\";alg=\"ed25519\"",
    "Signature": "agis=:BASE64_SIGNATURE:"
  }
}
```

Response:

```json
{
  "valid": true,
  "agent_id": "agent://example.com/support-agent",
  "trust_level": 4,
  "status": "active",
  "signature": "valid",
  "timestamp": "valid",
  "revocation": "not_revoked",
  "delegation": "not_present",
  "policy_hint": "apply_local_policy"
}
```

### 17.3 Batch Verification

Batch verification is OPTIONAL and not required for v0.2.2 conformance.

Future versions MAY define a standard batch verification endpoint.

Implementations MAY provide private or experimental batch verification APIs, but such APIs MUST NOT be required for independent verification.

---

## 18. Independent Verification

AgIS MUST remain independently verifiable.

A verifier SHOULD be able to verify an agent without a hosted resolver by:

1. Parsing the Agent ID.
2. Querying DNS TXT.
3. Fetching the Agent Card over HTTPS.
4. Canonicalizing the Agent Card using RFC 8785.
5. Validating Agent Card hash.
6. Validating key thumbprint.
7. Validating Agent Card signature.
8. Fetching status endpoint.
9. Validating HTTP Message Signature.
10. Validating `Content-Digest` when present or required.
11. Validating delegation token or delegation chain if present.
12. Applying replay protection.
13. Applying local policy.

Hosted resolvers MAY improve performance, developer experience, caching, analytics, and revocation freshness, but MUST NOT be the only way to verify an AgIS identity.

---

## 19. Operational Tooling

AgIS implementations SHOULD provide developer tooling.

### 19.1 Verify Agent

```bash
agis verify agent://example.com/support-agent
```

### 19.2 Diagnose Agent

```bash
agis doctor agent://example.com/support-agent
```

The diagnostic tool SHOULD detect:

```text
missing DNS record
invalid card URL
card hash mismatch
key thumbprint mismatch
invalid Agent Card signature
status endpoint unavailable
stale cache headers
revoked or compromised keys
unplanned rotation
delegation endpoint issues
delegation revocation endpoint issues
unsupported algorithms
JCS canonicalization failures
```

### 19.3 Initialize Agent

```bash
agis agent init --domain example.com --name support-agent
```

This SHOULD generate:

```text
Agent Card
status.json
JWKS
private key
public key
JWK thumbprint
DNS TXT instructions
test vector material where applicable
```

### 19.4 Rotate Key

```bash
agis rotate-key --agent agent://example.com/support-agent
```

This SHOULD guide the operator through a planned rotation lifecycle.

---

## 20. MCP Compatibility

AgIS complements MCP.

MCP handles tool and context protocol interactions.

AgIS handles agent identity and verification.

An MCP server MAY require an AgIS identity before allowing tool access.

Example MCP policy:

```yaml
allowed_agents:
  - agent://example.com/support-agent

required_status: active

required_capabilities:
  - signed_requests

deny_if:
  - revoked
  - suspended
  - unsigned_request
  - unknown_domain
  - expired_delegation
```

AgIS does not define MCP transport behavior. It defines how agent identity MAY be bound to MCP clients, sessions, or requests.

---

## 21. OAuth/OIDC and DPoP Compatibility

AgIS does not replace OAuth/OIDC.

AgIS answers:

```text
Who is this agent?
What public key belongs to it?
Is it active?
Can it prove possession of its private key?
```

OAuth/OIDC answers:

```text
What is this agent authorized to access?
What scopes were granted?
What resource owner approved access?
```

Recommended model:

1. Agent identifies using AgIS.
2. Authorization server resolves AgIS identity.
3. Agent proves possession of its private key.
4. Authorization server issues an access token.
5. Access token MAY be bound to a proof-of-possession mechanism such as DPoP.
6. API verifies both token authorization and agent identity.

---

## 22. Privacy and Data Minimization

Agent Cards are public documents.

They MUST NOT contain:

```text
private keys
API secrets
tokens
internal service credentials
sensitive internal topology
private prompts
confidential system instructions
customer data
```

Agent Cards SHOULD contain only information needed for identity verification, interoperability, and policy decisions.

Status endpoints SHOULD expose minimal status information.

Revocation reasons MAY be coarse-grained to avoid leaking incident details.

---

## 23. Security Considerations

### 23.1 DNS Compromise

If DNS is compromised, an attacker may attempt to publish malicious bindings.

High-assurance deployments SHOULD require DNSSEC or equivalent transparency proof.

### 23.2 Agent Card Tampering

Agent Card tampering SHOULD be detected through `card_sha256`, key thumbprint validation, and signature verification.

### 23.3 Key Compromise

If a key is compromised, the agent owner MUST revoke or mark the key compromised, update the status endpoint if applicable, and publish revocation data.

### 23.4 Replay Attacks

Signed requests SHOULD include freshness and replay protection.

High-assurance deployments MUST require replay protection stronger than `Date` freshness alone.

### 23.5 Header Modification

Signed headers MUST NOT be modified after signing.

Deployments using gateways SHOULD verify signatures at the edge or preserve signed components end-to-end.

### 23.6 Delegation Abuse

Delegation tokens SHOULD be short-lived, scoped, audience-bound, and depth-limited.

High-risk delegation SHOULD use short TTLs and synchronous revocation checks.

### 23.7 Delegation Chain Size

Delegation chains carried in HTTP headers may exceed limits enforced by web servers, reverse proxies, gateways, and load balancers.

Implementations SHOULD keep delegation chains short.

Implementations MAY carry delegation chains inside the signed request body when header size limits are a concern, provided that body integrity and signature coverage requirements are met.

### 23.8 Resolver Centralization

Hosted resolvers can improve usability but create dependency risk.

Implementations SHOULD support independent verification.

### 23.9 Public Metadata Exposure

Agent Cards and `.well-known` endpoints are public.

Publishers MUST NOT expose secrets or sensitive internal implementation details.

### 23.10 Unsupported Algorithms

Verifiers MUST reject signatures using algorithms that are unsupported or disallowed by local policy.

---

## 24. Interoperability Requirements

A conforming AgIS v0.2.2 implementation SHOULD include:

```text
Agent ID parser
HTTPS equivalent identifier resolver
DNS TXT verifier
Agent Card schema validator
RFC 8785 canonicalizer
JWK thumbprint validator
Agent Card hash validator
Agent Card signature validator
Status endpoint checker
HTTP Message Signature verifier
Content-Digest verifier
Delegation token validator
Delegation chain validator
Problem Details error responses
Trust level evaluator
CLI or SDK interface
Test vectors
```

Interoperability test suites SHOULD include:

```text
valid agent
valid HTTPS equivalent identifier
missing DNS record
invalid card URL
card hash mismatch
key thumbprint mismatch
invalid signature
revoked agent
expired key
planned key rotation
unplanned key mismatch
valid delegation
valid delegation chain
expired delegation
invalid delegation audience
invalid delegation order
modified signed header
oversized delegation chain
replayed request
unsupported algorithm
standard problem detail error response
```

---

## 25. Test Vectors

### 25.1 Purpose

Test vectors are REQUIRED for reference implementations.

Test vectors ensure that independent implementations produce the same canonical hashes, signatures, verification results, and error codes.

### 25.2 Required Test Vector Set

A reference implementation MUST provide test vectors for:

```text
Agent ID parsing
HTTPS equivalent identifier resolution
DNS TXT binding parsing
Agent Card canonicalization
Agent Card SHA-256 hashing
JWK thumbprint validation
Agent Card signature validation
HTTP Message Signature validation
Content-Digest validation
status endpoint validation
revoked agent validation
planned key rotation validation
delegation token validation
delegation chain validation
Problem Details error response validation
unsupported algorithm handling
```

### 25.3 Recommended Directory Structure

```text
test-vectors/
  agent-id/
  https-equivalent-id/
  dns/
  agent-card/
  canonicalization/
  keys/
  signatures/
  requests/
  status/
  revocation/
  delegation/
  errors/
  algorithms/
```

### 25.4 Example Test Vector Manifest

```json
{
  "agis_version": "0.2.2",
  "name": "valid-agent-card-hash",
  "description": "Valid Agent Card canonicalization and SHA-256 hash test.",
  "input": {
    "agent_card": "agent-card.valid.json"
  },
  "expected": {
    "canonical_file": "agent-card.valid.jcs",
    "sha256": "EXPECTED_SHA256"
  }
}
```

---

## 26. IANA and Standards Considerations

This draft uses the `agent://` URI scheme as an AgIS identifier.

Future versions MAY pursue formal registration of the URI scheme or define an equivalent HTTPS-based representation as a primary compatibility profile.

Potential future media type registration:

```text
application/agis+json
```

Potential future link relation types MAY be defined for:

```text
agent-card
agent-status
agent-verification
agent-revocation-feed
agis-server-metadata
```

---

## 27. Versioning

AgIS documents MUST include an `agis_version` field.

Example:

```json
{
  "agis_version": "0.2.2"
}
```

Resolvers SHOULD support version negotiation.

Breaking changes MUST use a new minor or major version.

Patch versions SHOULD preserve compatibility.

---

## 28. Conformance

### 28.1 Minimal Conforming Agent Publisher

A minimal conforming publisher MUST:

1. Publish a valid Agent ID.
2. Publish a DNS TXT binding.
3. Publish an Agent Card over HTTPS.
4. Publish at least one public key.
5. Publish a status endpoint.

### 28.2 Signed Agent Publisher

A signed conforming publisher MUST additionally:

1. Sign the Agent Card.
2. Bind the key thumbprint through DNS.
3. Support signed requests using HTTP Message Signatures.

### 28.3 High-Assurance Publisher

A high-assurance publisher SHOULD additionally:

1. Support DNSSEC or equivalent transparency proof.
2. Support short status TTLs.
3. Support revocation feeds.
4. Support key rotation metadata.
5. Support delegation revocation.
6. Support auditable signed activity records.
7. Support replay protection stronger than `Date` freshness alone.

### 28.4 Conforming Verifier

A conforming verifier MUST be able to:

1. Parse Agent IDs.
2. Resolve HTTPS equivalent identifiers where supported.
3. Resolve DNS bindings.
4. Fetch Agent Cards.
5. Canonicalize Agent Cards using RFC 8785.
6. Validate key thumbprints.
7. Validate Agent Card hashes when present.
8. Validate Agent Card signatures when present.
9. Check agent status.
10. Verify HTTP Message Signatures when signed requests are used.
11. Validate `Content-Digest` when present or required.
12. Validate delegation tokens and delegation chains when present.
13. Evaluate trust level.
14. Apply local policy.

### 28.5 Reference Implementation

A reference implementation MUST include test vectors.

A reference implementation SHOULD include:

```text
CLI verifier
library or SDK
schema validation
canonicalization tests
signature tests
delegation tests
error response tests
algorithm agility tests
```

---

## 29. Reference Architecture

```text
AI Agent
  |
  | Signed HTTP request
  v
Website / API / MCP Server
  |
  | verifyAgentRequest()
  v
AgIS SDK or Local Verifier
  |
  | resolve agent://domain/name
  v
DNS TXT Binding
  |
  | card URL + key thumbprint + card hash
  v
Agent Card over HTTPS
  |
  | public keys + endpoints + cache rules
  v
Status / Revocation Endpoint
  |
  | active / revoked / suspended / compromised
  v
Delegation Verification if present
  |
  | issuer / subject / audience / scope / expiry
  v
Replay Protection
  |
  | date / nonce / request ID / proof-of-possession
  v
Verification Result
  |
  | local policy decision
  v
Allow / Deny / Review / Limited Access
```

---

## 30. Normative References

The following standards are used by or referenced by AgIS v0.2.2:

```text
RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels
RFC 8174 — Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words
RFC 8785 — JSON Canonicalization Scheme
RFC 9421 — HTTP Message Signatures
RFC 9457 — Problem Details for HTTP APIs
RFC 9530 — Digest Fields
```

Additional technologies referenced for compatibility:

```text
DNS
DNSSEC
HTTPS
JSON
JWK
JWS
OAuth 2.0
OpenID Connect
DPoP
DID:web
MCP
```

---

## 31. Summary

AgIS v0.2.2 defines a DNS-backed, web-standard identity and verification profile for agents.

It provides:

```text
agent://domain/name
HTTPS equivalent identifiers
DNS TXT binding
Agent Card
JWK public keys
JWK thumbprints
Agent Card hashes
RFC 8785 canonicalization
HTTP Message Signatures
Content-Digest support
Status and revocation
Delegation tokens
Delegation chain headers
Problem Details error responses
Verification modes
Key rotation lifecycle
Optional server-side discovery
Resolver API
Independent verification
MCP compatibility
OAuth/OIDC compatibility
Optional DID:web mapping
Test vectors
```

AgIS is not a registry only.

AgIS is not a new internet.

AgIS is not a proprietary signing protocol.

AgIS is a practical identity layer for agents built on the existing web.
