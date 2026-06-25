---
title: "AgIS: An Agent Identity System for DNS-Backed Verification of AI and Software Agents"
abbrev: "AgIS Agent Identity"
docname: draft-ayoub-agis-agent-identity-system-00
category: info
ipr: trust200902
area: "Security"
workgroup: "Internet Engineering Task Force"
submissiontype: IETF
keyword:
  - agent identity
  - AI agents
  - DNS
  - HTTP message signatures
  - delegation
  - verification
stand_alone: true
pi:
  toc: true
  sortrefs: true
  symrefs: true

author:
  - ins: "R. Ayoub"
    name: "Rizk Ayoub"
    organization: "EPICORTEK Technologies Inc."
    email: "rizk.ayoub@epicortek.com"

normative:
  RFC2119:
  RFC8174:
  RFC3986:
  RFC5234:
  RFC7517:
  RFC7638:
  RFC8037:
  RFC8615:
  RFC8785:
  RFC9110:
  RFC9421:
  RFC9530:

informative:
  AGIS-IMPL:
    title: "AgIS v0.2.2-alpha.1 Reference Implementation, CLI, and Deterministic Test Vectors"
    author:
      - organization: "EPICORTEK Technologies Inc."
    date: 2026
    target: "https://github.com/epicortek/agis"
  AGIS-SDK:
    title: "AgIS TypeScript SDK"
    author:
      - organization: "EPICORTEK Technologies Inc."
    date: 2026
    target: "https://www.npmjs.com/package/@epicortek/agis-sdk-ts"
  AGIS-CLI:
    title: "AgIS CLI"
    author:
      - organization: "EPICORTEK Technologies Inc."
    date: 2026
    target: "https://www.npmjs.com/package/@epicortek/agis-cli"
---

--- abstract

This document specifies AgIS, the Agent Identity System, a DNS-backed identity and verification profile for AI agents, autonomous software agents, and agentic services operating on the existing web.

AgIS defines an agent identifier form, DNS TXT bindings, Agent Cards, key thumbprints, status and revocation documents, signed HTTP request verification, replay protection, delegation tokens, and delegation chains.  The design intentionally reuses existing Internet mechanisms, including DNS, HTTPS well-known resources, JSON Web Keys, JSON canonicalization, HTTP Message Signatures, and HTTP digest fields.

This document describes the v0.2.2 verification profile and the behavior exercised by the AgIS v0.2.2-alpha.1 reference implementation and deterministic test vectors.  It does not define a global trust authority, a production trust network, or a new public-key infrastructure.

--- middle

# Introduction

Software agents are increasingly used to perform actions across organizational, application, and network boundaries.  These agents may call APIs, retrieve data, initiate workflows, delegate tasks, and act on behalf of organizations, users, or other agents.

Existing web identity mechanisms are generally designed for human users, applications, domains, or service accounts.  They do not provide a compact, DNS-backed, agent-specific verification profile that allows a verifier to answer the following questions in a deterministic manner:

* What agent is making this request?
* Which domain is responsible for publishing that agent's identity information?
* Which Agent Card describes the agent?
* Which public key is bound to that agent?
* Has the Agent Card been tampered with?
* Is the agent active, suspended, revoked, deprecated, or compromised?
* Was this HTTP request signed by the expected agent key?
* Is the request fresh, or is it a replay?
* Is the acting agent using a valid delegation from another agent?
* Has a delegation chain attempted to escalate scope?

AgIS addresses these questions by defining a narrow identity and verification profile that can be deployed using ordinary DNS records and HTTPS resources.  It is intended to be small enough for developer tooling and deterministic enough for independent test-vector validation.

AgIS is not an authorization framework by itself.  A verifier MAY use AgIS verification results as input to a local authorization policy, but final authorization decisions remain local to the relying party.

AgIS is also not a claim that an agent is safe, truthful, lawful, beneficial, or aligned.  It verifies identity bindings, key material, request signatures, freshness signals, revocation status, and delegation constraints.  It does not certify the behavior or intent of the agent.

# Goals

AgIS has the following design goals:

1. Reuse existing web infrastructure.
2. Make agent identity independently verifiable.
3. Bind an agent identifier to a domain-controlled publication point.
4. Support deterministic offline verification.
5. Support signed HTTP requests using an existing HTTP signature framework.
6. Support revocation and status checks.
7. Support scoped delegation and delegation chains.
8. Avoid requiring a global AgIS root authority.
9. Avoid requiring blockchain, new DNS infrastructure, or new transport protocols.
10. Provide deterministic test vectors for independent implementations.

# Non-Goals

This version of AgIS does not define:

* a global trust registry;
* a certificate authority;
* a legal identity framework;
* a reputation system;
* a payment system;
* a production authorization policy language;
* a live DNS and HTTPS resolver profile;
* a mandatory hosted verification service;
* a registry for the `agent` URI scheme;
* an IANA registry for AgIS parameters.

Future documents may define live resolver behavior, additional transport bindings, registries, discovery mechanisms, or production policy profiles.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals.

Agent:
: A software actor that can make requests, receive requests, or perform tasks using an identity described by this specification.

Agent Identifier:
: A URI-like identifier beginning with `agent://` that names an agent under a domain.

Agent Card:
: A JSON document describing an agent, its identifier, owner metadata, capabilities, endpoints, public keys, cache information, and status.

Agent Card Hash:
: A SHA-256 digest of the JSON Canonicalization Scheme representation of the Agent Card, excluding the `signature` member.

DNS Binding:
: A DNS TXT record under the agent publisher's domain that binds an Agent Identifier to an Agent Card URL, and optionally to a JWK thumbprint and Agent Card hash.

Verifier:
: A party that evaluates AgIS identity material, request signatures, freshness, status, or delegation information.

Issuer:
: An agent that issues a delegation token.

Subject:
: An agent to which a delegation token is issued.

Acting Agent:
: The agent identified by the `AgIS-Agent` HTTP field in a signed request.

Delegation Chain:
: An ordered list of delegation tokens in which each token delegates from one agent to the next.

# Agent Identifier

An AgIS Agent Identifier has the following form:

```text
agent://{domain}/{agent-name}
```

For example:

```text
agent://example.com/support-agent
```

The `domain` component identifies the DNS domain responsible for publishing the agent binding.  The `agent-name` component identifies the agent under that domain.

The following ABNF defines the v0.2.2 Agent Identifier profile:

```abnf
agent-id     = "agent://" domain "/" agent-name
domain       = 1*(ALPHA / DIGIT / "-" / ".")
agent-name   = 1*(ALPHA / DIGIT / "-" / "_" / ".")
```

Implementations MUST compare the scheme component case-insensitively.  Implementations MUST compare the domain component using the normal DNS case-insensitive comparison rules.  Implementations MUST compare the agent-name component byte-for-byte after URI parsing.

An Agent Identifier MUST NOT contain a query component.  An Agent Identifier MUST NOT contain a fragment component.  An Agent Identifier MUST NOT contain userinfo.

This document does not request registration of the `agent` URI scheme at this time.

# HTTPS Equivalent Identifier

An Agent Identifier maps to a default HTTPS publication location:

```text
https://{domain}/.well-known/agis/id/{agent-name}
```

This HTTPS equivalent identifier is intended for human inspection, linking, debugging, and future resolver behavior.  The v0.2.2 profile does not require live fetching of this location for offline verification.

# Agent Card Location

The default Agent Card location is:

```text
https://{domain}/.well-known/agis/agents/{agent-name}.json
```

A DNS Binding MAY specify a different Agent Card URL using the `card` parameter.  If the `card` parameter is present, verifiers MUST use that value for the binding under evaluation.

Agent Card URLs MUST use HTTPS.  Verifiers MUST reject non-HTTPS Agent Card URLs except in explicitly configured local development environments.

# DNS TXT Binding

The default DNS TXT owner name for an agent is:

```text
_agis.{agent-name}.{domain}
```

For the Agent Identifier:

```text
agent://example.com/support-agent
```

the default DNS TXT owner name is:

```text
_agis.support-agent.example.com
```

A minimal DNS TXT binding has the following form:

```text
agis=0.2.2; agent=agent://example.com/support-agent; card=https://example.com/.well-known/agis/agents/support-agent.json
```

A recommended DNS TXT binding additionally includes a JWK thumbprint and Agent Card hash:

```text
agis=0.2.2; agent=agent://example.com/support-agent; card=https://example.com/.well-known/agis/agents/support-agent.json; jkt=dXBQ4ZkgA3nTvwrFeLAKYokanVfetC0fzXUiSFkYg08; card_sha256=842dbbbf1c807d020ceafe7fd8b51502cf7ae94314238e293a36c736463a3122
```

The following parameters are defined:

agis:
: The AgIS profile version.  For this document the value is `0.2.2`.

agent:
: The Agent Identifier.

card:
: The HTTPS URL of the Agent Card.

jkt:
: The JWK thumbprint of the signing key, encoded using base64url without padding.

card_sha256:
: The lowercase hexadecimal SHA-256 digest of the canonical Agent Card, excluding the `signature` member.

A verifier MUST reject a DNS Binding if the `agis`, `agent`, or `card` parameter is missing.  A verifier SHOULD reject a DNS Binding if `jkt` or `card_sha256` is present but does not match the Agent Card under evaluation.

The order of DNS Binding parameters is not significant.  Parameter names are case-sensitive.  Parameter values MUST NOT be interpreted as shell expressions, templates, or executable content.

# Agent Card

An Agent Card is a JSON document describing an agent.  The v0.2.2 profile defines the following required members:

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
  "issued_at": "2026-06-23T00:00:00Z",
  "updated_at": "2026-06-23T00:00:00Z",
  "capabilities": [
    "signed_requests",
    "agent_identity"
  ],
  "endpoints": {
    "jwks": "https://example.com/.well-known/agis/agents/support-agent/jwks.json",
    "status": "https://example.com/.well-known/agis/agents/support-agent/status.json"
  },
  "public_keys": [
    {
      "id": "key-2026-01",
      "type": "OKP",
      "use": "sig",
      "alg": "EdDSA",
      "crv": "Ed25519",
      "status": "active",
      "created_at": "2026-06-23T00:00:00Z",
      "public_key_jwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "ARcMgvwCLxMm4lHCAF5GfiC2N6D2w4tM7Mcrv-h81pg"
      },
      "jwk_thumbprint": "dXBQ4ZkgA3nTvwrFeLAKYokanVfetC0fzXUiSFkYg08"
    }
  ],
  "cache": {
    "agent_card_ttl_seconds": 86400,
    "status_ttl_seconds": 60
  }
}
```

An Agent Card MAY contain additional members.  Verifiers MUST ignore unknown members unless local policy requires otherwise.  However, unknown members are included in the canonical hash unless explicitly excluded by this specification.

The `signature` member, if present, MUST be excluded from Agent Card canonicalization and hashing.

# Agent Card Canonicalization and Hashing

Agent Card canonicalization uses the JSON Canonicalization Scheme defined by {{RFC8785}}.

To compute the Agent Card hash, a verifier MUST:

1. Parse the Agent Card as JSON.
2. Remove the top-level `signature` member if it is present.
3. Canonicalize the resulting JSON object using JCS.
4. Compute SHA-256 over the UTF-8 bytes of the canonicalized JSON.
5. Represent the digest as lowercase hexadecimal.

For the v0.2.2 test vector Agent Card, the expected SHA-256 digest is:

```text
842dbbbf1c807d020ceafe7fd8b51502cf7ae94314238e293a36c736463a3122
```

A verifier MUST compare the computed Agent Card hash with the DNS Binding `card_sha256` parameter if that parameter is present.

# Agent Keys and JWK Thumbprints

Agent public keys are represented as JSON Web Keys using {{RFC7517}}.

The preferred v0.2.2 signing key type is Ed25519 represented as an OKP JWK.  Ed25519 JWK representation follows {{RFC8037}}.

A verifier MUST compute JWK thumbprints according to {{RFC7638}}.  For the v0.2.2 test vector public key:

```json
{
  "crv": "Ed25519",
  "kty": "OKP",
  "x": "ARcMgvwCLxMm4lHCAF5GfiC2N6D2w4tM7Mcrv-h81pg"
}
```

the expected JWK thumbprint is:

```text
dXBQ4ZkgA3nTvwrFeLAKYokanVfetC0fzXUiSFkYg08
```

A verifier MUST reject an Agent Card if a key's declared `jwk_thumbprint` does not match the computed thumbprint for the corresponding `public_key_jwk`.

A verifier SHOULD reject a DNS Binding if the `jkt` parameter is present and does not match at least one active signing key in the Agent Card.

# Signed Agent Cards

An Agent Card MAY include a top-level `signature` member containing a detached or embedded signature over the canonical Agent Card representation.  The v0.2.2 reference implementation uses a compact JWS form with the following protected header:

```json
{
  "alg": "EdDSA",
  "kid": "key-2026-01",
  "typ": "agis-agent-card+jcs"
}
```

A verifier of a signed Agent Card MUST:

1. Remove the top-level `signature` member.
2. Canonicalize the remaining Agent Card using JCS.
3. Verify that the signed payload equals the canonical representation.
4. Locate the signing key by `kid`.
5. Verify the signature using the key's public JWK.
6. Verify that the Agent Card hash remains stable after excluding the `signature` member.

A verifier MUST reject a signed Agent Card if the signed payload does not match the canonical Agent Card representation.

# Agent Status

An Agent Status document describes the current status of an agent.  The default status endpoint is listed in the Agent Card under `endpoints.status`.

The following status values are defined:

active:
: The agent is active.

revoked:
: The agent has been revoked and MUST NOT be allowed to act.

suspended:
: The agent is temporarily suspended and SHOULD NOT be allowed to act unless local policy explicitly permits it.

deprecated:
: The agent remains resolvable for compatibility or audit purposes, but new integrations SHOULD NOT depend on it.

compromised:
: The agent or its key material is believed to be compromised and MUST NOT be allowed to act.

unknown:
: The publisher cannot currently assert a stronger status.  Verifiers SHOULD treat this status conservatively.

An example active status document is:

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

An example revoked status document is:

```json
{
  "agent_id": "agent://example.com/support-agent",
  "status": "revoked",
  "revoked": true,
  "revoked_at": "2026-06-23T00:00:00Z",
  "reason": "key_compromise",
  "updated_at": "2026-06-23T00:00:00Z",
  "cache": {
    "ttl_seconds": 30
  }
}
```

A verifier MUST reject a status document if the `agent_id` does not match the Agent Identifier under evaluation.

A verifier MUST treat `revoked` and `compromised` as denial states.

A revoked agent SHOULD remain resolvable for auditability, incident response, and historical verification.

# Offline Identity Verification

The v0.2.2 offline identity verification procedure takes as input:

* an Agent Identifier;
* a DNS Binding;
* an Agent Card;
* optionally, an Agent Status document.

A verifier performs the following checks:

1. The DNS Binding is syntactically valid.
2. The DNS Binding `agent` value matches the Agent Identifier.
3. The DNS Binding `card` value identifies the Agent Card URL under evaluation.
4. The Agent Card `agent_id` matches the Agent Identifier.
5. The Agent Card canonical hash matches `card_sha256`, if present.
6. At least one active Agent Card signing key matches `jkt`, if present.
7. Each declared JWK thumbprint matches its public JWK.
8. The Agent Card signature is valid, if present.
9. The status document is valid, if present.
10. Revocation or compromise status is enforced.

A verifier MUST NOT allow a revoked or compromised agent merely because its cryptographic signature is valid.

# HTTP Request Signing Profile

AgIS signed requests use HTTP Message Signatures {{RFC9421}}.

The following HTTP fields are defined by this profile:

AgIS-Agent:
: The Agent Identifier of the acting agent.

AgIS-Nonce:
: A nonce used for replay protection in high-assurance requests.

AgIS-Delegation:
: A single compact delegation token.

AgIS-Delegation-Chain:
: A comma-separated ordered list of delegation tokens.

AgIS request signatures use the signature label `agis`.

A basic signed AgIS request MUST cover at least the following components:

```text
"agis-agent"
"@method"
"@target-uri"
"content-digest"
"date"
```

The corresponding `Signature-Input` value has the following form:

```text
agis=("agis-agent" "@method" "@target-uri" "content-digest" "date");created=1782249000;keyid="key-2026-01";alg="ed25519"
```

The request MUST include both `Signature-Input` and `Signature` fields as required by HTTP Message Signatures.

The request body digest MUST be represented using `Content-Digest` as defined by {{RFC9530}}.  For the v0.2.2 request-body test vector, the expected value is:

```text
sha-256=:EElbeZnbXXnH5AMO46WOKBIN6fvWcuBFv/qlOLFgSYk=:
```

A verifier MUST reject a request if the message body does not match the `Content-Digest` field.

A verifier MUST reject a request if any covered signature component has been changed after signing.

# High-Assurance Requests, Freshness, and Replay Protection

A high-assurance AgIS request includes `AgIS-Nonce` and signs it.

A high-assurance request MUST cover at least the following components:

```text
"agis-agent"
"agis-nonce"
"@method"
"@target-uri"
"content-digest"
"date"
```

Example:

```text
agis=("agis-agent" "agis-nonce" "@method" "@target-uri" "content-digest" "date");created=1782249000;keyid="key-2026-01";alg="ed25519"
```

A verifier of high-assurance requests MUST enforce freshness.  The verifier SHOULD reject requests whose `Date` field falls outside a locally configured freshness window.  A default freshness window of 300 seconds is RECOMMENDED for deployments that do not have stronger time synchronization or policy requirements.

A verifier of high-assurance requests MUST enforce replay protection.  The tuple used for replay detection SHOULD include:

* the Agent Identifier;
* the nonce;
* the HTTP method;
* the target URI;
* the signature key identifier;
* a freshness-window identifier or expiration time.

A verifier MUST reject a high-assurance request if the nonce is missing.

A verifier MUST reject a high-assurance request if the nonce has already been observed within the replay-protection window.

# Delegation Tokens

AgIS delegation tokens allow one agent to delegate a constrained capability to another agent.

A v0.2.2 delegation token is a compact signed token whose payload contains at least the following members:

```json
{
  "type": "agis-delegation",
  "version": "0.2.2",
  "issuer": "agent://example.com/support-agent",
  "subject": "agent://example.com/invoice-worker",
  "audience": "https://api.service.example",
  "scope": [
    "resource:read",
    "invoice:read"
  ],
  "constraints": {
    "max_requests": 10,
    "purpose": "invoice-processing"
  },
  "issued_at": "2026-06-23T18:30:00Z",
  "expires_at": "2026-06-23T18:45:00Z",
  "jti": "delegation-2026-06-23-001"
}
```

The protected header for a v0.2.2 delegation token uses:

```json
{
  "alg": "EdDSA",
  "kid": "key-2026-01",
  "typ": "agis-delegation+jwt"
}
```

A verifier MUST reject a delegation token if:

* the signature is invalid;
* the token is expired;
* the token is not yet valid;
* the `audience` does not match the expected relying party;
* the required scope is not included in the delegated scope;
* the acting agent does not match the token subject;
* the `jti` member is missing;
* local policy rejects any declared constraint.

A delegation token MUST NOT be interpreted as an unrestricted bearer credential.  It is a signed, scoped, time-bounded statement whose validity depends on signature verification, subject matching, audience matching, scope checking, time validation, and local policy.

# Delegated Signed Requests

A delegated signed request includes:

* `AgIS-Agent`, identifying the acting agent;
* `AgIS-Delegation`, carrying the delegation token;
* `Content-Digest`;
* `Signature-Input`;
* `Signature`.

A delegated signed request MUST sign the `AgIS-Delegation` field.

The following signature components are REQUIRED for a single-delegation request:

```text
"agis-agent"
"agis-delegation"
"@method"
"@target-uri"
"content-digest"
"date"
```

A verifier MUST reject the request if the `AgIS-Agent` value does not match the delegation token subject.

A verifier MUST reject the request if the delegation token is changed after the HTTP signature is produced.

# Delegation Chains

A delegation chain is an ordered sequence of delegation tokens.  Each token delegates from one agent to the next.

For a valid chain:

* the first token's issuer is the root issuer;
* the first token's subject is the second token's issuer;
* each subsequent token's subject is the next token's issuer;
* the final token's subject is the acting agent;
* the acting agent matches `AgIS-Agent`;
* the audience is valid for each token;
* the required scope is included in the effective scope;
* each token is within its validity interval;
* each token has a valid signature;
* each token contains a `jti`.

The effective scope of a delegation chain MUST NOT exceed the scope granted upstream.  Implementations SHOULD compute effective scope as the intersection of scopes across the chain unless local policy defines a stricter rule.

A delegation chain signed request includes `AgIS-Delegation-Chain`.  The signature MUST cover that field.

The following signature components are REQUIRED for a delegation-chain request:

```text
"agis-agent"
"agis-delegation-chain"
"@method"
"@target-uri"
"content-digest"
"date"
```

A verifier MUST reject a delegation chain if:

* the chain order is reversed;
* any link is broken;
* a downstream token attempts scope escalation;
* the acting agent does not match the final subject;
* the required scope is not in the effective scope;
* any token is expired;
* the chain field is modified after signing.

# Trust Levels

AgIS defines the following non-normative trust levels for reporting verification strength:

Level 0:
: No usable AgIS identity evidence is available.

Level 1:
: The Agent Identifier and Agent Card are syntactically valid.

Level 2:
: A DNS Binding exists and links the Agent Identifier to an Agent Card URL.

Level 3:
: The Agent Card hash and JWK thumbprint are consistent with the DNS Binding and Agent Card.

Level 4:
: The Agent Card signature and status checks are valid, and the agent is active.

Level 5:
: A signed request is valid with freshness and replay protection enforced, and local policy accepts the result.

The v0.2.2 offline reference identity verification test vectors reach Level 4.  High-assurance signed request verification can reach Level 5 when freshness and replay protection are enforced by the verifier.

Trust levels are advisory.  Implementations MUST NOT treat a trust level as a replacement for local authorization policy.

# Error Model

AgIS implementations SHOULD expose deterministic error codes suitable for test-vector validation and debugging.

The following error categories are RECOMMENDED:

* DNS binding errors;
* Agent Card hash errors;
* JWK thumbprint errors;
* Agent Card signature errors;
* status and revocation errors;
* Content-Digest errors;
* HTTP signature errors;
* freshness errors;
* replay-detection errors;
* delegation token errors;
* delegation chain errors;
* local policy denial.

Error messages SHOULD be safe to log.  Error messages MUST NOT include private keys, secret tokens, bearer credentials, or unredacted sensitive request bodies.

# Deterministic Test Vectors

The v0.2.2 reference implementation includes deterministic test vectors for:

* Agent Card canonical hash;
* skeleton Agent Card canonical hash;
* JWK thumbprint;
* DNS TXT Binding;
* signed Agent Card;
* Agent Card tampering;
* Agent Status and revocation;
* invalid status documents;
* offline composite identity verification;
* invalid composite verification cases;
* Content-Digest;
* invalid Content-Digest cases;
* HTTP Message Signatures;
* invalid HTTP signature cases;
* offline signed request verification;
* invalid signed request cases;
* freshness and replay protection;
* invalid freshness and replay cases;
* single delegation token;
* invalid delegation token cases;
* delegated signed request;
* invalid delegated request cases;
* delegation chain signed request;
* invalid delegation chain request cases.

Independent implementations SHOULD validate against the deterministic test vectors before claiming compatibility with this profile.

# Security Considerations

AgIS is a security-sensitive identity and request-verification profile.  Implementations and deployments need to consider at least the following threats.

## DNS Control and Domain Compromise

AgIS binds agent identity to DNS names.  If an attacker controls the DNS zone, registrar account, authoritative DNS provider account, or DNS publication pipeline, the attacker can publish malicious Agent Bindings.

Deployments SHOULD protect registrar and DNS provider accounts with strong authentication and operational controls.  DNSSEC MAY be used where available, but this document does not require DNSSEC.

## HTTPS Publication Security

Agent Cards and status documents are expected to be published over HTTPS.  If HTTPS publication infrastructure is compromised, an attacker may publish altered Agent Cards or status documents.

Verifiers SHOULD prefer DNS Binding values that include `card_sha256` and `jkt`, because these allow detection of Agent Card or key substitution when the DNS Binding remains trustworthy.

## Canonicalization Attacks

Incorrect JSON canonicalization can cause implementations to compute different hashes or verify different payloads.  Implementations MUST use JCS as specified by this document and MUST exclude only the top-level `signature` member from Agent Card hashing.

Implementations MUST NOT canonicalize by using ordinary pretty-printing, unstable object key ordering, locale-sensitive ordering, or runtime-specific serialization behavior.

## Key Compromise

If an agent signing key is compromised, an attacker may produce valid signatures until the key is revoked or removed from the Agent Card and status information is updated.

Publishers SHOULD provide short status TTLs for higher-risk agents.  Verifiers SHOULD respect revocation and compromised states even when signatures remain cryptographically valid.

## Revocation Caching

Caching improves availability but can delay enforcement of revocation.  Publishers SHOULD use conservative status TTLs.  Verifiers SHOULD bound cache lifetime and MAY re-check status for high-risk operations.

## Replay Attacks

Signed requests without freshness and replay protection can be captured and replayed.  High-assurance deployments MUST require freshness checking and nonce-based replay protection.

## Clock Skew

Freshness checks depend on clocks.  Verifiers SHOULD define an acceptable clock-skew window.  Deployments SHOULD maintain reliable time synchronization.

## Signature Confusion

Implementations MUST verify the expected signature label and covered components.  A signature over one set of components MUST NOT be accepted as proof over a different set of components.

## Delegation Confusion

Delegation tokens MUST be checked for issuer, subject, audience, scope, time validity, and `jti`.  A delegation token MUST NOT be treated as an unrestricted bearer credential.

Delegation chains MUST preserve order and MUST prevent downstream scope escalation.

## Test Keys

The deterministic test keys included with the reference implementation are public test material.  They MUST NOT be used in production.

## Local Authorization

AgIS verification does not authorize an action by itself.  A relying party MUST apply local authorization policy after identity, request, freshness, status, and delegation checks.

# Privacy Considerations

AgIS identifiers, DNS Binding names, Agent Card URLs, and status endpoints may reveal information about an organization's internal agent naming, capabilities, deployment structure, or operational status.

Publishers SHOULD avoid embedding sensitive internal project names, customer names, incident information, or confidential workflow details in public Agent Identifiers or Agent Cards.

Verifiers SHOULD avoid logging sensitive request bodies, delegation tokens, or identifiers beyond operational necessity.

Delegation chains can reveal workflow structure.  Deployments SHOULD minimize delegated scope, token lifetime, and exposed constraints.

# IANA Considerations

This document makes no IANA requests at this time.

Future versions may request registration of:

* the `agent` URI scheme;
* an AgIS well-known URI;
* AgIS-specific HTTP field names;
* AgIS parameter registries.

No such registrations are requested by this version of the document.

# Implementation Status

This section records implementation status for informational purposes and is expected to be removed or updated before publication as an RFC.

The AgIS v0.2.2-alpha.1 reference implementation includes:

* a TypeScript SDK;
* a CLI named `agis`;
* deterministic test vectors;
* offline identity verification;
* Agent Card canonical hashing;
* JWK thumbprint verification;
* DNS Binding parsing;
* signed Agent Card verification;
* status and revocation validation;
* Content-Digest validation;
* HTTP Message Signature verification;
* freshness and replay protection;
* single delegation token verification;
* delegated signed request verification;
* delegation chain verification.

The implementation does not yet define production live DNS or HTTPS resolver behavior.

# Acknowledgements

The author thanks the broader Internet standards community whose existing specifications make it possible to define AgIS as a narrow profile over deployed web infrastructure rather than as a new stack.

--- back

# Example Agent Identifier

```text
agent://example.com/support-agent
```

# Example DNS TXT Binding

```text
agis=0.2.2; agent=agent://example.com/support-agent; card=https://example.com/.well-known/agis/agents/support-agent.json; jkt=dXBQ4ZkgA3nTvwrFeLAKYokanVfetC0fzXUiSFkYg08; card_sha256=842dbbbf1c807d020ceafe7fd8b51502cf7ae94314238e293a36c736463a3122
```

# Example Agent Card Hash

```text
842dbbbf1c807d020ceafe7fd8b51502cf7ae94314238e293a36c736463a3122
```

# Example JWK Thumbprint

```text
dXBQ4ZkgA3nTvwrFeLAKYokanVfetC0fzXUiSFkYg08
```

# Example Content-Digest

```text
sha-256=:EElbeZnbXXnH5AMO46WOKBIN6fvWcuBFv/qlOLFgSYk=:
```
