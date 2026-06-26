# AgIS and ANS Compatibility

AgIS is designed to be compatible with Agent Name Service (ANS) and similar ecosystem-level agent identity and naming systems. This document explains the relationship, the layer boundaries, and how the two systems complement each other.

## Summary

| System | Role |
|--------|------|
| ANS (Agent Name Service) | Ecosystem-level agent naming, discovery, and identity |
| AgIS (Agent Identity System) | Local verification, governance, policy, and enforcement layer |

AgIS does not replace ANS. AgIS consumes identity evidence — including ANS-style evidence — and turns it into clear operational trust decisions.

## Concept mapping

| ANS concept | AgIS role |
|---|---|
| Agent name | Agent ID / identity subject |
| Identity evidence | Verification input |
| Registry / transparency data | Trust evidence |
| Lifecycle state | Status decision (allow / deny / review) |
| Certificate / receipt | Future verifier adapter |
| Resolver output | Agent card / evidence bundle |

## What each system provides

### ANS provides

- A global, ecosystem-level namespace for AI agent identifiers.
- Agent registration, discovery, and identity anchoring.
- Transparency registry data and lifecycle events.
- A standardized way for agents to be found and identified across the ecosystem.

### AgIS provides

- Offline, deterministic verification of agent identity signals.
- Status-based policy decisions (allow / deny / review) based on the agent's current lifecycle state.
- Request signing and signature verification (HTTP Message Signatures, RFC 9421).
- Request freshness and replay protection.
- Delegation token verification (scoped, time-limited, chain-enforced authority).
- Audit-friendly, structured verification results.

## How they work together

1. **ANS resolves an agent.** An ANS resolver returns identity evidence for an agent identifier — such as an agent card, public key, and lifecycle state.
2. **AgIS verifies the evidence.** AgIS takes that evidence and verifies it cryptographically, offline, against the DNS binding, public key, and signed agent card.
3. **AgIS applies the status policy.** Based on the agent's current lifecycle status, AgIS produces a policy decision:
   - `active` → allow
   - `revoked` / `suspended` / `compromised` → deny
   - `unknown` / `deprecated` → review
4. **The application enforces the decision.** The consuming application, MCP server, or API gateway acts on the AgIS result.

## Non-goals

- **AgIS does not replace ANS.** AgIS does not provide global agent naming or a public registry.
- **AgIS does not operate a global root namespace.** Agent identifiers used in AgIS test vectors are for development and interoperability testing only.
- **AgIS does not claim Linux Foundation endorsement.** ANS is a Linux Foundation project. AgIS is an independent, complementary toolkit.
- **AgIS does not provide production DNSSEC validation yet.** DNS binding verification is currently implemented for development and testing; DNSSEC enforcement is a planned future capability.
- **AgIS is not the ANS standard.** ANS defines the ecosystem-level naming conventions. AgIS defines a local verification and governance layer that can consume ANS-style evidence.

## Future integration

AgIS is designed to support future adapter modules that connect directly to ANS resolvers, certificate transparency logs, and other identity evidence sources. These adapters will allow AgIS to consume live ANS data while preserving the same offline-verifiable, deterministic verification model.

## References

- ANS (Agent Name Service): Linux Foundation project — <https://agentnamingservice.org>
- AgIS specification: [`docs/ietf/draft-ayoub-agis-agent-identity-system-00.md`](ietf/draft-ayoub-agis-agent-identity-system-00.md)
- AgIS SDK: [`packages/agis-sdk-ts`](../packages/agis-sdk-ts)
