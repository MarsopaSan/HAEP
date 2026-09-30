# HAEP — AI CONTEXT

Read this file before modifying HAEP.

## Project purpose
HAEP is the security/protocol layer for a local multi-agent home AI ecosystem centered on Hermes.

## Frozen 0.1 architecture
The architecture is frozen for the GitHub baseline:

```text
User → authenticated session → Hermes → Security/Policy Authority → AuthorizationAssertion → Agent
```

Hermes is the conversational/orchestration layer. A separate Security/Policy Authority is responsible for deterministic authorization. Domain Agents execute operations and remain authoritative over their own domain data.

## Critical separation
- Hermes interprets natural language and can answer general questions.
- Hermes must not invent domain data.
- Hermes does not directly access domain databases.
- Policy Authority decides whether an operation is authorized.
- Agent does not query GrantRegistry.
- Agent verifies cryptographic authorization evidence and executes domain operations.
- Device/network presence is not equivalent to authorization.
- Pairing/trust is not equivalent to capability authorization.

## Current protocol mechanisms
- Ed25519 identities
- SHA-256 public-key fingerprints
- RFC 8785 JSON Canonicalization Scheme
- signed Envelopes
- pairing/trust states
- capability registry
- resource registry
- grants + deterministic PolicyEngine
- signed AuthorizationAssertion
- TTL / issued_at validation
- request_id + nonce replay protection

## AuthorizationAssertion
The Policy Authority signs an assertion bound to:
`request_id`, `controller_fingerprint`, `agent_fingerprint`, `capability`, `resource_id`, `nonce`, `issued_at`, `ttl`, `parameters_hash`.

The Agent verifies this assertion using the trusted Policy Authority public key.

## Identity and sessions
Human authentication, authenticated sessions, Hermes identity, Agent identity, and device context are separate concepts. See `docs/IDENTITY_AND_SESSION.md`.

A caller does not gain access to private Agent data merely by reaching Hermes or by claiming an identity in text.

## Do not introduce without an explicit architecture review
- LLM access to domain databases
- GrantRegistry queries from Agents
- implicit trust from network discovery
- MAC/name as cryptographic identity
- agent-to-agent commands in the minimal baseline
- large home-automation frameworks before the protocol needs them
- automatic all-domain access for Hermes

## Collaboration rule
When changing security semantics, update tests and documentation. If another AI proposes a change that conflicts with this architecture, flag the conflict before implementing it.

GitHub `main` is the stable source of truth. Prefer isolated branches/PRs for architectural changes rather than direct edits to `main`.
