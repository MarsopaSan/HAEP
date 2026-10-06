# HAEP — AI Context

## 1. Purpose

HAEP is a local/home AI ecosystem architecture in which **Hermes** acts as the
general assistant/orchestrator and specialized **Agents** own domain-specific
data and operations.

The project is being developed incrementally. `TEST-0001` is intentionally
small: its purpose is to validate the security and authorization boundaries
before adding broader infrastructure.

## 2. Architectural invariant

HAEP deliberately separates three responsibilities:

1. **Interpretation / orchestration** — Hermes / LLM.
2. **Authorization** — deterministic Policy Authority.
3. **Execution / canonical domain state** — Agent.

The LLM is not the security authority.

Canonical flow:

```text
Hermes / LLM
    |
    | interpreted request
    v
Policy Authority
    |
    | signed AuthorizationAssertion
    v
RequestBuilder
    |
    | signed REQUEST
    v
Agent / RequestProcessor
    |
    | verify identity, authorization, scope,
    | TTL, replay, capability and resource
    v
Domain execution
```

An Agent owns the canonical truth for its domain. Hermes must not directly
query or modify an Agent's domain database.

## 3. Security invariants

These are current architectural decisions:

- Discovery is not trust.
- Pairing is not capability authorization.
- A valid cryptographic signature alone does not constitute human approval for
  a new pairing.
- New controllers require explicit OOB pairing approval.
- Authorization is separate from pairing.
- The Policy Authority is deterministic and outside the LLM's authority.
- Authorization assertions are bound to the concrete request.
- Agents verify the authorization assertion before executing.
- Requests are protected by identity, TTL and replay checks.
- Capability and resource scope must match the authorization assertion.
- Agents own canonical domain data.
- Agent-to-agent command paths are not part of the first prototype.
- TEST-0001 should remain minimal; advanced infrastructure must be justified
  before introduction.

## 4. Current pairing model

A new controller:

1. creates a signed `PAIRING_REQUEST`;
2. the Agent verifies identity, signature, declared fingerprint, time policy
   and replay state;
3. if the controller is unknown, the Agent requires an open pairing window;
4. the request becomes `PAIRING_PENDING`;
5. an explicit local/OOB approval is required;
6. approval checks that the original request is still within its TTL;
7. only then does TrustManager establish the paired state.

Known controllers may re-establish pairing without repeating OOB, unless
revoked.

Pairing currently protects `request_id` and `nonce` against replay.

## 5. Authorization model

The current authorization chain is:

```text
Hermes
  -> PolicyEngine / Policy Authority
  -> AuthorizationAssertion
  -> RequestBuilder
  -> signed REQUEST
  -> Agent RequestProcessor
  -> assertion verification + binding checks
  -> capability execution
```

`AuthorizationAssertion` is signed by the Policy Authority and is bound to
request-specific values including:

- request_id
- controller_fingerprint
- agent_fingerprint
- capability
- resource_id
- nonce
- issued_at
- ttl
- parameters_hash

The Agent verifies the authority signature and compares the assertion scope
with the actual request.

## 6. Current implementation state

Known current branch:

`fix/test-imports`

Latest known commit:

`fab1f2f Add explicit OOB pairing approval`

Previous commit:

`e8b844c Fix pytest import path`

The current branch has the pytest import-path correction, Policy Authority /
AuthorizationAssertion flow, RequestBuilder, RequestProcessor, Trust / Pairing,
OOB pairing with a temporary window, pairing anti-replay, pairing TTL
revalidation and pairing tests.

The test suite was passing at 100% immediately before this documentation
work.

## 7. Important known limitations / review items

These are not silently considered solved:

- The trust/bootstrap path for the Policy Authority public key must remain
  explicitly trusted and documented.
- Request replay state in the current TEST-0001 implementation is in memory;
  restart persistence is not yet a complete production replay strategy.
- `confirmation` exists in the authorization assertion model, but a complete
  user-confirmation workflow is not yet the same thing as having the field.
- Pairing approval is currently represented as a local service operation in
  TEST-0001; a richer network pairing acknowledgement can be designed later.
- Private-key storage in the prototype is not a production key-management
  solution.

Do not turn these limitations into new infrastructure automatically. First
define the requirement and threat model.

## 8. Out of scope for TEST-0001 unless justified

Do not add merely for completeness:

- MQTT
- complex PKI
- anomaly detection
- automatic quarantine
- broad Home Assistant / Matter integration
- agent-to-agent command routing
- centralized business databases in Hermes
- unnecessary distributed infrastructure

## 9. Rules for an AI modifying HAEP

Before changing code:

1. Read this file.
2. Read the relevant architecture/security/protocol/development documents.
3. Inspect the current code and tests.
4. State the problem and proposed minimal change.
5. Do not silently change architectural boundaries.
6. Add/update tests for behavior changes.
7. Run the complete test suite.
8. Review the final diff.
9. Keep secrets and private keys out of Git.

When documentation conflicts with actual code/tests, report the discrepancy
instead of silently inventing a resolution.

## 10. Source of truth

The persistent source of truth is the versioned repository:

https://github.com/MarsopaSan/HAEP

Conversation history is useful for context, but important architectural
decisions should be reflected in versioned documentation.
