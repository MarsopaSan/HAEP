# HAEP — Architecture

## 1. Goal

HAEP is a local architecture for a central assistant/orchestrator (Hermes)
working with specialized Agents.

The design separates interpretation, authorization and execution.

## 2. Main components

### Hermes

Hermes is the general assistant and orchestrator.

Responsibilities:

- understand user intent;
- reason and calculate;
- decide whether an Agent is needed;
- construct a request through the defined request path;
- present results to the user.

Hermes is **not** the final security authority.

The LLM itself is outside the trusted security boundary.

### Policy Authority

The Policy Authority is the deterministic authorization component.

Responsibilities:

- evaluate grants and policy;
- determine allow/deny;
- issue a signed AuthorizationAssertion;
- bind authorization to the concrete request.

The Policy Authority must not be replaced by an LLM judgment.

### Agent

An Agent owns a specific domain.

Responsibilities:

- maintain canonical domain state;
- advertise its capabilities/resources;
- authenticate the controller;
- verify authorization;
- enforce TTL and replay protection;
- execute only authorized capabilities.

### RequestBuilder

RequestBuilder creates the request that carries the authorization assertion
and is signed by the controller identity.

### RequestProcessor

RequestProcessor is the Agent-side enforcement point.

It verifies, among other things:

- request type;
- request signature;
- trusted controller;
- target Agent;
- nonce / replay state;
- TTL / time policy;
- capability;
- resource;
- AuthorizationAssertion signature;
- authorization binding.

Only after these checks may the capability execute.

## 3. Trust boundaries

The important boundaries are:

```text
User
  |
  v
Hermes / LLM
  |
  | request proposal
  v
Policy Authority
  |
  | signed authorization
  v
RequestBuilder
  |
  | signed request
  v
Agent
  |
  v
Domain data / execution
```

The LLM is not allowed to bypass the Policy Authority.

The Agent is the final enforcement point for its own capabilities.

## 4. Pairing boundary

Discovery is only a mechanism for finding candidates.

Pairing establishes trust.

Authorization grants permission to perform capabilities.

These are three distinct concepts:

```text
Discovery
    !=
Pairing / Trust
    !=
Capability Authorization
```

## 5. Data ownership

Each Agent owns its canonical business/domain data.

Hermes may receive authorized results, but should not become a second canonical
database for every domain.

This avoids turning Hermes into a centralized business-data authority.

## 6. TEST-0001 philosophy

TEST-0001 validates the minimum security architecture.

It deliberately avoids premature infrastructure such as MQTT, complex PKI,
automatic quarantine or broad home-automation integration.

The objective is to prove the security boundaries first.

## 7. Future evolution

Future additions may include more Agents, discovery, home devices and richer
authorization workflows, but they must preserve the core separation unless a
new architectural decision explicitly replaces it.
