# HAEP 0.1 — Protocol Contract

This document describes the message-level contract frozen for the GitHub baseline.

## REQUEST lifecycle

```text
1. Hermes interprets the user's intent.
2. Hermes asks the Security/Policy Authority for authorization.
3. Policy Authority evaluates grants, capability, resource and policy.
4. Policy Authority signs an AuthorizationAssertion.
5. RequestBuilder creates the controller-signed REQUEST.
6. Agent verifies the controller signature.
7. Agent verifies trust and target identity.
8. Agent verifies TTL and replay state.
9. Agent verifies the Policy Authority signature.
10. Agent verifies that the assertion exactly matches the REQUEST.
11. Agent executes the registered capability.
12. Agent returns a signed RESPONSE.
```

## AuthorizationAssertion binding

The signed assertion is bound to:

```text
request_id
controller_fingerprint
agent_fingerprint
capability
resource_id
nonce
issued_at
ttl
parameters_hash
allowed
confirmation
authority_kid
```

Changing any request field covered by the assertion invalidates the authorization scope.

## Cryptography

- Agent/controller/authority identities use Ed25519.
- Public-key fingerprints use SHA-256.
- Signed structured data is canonicalized using RFC 8785 JCS.
- Requests use a unique `request_id`.
- Requests use a nonce and TTL to limit replay.

## Trust

Pairing establishes trust between identities. It does not grant every capability.

Discovery is informational and must never be interpreted as authorization.

## Agent boundary

The Agent must not consult the Policy Authority's `GrantRegistry`. It receives the authorization evidence it needs and verifies it locally.

The Agent owns its domain data and is the canonical source for that domain.

## Frozen scope

The 0.1 baseline does **not** define:

- agent-to-agent command delegation;
- direct LLM database access;
- MAC-address identity;
- implicit trust based on LAN presence;
- a large home-automation framework;
- a mandatory remote cloud security service.
