# HAEP 0.1 — Identity and Session Model

This document freezes the identity and access model for the HAEP 0.1 baseline.

## 1. Identity layers

HAEP distinguishes four different concepts:

1. **Human identity** — the person interacting with Hermes.
2. **Session identity** — an authenticated interaction established after human authentication.
3. **Hermes/controller identity** — the cryptographic identity of the HAEP controller that signs requests.
4. **Agent identity** — the cryptographic identity of a domain agent.

A device is **context**, not by itself a permission to access private data.

## 2. Authentication is not authorization

A message such as `"Soy Reno"` is not authentication evidence.

Authentication establishes who is operating the session. Authorization is a separate deterministic decision made by the Security/Policy Authority.

The baseline flow is:

```text
Human
  ↓
Authentication
  ↓
Authenticated Session
  ↓
Hermes
  ↓
Security / Policy Authority
  ↓
ALLOW / DENY
  ↓
AuthorizationAssertion
  ↓
Agent
```

## 3. Device context

The originating device may contribute useful security context, such as whether the session is local or remote and whether the device/session is known.

However:

- device identity does not automatically grant agent access;
- network presence does not establish trust;
- pairing a device is not equivalent to authorizing every capability;
- a compromised or shared device must not bypass Policy Authority decisions.

## 4. Capability-based access

Access is granted per capability and resource, not per agent as an all-or-nothing permission.

Example Finance capabilities:

```text
finance.balance.read
finance.expenses.read
finance.income.read
finance.cards.read
finance.transactions.read
finance.transfer.execute
```

Permission for `finance.balance.read` does not imply permission for `finance.transfer.execute`.

## 5. Access levels

These are conceptual policy levels, not numeric privileges encoded into the protocol yet:

- **Level 0:** general Hermes interaction; no private domain data.
- **Level 1:** authenticated user session; non-sensitive personal operations.
- **Level 2:** authorized access to a specific agent capability/resource.
- **Level 3:** sensitive data or real-world side effects; stronger policy and, where configured, explicit confirmation.

The Policy Authority decides the actual authorization for the concrete request.

## 6. Sensitive domains

Finance data, cameras, locks, alarms, transfers, and other high-impact operations must never become accessible merely because Hermes can interpret the user's request.

Hermes may reason about data it has legitimately received, but it does not obtain database credentials or direct database access.

## 7. External access

An external caller may be able to reach a Hermes endpoint without thereby obtaining private agent information.

The minimum security condition is:

```text
unknown principal/session
        ↓
Policy Authority
        ↓
DENY
```

The agent remains the final verifier of the signed authorization evidence for the operation it receives.

## 8. Baseline rule

> Hermes can reason freely; to obtain private domain data or execute an external side effect, it needs valid HAEP authorization.

Future work may add stronger user-authentication mechanisms, device attestation, step-up authentication, or remote-access controls. Such additions must preserve this separation rather than move authorization into the LLM.
