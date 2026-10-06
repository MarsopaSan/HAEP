# HAEP — Protocol Notes

## 1. Protocol scope

This document describes the current TEST-0001 protocol concepts. It is not yet
a claim of a frozen production wire specification.

## 2. Message types

The current implementation includes a pairing flow and request/response flow.

Relevant concepts include:

- `PAIRING_REQUEST`
- `PAIRING_RESPONSE`
- `REQUEST`
- `RESPONSE`

Exact schemas must be taken from the current implementation when implementing
wire-compatible code.

## 3. Pairing request

A pairing request carries identity information sufficient for the Agent to:

- identify the controller key;
- verify that the declared fingerprint matches the key;
- verify the request signature;
- validate time policy;
- detect replay.

An unknown controller is not trusted merely because these checks pass.

If the pairing window is closed, the new pairing is denied.

If the pairing window is open, the request becomes pending until explicit
approval.

## 4. Pairing approval

Approval is separate from receipt of the pairing request.

Approval identifies the pending request and controller fingerprint.

Approval must revalidate the original request's time validity.

Only successful approval establishes the paired trust state.

## 5. AuthorizationAssertion

The assertion is signed by the Policy Authority.

The current model includes:

- request_id
- controller_fingerprint
- agent_fingerprint
- capability
- resource_id
- nonce
- issued_at
- ttl
- parameters_hash
- allowed
- confirmation
- authority_kid
- signature

The Agent must verify both the authority signature and the assertion's binding
to the actual request.

## 6. Request processing

The Agent-side processor must not treat a JSON payload as sufficient authority.

The effective order is conceptually:

1. verify message type;
2. verify controller/request signature;
3. verify trust state;
4. verify target Agent;
5. verify nonce/request replay state;
6. validate TTL;
7. validate capability;
8. validate resource;
9. parse and verify AuthorizationAssertion;
10. verify authorization scope binding;
11. check authorization decision;
12. execute capability;
13. produce response.

The exact implementation is authoritative if this document and the code diverge.

## 7. Cryptographic canonicalization

The current implementation uses canonical signing data for security-sensitive
objects and RFC 8785/JCS support is part of the project dependencies.

Do not alter canonicalization casually: changing signed representation is a
protocol change.

## 8. Versioning rule

Changes to signed fields, message types, identity semantics, authorization
binding or replay behavior are protocol changes and require:

- documentation;
- tests;
- explicit review;
- compatibility consideration.

## 9. Current prototype limitations

The protocol is still a TEST-0001 baseline, not a final interoperability
standard.

Do not invent fields or compatibility requirements not present in the current
code.
