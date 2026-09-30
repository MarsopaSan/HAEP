# HAEP 0.1 — Security Model

## Core rules

- Discovery != trust.
- Pairing != authorization.
- Hermes LLM != security authority.
- GrantRegistry belongs to the Policy Authority, not the Agent.
- Agents own their domain data.
- Default deny.
- Requests require controller authentication.
- Requests require a valid Policy Authority AuthorizationAssertion.
- Authorization is bound to request_id, nonce, issued_at, ttl, controller, agent, capability, resource and parameters hash.
- Replay protection is enforced by request_id and nonce.
- Private keys never belong in Git.
