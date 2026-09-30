# HAEP

**HAEP — Home Agent Exchange Protocol**

Security and protocol layer for a local multi-agent home AI ecosystem centered on Hermes.

## HAEP 0.1 baseline

The 0.1 baseline freezes the core security separation:

```text
Human / Session
      ↓
    Hermes
      ↓
Security / Policy Authority
      ↓
AuthorizationAssertion
      ↓
    Agent
      ↓
Domain data / operation
```

### Responsibilities

- **Hermes:** natural-language interpretation, reasoning, orchestration and general assistant behavior.
- **Security/Policy Authority:** deterministic trust, grant, capability, resource and policy decisions.
- **Agent:** cryptographic verification and execution of domain operations; canonical owner of domain data.

Hermes never receives direct database access merely because it is the central assistant.

## Security mechanisms

- Ed25519 identities
- SHA-256 public-key fingerprints
- RFC 8785 JCS canonicalization
- signed requests/responses
- pairing and explicit trust state
- capability/resource authorization
- signed AuthorizationAssertion
- TTL and issued-at validation
- request ID and nonce replay protection
- default deny

## Repository layout

- `core/` — protocol and security primitives
- `agents/` — test/domain agents
- `tests/` — active baseline tests
- `legacy_tests/` — retained pre-GitHub tests for migration/reference
- `docs/` — architecture, protocol, security and development contracts
- `AI_CONTEXT.md` — instructions for AI-assisted development
- `.devcontainer/` — reproducible GitHub Codespaces environment
- `.github/workflows/` — continuous integration

## Development

Install the real dependencies and run:

```bash
python -m pip install -r requirements.txt
pytest
```

GitHub Actions performs the same dependency installation and test run. The Codespaces configuration provides a reproducible browser-based development environment.

## Security warning

Private keys, databases, credentials and local identity material are intentionally excluded from Git. Generate test identities locally or ephemerally.

## Status

**HAEP 0.1 — GitHub baseline / architecture frozen.**

Feature expansion should begin only after this baseline is committed and CI is green.
