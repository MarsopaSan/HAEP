# HAEP 0.1 Audit — supplied archive

## Findings

### F1 — Authorization was not enforced at the Agent boundary
`PolicyEngine` existed and `RequestBuilder` consulted it, but `RequestProcessor` did not verify evidence from the Policy Authority. This meant the Agent's acceptance path did not cryptographically demonstrate that the security component authorized the exact request.

**Correction:** added `AuthorizationAssertion`, signed by the Policy Authority and bound to the exact request scope.

### F2 — Test suite contained script-style tests
Several `test_*.py` files executed assertions at import time and printed PASS/FAIL.

**Correction:** active CI suite is separated into `tests/`; original tests remain in `legacy_tests/` for migration.

### F3 — Development artifacts were mixed with source
`.vs`, `__pycache__`, `.pytest_cache` and `backup/core` were present.

**Correction:** excluded from the GitHub staging repository.

### F4 — Private test identity was present in the archive
`agents/TEST_0001/identity/private_key.pem` was present.

**Correction:** excluded from the GitHub staging repository and blocked by `.gitignore`.

### F5 — Reproducibility dependency issue
The uploaded environment could not import `rfc8785` even though it was declared in `requirements.txt`. The audit environment had no network access, so dependency installation could not be completed here.

**Correction:** dependency declaration, devcontainer and GitHub Actions are included. CI will install the declared dependencies in a clean environment.

## Architectural decision
The Policy Engine is the security authority. The Agent does not read GrantRegistry.
