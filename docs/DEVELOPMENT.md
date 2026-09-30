# Development

## Frozen baseline rule

HAEP 0.1 is the architectural baseline. New work must preserve the separation between:

```text
interpretation → authorization → execution
```

A change to security semantics requires:

1. an explicit reason;
2. updated documentation;
3. updated tests;
4. review of the impact on the trust boundary.

Do not silently move authorization into Hermes or into an Agent.

## Local

```bash
python -m venv .venv
.venv\Scripts\activate       # Windows
source .venv/bin/activate     # Linux/macOS
python -m pip install -r requirements.txt
pytest
```

## GitHub Codespaces

The repository contains `.devcontainer/devcontainer.json` so the project can be developed from a browser-based Codespace with a reproducible Python environment.

## CI

GitHub Actions installs the real dependencies from `requirements.txt` and runs `pytest`. CI is therefore the authoritative environment for validating the cryptographic dependency set.

## Collaboration with AI tools

ChatGPT, Grok, or another AI may propose changes, but the repository is the source of truth. AI-generated changes must be reviewed against `AI_CONTEXT.md`, the architecture documents, and the tests before merging.
