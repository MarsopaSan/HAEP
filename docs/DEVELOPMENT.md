# HAEP — Development Guide

## 1. Development principle

Prefer small, reviewable changes.

Do not modify architecture merely to make implementation easier.

A change should solve a defined problem with the minimum necessary surface
area.

## 2. First setup on Windows

Install:

- Git
- Python 3

Clone:

```bat
git clone https://github.com/MarsopaSan/HAEP.git
cd HAEP
git checkout fix/test-imports
```

Create and activate a virtual environment:

```bat
python -m venv .venv
.venv\Scripts\activate
```

Install dependencies:

```bat
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Run tests:

```bat
pytest -q
```

## 3. Start of a work session

```bat
git status
git pull
pytest -q
```

Start new work only from a known clean state unless intentionally continuing
an unfinished change.

## 4. Before modifying code

Determine:

1. What problem is being solved?
2. Which architectural boundary is involved?
3. Which files are actually necessary?
4. What behavior must be tested?
5. Does the change alter the protocol or security model?

If the change affects security or protocol semantics, document that explicitly.

## 5. Testing

Run the full suite:

```bat
pytest -q
```

A feature or security behavior should have focused tests in addition to the
full-suite result.

Do not declare success based only on manual execution.

## 6. Diff review

Before committing:

```bat
git diff
git status
```

After staging:

```bat
git diff --cached
git status
```

Prefer explicit file lists:

```bat
git add core/example.py tests/test_example.py
```

Avoid blindly using:

```bat
git add .
```

especially when temporary files, keys or generated artifacts may exist.

## 7. Commit and push

Use focused commit messages:

```bat
git commit -m "Describe the change"
git push
```

Work should normally be developed on a branch and reviewed before merging into
`main`.

## 8. Security hygiene

Never commit:

- private keys;
- passwords;
- tokens;
- credentials;
- production `.env`;
- `.venv`;
- `__pycache__`;
- `.pytest_cache`;
- temporary patch/review files.

If a private key appears in the repository, stop and investigate before pushing.

## 9. AI-assisted development

An AI must:

1. read `AI_CONTEXT.md`;
2. inspect relevant code;
3. inspect relevant tests;
4. explain the proposed change;
5. avoid silent architectural changes;
6. make minimal edits;
7. run tests;
8. review the diff;
9. report limitations or unresolved assumptions.

The AI must treat the repository as the persistent source of truth.

## 10. Documentation maintenance

Update documentation when a change modifies:

- architecture;
- trust model;
- protocol;
- security assumptions;
- development workflow.

Do not update documentation merely to make an unverified implementation look
complete.

## 11. Definition of done

A change is ready for review when:

- the implementation is complete;
- tests pass;
- relevant tests were added/updated;
- the diff has been reviewed;
- no secrets or temporary artifacts are staged;
- documentation is updated if semantics changed;
- the commit has a clear message.

Merge into `main` is a separate decision from implementation completion.
