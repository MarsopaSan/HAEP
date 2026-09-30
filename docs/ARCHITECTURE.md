# HAEP 0.1 — Architecture

## Separation of responsibilities

```text
User
  ↓
Hermes / Local LLM
  ├─ answers general questions itself
  ├─ interprets intent
  └─ decides when an agent/tool is needed
           ↓
Security / Policy Authority
  ├─ Trust / pairing state
  ├─ Grants
  ├─ capability + resource authorization
  ├─ confirmation requirements
  └─ signs AuthorizationAssertion
           ↓
RequestBuilder
  └─ creates controller-signed REQUEST containing the assertion
           ↓
Agent
  ├─ verifies controller signature
  ├─ verifies Policy Authority signature
  ├─ verifies assertion scope matches the REQUEST
  ├─ validates trust / TTL / replay / capability / resource
  └─ executes only the requested domain operation
```

The Agent does **not** consult the GrantRegistry. The GrantRegistry is authority-side state.

The Policy Authority is intentionally modeled as a separate security component even if, in the first local implementation, it runs as a local process/module alongside Hermes. The trust boundary and message contract come first; process isolation can be added later.

## Hermes as general local assistant

Hermes is not only a router. It can answer ordinary questions with its local LLM and tools. An agent is invoked only when the question needs authoritative domain data or an action.

Example:

1. User: “¿Cuántas cenas de $X puedo pagar este mes con lo disponible?”
2. Hermes interprets the calculation request.
3. Hermes asks the Finance Agent for the authoritative available amount.
4. The Finance Agent returns canonical financial data.
5. Hermes performs the arithmetic locally.
6. Hermes answers the user and can show the source agent/data used.

The LLM never receives direct database access. The Finance Agent remains authoritative over its own financial state.
