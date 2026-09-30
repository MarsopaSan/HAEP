from datetime import datetime, timedelta, timezone

from core.grant import Grant, GrantRegistry


print("================================")
print(" HAEP GRANT TEST")
print("================================")
print()


registry = GrantRegistry()


agent = "agent-test-001"


# ==========================================
# GRANT VÁLIDO
# ==========================================

registry.register(
    Grant(
        agent_fingerprint=agent,
        capability="test.read",
        resource_id="test.device",
        allowed=True,
        confirmation="NONE",
    )
)


print("1. Grant válido:")

allowed = registry.is_allowed(
    agent_fingerprint=agent,
    capability="test.read",
    resource_id="test.device",
)

print(" ", allowed)


if not allowed:
    print()
    print("ERROR: el Grant debería permitir la operación.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# CAPABILITY DIFERENTE
# ==========================================

print()
print("2. Capability no autorizada:")

allowed = registry.is_allowed(
    agent_fingerprint=agent,
    capability="test.echo",
    resource_id="test.device",
)

print(" ", allowed)


if allowed:
    print()
    print("ERROR: test.echo no debería estar autorizada.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# RESOURCE DIFERENTE
# ==========================================

print()
print("3. Resource no autorizado:")

allowed = registry.is_allowed(
    agent_fingerprint=agent,
    capability="test.read",
    resource_id="inventado.xyz",
)

print(" ", allowed)


if allowed:
    print()
    print("ERROR: inventado.xyz no debería estar autorizado.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# AGENT DIFERENTE
# ==========================================

print()
print("4. Agent no autorizado:")

allowed = registry.is_allowed(
    agent_fingerprint="otro-agent",
    capability="test.read",
    resource_id="test.device",
)

print(" ", allowed)


if allowed:
    print()
    print("ERROR: otro-agent no debería estar autorizado.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# GRANT DENEGADO
# ==========================================

print()
print("5. Grant explícitamente denegado:")

registry.register(
    Grant(
        agent_fingerprint=agent,
        capability="test.delete",
        resource_id="test.device",
        allowed=False,
        confirmation="CRITICAL",
    )
)

allowed = registry.is_allowed(
    agent_fingerprint=agent,
    capability="test.delete",
    resource_id="test.device",
)

print(" ", allowed)


if allowed:
    print()
    print("ERROR: el Grant denegado no debería permitir.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# GRANT EXPIRADO
# ==========================================

print()
print("6. Grant expirado:")

expired_time = datetime.now(timezone.utc) - timedelta(seconds=1)

registry.register(
    Grant(
        agent_fingerprint=agent,
        capability="test.expired",
        resource_id="test.device",
        allowed=True,
        confirmation="NONE",
        expires_at=expired_time,
    )
)

allowed = registry.is_allowed(
    agent_fingerprint=agent,
    capability="test.expired",
    resource_id="test.device",
)

print(" ", allowed)


if allowed:
    print()
    print("ERROR: el Grant expirado no debería permitir.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


print()
print("================================")
print(" RESULT: PASS")
print("================================")
