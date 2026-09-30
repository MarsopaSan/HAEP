import time

from core.identity import Identity
from core.envelope import Envelope
from core.capability import Capability, CapabilityRegistry
from core.resource import Resource, ResourceRegistry
from core.request_processor import RequestProcessor


print("================================")
print(" HAEP REPLAY TTL TEST")
print("================================")
print()


controller = Identity.generate()
agent = Identity.generate()


# ==========================================
# CAPABILITY
# ==========================================

registry = CapabilityRegistry()

execution_count = 0


def test_read(parameters):
    global execution_count

    execution_count += 1

    return {
        "message": "TEST READ OK",
        "execution_count": execution_count,
    }


registry.register(
    Capability(
        name="test.read",
        version="1",
        access="READ",
        idempotency="IDEMPOTENT",
        side_effects=False,
        handler=test_read,
    )
)


# ==========================================
# RESOURCE
# ==========================================

resource_registry = ResourceRegistry()

resource_registry.register(
    Resource(
        resource_id="test.device",
        name="Test Device",
        description="Recurso virtual de prueba",
    )
)


# ==========================================
# PROCESSOR
# ==========================================

processor = RequestProcessor(
    identity=agent,
    controller_public_key=controller.public_key,
    registry=registry,
    resource_registry=resource_registry,
)


# ==========================================
# REQUEST
# ==========================================

request = Envelope.create(
    identity=controller,
    message_type="REQUEST",
    request_id="00000000-0000-0000-0000-000000000200",
    payload={
        "nonce": "nonce-ttl-001",
        "issued_at": "2026-09-21T13:00:00Z",
        "ttl": 2,
        "agent_fingerprint": agent.fingerprint,
        "capability": "test.read",
        "resource_id": "test.device",
        "parameters": {},
    },
)


# ==========================================
# 1. REQUEST ORIGINAL
# ==========================================

print("1. REQUEST original...")

response_1 = processor.process(request)

print()
print("Resultado:")
print(" ", response_1.to_dict())


if response_1.payload["status"] != "SUCCESS":
    print()
    print("ERROR: REQUEST original deveria ser SUCCESS.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# 2. REPLAY INMEDIATO
# ==========================================

print()
print("2. Replay inmediato...")

response_2 = processor.process(request)

print()
print("Resultado:")
print(" ", response_2.to_dict())


if response_2.payload["status"] != "REPLAY":
    print()
    print("ERROR: replay inmediato debería ser REPLAY.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# ESPERAR TTL
# ==========================================

print()
print("Esperando 3 segundos para superar TTL...")

time.sleep(3)


# ==========================================
# 3. REENVIAR DESPUÉS DEL TTL
# ==========================================

print()
print("3. Reenviando REQUEST después del TTL...")

response_3 = processor.process(request)

print()
print("Resultado:")
print(" ", response_3.to_dict())


if response_3.payload["status"] != "SUCCESS":
    print()
    print("ERROR: REQUEST después del TTL debería ser SUCCESS.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# EXECUTION COUNT
# ==========================================

print()
print("Execution count:")
print(" ", execution_count)


if execution_count != 2:
    print()
    print("ERROR: execution_count debería ser 2.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


print()
print("================================")
print(" RESULT: PASS")
print("================================")