from core.identity import Identity
from core.envelope import Envelope
from core.capability import Capability, CapabilityRegistry
from core.resource import Resource, ResourceRegistry
from core.request_processor import RequestProcessor
from core.trust import TrustManager
from datetime import datetime, timezone


print("================================")
print(" HAEP REPLAY PROTECTION TEST")
print("================================")
print()


# ==========================================
# IDENTIDADES
# ==========================================

controller = Identity.generate()
agent = Identity.generate()
issued_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ==========================================
# TRUST
# ==========================================

trust = TrustManager()
trust.pair()


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
    trust_manager=trust,
)


# ==========================================
# REQUEST ORIGINAL
# ==========================================

request = Envelope.create(
    identity=controller,
    message_type="REQUEST",
    request_id="replay-test-001",
    payload={
        "nonce": "nonce-replay-001",
        "issued_at": issued_at,
        "ttl": 30,
        "agent_fingerprint": agent.fingerprint,
        "capability": "test.read",
        "resource_id": "test.device",
        "parameters": {},
    },
)


response_1 = processor.process(request)

print("1. REQUEST original:")
print(" ", response_1.payload)


if response_1.payload["status"] != "SUCCESS":
    print()
    print("ERROR: el REQUEST original debería ser SUCCESS.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# MISMO REQUEST
# ==========================================

response_2 = processor.process(request)

print()
print("2. Replay inmediato:")
print(" ", response_2.payload)


if response_2.payload["status"] != "REPLAY":
    print()
    print("ERROR: el replay debería ser rechazado.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


if response_2.payload["error"] != "REQUEST_ID_ALREADY_USED":
    print()
    print("ERROR: motivo de replay inesperado.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# NUEVO REQUEST_ID + MISMO NONCE
# ==========================================

request_nonce_replay = Envelope.create(
    identity=controller,
    message_type="REQUEST",
    request_id="replay-test-002",
    payload={
        "nonce": "nonce-replay-001",
        "issued_at": issued_at,
        "ttl": 30,
        "agent_fingerprint": agent.fingerprint,
        "capability": "test.read",
        "resource_id": "test.device",
        "parameters": {},
    },
)


response_3 = processor.process(request_nonce_replay)

print()
print("3. Nuevo request_id + mismo nonce:")
print(" ", response_3.payload)


if response_3.payload["status"] != "REPLAY":
    print()
    print("ERROR: el nonce reutilizado debería ser rechazado.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


if response_3.payload["error"] != "NONCE_ALREADY_USED":
    print()
    print("ERROR: motivo de replay inesperado.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# EJECUCIÓN TOTAL
# ==========================================

print()
print("Execution count:")
print(" ", execution_count)


if execution_count != 1:
    print()
    print("ERROR: el handler se ejecutó más de una vez.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


print()
print("================================")
print(" RESULT: PASS")
print("================================")