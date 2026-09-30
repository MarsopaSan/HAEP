from core.identity import Identity
from core.envelope import Envelope
from core.capability import Capability, CapabilityRegistry
from core.resource import Resource, ResourceRegistry
from core.request_processor import RequestProcessor


print("================================")
print(" HAEP REQUEST RESOURCE TEST")
print("================================")
print()


controller = Identity.generate()
agent = Identity.generate()


# ==========================================
# CAPABILITY
# ==========================================

capability_registry = CapabilityRegistry()


def test_read(parameters):
    return {
        "message": "TEST READ OK"
    }


capability_registry.register(
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
# REQUEST PROCESSOR
# ==========================================

processor = RequestProcessor(
    identity=agent,
    controller_public_key=controller.public_key,
    registry=capability_registry,
    resource_registry=resource_registry,
)


# ==========================================
# REQUEST 1 — RECURSO VÁLIDO
# ==========================================

request_valid = Envelope.create(
    identity=controller,
    message_type="REQUEST",
    request_id="resource-test-001",
    payload={
        "nonce": "nonce-resource-001",
        "issued_at": "2026-09-21T15:00:00Z",
        "ttl": 30,
        "agent_fingerprint": agent.fingerprint,
        "capability": "test.read",
        "resource_id": "test.device",
        "parameters": {},
    },
)

response_valid = processor.process(request_valid)

print("1. Recurso válido:")
print(" ", response_valid.payload)


if response_valid.payload["status"] != "SUCCESS":
    print()
    print("ERROR: el recurso válido fue rechazado.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# REQUEST 2 — RECURSO INEXISTENTE
# ==========================================

request_invalid = Envelope.create(
    identity=controller,
    message_type="REQUEST",
    request_id="resource-test-002",
    payload={
        "nonce": "nonce-resource-002",
        "issued_at": "2026-09-21T15:00:00Z",
        "ttl": 30,
        "agent_fingerprint": agent.fingerprint,
        "capability": "test.read",
        "resource_id": "inventado.xyz",
        "parameters": {},
    },
)

response_invalid = processor.process(request_invalid)

print()
print("2. Recurso inexistente:")
print(" ", response_invalid.payload)


if response_invalid.payload["status"] != "UNKNOWN_RESOURCE":
    print()
    print("ERROR: el recurso inexistente fue aceptado.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


print()
print("================================")
print(" RESULT: PASS")
print("================================")
