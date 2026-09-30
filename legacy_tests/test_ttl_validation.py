from core.identity import Identity
from core.envelope import Envelope
from core.capability import Capability, CapabilityRegistry
from core.request_processor import RequestProcessor


print("================================")
print(" HAEP TTL VALIDATION TEST")
print("================================")
print()


controller = Identity.generate()
agent = Identity.generate()


def test_read(parameters):
    return {
        "message": "TEST READ OK"
    }


registry = CapabilityRegistry()

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


processor = RequestProcessor(
    identity=agent,
    controller_public_key=controller.public_key,
    registry=registry,
)


# ==========================================
# FUNCIÓN DE PRUEBA
# ==========================================

def test_ttl(value, expected_status):

    request = Envelope.create(
        identity=controller,
        message_type="REQUEST",
        request_id=f"ttl-test-{str(value)}",
        payload={
            "nonce": f"nonce-{str(value)}",
            "issued_at": "2026-09-21T13:00:00Z",
            "ttl": value,
            "agent_fingerprint": agent.fingerprint,
            "capability": "test.read",
            "resource_id": "test.device",
            "parameters": {},
        },
    )

    response = processor.process(request)

    print()
    print("TTL:")
    print(" ", repr(value))

    print("Resultado:")
    print(" ", response.payload)

    if response.payload["status"] != expected_status:
        print()
        print("ERROR: resultado inesperado.")
        print()
        print("RESULT: FAIL")
        raise SystemExit(1)


# ==========================================
# TTL VÁLIDOS
# ==========================================

test_ttl(1, "SUCCESS")
test_ttl(30, "SUCCESS")


# ==========================================
# TTL INVÁLIDOS
# ==========================================

test_ttl(0, "EXPIRED")
test_ttl(-1, "EXPIRED")
test_ttl("30", "DENIED")
test_ttl(None, "DENIED")
test_ttl(True, "DENIED")


print()
print("================================")
print(" RESULT: PASS")
print("================================")
