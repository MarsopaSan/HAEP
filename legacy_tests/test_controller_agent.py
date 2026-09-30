
from core.identity import Identity
from core.envelope import Envelope


print("================================")
print(" HAEP CONTROLLER / AGENT TEST")
print("================================")
print()


# --------------------------------------------------
# 1. Crear las tres identidades
# --------------------------------------------------

controller = Identity.generate()
agent = Identity.generate()
attacker = Identity.generate()


print("Controller fingerprint:")
print(" ", controller.fingerprint)
print()

print("Agent fingerprint:")
print(" ", agent.fingerprint)
print()

print("Attacker fingerprint:")
print(" ", attacker.fingerprint)
print()


# --------------------------------------------------
# 2. Controller crea un REQUEST
# --------------------------------------------------

payload = {
    "nonce": "AQIDBAUGBwgJCgsMDQ4PEA",
    "issued_at": "2026-09-10T18:00:00Z",
    "ttl": 30,
    "agent_fingerprint": agent.fingerprint,
    "capability": "test.read",
    "resource_id": "test.device",
    "parameters": {},
}


request = Envelope.create(
    identity=controller,
    message_type="REQUEST",
    request_id="00000000-0000-0000-0000-000000000002",
    payload=payload,
)


print("REQUEST created:")
print(" ", request.to_dict())
print()


# --------------------------------------------------
# 3. TEST-0001 verifica al Controller
# --------------------------------------------------

valid_controller = request.verify(controller.public_key)

print("Agent verifies Controller signature:")
print(" ", valid_controller)

if not valid_controller:
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# --------------------------------------------------
# 4. Un atacante intenta hacerse pasar por Controller
# --------------------------------------------------

valid_attacker = request.verify(attacker.public_key)

print()
print("Attacker verification attempt:")
print(" ", valid_attacker)

if valid_attacker:
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# --------------------------------------------------
# 5. Comprobar que el KID pertenece al Controller
# --------------------------------------------------

kid_matches = request.kid == controller.fingerprint

print()
print("REQUEST KID matches Controller fingerprint:")
print(" ", kid_matches)

if not kid_matches:
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# --------------------------------------------------
# RESULTADO
# --------------------------------------------------

print()
print("================================")
print(" RESULT: PASS")
print("================================")