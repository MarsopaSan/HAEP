
from core.identity import Identity
from core.envelope import Envelope


identity = Identity.generate()


payload = {
    "capability": "test.read",
    "resource_id": "test.device",
    "parameters": {},
}


envelope = Envelope.create(
    identity=identity,
    message_type="REQUEST",
    request_id="00000000-0000-0000-0000-000000000001",
    payload=payload,
)


print("================================")
print(" HAEP ENVELOPE TEST")
print("================================")
print()

print("Message type:")
print(" ", envelope.message_type)
print()

print("KID:")
print(" ", envelope.kid)
print()

print("Payload:")
print(" ", envelope.payload)
print()

print("Signature:")
print(" ", envelope.signature)
print()

valid = envelope.verify(identity.public_key)

print("Signature verification:")
print(" ", valid)

if not valid:
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)

print()
print("RESULT: PASS")