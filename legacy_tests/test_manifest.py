from core.identity import Identity
from core.manifest import Manifest


print("================================")
print(" HAEP MANIFEST TEST")
print("================================")
print()

identity = Identity.generate()

capabilities = [
    {
        "name": "test.status",
        "version": "1",
        "access": "READ",
    },
    {
        "name": "test.read",
        "version": "1",
        "access": "READ",
    },
    {
        "name": "test.echo",
        "version": "1",
        "access": "WRITE",
    },
    {
        "name": "test.deny_me",
        "version": "1",
        "access": "READ",
    },
]

manifest = Manifest(
    agent_id="TEST-0001",
    name="HAEP Test Agent",
    domain="test",
    haep_version="0.1",
    agent_version="0.1.0",
    fingerprint=identity.fingerprint,
    capabilities=capabilities,
)

manifest.sign(identity)

print("Agent ID:")
print(" ", manifest.agent_id)
print()

print("Name:")
print(" ", manifest.name)
print()

print("Domain:")
print(" ", manifest.domain)
print()

print("HAEP version:")
print(" ", manifest.haep_version)
print()

print("Agent version:")
print(" ", manifest.agent_version)
print()

print("Fingerprint:")
print(" ", manifest.fingerprint)
print()

print("Capabilities:")
for capability in manifest.capabilities:
    print(" ", capability)

print()

print("Signature:")
print(" ", manifest.signature)
print()

valid = manifest.verify(identity.public_key)

print("Manifest signature verification:")
print(" ", valid)

if not valid:
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


print()
print("================================")
print(" RESULT: PASS")
print("================================")
