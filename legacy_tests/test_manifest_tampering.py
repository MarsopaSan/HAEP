from core.identity import Identity
from core.manifest import Manifest


print("================================")
print(" HAEP MANIFEST TAMPERING TEST")
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

print("Manifest original firmado.")
print()

valid_original = manifest.verify(identity.public_key)

print("Verificación original:")
print(" ", valid_original)

if not valid_original:
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# MANIPULACIÓN
# ==========================================

print()
print("Modificando una capacidad...")
print()

manifest.capabilities[2]["name"] = "admin.delete"

print("Capacidades modificadas:")
for capability in manifest.capabilities:
    print(" ", capability)

print()

valid_tampered = manifest.verify(identity.public_key)

print("Verificación después de la manipulación:")
print(" ", valid_tampered)

if valid_tampered:
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


print()
print("================================")
print(" RESULT: PASS")
print("================================")
