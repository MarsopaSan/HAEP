from core.identity import Identity
from core.manifest import Manifest
from core.capability import Capability, CapabilityRegistry


print("================================")
print(" HAEP MANIFEST / CAPABILITY TEST")
print("================================")
print()


def test_status(parameters):
    return {"status": "SUCCESS"}


def test_read(parameters):
    return {"status": "SUCCESS"}


def test_echo(parameters):
    return {
        "status": "SUCCESS",
        "echo": parameters,
    }


# ==========================================
# IDENTITY
# ==========================================

identity = Identity.generate()


# ==========================================
# CAPABILITY REGISTRY
# ==========================================

registry = CapabilityRegistry()

registry.register(
    Capability(
        name="test.status",
        version="1",
        access="READ",
        idempotency="IDEMPOTENT",
        side_effects=False,
        handler=test_status,
    )
)

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

registry.register(
    Capability(
        name="test.echo",
        version="1",
        access="WRITE",
        idempotency="NON_IDEMPOTENT",
        side_effects=True,
        handler=test_echo,
    )
)


# ==========================================
# MANIFEST
# ==========================================

manifest_capabilities = [
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
    capabilities=manifest_capabilities,
)

manifest.sign(identity)


# ==========================================
# COMPARACIÓN
# ==========================================

print("Manifest capabilities:")
for capability in manifest.capabilities:
    print(" ", capability["name"])

print()
print("Registry capabilities:")
for capability in registry.list():
    print(" ", capability.name)

print()

manifest_names = {
    capability["name"]
    for capability in manifest.capabilities
}

registry_names = {
    capability.name
    for capability in registry.list()
}

match = manifest_names == registry_names

print("Manifest / Registry coincide:")
print(" ", match)

if not match:
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# ==========================================
# VERIFICAR QUE CADA CAPABILITY ES EJECUTABLE
# ==========================================

print()
print("Verificando handlers...")

for capability_name in manifest_names:
    capability = registry.get(capability_name)

    if capability is None:
        print()
        print("RESULT: FAIL")
        raise SystemExit(1)

    if capability.handler is None:
        print()
        print(
            "Capability sin handler:",
            capability_name,
        )
        print()
        print("RESULT: FAIL")
        raise SystemExit(1)

    print(
        " ",
        capability_name,
        "→ handler OK",
    )


# ==========================================
# VERIFICAR FIRMA
# ==========================================

signature_valid = manifest.verify(
    identity.public_key
)

print()
print("Firma del Manifest válida:")
print(" ", signature_valid)

if not signature_valid:
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


print()
print("================================")
print(" RESULT: PASS")
print("================================")
