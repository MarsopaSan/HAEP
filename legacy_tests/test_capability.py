from core.capability import Capability, CapabilityRegistry


print("================================")
print(" HAEP CAPABILITY TEST")
print("================================")
print()


def test_read(parameters):
    return {
        "status": "SUCCESS",
        "message": "TEST READ OK",
        "parameters": parameters,
    }


registry = CapabilityRegistry()

capability = Capability(
    name="test.read",
    version="1",
    access="READ",
    idempotency="IDEMPOTENT",
    side_effects=False,
    handler=test_read,
)

registry.register(capability)

print("Capability registrada:")
print(" ", capability.name)

print()
print("Capability existe:")
print(" ", registry.exists("test.read"))

if not registry.exists("test.read"):
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


found = registry.get("test.read")

print()
print("Capability recuperada:")
print(" ", found.name if found else None)

if found is None:
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


result = found.execute(
    {
        "value": 123
    }
)

print()
print("Resultado de ejecución:")
print(" ", result)

if result["status"] != "SUCCESS":
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


print()
print("Capabilities registradas:")

for item in registry.list():
    print(
        " ",
        item.name,
        "|",
        item.access,
        "|",
        item.idempotency,
        "| side_effects:",
        item.side_effects,
    )


print()
print("================================")
print(" RESULT: PASS")
print("================================")
