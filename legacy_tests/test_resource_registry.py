from core.resource import Resource, ResourceRegistry


print("================================")
print(" HAEP RESOURCE REGISTRY TEST")
print("================================")
print()


registry = ResourceRegistry()


# Registrar un recurso válido
registry.register(
    Resource(
        resource_id="test.device",
        name="Test Device",
        description="Recurso virtual del agente de prueba",
    )
)


print("Recursos registrados:")

for resource in registry.list():
    print(
        f"  {resource.resource_id} | "
        f"{resource.name} | "
        f"{resource.description}"
    )


print()
print("Comprobando recurso existente...")

if not registry.exists("test.device"):
    print("ERROR: test.device debería existir.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)

print("  test.device → EXISTE")


print()
print("Comprobando recurso inexistente...")

if registry.exists("inventado.xyz"):
    print("ERROR: inventado.xyz no debería existir.")
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)

print("  inventado.xyz → NO EXISTE")


print()
print("================================")
print(" RESULT: PASS")
print("================================")
