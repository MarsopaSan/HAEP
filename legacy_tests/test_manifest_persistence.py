from pathlib import Path

from core.identity import Identity
from core.manifest import Manifest
from core.manifest_storage import save_manifest, load_manifest


print("================================")
print(" HAEP MANIFEST PERSISTENCE TEST")
print("================================")
print()

identity_path = Path(
    "agents/TEST-0001/identity/private_key.pem"
)

manifest_path = Path(
    "agents/TEST-0001/manifest/manifest.json"
)

# ==========================================
# IDENTITY
# ==========================================

if identity_path.exists():
    print("Identity encontrada.")
    identity = Identity.load(identity_path)
else:
    print("Identity no encontrada.")
    print("Generando nueva Identity...")
    identity = Identity.generate()
    identity.save(identity_path)

print()
print("Identity fingerprint:")
print(" ", identity.fingerprint)

# ==========================================
# MANIFEST
# ==========================================

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

print()
print("Manifest firmado.")

# ==========================================
# GUARDAR
# ==========================================

save_manifest(manifest, manifest_path)

print()
print("Manifest guardado en:")
print(" ", manifest_path)

if not manifest_path.exists():
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)

# ==========================================
# CARGAR
# ==========================================

loaded_manifest = load_manifest(manifest_path)

print()
print("Manifest cargado nuevamente.")

print()
print("Agent ID:")
print(" ", loaded_manifest.agent_id)

print()
print("Fingerprint:")
print(" ", loaded_manifest.fingerprint)

print()
print("Firma:")
print(" ", loaded_manifest.signature)

# ==========================================
# VERIFICACIONES
# ==========================================

fingerprint_matches = (
    loaded_manifest.fingerprint
    == identity.fingerprint
)

signature_valid = loaded_manifest.verify(
    identity.public_key
)

print()
print("Fingerprint coincide con Identity:")
print(" ", fingerprint_matches)

print()
print("Firma del Manifest válida:")
print(" ", signature_valid)

if not fingerprint_matches:
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)

if not signature_valid:
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)

print()
print("================================")
print(" RESULT: PASS")
print("================================")
