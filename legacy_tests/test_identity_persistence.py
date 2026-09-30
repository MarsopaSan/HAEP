from pathlib import Path

from core.identity import Identity


identity_path = Path("agents/TEST-0001/identity/private_key.pem")


print("================================")
print(" HAEP IDENTITY PERSISTENCE TEST")
print("================================")
print()


# --------------------------------------------------
# 1. Crear o cargar identidad
# --------------------------------------------------

if identity_path.exists():

    print("Identity file found.")
    print("Loading existing identity...")

    identity = Identity.load(identity_path)

    created = False

else:

    print("Identity file not found.")
    print("Generating new identity...")

    identity = Identity.generate()

    identity.save(identity_path)

    created = True


print()
print("Fingerprint:")
print(" ", identity.fingerprint)

print()
print("Identity file:")
print(" ", identity_path)

print()
print("File exists:")
print(" ", identity_path.exists())


if not identity_path.exists():
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)


# --------------------------------------------------
# 2. Cargar nuevamente la identidad
# --------------------------------------------------

loaded_identity = Identity.load(identity_path)


print()
print("Reloaded fingerprint:")
print(" ", loaded_identity.fingerprint)


# --------------------------------------------------
# 3. Comparar fingerprints
# --------------------------------------------------

same_identity = (
    identity.fingerprint == loaded_identity.fingerprint
)


print()
print("Fingerprint preserved:")
print(" ", same_identity)


if not same_identity:
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
