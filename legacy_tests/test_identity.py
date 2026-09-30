from core.identity import Identity


identity = Identity.generate()

print("================================")
print(" HAEP IDENTITY TEST")
print("================================")
print()

print("Algorithm:")
print("  Ed25519")
print()

print("Public Key:")
print(" ", identity.public_key_base64url())
print()

print("Fingerprint:")
print(" ", identity.fingerprint)
print()

message = b"HAEP Identity Test"

signature = identity.sign(message)

print("Signature:")
print(" ", identity.sign_base64url(message))
print()

print("Signature length:")
print(" ", len(signature), "bytes")
print()

# --------------------------------------------------
# TEST 1: firma válida
# --------------------------------------------------

valid = Identity.verify(
    identity.public_key,
    signature,
    message,
)

print("Valid signature verification:")
print(" ", valid)

if not valid:
    print()
    print("RESULT: FAIL")
    raise SystemExit(1)

# --------------------------------------------------
# TEST 2: mensaje alterado
# --------------------------------------------------

tampered_message = b"HAEP Identity Test ALTERED"

tampered = Identity.verify(
    identity.public_key,
    signature,
    tampered_message,
)

print()
print("Tampered message verification:")
print(" ", tampered)

if tampered:
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
