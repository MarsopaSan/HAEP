"""HAEP 0.1 - Crypto Vector 001

Purpose:
- deterministic Ed25519 identity
- SHA-256 fingerprint
- RFC 8785 JCS canonicalization
- Ed25519 signing and verification
- tamper detection

This is a reproducible test vector, NOT a production key.
"""

import base64
import hashlib

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Deliberately public/test-only deterministic seed. Never use this as a real secret.
TEST_SEED = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)

EXPECTED_PUBLIC_KEY_B64URL = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
EXPECTED_FINGERPRINT = "56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c"
EXPECTED_CANONICAL = (
    '{"haep_version":"0.1","kid":"56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c",'
    '"message_type":"TEST_VECTOR","payload":{"message":"HAEP Crypto Vector 001","value":42},'
    '"request_id":"00000000-0000-0000-0000-000000000001"}'
)
EXPECTED_SIGNATURE_B64URL = (
    "rL8TXI-1iE0rhgP4xVbepXq33B-0N7lBi363UZMSkBEnnZpurVmOEoRb29tbbhDeWI0Sl_CnQBFI-aNby3bgCA"
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def main() -> None:
    print("HAEP 0.1 — CRYPTO VECTOR 001")
    print()

    # 1. Deterministic identity
    private_key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    public_key = private_key.public_key()
    public_key_raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    public_key_b64url = b64url(public_key_raw)
    fingerprint = hashlib.sha256(public_key_raw).hexdigest()

    assert public_key_b64url == EXPECTED_PUBLIC_KEY_B64URL
    assert fingerprint == EXPECTED_FINGERPRINT
    print("[IDENTITY]")
    print("Public Key .............. PASS")
    print("Fingerprint ............. PASS")
    print(f"kid ..................... {fingerprint}")
    print()

    # 2. HAEP signed material (signature field is intentionally absent)
    signed_object = {
        "haep_version": "0.1",
        "message_type": "TEST_VECTOR",
        "request_id": "00000000-0000-0000-0000-000000000001",
        "kid": fingerprint,
        "payload": {
            "message": "HAEP Crypto Vector 001",
            "value": 42,
        },
    }

    # RFC 8785 JCS returns UTF-8 bytes.
    canonical = rfc8785.dumps(signed_object)
    canonical_text = canonical.decode("utf-8")
    assert canonical_text == EXPECTED_CANONICAL
    print("[CANONICALIZATION]")
    print("RFC 8785 JCS ............ PASS")
    print(f"Canonical JSON:")
    print(canonical_text)
    print()

    # 3. Sign
    signature = private_key.sign(canonical)
    signature_b64url = b64url(signature)
    assert signature_b64url == EXPECTED_SIGNATURE_B64URL
    print("[SIGNATURE]")
    print("Sign .................... PASS")
    print("Verify ..................", end=" ")
    public_key.verify(signature, canonical)
    print("PASS")
    print()

    # 4. Tamper test: change one value, keep the original signature.
    tampered = {
        **signed_object,
        "payload": {
            "message": "HAEP Crypto Vector 001",
            "value": 43,
        },
    }
    tampered_canonical = rfc8785.dumps(tampered)

    print("[TAMPERING TEST]")
    try:
        public_key.verify(signature, tampered_canonical)
    except InvalidSignature:
        print("Modified payload ........ REJECTED")
        print("Signature verification . PASS")
    else:
        raise AssertionError("Tampered payload was incorrectly accepted")

    print()
    print("RESULT: PASS")


if __name__ == "__main__":
    main()
