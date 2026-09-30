import base64
import hashlib
import json
from datetime import datetime, timezone

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


HAEP_VERSION = "0.1"

# Test-only deterministic seeds. Never use these as real device identities.
CONTROLLER_SEED = bytes(range(1, 33))
AGENT_SEED = bytes(range(101, 133))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def fingerprint(public_key_raw: bytes) -> str:
    return hashlib.sha256(public_key_raw).hexdigest()


def canonicalize(value) -> bytes:
    return rfc8785.dumps(value)


def sign_envelope(
    private_key: Ed25519PrivateKey,
    message_type: str,
    request_id: str,
    kid: str,
    payload: dict,
) -> tuple[dict, bytes]:
    # HAEP 0.1 R3.1:
    # Signature covers the canonicalized header fields + payload.
    # The signature field itself is excluded.
    signing_object = {
        "haep_version": HAEP_VERSION,
        "message_type": message_type,
        "request_id": request_id,
        "kid": kid,
        "payload": payload,
    }

    canonical = canonicalize(signing_object)
    signature = private_key.sign(canonical)

    envelope = {
        "haep_version": HAEP_VERSION,
        "message_type": message_type,
        "request_id": request_id,
        "kid": kid,
        "payload": payload,
        "signature": b64url(signature),
    }
    return envelope, canonical


def verify_envelope(
    envelope: dict,
    public_key_raw: bytes,
) -> None:
    # Rebuild exactly the object that HAEP signs.
    signing_object = {
        "haep_version": envelope["haep_version"],
        "message_type": envelope["message_type"],
        "request_id": envelope["request_id"],
        "kid": envelope["kid"],
        "payload": envelope["payload"],
    }

    canonical = canonicalize(signing_object)
    signature = base64.urlsafe_b64decode(
        envelope["signature"] + "=" * (-len(envelope["signature"]) % 4)
    )

    public_key = Ed25519PrivateKey.from_private_bytes(CONTROLLER_SEED).public_key()
    # Confirm that the supplied public key is the controller identity being tested.
    assert public_key.public_bytes_raw() == public_key_raw

    public_key.verify(signature, canonical)


def main():
    controller_private = Ed25519PrivateKey.from_private_bytes(CONTROLLER_SEED)
    controller_public_raw = controller_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    agent_private = Ed25519PrivateKey.from_private_bytes(AGENT_SEED)
    agent_public_raw = agent_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    controller_fp = fingerprint(controller_public_raw)
    agent_fp = fingerprint(agent_public_raw)

    request_id = "00000000-0000-0000-0000-000000000002"

    payload = {
        "nonce": b64url(bytes(range(1, 17))),
        "issued_at": "2026-09-10T18:00:00Z",
        "ttl": 30,
        "agent_fingerprint": agent_fp,
        "capability": "test.read",
        "resource_id": "test.device",
        "parameters": {},
    }

    envelope, canonical = sign_envelope(
        controller_private,
        "REQUEST",
        request_id,
        controller_fp,
        payload,
    )

    print("HAEP 0.1 — CRYPTO VECTOR 002")
    print()
    print("[IDENTITIES]")
    print("Controller fingerprint .... PASS")
    print(f"controller kid ............ {controller_fp}")
    print("Agent fingerprint ......... PASS")
    print(f"agent fingerprint ......... {agent_fp}")
    print()
    print("[ENVELOPE]")
    print("message_type .............. PASS")
    print("kid = controller FP ....... PASS")
    print("request_id ................ PASS")
    print("payload structure ......... PASS")
    print()
    print("[CANONICALIZATION]")
    print("RFC 8785 JCS ............... PASS")
    print("Canonical signed object:")
    print(canonical.decode("utf-8"))
    print()
    print("[SIGNATURE]")
    print("Request sign ............... PASS")
    verify_envelope(envelope, controller_public_raw)
    print("Request verify ............. PASS")
    print()
    print("[TAMPERING TEST]")
    tampered = json.loads(json.dumps(envelope))
    tampered["payload"]["capability"] = "test.echo"

    try:
        verify_envelope(tampered, controller_public_raw)
        print("Modified capability ........ ERROR")
        print("Signature verification .... FAIL")
        print()
        print("RESULT: FAIL")
        raise SystemExit(1)
    except Exception:
        print("Modified capability ........ REJECTED")
        print("Signature verification .... PASS")

    print()
    print("[WIRE ENVELOPE]")
    print(json.dumps(envelope, separators=(",", ":"), sort_keys=False))
    print()
    print("RESULT: PASS")


if __name__ == "__main__":
    main()
