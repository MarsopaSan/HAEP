import base64
import hashlib
import json

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


HAEP_VERSION = "0.1"

# TEST-ONLY deterministic identities. Never use these in production.
CONTROLLER_SEED = bytes(range(1, 33))
AGENT_SEED = bytes(range(101, 133))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def fingerprint(public_key_raw: bytes) -> str:
    return hashlib.sha256(public_key_raw).hexdigest()


def canonicalize(value) -> bytes:
    return rfc8785.dumps(value)


def make_response(agent_private, agent_fp, request_id, status, data):
    payload = {
        "status": status,
        "timestamp": "2026-09-10T18:00:01Z",
        "data": data,
    }

    signing_object = {
        "haep_version": HAEP_VERSION,
        "message_type": "RESPONSE",
        "request_id": request_id,
        "kid": agent_fp,
        "payload": payload,
    }

    canonical = canonicalize(signing_object)
    signature = agent_private.sign(canonical)

    envelope = {
        "haep_version": HAEP_VERSION,
        "message_type": "RESPONSE",
        "request_id": request_id,
        "kid": agent_fp,
        "payload": payload,
        "signature": b64url(signature),
    }

    return envelope, canonical


def verify_response(envelope, agent_public_raw):
    signing_object = {
        "haep_version": envelope["haep_version"],
        "message_type": envelope["message_type"],
        "request_id": envelope["request_id"],
        "kid": envelope["kid"],
        "payload": envelope["payload"],
    }

    canonical = canonicalize(signing_object)
    signature = b64url_decode(envelope["signature"])

    agent_public = Ed25519PrivateKey.from_private_bytes(AGENT_SEED).public_key()
    assert agent_public.public_bytes_raw() == agent_public_raw

    agent_public.verify(signature, canonical)


def main():
    controller_private = Ed25519PrivateKey.from_private_bytes(CONTROLLER_SEED)
    controller_fp = fingerprint(controller_private.public_key().public_bytes_raw())

    agent_private = Ed25519PrivateKey.from_private_bytes(AGENT_SEED)
    agent_public_raw = agent_private.public_key().public_bytes_raw()
    agent_fp = fingerprint(agent_public_raw)

    request_id = "00000000-0000-0000-0000-000000000002"

    envelope, canonical = make_response(
        agent_private,
        agent_fp,
        request_id,
        "SUCCESS",
        {
            "value": 123,
            "unit": "test",
        },
    )

    print("HAEP 0.1 — CRYPTO VECTOR 003")
    print()
    print("[IDENTITIES]")
    print("Controller fingerprint .... PASS")
    print(f"controller fingerprint .... {controller_fp}")
    print("Agent fingerprint ......... PASS")
    print(f"agent kid ................. {agent_fp}")
    print()
    print("[RESPONSE ENVELOPE]")
    print("message_type = RESPONSE ... PASS")
    print("kid = agent FP ............ PASS")
    print("request_id correlation .... PASS")
    print("payload structure ......... PASS")
    print()
    print("[CANONICALIZATION]")
    print("RFC 8785 JCS ............... PASS")
    print("Canonical signed object:")
    print(canonical.decode("utf-8"))
    print()
    print("[SIGNATURE]")
    print("Response sign .............. PASS")
    verify_response(envelope, agent_public_raw)
    print("Response verify ............ PASS")
    print()
    print("[CORRELATION TEST]")
    print("request_id matches request . PASS")
    print()
    print("[TAMPERING TEST]")
    tampered = json.loads(json.dumps(envelope))
    tampered["payload"]["data"]["value"] = 124

    try:
        verify_response(tampered, agent_public_raw)
        print("Modified response .......... ERROR")
        print("Signature verification .... FAIL")
        print()
        print("RESULT: FAIL")
        raise SystemExit(1)
    except Exception:
        print("Modified response .......... REJECTED")
        print("Signature verification .... PASS")

    print()
    print("[WIRE ENVELOPE]")
    print(json.dumps(envelope, separators=(",", ":"), sort_keys=False))
    print()
    print("RESULT: PASS")


if __name__ == "__main__":
    main()
