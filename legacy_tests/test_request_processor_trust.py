from datetime import datetime, timezone

import pytest

from core.capability import Capability, CapabilityRegistry
from core.envelope import Envelope
from core.identity import Identity
from core.request_processor import RequestProcessor
from core.resource import Resource, ResourceRegistry
from core.trust import TrustManager, TrustState


def build_request(controller, agent, capability="test.read"):
    payload = {
        "nonce": "trust-test-nonce",
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "ttl": 30,
        "agent_fingerprint": agent.fingerprint,
        "capability": capability,
        "resource_id": "test.device",
        "parameters": {},
    }

    return Envelope.create(
        identity=controller,
        message_type="REQUEST",
        request_id="trust-test-request",
        payload=payload,
    )


def build_processor(agent, controller, trust):
    registry = CapabilityRegistry()

    registry.register(
        Capability(
            name="test.read",
            version="1.0",
            access="READ",
            idempotency="IDEMPOTENT",
            side_effects=False,
            handler=lambda parameters: {"value": "ok"},
        )
    )

    resources = ResourceRegistry()

    resources.register(
        Resource(
            resource_id="test.device",
            name="Test Device",
        )
    )

    return RequestProcessor(
        identity=agent,
        controller_public_key=controller.public_key,
        registry=registry,
        resource_registry=resources,
        time_policy=None,
        trust_manager=trust,
    )


def test_unpaired_request_is_rejected():
    controller = Identity.generate()
    agent = Identity.generate()
    trust = TrustManager()

    processor = build_processor(agent, controller, trust)
    request = build_request(controller, agent)

    response = processor.process(request)

    assert trust.state == TrustState.UNPAIRED
    assert response.payload["status"] == "PAIRING_REQUIRED"


def test_paired_request_is_allowed():
    controller = Identity.generate()
    agent = Identity.generate()
    trust = TrustManager()

    trust.pair()

    processor = build_processor(agent, controller, trust)
    request = build_request(controller, agent)

    response = processor.process(request)

    assert trust.state == TrustState.PAIRED
    assert response.payload["status"] == "SUCCESS"


def test_revoked_request_is_rejected():
    controller = Identity.generate()
    agent = Identity.generate()
    trust = TrustManager()

    trust.pair()
    trust.revoke()

    processor = build_processor(agent, controller, trust)
    request = build_request(controller, agent)

    response = processor.process(request)

    assert trust.state == TrustState.REVOKED
    assert response.payload["status"] == "REVOKED"