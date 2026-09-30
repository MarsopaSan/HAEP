from datetime import datetime, timedelta, timezone

from core.capability import Capability, CapabilityRegistry
from core.envelope import Envelope
from core.identity import Identity
from core.request_processor import RequestProcessor
from core.resource import Resource, ResourceRegistry


def create_processor():
    controller = Identity.generate()
    agent = Identity.generate()

    capabilities = CapabilityRegistry()

    execution_count = {"value": 0}

    def read_test(_parameters):
        execution_count["value"] += 1
        return {"value": "ok"}

    capabilities.register(
        Capability(
            name="test.read",
            version="1.0",
            access="READ",
            idempotency="IDEMPOTENT",
            side_effects=False,
            handler=read_test,
        )
    )

    resources = ResourceRegistry()

    resources.register(
        Resource(
            resource_id="test.device",
            name="Test Device",
        )
    )

    processor = RequestProcessor(
        identity=agent,
        controller_public_key=controller.public_key,
        registry=capabilities,
        resource_registry=resources,
    )

    return controller, agent, processor, execution_count


def create_request(
    controller,
    agent,
    issued_at,
    ttl=30,
    nonce="nonce-001",
):
    return Envelope.create(
        identity=controller,
        message_type="REQUEST",
        request_id="request-001",
        payload={
            "nonce": nonce,
            "issued_at": issued_at,
            "ttl": ttl,
            "agent_fingerprint": agent.fingerprint,
            "capability": "test.read",
            "resource_id": "test.device",
            "parameters": {},
        },
    )


def test_valid_temporal_request_executes():
    controller, agent, processor, execution_count = create_processor()

    now = datetime.now(timezone.utc)

    request = create_request(
        controller=controller,
        agent=agent,
        issued_at=now.isoformat(),
        ttl=30,
    )

    response = processor.process(request)

    assert response.payload["status"] == "SUCCESS"
    assert execution_count["value"] == 1


def test_expired_request_is_not_executed():
    controller, agent, processor, execution_count = create_processor()

    issued_at = datetime.now(timezone.utc) - timedelta(seconds=31)

    request = create_request(
        controller=controller,
        agent=agent,
        issued_at=issued_at.isoformat(),
        ttl=30,
    )

    response = processor.process(request)

    assert response.payload["status"] == "EXPIRED"
    assert execution_count["value"] == 0


def test_zero_ttl_is_rejected():
    controller, agent, processor, execution_count = create_processor()

    now = datetime.now(timezone.utc)

    request = create_request(
        controller=controller,
        agent=agent,
        issued_at=now.isoformat(),
        ttl=0,
    )

    response = processor.process(request)

    assert response.payload["status"] == "INVALID_TTL"
    assert execution_count["value"] == 0


def test_ttl_above_maximum_is_rejected():
    controller, agent, processor, execution_count = create_processor()

    now = datetime.now(timezone.utc)

    request = create_request(
        controller=controller,
        agent=agent,
        issued_at=now.isoformat(),
        ttl=301,
    )

    response = processor.process(request)

    assert response.payload["status"] == "INVALID_TTL"
    assert execution_count["value"] == 0


def test_invalid_issued_at_is_rejected():
    controller, agent, processor, execution_count = create_processor()

    request = create_request(
        controller=controller,
        agent=agent,
        issued_at="fecha-invalida",
        ttl=30,
    )

    response = processor.process(request)

    assert response.payload["status"] == "INVALID_ISSUED_AT"
    assert execution_count["value"] == 0


def test_expired_request_does_not_consume_replay_nonce():
    controller, agent, processor, execution_count = create_processor()

    issued_at = datetime.now(timezone.utc) - timedelta(seconds=31)

    expired_request = create_request(
        controller=controller,
        agent=agent,
        issued_at=issued_at.isoformat(),
        ttl=30,
        nonce="same-nonce",
    )

    expired_response = processor.process(expired_request)

    assert expired_response.payload["status"] == "EXPIRED"
    assert execution_count["value"] == 0

    valid_request = Envelope.create(
        identity=controller,
        message_type="REQUEST",
        request_id="request-002",
        payload={
            "nonce": "same-nonce",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "ttl": 30,
            "agent_fingerprint": agent.fingerprint,
            "capability": "test.read",
            "resource_id": "test.device",
            "parameters": {},
        },
    )

    valid_response = processor.process(valid_request)

    assert valid_response.payload["status"] == "SUCCESS"
    assert execution_count["value"] == 1