import pytest

from core.grant import Grant, GrantRegistry
from core.identity import Identity
from core.policy import PolicyEngine
from core.request_builder import RequestBuilder


AGENT = "agent-fingerprint-001"
CAPABILITY = "test.read"
RESOURCE = "test.device"


def create_builder():
    controller_identity = Identity.generate()

    grants = GrantRegistry()

    grants.register(
        Grant(
            agent_fingerprint=AGENT,
            capability=CAPABILITY,
            resource_id=RESOURCE,
            allowed=True,
        )
    )

    policy = PolicyEngine(grants, authority_identity=Identity.generate())

    builder = RequestBuilder(
        controller_identity=controller_identity,
        policy_engine=policy,
    )

    return builder, controller_identity


def test_authorized_request_is_created():
    builder, controller_identity = create_builder()

    request = builder.build_request(
        agent_fingerprint=AGENT,
        capability=CAPABILITY,
        resource_id=RESOURCE,
        parameters={},
        nonce="nonce-001",
    )

    assert request.message_type == "REQUEST"
    assert request.kid == controller_identity.fingerprint
    assert request.payload["agent_fingerprint"] == AGENT
    assert request.payload["capability"] == CAPABILITY
    assert request.payload["resource_id"] == RESOURCE
    assert request.payload["nonce"] == "nonce-001"


def test_authorized_request_has_valid_signature():
    builder, controller_identity = create_builder()

    request = builder.build_request(
        agent_fingerprint=AGENT,
        capability=CAPABILITY,
        resource_id=RESOURCE,
        parameters={},
        nonce="nonce-002",
    )

    assert request.verify(controller_identity.public_key) is True


def test_unauthorized_request_is_not_created():
    controller_identity = Identity.generate()

    grants = GrantRegistry()
    policy = PolicyEngine(grants, authority_identity=Identity.generate())

    builder = RequestBuilder(
        controller_identity=controller_identity,
        policy_engine=policy,
    )

    with pytest.raises(PermissionError, match="NO_GRANT"):
        builder.build_request(
            agent_fingerprint=AGENT,
            capability=CAPABILITY,
            resource_id=RESOURCE,
            parameters={},
            nonce="nonce-003",
        )


def test_wrong_resource_is_denied_before_request_creation():
    builder, _ = create_builder()

    with pytest.raises(PermissionError, match="NO_GRANT"):
        builder.build_request(
            agent_fingerprint=AGENT,
            capability=CAPABILITY,
            resource_id="inventado.xyz",
            parameters={},
            nonce="nonce-004",
        )


def test_denied_grant_is_not_sent():
    controller_identity = Identity.generate()

    grants = GrantRegistry()

    grants.register(
        Grant(
            agent_fingerprint=AGENT,
            capability=CAPABILITY,
            resource_id=RESOURCE,
            allowed=False,
        )
    )

    policy = PolicyEngine(grants, authority_identity=Identity.generate())

    builder = RequestBuilder(
        controller_identity=controller_identity,
        policy_engine=policy,
    )

    with pytest.raises(PermissionError, match="GRANT_DENIED"):
        builder.build_request(
            agent_fingerprint=AGENT,
            capability=CAPABILITY,
            resource_id=RESOURCE,
            parameters={},
            nonce="nonce-005",
        )

def test_issued_at_is_populated():
    builder, _ = create_builder()

    request = builder.build_request(
        agent_fingerprint=AGENT,
        capability=CAPABILITY,
        resource_id=RESOURCE,
        parameters={},
        nonce="nonce-issued-at",
    )

    issued_at = request.payload["issued_at"]
    assert isinstance(issued_at, str)
    assert "T" in issued_at  # formato ISO
    assert issued_at.endswith("Z") or "+" in issued_at or issued_at.count(":") >= 2