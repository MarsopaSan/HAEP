from datetime import datetime, timedelta, timezone

from core.grant import Grant, GrantRegistry
from core.policy import PolicyEngine


AGENT = "agent-fingerprint-001"
CAPABILITY = "test.read"
RESOURCE = "test.device"


def test_allowed_grant():
    registry = GrantRegistry()

    registry.register(
        Grant(
            agent_fingerprint=AGENT,
            capability=CAPABILITY,
            resource_id=RESOURCE,
            allowed=True,
        )
    )

    policy = PolicyEngine(registry)

    decision = policy.evaluate(
        agent_fingerprint=AGENT,
        capability=CAPABILITY,
        resource_id=RESOURCE,
    )

    assert decision.allowed is True
    assert decision.reason == "AUTHORIZED"


def test_missing_grant():
    registry = GrantRegistry()
    policy = PolicyEngine(registry)

    decision = policy.evaluate(
        agent_fingerprint=AGENT,
        capability=CAPABILITY,
        resource_id=RESOURCE,
    )

    assert decision.allowed is False
    assert decision.reason == "NO_GRANT"


def test_wrong_capability_is_denied():
    registry = GrantRegistry()

    registry.register(
        Grant(
            agent_fingerprint=AGENT,
            capability=CAPABILITY,
            resource_id=RESOURCE,
            allowed=True,
        )
    )

    policy = PolicyEngine(registry)

    decision = policy.evaluate(
        agent_fingerprint=AGENT,
        capability="test.echo",
        resource_id=RESOURCE,
    )

    assert decision.allowed is False
    assert decision.reason == "NO_GRANT"


def test_wrong_resource_is_denied():
    registry = GrantRegistry()

    registry.register(
        Grant(
            agent_fingerprint=AGENT,
            capability=CAPABILITY,
            resource_id=RESOURCE,
            allowed=True,
        )
    )

    policy = PolicyEngine(registry)

    decision = policy.evaluate(
        agent_fingerprint=AGENT,
        capability=CAPABILITY,
        resource_id="inventado.xyz",
    )

    assert decision.allowed is False
    assert decision.reason == "NO_GRANT"


def test_wrong_agent_is_denied():
    registry = GrantRegistry()

    registry.register(
        Grant(
            agent_fingerprint=AGENT,
            capability=CAPABILITY,
            resource_id=RESOURCE,
            allowed=True,
        )
    )

    policy = PolicyEngine(registry)

    decision = policy.evaluate(
        agent_fingerprint="attacker-agent",
        capability=CAPABILITY,
        resource_id=RESOURCE,
    )

    assert decision.allowed is False
    assert decision.reason == "NO_GRANT"


def test_explicitly_denied_grant():
    registry = GrantRegistry()

    registry.register(
        Grant(
            agent_fingerprint=AGENT,
            capability=CAPABILITY,
            resource_id=RESOURCE,
            allowed=False,
        )
    )

    policy = PolicyEngine(registry)

    decision = policy.evaluate(
        agent_fingerprint=AGENT,
        capability=CAPABILITY,
        resource_id=RESOURCE,
    )

    assert decision.allowed is False
    assert decision.reason == "GRANT_DENIED"


def test_expired_grant():
    registry = GrantRegistry()

    registry.register(
        Grant(
            agent_fingerprint=AGENT,
            capability=CAPABILITY,
            resource_id=RESOURCE,
            allowed=True,
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
    )

    policy = PolicyEngine(registry)

    decision = policy.evaluate(
        agent_fingerprint=AGENT,
        capability=CAPABILITY,
        resource_id=RESOURCE,
    )

    assert decision.allowed is False
    assert decision.reason == "GRANT_EXPIRED"
