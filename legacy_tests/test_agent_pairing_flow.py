from agents.TEST_0001.agent import HaepAgent
from core.grant import Grant, GrantRegistry
from core.identity import Identity
from core.pairing import PairingService
from core.policy import PolicyEngine
from core.request_builder import RequestBuilder
from core.trust import TrustState


def test_request_before_pairing_is_rejected():
    agent = HaepAgent()
    agent.start()

    controller = Identity.generate()
    grants = GrantRegistry()
    grants.register(
        Grant(
            agent_fingerprint=agent.identity.fingerprint,
            capability="test.read",
            resource_id="test.device",
        )
    )
    builder = RequestBuilder(controller, PolicyEngine(grants))

    request = builder.build_request(
        agent_fingerprint=agent.identity.fingerprint,
        capability="test.read",
        resource_id="test.device",
        parameters={},
        nonce="nonce-before-pair",
    )

    response = agent.handle_message(request)

    assert response.payload["status"] == "PAIRING_REQUIRED"
    assert agent.trust.state == TrustState.UNPAIRED


def test_pairing_then_request_succeeds():
    agent = HaepAgent()
    agent.start()

    controller = Identity.generate()
    pairing = PairingService()

    pairing_request = pairing.build_pairing_request(controller)
    pairing_response = agent.handle_message(pairing_request)

    assert pairing_response.payload["status"] == "PAIRED"
    assert agent.trust.state == TrustState.PAIRED
    assert agent.controller_fingerprint == controller.fingerprint

    grants = GrantRegistry()
    grants.register(
        Grant(
            agent_fingerprint=agent.identity.fingerprint,
            capability="test.read",
            resource_id="test.device",
        )
    )
    builder = RequestBuilder(controller, PolicyEngine(grants))

    request = builder.build_request(
        agent_fingerprint=agent.identity.fingerprint,
        capability="test.read",
        resource_id="test.device",
        parameters={"foo": "bar"},
        nonce="nonce-after-pair",
    )

    response = agent.handle_message(request)

    assert response.payload["status"] == "SUCCESS"
    assert response.payload["data"]["message"] == "TEST READ OK"


def test_echo_capability_after_pairing():
    agent = HaepAgent()
    agent.start()

    controller = Identity.generate()
    pairing = PairingService()
    agent.handle_message(pairing.build_pairing_request(controller))

    grants = GrantRegistry()
    grants.register(
        Grant(
            agent_fingerprint=agent.identity.fingerprint,
            capability="test.echo",
            resource_id="test.device",
        )
    )
    builder = RequestBuilder(controller, PolicyEngine(grants))

    request = builder.build_request(
        agent_fingerprint=agent.identity.fingerprint,
        capability="test.echo",
        resource_id="test.device",
        parameters={"hello": "world"},
        nonce="nonce-echo",
    )

    response = agent.handle_message(request)

    assert response.payload["status"] == "SUCCESS"
    assert response.payload["data"]["echo"]["hello"] == "world"


def test_restart_requires_pairing_again():
    agent = HaepAgent()
    agent.start()

    controller = Identity.generate()
    pairing = PairingService()
    agent.handle_message(pairing.build_pairing_request(controller))
    assert agent.trust.state == TrustState.PAIRED

    agent.start()
    assert agent.trust.state == TrustState.UNPAIRED

    grants = GrantRegistry()
    grants.register(
        Grant(
            agent_fingerprint=agent.identity.fingerprint,
            capability="test.read",
            resource_id="test.device",
        )
    )
    builder = RequestBuilder(controller, PolicyEngine(grants))

    request = builder.build_request(
        agent_fingerprint=agent.identity.fingerprint,
        capability="test.read",
        resource_id="test.device",
        parameters={},
        nonce="nonce-after-restart",
    )

    response = agent.handle_message(request)
    assert response.payload["status"] == "PAIRING_REQUIRED"