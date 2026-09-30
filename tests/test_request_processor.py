from datetime import datetime, timezone

from core.capability import Capability, CapabilityRegistry
from core.grant import Grant, GrantRegistry
from core.identity import Identity
from core.policy import PolicyEngine
from core.request_builder import RequestBuilder
from core.request_processor import RequestProcessor
from core.resource import Resource, ResourceRegistry
from core.trust import TrustManager


def build_stack():
    controller = Identity.generate()
    agent = Identity.generate()
    authority = Identity.generate()

    trust = TrustManager()
    trust.pair(controller.fingerprint)

    registry = CapabilityRegistry()
    registry.register(Capability(
        name="test.read", version="1", access="READ",
        idempotency="IDEMPOTENT", side_effects=False,
        handler=lambda parameters: {"message": "TEST READ OK", "parameters": parameters},
    ))

    resources = ResourceRegistry()
    resources.register(Resource(
        resource_id="test.device", name="Test Device",
        description="Recurso virtual del agente de prueba",
    ))

    grants = GrantRegistry()
    grants.register(Grant(
        agent_fingerprint=agent.fingerprint,
        capability="test.read",
        resource_id="test.device",
    ))
    policy = PolicyEngine(grants, authority_identity=authority)
    builder = RequestBuilder(controller, policy)
    processor = RequestProcessor(
        identity=agent,
        controller_public_key=controller.public_key,
        policy_authority_public_key=authority.public_key,
        registry=registry,
        resource_registry=resources,
        trust_manager=trust,
    )
    return controller, agent, authority, builder, processor


def test_authorized_request_executes():
    controller, agent, authority, builder, processor = build_stack()
    request = builder.build_request(
        agent_fingerprint=agent.fingerprint,
        capability="test.read",
        resource_id="test.device",
        parameters={"value": 123},
        nonce="nonce-valid",
    )
    response = processor.process(request)
    assert response.payload["status"] == "SUCCESS"
    assert response.verify(agent.public_key)


def test_request_without_policy_assertion_is_rejected():
    controller, agent, authority, builder, processor = build_stack()
    request = builder.build_request(
        agent_fingerprint=agent.fingerprint, capability="test.read",
        resource_id="test.device", parameters={}, nonce="nonce-no-assertion"
    )
    request.payload.pop("authorization")
    # La firma ya no corresponde al payload alterado; esto debe fallar primero.
    response = processor.process(request)
    assert response.payload["status"] == "AUTHN_FAILED"


def test_authorization_scope_cannot_be_reused_for_changed_parameters():
    controller, agent, authority, builder, processor = build_stack()
    request = builder.build_request(
        agent_fingerprint=agent.fingerprint, capability="test.read",
        resource_id="test.device", parameters={"value": 1}, nonce="nonce-scope"
    )
    request.payload["parameters"]["value"] = 999
    # Envelope signature ahora es inválida; un atacante no puede cambiar parámetros.
    response = processor.process(request)
    assert response.payload["status"] == "AUTHN_FAILED"
