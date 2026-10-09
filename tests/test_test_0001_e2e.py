
import json

from agents.TEST_0001.agent import HaepAgent
from core.grant import Grant, GrantRegistry
from core.identity import Identity
from core.manifest import Manifest
from core.policy import PolicyEngine
from core.request_builder import RequestBuilder


def test_test_0001_end_to_end(tmp_path):
    # 1. Crear identidades temporales
    controller = Identity.generate()
    authority = Identity.generate()
    agent_identity = Identity.generate()

    # 2. Crear y firmar el manifest con la identidad del agente
    manifest = Manifest(
        agent_id="TEST-0001",
        name="HAEP Test Agent",
        domain="test",
        haep_version="0.1",
        agent_version="0.1.0",
        fingerprint=agent_identity.fingerprint,
        capabilities=[
            {
                "name": "test.status",
                "version": "1",
                "access": "READ",
            },
            {
                "name": "test.read",
                "version": "1",
                "access": "READ",
            },
            {
                "name": "test.echo",
                "version": "1",
                "access": "WRITE",
            },
            {
                "name": "test.deny_me",
                "version": "1",
                "access": "READ",
            },
        ],
    )
    manifest.sign(agent_identity)

    # 3. Guardar los archivos dentro del directorio temporal de pytest
    identity_path = tmp_path / "private_key.pem"
    manifest_path = tmp_path / "manifest.json"

    agent_identity.save(identity_path)
    manifest_path.write_text(
        json.dumps(manifest.to_dict(), indent=2),
        encoding="utf-8",
    )

    # 4. Arrancar el agente usando exclusivamente esos archivos
    agent = HaepAgent(
        policy_authority_public_key=authority.public_key,
        identity_path=identity_path,
        manifest_path=manifest_path,
    )
    agent.start()

    # 5. Abrir la ventana de pairing
    agent.open_pairing_window(seconds=60)

    pairing_request = agent.pairing.build_pairing_request(
        controller_identity=controller,
        nonce="e2e-pairing-nonce-0001",
        ttl=60,
    )

    pairing_response = agent.handle_message(pairing_request)
    assert pairing_response.payload["status"] == "PAIRING_PENDING"

    # 6. Aprobar explícitamente el pairing
    approved = agent.approve_pairing(
        request_id=pairing_request.request_id,
        controller_fingerprint=controller.fingerprint,
    )
    assert approved is True
    assert agent.trust.state.value == "PAIRED"

    # 7. Conceder permiso para test.echo
    grants = GrantRegistry()
    grants.register(
        Grant(
            agent_fingerprint=agent.identity.fingerprint,
            capability="test.echo",
            resource_id="test.device",
        )
    )

    policy = PolicyEngine(grants, authority_identity=authority)
    builder = RequestBuilder(controller, policy)

    # 8. Construir y enviar la solicitud autorizada
    request = builder.build_request(
        agent_fingerprint=agent.identity.fingerprint,
        capability="test.echo",
        resource_id="test.device",
        parameters={
            "message": "HELLO FROM E2E",
            "value": 123,
        },
        nonce="e2e-request-nonce-0001",
    )

    response = agent.handle_message(request)

    # 9. Verificar el resultado
    assert response.payload["status"] == "SUCCESS"
    assert response.payload["data"] == {
        "echo": {
            "message": "HELLO FROM E2E",
            "value": 123,
        }
    }

    # 10. Verificar la firma de la respuesta
    assert response.verify(agent.identity.public_key)