from core.identity import Identity
from core.pairing import PairingService
from core.trust import TrustManager, TrustState


def test_successful_pairing():
    controller = Identity.generate()
    agent = Identity.generate()
    trust = TrustManager()
    service = PairingService()

    assert trust.state == TrustState.UNPAIRED

    request = service.build_pairing_request(controller)
    response = service.process_pairing_request(request, agent, trust)

    assert response.message_type == "PAIRING_RESPONSE"
    assert response.payload["status"] == "PAIRED"
    assert trust.state == TrustState.PAIRED
    assert trust.is_known(controller.fingerprint)


def test_invalid_signature_is_rejected():
    controller = Identity.generate()
    attacker = Identity.generate()
    agent = Identity.generate()
    trust = TrustManager()
    service = PairingService()

    request = service.build_pairing_request(controller)
    # Firmar con otra identidad rompe la coherencia kid/clave
    request.signature = attacker.sign_base64url(request.signing_data())

    response = service.process_pairing_request(request, agent, trust)

    assert response.payload["status"] in ("INVALID_SIGNATURE", "DENIED")
    assert trust.state == TrustState.UNPAIRED


def test_revoked_agent_rejects_pairing():
    controller = Identity.generate()
    agent = Identity.generate()
    trust = TrustManager()
    service = PairingService()

    trust.pair(controller.fingerprint)
    trust.revoke()

    request = service.build_pairing_request(controller)
    response = service.process_pairing_request(request, agent, trust)

    assert response.payload["status"] == "REVOKED"
    assert trust.state == TrustState.REVOKED


def test_require_known_controller():
    controller = Identity.generate()
    unknown = Identity.generate()
    agent = Identity.generate()
    trust = TrustManager()
    service = PairingService(require_known_controller=True)

    trust.register_known_controller(controller.fingerprint)

    # Controller conocido → OK
    req_ok = service.build_pairing_request(controller)
    resp_ok = service.process_pairing_request(req_ok, agent, trust)
    assert resp_ok.payload["status"] == "PAIRED"

    trust.on_startup()  # fuerza UNPAIRED de nuevo

    # Controller desconocido → DENIED
    req_bad = service.build_pairing_request(unknown)
    resp_bad = service.process_pairing_request(req_bad, agent, trust)
    assert resp_bad.payload["status"] == "DENIED"
    assert resp_bad.payload["error"] == "UNKNOWN_CONTROLLER"


def test_pairing_request_has_valid_fields():
    controller = Identity.generate()
    service = PairingService()

    request = service.build_pairing_request(controller, ttl=45)

    assert request.message_type == "PAIRING_REQUEST"
    assert request.payload["ttl"] == 45
    assert request.payload["controller_fingerprint"] == controller.fingerprint
    assert "issued_at" in request.payload
    assert "nonce" in request.payload
    assert request.verify(controller.public_key) is True