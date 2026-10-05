from core.identity import Identity
from core.pairing import PairingService
from core.trust import TrustManager, TrustState


def test_new_controller_requires_explicit_oob_approval():
    controller = Identity.generate(); agent = Identity.generate(); trust = TrustManager(); service = PairingService()
    request = service.build_pairing_request(controller)
    response = service.process_pairing_request(request, agent, trust)
    assert response.payload["status"] == "DENIED"
    assert response.payload["error"] == "PAIRING_WINDOW_CLOSED"
    assert trust.state == TrustState.UNPAIRED


def test_pairing_pending_then_oob_approval_pairs():
    controller = Identity.generate(); agent = Identity.generate(); trust = TrustManager(); service = PairingService()
    service.open_pairing_window(60)
    request = service.build_pairing_request(controller)
    response = service.process_pairing_request(request, agent, trust)
    assert response.payload["status"] == "PAIRING_PENDING"
    assert trust.state == TrustState.UNPAIRED
    assert service.approve_pairing(request.request_id, controller.fingerprint, trust) is True
    assert trust.state == TrustState.PAIRED
    assert trust.is_known(controller.fingerprint)


def test_pairing_replay_is_rejected():
    controller = Identity.generate(); agent = Identity.generate(); trust = TrustManager(); service = PairingService()
    service.open_pairing_window(60)
    request = service.build_pairing_request(controller)
    first = service.process_pairing_request(request, agent, trust)
    assert first.payload["status"] == "PAIRING_PENDING"
    second = service.process_pairing_request(request, agent, trust)
    assert second.payload["error"] == "PAIRING_REPLAY"


def test_known_controller_can_repair_without_oob():
    controller = Identity.generate(); agent = Identity.generate(); trust = TrustManager(); service = PairingService()
    trust.register_known_controller(controller.fingerprint)
    request = service.build_pairing_request(controller)
    response = service.process_pairing_request(request, agent, trust)
    assert response.payload["status"] == "PAIRED"
    assert trust.state == TrustState.PAIRED


def test_pairing_window_expires():
    controller = Identity.generate(); agent = Identity.generate(); trust = TrustManager(); service = PairingService()
    service.open_pairing_window(1)
    service._pairing_window_expires_at = 0
    request = service.build_pairing_request(controller)
    response = service.process_pairing_request(request, agent, trust)
    assert response.payload["error"] == "PAIRING_WINDOW_CLOSED"


def test_revoked_agent_rejects_pairing():
    controller = Identity.generate(); agent = Identity.generate(); trust = TrustManager(); service = PairingService()
    trust.revoke()
    service.open_pairing_window(60)
    request = service.build_pairing_request(controller)
    response = service.process_pairing_request(request, agent, trust)
    assert response.payload["status"] == "REVOKED"


class _ExpiringAfterPendingPolicy:
    def __init__(self):
        self.calls = 0

    def validate(self, issued_at, ttl, now=None):
        from core.time_policy import TimeDecision
        self.calls += 1
        if self.calls == 1:
            return TimeDecision(True, "VALID")
        return TimeDecision(False, "EXPIRED")


def test_pending_pairing_cannot_be_approved_after_request_ttl():
    controller = Identity.generate(); agent = Identity.generate(); trust = TrustManager()
    policy = _ExpiringAfterPendingPolicy()
    service = PairingService(time_policy=policy)
    service.open_pairing_window(60)
    request = service.build_pairing_request(controller, ttl=60)
    response = service.process_pairing_request(request, agent, trust)
    assert response.payload["status"] == "PAIRING_PENDING"
    assert service.approve_pairing(request.request_id, controller.fingerprint, trust) is False
    assert trust.state == TrustState.UNPAIRED
