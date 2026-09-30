import pytest

from core.trust import TrustManager, TrustState


def test_initial_state_is_unpaired():
    trust = TrustManager()

    assert trust.state == TrustState.UNPAIRED
    assert trust.is_paired() is False


def test_pair_changes_state_to_paired():
    trust = TrustManager()
    trust.pair(controller_fingerprint="abc123")

    assert trust.state == TrustState.PAIRED
    assert trust.is_paired() is True
    assert trust.is_known("abc123") is True


def test_revoke_changes_state_to_revoked():
    trust = TrustManager()
    trust.pair("abc123")
    trust.revoke()

    assert trust.state == TrustState.REVOKED
    assert trust.is_paired() is False


def test_reset_returns_to_unpaired():
    trust = TrustManager()
    trust.pair("abc123")
    trust.revoke()
    trust.reset()

    assert trust.state == TrustState.UNPAIRED
    assert trust.is_paired() is False
    # allowlist se conserva
    assert trust.is_known("abc123") is True


def test_pairing_from_revoked_requires_reset():
    trust = TrustManager()
    trust.pair("abc123")
    trust.revoke()

    with pytest.raises(RuntimeError):
        trust.pair("abc123")

    trust.reset()
    trust.pair("abc123")
    assert trust.state == TrustState.PAIRED


def test_on_startup_forces_unpaired():
    trust = TrustManager()
    trust.pair("abc123")
    trust.on_startup()

    assert trust.state == TrustState.UNPAIRED
    assert trust.is_known("abc123") is True


def test_register_known_controller_without_pairing():
    trust = TrustManager()
    trust.register_known_controller("controller-fp-001")

    assert trust.is_known("controller-fp-001") is True
    assert trust.state == TrustState.UNPAIRED