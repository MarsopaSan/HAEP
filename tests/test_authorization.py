from core.authorization import AuthorizationAssertion, parameters_hash
from core.identity import Identity


def test_assertion_signature_and_scope():
    authority = Identity.generate()
    assertion = AuthorizationAssertion.issue(
        authority, request_id="r1", controller_fingerprint="c1",
        agent_fingerprint="a1", capability="test.read",
        resource_id="test.device", nonce="n1",
        issued_at="2026-09-28T10:00:00Z", ttl=30,
        parameters={"x": 1}, allowed=True, confirmation="NONE",
    )
    assert assertion.verify(authority.public_key)
    assert assertion.parameters_hash == parameters_hash({"x": 1})


def test_assertion_fails_with_wrong_authority():
    authority = Identity.generate()
    other = Identity.generate()
    assertion = AuthorizationAssertion.issue(
        authority, request_id="r1", controller_fingerprint="c1",
        agent_fingerprint="a1", capability="test.read",
        resource_id="test.device", nonce="n1",
        issued_at="2026-09-28T10:00:00Z", ttl=30,
        parameters={}, allowed=True, confirmation="NONE",
    )
    assert not assertion.verify(other.public_key)
