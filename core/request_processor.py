from datetime import datetime, timedelta, timezone

from .authorization import AuthorizationAssertion, parameters_hash
from .capability import CapabilityRegistry
from .envelope import Envelope
from .identity import Identity
from .resource import ResourceRegistry
from .time_policy import TimePolicy
from .trust import TrustManager, TrustState


class RequestProcessor:
    """Valida y ejecuta Requests previamente autorizados por la Policy Authority."""

    def __init__(
        self,
        identity: Identity,
        controller_public_key: bytes,
        registry: CapabilityRegistry,
        resource_registry: ResourceRegistry,
        policy_authority_public_key: bytes,
        time_policy: TimePolicy | None = None,
        trust_manager: TrustManager | None = None,
    ):
        self.identity = identity
        self.controller_public_key = controller_public_key
        self.policy_authority_public_key = policy_authority_public_key
        self.registry = registry
        self.resource_registry = resource_registry
        self.time_policy = time_policy or TimePolicy()
        self.trust_manager = trust_manager or TrustManager()
        self._used_request_ids: dict[str, datetime] = {}
        self._used_nonces: dict[str, datetime] = {}

    def _cleanup_expired(self) -> None:
        now = datetime.now(timezone.utc)
        self._used_request_ids = {k: v for k, v in self._used_request_ids.items() if v > now}
        self._used_nonces = {k: v for k, v in self._used_nonces.items() if v > now}

    def process(self, request: Envelope) -> Envelope:
        if request.message_type != "REQUEST":
            return self._response(request, "DENIED", {"error": "INVALID_MESSAGE_TYPE"})

        if not request.verify(self.controller_public_key):
            return self._response(request, "AUTHN_FAILED", {"error": "INVALID_SIGNATURE"})

        expected_controller_kid = Identity.verify_public_key_fingerprint(self.controller_public_key)
        if request.kid != expected_controller_kid:
            return self._response(request, "AUTHN_FAILED", {"error": "UNKNOWN_CONTROLLER"})

        if self.trust_manager.state == TrustState.UNPAIRED:
            return self._response(request, "PAIRING_REQUIRED", {"error": "AGENT_NOT_PAIRED"})
        if self.trust_manager.state == TrustState.REVOKED:
            return self._response(request, "REVOKED", {"error": "AGENT_TRUST_REVOKED"})

        payload = request.payload
        if payload.get("agent_fingerprint") != self.identity.fingerprint:
            return self._response(request, "DENIED", {"error": "WRONG_AGENT"})

        nonce = payload.get("nonce")
        if not nonce:
            return self._response(request, "DENIED", {"error": "MISSING_NONCE"})

        ttl = payload.get("ttl")
        if not isinstance(ttl, int) or isinstance(ttl, bool):
            return self._response(request, "DENIED", {"error": "INVALID_TTL"})

        issued_at = payload.get("issued_at")
        time_decision = self.time_policy.validate(issued_at=issued_at, ttl=ttl)
        if not time_decision.valid:
            return self._response(request, time_decision.reason, {"error": time_decision.reason})

        self._cleanup_expired()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl)
        if request.request_id in self._used_request_ids:
            return self._response(request, "REPLAY", {"error": "REQUEST_ID_ALREADY_USED"})
        if nonce in self._used_nonces:
            return self._response(request, "REPLAY", {"error": "NONCE_ALREADY_USED"})

        capability_name = payload.get("capability")
        capability = self.registry.get(capability_name)
        if capability is None:
            return self._response(request, "UNKNOWN_CAPABILITY", {"error": capability_name})

        resource_id = payload.get("resource_id")
        if not self.resource_registry.exists(resource_id):
            return self._response(request, "UNKNOWN_RESOURCE", {"error": resource_id})

        parameters = payload.get("parameters", {})
        try:
            assertion = AuthorizationAssertion.from_dict(payload.get("authorization", {}))
        except (TypeError, ValueError):
            return self._response(request, "AUTHZ_FAILED", {"error": "INVALID_AUTHORIZATION_ASSERTION"})

        if not assertion.verify(self.policy_authority_public_key):
            return self._response(request, "AUTHZ_FAILED", {"error": "INVALID_AUTHORIZATION_SIGNATURE"})

        expected = {
            "request_id": request.request_id,
            "controller_fingerprint": request.kid,
            "agent_fingerprint": self.identity.fingerprint,
            "capability": capability_name,
            "resource_id": resource_id,
            "nonce": nonce,
            "issued_at": issued_at,
            "ttl": ttl,
            "parameters_hash": parameters_hash(parameters),
        }
        actual = {key: getattr(assertion, key) for key in expected}
        if actual != expected:
            return self._response(request, "AUTHZ_FAILED", {"error": "AUTHORIZATION_SCOPE_MISMATCH"})

        if not assertion.allowed:
            return self._response(request, "DENIED", {"error": "POLICY_DENIED"})

        self._used_request_ids[request.request_id] = expires_at
        self._used_nonces[nonce] = expires_at

        try:
            result = capability.execute(parameters)
        except Exception as exc:
            return self._response(request, "ERROR", {"error": str(exc)})

        return self._response(request, "SUCCESS", {"data": result})

    def _response(self, request: Envelope, status: str, data: dict) -> Envelope:
        return Envelope.create(
            identity=self.identity,
            message_type="RESPONSE",
            request_id=request.request_id,
            payload={"status": status, **data},
        )
