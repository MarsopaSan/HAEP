from datetime import datetime, timezone
from uuid import uuid4

from .envelope import Envelope
from .identity import Identity, b64url_decode, b64url_encode
from .time_policy import TimePolicy
from .trust import TrustManager, TrustState


class PairingError(Exception):
    """Error durante el proceso de pairing."""


class PairingService:
    """
    Servicio de pairing formal HAEP 0.1.

    - Controller: construye PAIRING_REQUEST firmados.
    - Agent: procesa PAIRING_REQUEST y responde PAIRING_RESPONSE.
    """

    def __init__(
        self,
        time_policy: TimePolicy | None = None,
        require_known_controller: bool = False,
    ):
        self.time_policy = time_policy or TimePolicy(max_ttl_seconds=120)
        # Si True, solo acepta controllers ya registrados en allowlist.
        self.require_known_controller = require_known_controller

    # ------------------------------------------------------------------
    # Lado Controller (Hermes)
    # ------------------------------------------------------------------

    def build_pairing_request(
        self,
        controller_identity: Identity,
        nonce: str | None = None,
        ttl: int = 60,
        issued_at: str | None = None,
    ) -> Envelope:
        """
        Construye y firma un PAIRING_REQUEST.
        """
        if issued_at is None:
            issued_at = (
                datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )

        if nonce is None:
            nonce = str(uuid4())

        payload = {
            "nonce": nonce,
            "issued_at": issued_at,
            "ttl": ttl,
            "controller_fingerprint": controller_identity.fingerprint,
            "controller_public_key": controller_identity.public_key_base64url(),
        }

        return Envelope.create(
            identity=controller_identity,
            message_type="PAIRING_REQUEST",
            request_id=str(uuid4()),
            payload=payload,
        )

    # ------------------------------------------------------------------
    # Lado Agent
    # ------------------------------------------------------------------

    def process_pairing_request(
        self,
        request: Envelope,
        agent_identity: Identity,
        trust_manager: TrustManager,
    ) -> Envelope:
        """
        Procesa un PAIRING_REQUEST y devuelve un PAIRING_RESPONSE firmado.
        """
        if request.message_type != "PAIRING_REQUEST":
            return self._response(
                agent_identity,
                request.request_id,
                "DENIED",
                {"error": "INVALID_MESSAGE_TYPE"},
            )

        payload = request.payload
        controller_fingerprint = payload.get("controller_fingerprint")
        controller_public_key_b64 = payload.get("controller_public_key")
        nonce = payload.get("nonce")
        issued_at = payload.get("issued_at")
        ttl = payload.get("ttl")

        if not controller_fingerprint or not controller_public_key_b64:
            return self._response(
                agent_identity,
                request.request_id,
                "DENIED",
                {"error": "MISSING_CONTROLLER_IDENTITY"},
            )

        try:
            controller_public_key = b64url_decode(controller_public_key_b64)
        except Exception:
            return self._response(
                agent_identity,
                request.request_id,
                "DENIED",
                {"error": "INVALID_PUBLIC_KEY"},
            )

        # El kid del envelope debe coincidir con el fingerprint declarado
        expected_fp = Identity.verify_public_key_fingerprint(controller_public_key)
        if (
            request.kid != expected_fp
            or controller_fingerprint != expected_fp
        ):
            return self._response(
                agent_identity,
                request.request_id,
                "DENIED",
                {"error": "FINGERPRINT_MISMATCH"},
            )

        if not request.verify(controller_public_key):
            return self._response(
                agent_identity,
                request.request_id,
                "INVALID_SIGNATURE",
                {"error": "INVALID_SIGNATURE"},
            )

        if not nonce:
            return self._response(
                agent_identity,
                request.request_id,
                "DENIED",
                {"error": "MISSING_NONCE"},
            )

        time_decision = self.time_policy.validate(
            issued_at=issued_at,
            ttl=ttl if isinstance(ttl, int) else -1,
        )
        if not time_decision.valid:
            return self._response(
                agent_identity,
                request.request_id,
                time_decision.reason,
                {"error": time_decision.reason},
            )

        if trust_manager.state == TrustState.REVOKED:
            return self._response(
                agent_identity,
                request.request_id,
                "REVOKED",
                {"error": "AGENT_TRUST_REVOKED"},
            )

        if self.require_known_controller and not trust_manager.is_known(
            controller_fingerprint
        ):
            return self._response(
                agent_identity,
                request.request_id,
                "DENIED",
                {"error": "UNKNOWN_CONTROLLER"},
            )

        # Éxito: establecer sesión de confianza
        try:
            trust_manager.pair(controller_fingerprint)
        except RuntimeError as exc:
            return self._response(
                agent_identity,
                request.request_id,
                "DENIED",
                {"error": str(exc)},
            )

        return self._response(
            agent_identity,
            request.request_id,
            "PAIRED",
            {
                "agent_fingerprint": agent_identity.fingerprint,
                "controller_fingerprint": controller_fingerprint,
            },
        )

    def _response(
        self,
        agent_identity: Identity,
        request_id: str,
        status: str,
        data: dict,
    ) -> Envelope:
        payload = {
            "status": status,
            **data,
        }
        return Envelope.create(
            identity=agent_identity,
            message_type="PAIRING_RESPONSE",
            request_id=request_id,
            payload=payload,
        )
