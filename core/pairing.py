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
        self._pairing_window_expires_at = None
        self._pending_requests = {}
        self._used_request_ids = set()
        self._used_nonces = set()

    def open_pairing_window(self, seconds: int = 60) -> None:
        """Abre una ventana temporal para aceptar nuevos pairings OOB."""
        if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds <= 0:
            raise ValueError("seconds debe ser un entero positivo")
        self._pairing_window_expires_at = datetime.now(timezone.utc).timestamp() + seconds

    def pairing_window_open(self) -> bool:
        """Indica si la ventana OOB de pairing está actualmente abierta."""
        if self._pairing_window_expires_at is None:
            return False
        if datetime.now(timezone.utc).timestamp() >= self._pairing_window_expires_at:
            self._pairing_window_expires_at = None
            return False
        return True

    def approve_pairing(
        self,
        request_id: str,
        controller_fingerprint: str,
        trust_manager: TrustManager,
    ) -> bool:
        """Aprueba explícitamente un pairing pendiente mediante OOB."""
        pending = self._pending_requests.get(request_id)
        if pending is None or pending["controller_fingerprint"] != controller_fingerprint:
            return False
        if not self.pairing_window_open():
            self._pending_requests.pop(request_id, None)
            return False

        time_decision = self.time_policy.validate(
            issued_at=pending["issued_at"],
            ttl=pending["ttl"],
        )
        if not time_decision.valid:
            self._pending_requests.pop(request_id, None)
            return False

        try:
            trust_manager.pair(controller_fingerprint)
        except RuntimeError:
            return False
        self._pending_requests.pop(request_id, None)
        return True

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

        if request.request_id in self._used_request_ids or nonce in self._used_nonces:
            return self._response(
                agent_identity,
                request.request_id,
                "DENIED",
                {"error": "PAIRING_REPLAY"},
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

        # Un controller ya conocido puede re-certificar la sesión sin OOB.
        if trust_manager.is_known(controller_fingerprint):
            try:
                trust_manager.pair(controller_fingerprint)
            except RuntimeError as exc:
                return self._response(
                    agent_identity,
                    request.request_id,
                    "DENIED",
                    {"error": str(exc)},
                )
            self._used_request_ids.add(request.request_id)
            self._used_nonces.add(nonce)
            return self._response(
                agent_identity,
                request.request_id,
                "PAIRED",
                {
                    "agent_fingerprint": agent_identity.fingerprint,
                    "controller_fingerprint": controller_fingerprint,
                },
            )

        if not self.pairing_window_open():
            return self._response(
                agent_identity,
                request.request_id,
                "DENIED",
                {"error": "PAIRING_WINDOW_CLOSED"},
            )

        self._pending_requests[request.request_id] = {
            "controller_fingerprint": controller_fingerprint,
            "nonce": nonce,
            "issued_at": issued_at,
            "ttl": ttl,
        }
        self._used_request_ids.add(request.request_id)
        self._used_nonces.add(nonce)

        return self._response(
            agent_identity,
            request.request_id,
            "PAIRING_PENDING",
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
