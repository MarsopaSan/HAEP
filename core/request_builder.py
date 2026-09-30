from datetime import datetime, timezone
from uuid import uuid4

from .envelope import Envelope
from .identity import Identity
from .policy import PolicyEngine


class RequestBuilder:
    """Construye Requests autorizados por la Security/Policy Authority."""

    def __init__(self, controller_identity: Identity, policy_engine: PolicyEngine):
        self.controller_identity = controller_identity
        self.policy_engine = policy_engine

    def build_request(
        self,
        agent_fingerprint: str,
        capability: str,
        resource_id: str,
        parameters: dict,
        nonce: str,
        ttl: int = 30,
        issued_at: str | None = None,
    ) -> Envelope:
        if issued_at is None:
            issued_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        request_id = str(uuid4())
        assertion = self.policy_engine.authorize(
            request_id=request_id,
            controller_fingerprint=self.controller_identity.fingerprint,
            agent_fingerprint=agent_fingerprint,
            capability=capability,
            resource_id=resource_id,
            parameters=parameters,
            nonce=nonce,
            issued_at=issued_at,
            ttl=ttl,
        )

        payload = {
            "nonce": nonce,
            "issued_at": issued_at,
            "ttl": ttl,
            "agent_fingerprint": agent_fingerprint,
            "capability": capability,
            "resource_id": resource_id,
            "parameters": parameters,
            "authorization": assertion.to_dict(),
        }

        return Envelope.create(
            identity=self.controller_identity,
            message_type="REQUEST",
            request_id=request_id,
            payload=payload,
        )
