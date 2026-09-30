from dataclasses import dataclass
from typing import Any
import hashlib

from .canonical import canonicalize
from .identity import Identity, b64url_decode


def parameters_hash(parameters: dict[str, Any]) -> str:
    """SHA-256 del contenido canónico de los parámetros autorizados."""
    return hashlib.sha256(canonicalize(parameters)).hexdigest()


@dataclass(frozen=True)
class AuthorizationAssertion:
    """
    Evidencia criptográfica emitida por la Security/Policy Authority.

    La aserción liga la decisión de autorización a una solicitud concreta.
    El Agent la verifica, pero nunca consulta el GrantRegistry de Hermes.
    """

    request_id: str
    controller_fingerprint: str
    agent_fingerprint: str
    capability: str
    resource_id: str
    nonce: str
    issued_at: str
    ttl: int
    parameters_hash: str
    allowed: bool
    confirmation: str
    authority_kid: str
    signature: str

    def signing_data(self) -> bytes:
        data = {
            "haep_version": "0.1",
            "assertion_type": "AUTHORIZATION_ASSERTION",
            "request_id": self.request_id,
            "controller_fingerprint": self.controller_fingerprint,
            "agent_fingerprint": self.agent_fingerprint,
            "capability": self.capability,
            "resource_id": self.resource_id,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "ttl": self.ttl,
            "parameters_hash": self.parameters_hash,
            "allowed": self.allowed,
            "confirmation": self.confirmation,
            "authority_kid": self.authority_kid,
        }
        return canonicalize(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "controller_fingerprint": self.controller_fingerprint,
            "agent_fingerprint": self.agent_fingerprint,
            "capability": self.capability,
            "resource_id": self.resource_id,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "ttl": self.ttl,
            "parameters_hash": self.parameters_hash,
            "allowed": self.allowed,
            "confirmation": self.confirmation,
            "authority_kid": self.authority_kid,
            "signature": self.signature,
        }

    @classmethod
    def issue(
        cls,
        authority_identity: Identity,
        *,
        request_id: str,
        controller_fingerprint: str,
        agent_fingerprint: str,
        capability: str,
        resource_id: str,
        nonce: str,
        issued_at: str,
        ttl: int,
        parameters: dict[str, Any],
        allowed: bool,
        confirmation: str,
    ) -> "AuthorizationAssertion":
        assertion = cls(
            request_id=request_id,
            controller_fingerprint=controller_fingerprint,
            agent_fingerprint=agent_fingerprint,
            capability=capability,
            resource_id=resource_id,
            nonce=nonce,
            issued_at=issued_at,
            ttl=ttl,
            parameters_hash=parameters_hash(parameters),
            allowed=allowed,
            confirmation=confirmation,
            authority_kid=authority_identity.fingerprint,
            signature="",
        )
        return cls(**{**assertion.__dict__, "signature": authority_identity.sign_base64url(assertion.signing_data())})

    def verify(self, authority_public_key: bytes) -> bool:
        try:
            if Identity.verify_public_key_fingerprint(authority_public_key) != self.authority_kid:
                return False
            return Identity.verify(
                authority_public_key,
                b64url_decode(self.signature),
                self.signing_data(),
            )
        except Exception:
            return False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthorizationAssertion":
        fields = {
            "request_id", "controller_fingerprint", "agent_fingerprint",
            "capability", "resource_id", "nonce", "issued_at", "ttl",
            "parameters_hash", "allowed", "confirmation", "authority_kid",
            "signature",
        }
        missing = fields - data.keys()
        if missing:
            raise ValueError(f"Missing authorization assertion fields: {sorted(missing)}")
        return cls(**{key: data[key] for key in fields})
