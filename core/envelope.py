from dataclasses import dataclass
from typing import Any

from .canonical import canonicalize
from .identity import Identity, b64url_decode


@dataclass
class Envelope:
    """
    Mensaje base HAEP.

    La firma cubre:
        haep_version
        message_type
        request_id
        kid
        payload

    La firma NO forma parte de los datos firmados.
    """

    haep_version: str
    message_type: str
    request_id: str
    kid: str
    payload: dict[str, Any]
    signature: str

    def signing_data(self) -> bytes:
        """
        Construye exactamente los datos que deben firmarse.
        """

        data = {
            "haep_version": self.haep_version,
            "message_type": self.message_type,
            "request_id": self.request_id,
            "kid": self.kid,
            "payload": self.payload,
        }

        return canonicalize(data)

    def to_dict(self) -> dict[str, Any]:
        """
        Convierte el Envelope a un diccionario Python.
        """

        return {
            "haep_version": self.haep_version,
            "message_type": self.message_type,
            "request_id": self.request_id,
            "kid": self.kid,
            "payload": self.payload,
            "signature": self.signature,
        }

    @classmethod
    def create(
        cls,
        identity: Identity,
        message_type: str,
        request_id: str,
        payload: dict[str, Any],
    ) -> "Envelope":
        """
        Crea y firma un Envelope HAEP.
        """

        envelope = cls(
            haep_version="0.1",
            message_type=message_type,
            request_id=request_id,
            kid=identity.fingerprint,
            payload=payload,
            signature="",
        )

        signing_data = envelope.signing_data()

        envelope.signature = identity.sign_base64url(signing_data)

        return envelope

    def verify(self, public_key: bytes) -> bool:
        """
        Verifica la firma del Envelope utilizando
        la clave pública proporcionada.
        """

        signature = b64url_decode(self.signature)

        return Identity.verify(
            public_key,
            signature,
            self.signing_data(),
        )
