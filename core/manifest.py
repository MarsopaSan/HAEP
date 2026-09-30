from dataclasses import dataclass
from typing import Any

from .canonical import canonicalize
from .identity import Identity, b64url_decode


@dataclass
class Manifest:
    agent_id: str
    name: str
    domain: str
    haep_version: str
    agent_version: str
    fingerprint: str
    capabilities: list[dict[str, Any]]
    signature: str = ""

    def signing_data(self) -> bytes:
        data = {
            "agent_id": self.agent_id,
            "name": self.name,
            "domain": self.domain,
            "haep_version": self.haep_version,
            "agent_version": self.agent_version,
            "fingerprint": self.fingerprint,
            "capabilities": self.capabilities,
        }

        return canonicalize(data)

    def sign(self, identity: Identity) -> None:
        self.signature = identity.sign_base64url(
            self.signing_data()
        )

    def verify(self, public_key: bytes) -> bool:
        if not self.signature:
            return False

        signature = b64url_decode(self.signature)

        return Identity.verify(
            public_key,
            signature,
            self.signing_data(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "domain": self.domain,
            "haep_version": self.haep_version,
            "agent_version": self.agent_version,
            "fingerprint": self.fingerprint,
            "capabilities": self.capabilities,
            "signature": self.signature,
        }