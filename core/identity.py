from dataclasses import dataclass
from pathlib import Path
import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def b64url_encode(data: bytes) -> str:
    """
    Codifica bytes usando Base64URL sin padding.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    """
    Decodifica Base64URL sin padding.
    """
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def fingerprint_from_public_key(public_key: bytes) -> str:
    """
    Calcula el fingerprint HAEP:

    SHA-256(raw public key bytes)

    Resultado:
        64 caracteres hexadecimales en minúsculas.
    """
    return hashlib.sha256(public_key).hexdigest()


@dataclass
class Identity:
    """
    Identidad criptográfica de un participante HAEP.

    La clave privada nunca debe salir del dispositivo.
    """

    private_key: ed25519.Ed25519PrivateKey
    public_key: bytes
    fingerprint: str

    @classmethod
    def generate(cls) -> "Identity":
        """
        Genera una identidad Ed25519 completamente nueva.
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw()
        fingerprint = fingerprint_from_public_key(public_key)

        return cls(
            private_key=private_key,
            public_key=public_key,
            fingerprint=fingerprint,
        )

    @classmethod
    def load(cls, path: str | Path) -> "Identity":
        """
        Carga una identidad existente desde una clave privada PEM.
        """
        path = Path(path)
        private_key_bytes = path.read_bytes()

        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
        )

        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TypeError("La clave almacenada no es Ed25519.")

        public_key = private_key.public_key().public_bytes_raw()
        fingerprint = fingerprint_from_public_key(public_key)

        return cls(
            private_key=private_key,
            public_key=public_key,
            fingerprint=fingerprint,
        )

    def save(self, path: str | Path) -> None:
        """
        Guarda la clave privada en formato PEM.

        La clave privada no se imprime ni se incluye en el manifest.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        private_key_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        path.write_bytes(private_key_bytes)

    def public_key_base64url(self) -> str:
        """
        Devuelve la clave pública en Base64URL sin padding.
        """
        return b64url_encode(self.public_key)

    def sign(self, data: bytes) -> bytes:
        """
        Firma datos con la clave privada Ed25519.
        """
        return self.private_key.sign(data)

    def sign_base64url(self, data: bytes) -> str:
        """
        Firma datos y devuelve la firma en Base64URL.
        """
        return b64url_encode(self.sign(data))

    @staticmethod
    def verify(
        public_key: bytes,
        signature: bytes,
        data: bytes,
    ) -> bool:
        """
        Verifica una firma Ed25519.

        Devuelve:
            True  → firma válida
            False → firma inválida
        """
        try:
            public_key_object = ed25519.Ed25519PublicKey.from_public_bytes(
                public_key
            )
            public_key_object.verify(signature, data)
            return True
        except Exception:
            return False

    @staticmethod
    def verify_public_key_fingerprint(public_key: bytes) -> str:
        """
        Calcula el fingerprint a partir de una clave pública raw.
        """
        return fingerprint_from_public_key(public_key)