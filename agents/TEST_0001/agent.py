from pathlib import Path

from core.capability import Capability, CapabilityRegistry
from core.envelope import Envelope
from core.identity import Identity, b64url_decode
from core.manifest_storage import load_manifest
from core.pairing import PairingService
from core.request_processor import RequestProcessor
from core.resource import Resource, ResourceRegistry
from core.trust import TrustManager, TrustState


AGENT_DIR = Path(__file__).resolve().parent
IDENTITY_PATH = AGENT_DIR / "identity" / "private_key.pem"
MANIFEST_PATH = AGENT_DIR / "manifest" / "manifest.json"


class HaepAgent:
    """Agente HAEP de prueba. Al arrancar queda UNPAIRED hasta un PAIRING_REQUEST."""

    def __init__(
        self,
        require_known_controller: bool = False,
        policy_authority_public_key: bytes | None = None,
        identity_path: Path = IDENTITY_PATH,
        manifest_path: Path = MANIFEST_PATH,
    ):
        self.identity = None
        self.manifest = None
        self.identity_path = identity_path
        self.manifest_path = manifest_path
        self.trust = TrustManager()
        self.pairing = PairingService(
            require_known_controller=require_known_controller,
        )
        self.capability_registry = CapabilityRegistry()
        self.resource_registry = ResourceRegistry()
        self.controller_public_key = None
        self.controller_fingerprint = None
        self.policy_authority_public_key = policy_authority_public_key
        self.processor = None

    def start(self) -> None:
        print("================================")
        print(" HAEP TEST AGENT")
        print("================================")
        print()

        print("Loading Identity...")
        if not self.identity_path.exists():
            raise FileNotFoundError(
                f"Identity no encontrada: {self.identity_path}"
            )

        self.identity = Identity.load(self.identity_path)
        print("Identity loaded.")
        print()

        print("Loading Manifest...")
        if not self.manifest_path.exists():
            raise FileNotFoundError(
                f"Manifest no encontrado: {self.manifest_path}"
            )

        self.manifest = load_manifest(self.manifest_path)
        print("Manifest loaded.")
        print()

        self.validate_manifest()

        self.capability_registry = CapabilityRegistry()
        self.resource_registry = ResourceRegistry()
        self._register_capabilities()
        self._register_resources()

        self.trust.on_startup()
        self.controller_public_key = None
        self.controller_fingerprint = None
        self.processor = None

        print()
        print("================================")
        print(" AGENT READY (waiting for PAIRING)")
        print(" Trust state:", self.trust.state.value)
        print("================================")

    def validate_manifest(self) -> None:
        print("Validating Manifest...")
        print()

        fingerprint_matches = (
            self.manifest.fingerprint == self.identity.fingerprint
        )
        print("Manifest fingerprint:")
        print(" ", self.manifest.fingerprint)
        print()
        print("Identity fingerprint:")
        print(" ", self.identity.fingerprint)
        print()
        print("Fingerprint matches:")
        print(" ", fingerprint_matches)

        if not fingerprint_matches:
            raise RuntimeError(
                "El Manifest no pertenece a la Identity del agente."
            )

        signature_valid = self.manifest.verify(self.identity.public_key)
        print()
        print("Manifest signature valid:")
        print(" ", signature_valid)

        if not signature_valid:
            raise RuntimeError("La firma del Manifest no es válida.")

    def _register_capabilities(self) -> None:
        def handle_status(parameters):
            return {
                "agent_id": self.manifest.agent_id,
                "trust_state": self.trust.state.value,
                "paired": self.trust.is_paired(),
            }

        def handle_read(parameters):
            return {
                "message": "TEST READ OK",
                "parameters": parameters,
            }

        def handle_echo(parameters):
            return {"echo": parameters}

        def handle_deny_me(parameters):
            return {
                "message": "This capability exists but policy may deny it",
            }

        handlers = {
            "test.status": handle_status,
            "test.read": handle_read,
            "test.echo": handle_echo,
            "test.deny_me": handle_deny_me,
        }

        for cap in self.manifest.capabilities:
            name = cap["name"]
            handler = handlers.get(name)
            if handler is None:
                continue
            self.capability_registry.register(
                Capability(
                    name=name,
                    version=str(cap.get("version", "1")),
                    access=cap.get("access", "READ"),
                    idempotency="IDEMPOTENT",
                    side_effects=(cap.get("access") == "WRITE"),
                    handler=handler,
                )
            )

        print()
        print("Capabilities registered:")
        for cap in self.capability_registry.list():
            print(f"  {cap.name} | {cap.access} | v{cap.version}")

    def _register_resources(self) -> None:
        self.resource_registry.register(
            Resource(
                resource_id="test.device",
                name="Test Device",
                description="Recurso virtual del agente de prueba",
            )
        )
        print()
        print("Resources registered:")
        for resource in self.resource_registry.list():
            print(f"  {resource.resource_id} | {resource.name}")

    def open_pairing_window(self, seconds: int = 60) -> None:
        """Habilita temporalmente nuevos pairings con aprobación OOB."""
        self.pairing.open_pairing_window(seconds)

    def approve_pairing(self, request_id: str, controller_fingerprint: str) -> bool:
        """Aprueba localmente un pairing pendiente."""
        approved = self.pairing.approve_pairing(
            request_id=request_id,
            controller_fingerprint=controller_fingerprint,
            trust_manager=self.trust,
        )
        if approved:
            self.controller_fingerprint = controller_fingerprint
            if self.controller_public_key is not None and self.policy_authority_public_key is not None:
                self.processor = RequestProcessor(
                    identity=self.identity,
                    controller_public_key=self.controller_public_key,
                    registry=self.capability_registry,
                    resource_registry=self.resource_registry,
                    policy_authority_public_key=self.policy_authority_public_key,
                    trust_manager=self.trust,
                )
        return approved

    def handle_message(self, envelope: Envelope) -> Envelope:
        if self.identity is None:
            raise RuntimeError("Agent not started. Call start() first.")

        if envelope.message_type == "PAIRING_REQUEST":
            return self._handle_pairing(envelope)

        if envelope.message_type == "REQUEST":
            return self._handle_request(envelope)

        return Envelope.create(
            identity=self.identity,
            message_type="RESPONSE",
            request_id=envelope.request_id,
            payload={
                "status": "DENIED",
                "error": "UNSUPPORTED_MESSAGE_TYPE",
            },
        )

    def _handle_pairing(self, request: Envelope) -> Envelope:
        response = self.pairing.process_pairing_request(
            request=request,
            agent_identity=self.identity,
            trust_manager=self.trust,
        )

        if response.payload.get("status") in ("PAIRED", "PAIRING_PENDING"):
            pub_b64 = request.payload.get("controller_public_key")
            self.controller_public_key = b64url_decode(pub_b64)
            self.controller_fingerprint = request.payload.get(
                "controller_fingerprint"
            )

        if response.payload.get("status") == "PAIRED":
            if self.policy_authority_public_key is None:
                self.processor = None
                return response

            self.processor = RequestProcessor(
                identity=self.identity,
                controller_public_key=self.controller_public_key,
                registry=self.capability_registry,
                resource_registry=self.resource_registry,
                policy_authority_public_key=self.policy_authority_public_key,
                trust_manager=self.trust,
            )
            print()
            print(">>> PAIRED with controller:")
            print("   ", self.controller_fingerprint)

        return response

    def _handle_request(self, request: Envelope) -> Envelope:
        if self.trust.state == TrustState.UNPAIRED:
            return Envelope.create(
                identity=self.identity,
                message_type="RESPONSE",
                request_id=request.request_id,
                payload={
                    "status": "PAIRING_REQUIRED",
                    "error": "AGENT_NOT_PAIRED",
                },
            )

        if self.trust.state == TrustState.REVOKED:
            return Envelope.create(
                identity=self.identity,
                message_type="RESPONSE",
                request_id=request.request_id,
                payload={
                    "status": "REVOKED",
                    "error": "AGENT_TRUST_REVOKED",
                },
            )

        if self.processor is None or self.controller_public_key is None:
            return Envelope.create(
                identity=self.identity,
                message_type="RESPONSE",
                request_id=request.request_id,
                payload={
                    "status": "PAIRING_REQUIRED",
                    "error": "POLICY_AUTHORITY_NOT_CONFIGURED",
                },
            )

        return self.processor.process(request)

    def show_info(self) -> None:
        print()
        print("Agent information:")
        print("------------------")
        print("Agent ID:")
        print(" ", self.manifest.agent_id)
        print()
        print("Name:")
        print(" ", self.manifest.name)
        print()
        print("Domain:")
        print(" ", self.manifest.domain)
        print()
        print("HAEP version:")
        print(" ", self.manifest.haep_version)
        print()
        print("Agent version:")
        print(" ", self.manifest.agent_version)
        print()
        print("Trust state:")
        print(" ", self.trust.state.value)
        print()
        print("Capabilities:")
        for capability in self.manifest.capabilities:
            print(
                " ",
                capability["name"],
                "|",
                capability["access"],
                "| v" + str(capability["version"]),
            )


if __name__ == "__main__":
    agent = HaepAgent()
    agent.start()
    agent.show_info()