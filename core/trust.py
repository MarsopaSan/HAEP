from enum import Enum


class TrustState(str, Enum):
    UNPAIRED = "UNPAIRED"
    PAIRED = "PAIRED"
    REVOKED = "REVOKED"


class TrustManager:
    """
    Gestiona el estado de confianza de sesión del Agent.

    Diseño:
    - Al arrancar el proceso el estado siempre es UNPAIRED.
    - Los fingerprints conocidos (allowlist) pueden persistirse
      fuera de este objeto (archivo, DB, etc.).
    - Cada vez que el dispositivo se apaga y vuelve a encender
      debe re-certificar (pair) antes de aceptar REQUESTs.
    - REVOKED bloquea hasta un reset explícito.
    """

    def __init__(self) -> None:
        self._state = TrustState.UNPAIRED
        # Fingerprints de controllers que ya fueron pairados alguna vez.
        # En producción se puede cargar desde disco al iniciar.
        self._known_controllers: set[str] = set()

    @property
    def state(self) -> TrustState:
        return self._state

    def is_paired(self) -> bool:
        return self._state == TrustState.PAIRED

    def is_known(self, controller_fingerprint: str) -> bool:
        return controller_fingerprint in self._known_controllers

    def register_known_controller(self, controller_fingerprint: str) -> None:
        """
        Marca un controller como conocido (allowlist).
        No cambia el estado de sesión; solo habilita re-pairing rápido.
        """
        self._known_controllers.add(controller_fingerprint)

    def pair(self, controller_fingerprint: str | None = None) -> None:
        """
        Establece sesión de confianza activa.

        Si se pasa controller_fingerprint, también se registra
        en la allowlist de controllers conocidos.
        """
        if self._state == TrustState.REVOKED:
            raise RuntimeError(
                "No se puede pairar: trust está REVOKED. "
                "Usá reset() antes de volver a pairar."
            )

        if controller_fingerprint is not None:
            self._known_controllers.add(controller_fingerprint)

        self._state = TrustState.PAIRED

    def revoke(self) -> None:
        """Revoca la confianza de sesión (y bloquea hasta reset)."""
        self._state = TrustState.REVOKED

    def reset(self) -> None:
        """
        Vuelve a UNPAIRED.

        Útil tras un revoke o al reiniciar el dispositivo.
        No borra la allowlist de controllers conocidos.
        """
        self._state = TrustState.UNPAIRED

    def on_startup(self) -> None:
        """
        Llamar al arrancar el Agent.

        Fuerza re-certificación de sesión aunque el controller
        ya sea conocido.
        """
        if self._state != TrustState.REVOKED:
            self._state = TrustState.UNPAIRED