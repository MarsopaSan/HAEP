from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


MAX_TTL_SECONDS = 300


@dataclass(frozen=True)
class TimeDecision:
    valid: bool
    reason: str


class TimePolicy:
    """
    Valida las reglas temporales de una solicitud HAEP.

    No ejecuta acciones.
    No valida firmas.
    No controla permisos.
    Solamente determina si la ventana temporal de una
    solicitud es válida.
    """

    def __init__(self, max_ttl_seconds: int = MAX_TTL_SECONDS):
        if max_ttl_seconds <= 0:
            raise ValueError("max_ttl_seconds debe ser mayor que cero.")

        self.max_ttl_seconds = max_ttl_seconds

    def validate(
        self,
        issued_at: str,
        ttl: int,
        now: datetime | None = None,
    ) -> TimeDecision:

        if not isinstance(issued_at, str):
            return TimeDecision(
                valid=False,
                reason="INVALID_ISSUED_AT",
            )

        try:
            issued_time = datetime.fromisoformat(
                issued_at.replace("Z", "+00:00")
            )
        except ValueError:
            return TimeDecision(
                valid=False,
                reason="INVALID_ISSUED_AT",
            )

        if issued_time.tzinfo is None:
            return TimeDecision(
                valid=False,
                reason="INVALID_ISSUED_AT",
            )

        if not isinstance(ttl, int) or isinstance(ttl, bool):
            return TimeDecision(
                valid=False,
                reason="INVALID_TTL",
            )

        if ttl <= 0:
            return TimeDecision(
                valid=False,
                reason="INVALID_TTL",
            )

        if ttl > self.max_ttl_seconds:
            return TimeDecision(
                valid=False,
                reason="INVALID_TTL",
            )

        if now is None:
            now = datetime.now(timezone.utc)

        expires_at = issued_time + timedelta(seconds=ttl)

        if now >= expires_at:
            return TimeDecision(
                valid=False,
                reason="EXPIRED",
            )

        return TimeDecision(
            valid=True,
            reason="VALID",
        )
