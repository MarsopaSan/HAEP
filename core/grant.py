from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class Grant:
    agent_fingerprint: str
    capability: str
    resource_id: str
    allowed: bool = True
    confirmation: str = "NONE"
    expires_at: datetime | None = None

    def is_valid(self) -> bool:
        if not self.allowed:
            return False

        if self.expires_at is not None:
            now = datetime.now(timezone.utc)

            if now >= self.expires_at:
                return False

        return True


class GrantRegistry:
    def __init__(self):
        self._grants: dict[
            tuple[str, str, str],
            Grant,
        ] = {}

    def register(self, grant: Grant) -> None:
        key = (
            grant.agent_fingerprint,
            grant.capability,
            grant.resource_id,
        )

        self._grants[key] = grant

    def get(
        self,
        agent_fingerprint: str,
        capability: str,
        resource_id: str,
    ) -> Grant | None:

        key = (
            agent_fingerprint,
            capability,
            resource_id,
        )

        return self._grants.get(key)

    def is_allowed(
        self,
        agent_fingerprint: str,
        capability: str,
        resource_id: str,
    ) -> bool:

        grant = self.get(
            agent_fingerprint,
            capability,
            resource_id,
        )

        if grant is None:
            return False

        return grant.is_valid()
