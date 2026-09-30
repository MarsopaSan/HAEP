from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class Capability:
    name: str
    version: str
    access: str
    idempotency: str
    side_effects: bool
    handler: Callable[..., Any] | None = None

    def execute(self, parameters: dict[str, Any]) -> Any:
        if self.handler is None:
            raise RuntimeError(
                f"La capability '{self.name}' no tiene handler."
            )

        return self.handler(parameters)


class CapabilityRegistry:
    def __init__(self):
        self._capabilities: dict[str, Capability] = {}

    def register(self, capability: Capability) -> None:
        if capability.name in self._capabilities:
            raise ValueError(
                f"La capability '{capability.name}' ya está registrada."
            )

        self._capabilities[capability.name] = capability

    def get(self, name: str) -> Capability | None:
        return self._capabilities.get(name)

    def exists(self, name: str) -> bool:
        return name in self._capabilities

    def list(self) -> list[Capability]:
        return list(self._capabilities.values())
