from dataclasses import dataclass


@dataclass(frozen=True)
class Resource:
    resource_id: str
    name: str
    description: str = ""


class ResourceRegistry:
    def __init__(self):
        self._resources: dict[str, Resource] = {}

    def register(self, resource: Resource) -> None:
        if resource.resource_id in self._resources:
            raise ValueError(
                f"El recurso ya está registrado: {resource.resource_id}"
            )

        self._resources[resource.resource_id] = resource

    def get(self, resource_id: str) -> Resource | None:
        return self._resources.get(resource_id)

    def exists(self, resource_id: str) -> bool:
        return resource_id in self._resources

    def list(self) -> list[Resource]:
        return list(self._resources.values())
