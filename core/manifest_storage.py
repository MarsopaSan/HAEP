import json
from pathlib import Path

from .manifest import Manifest


def save_manifest(manifest: Manifest, path: str | Path) -> None:
    path = Path(path)

    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(
            manifest.to_dict(),
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def load_manifest(path: str | Path) -> Manifest:
    path = Path(path)

    data = json.loads(
        path.read_text(encoding="utf-8")
    )

    return Manifest(
        agent_id=data["agent_id"],
        name=data["name"],
        domain=data["domain"],
        haep_version=data["haep_version"],
        agent_version=data["agent_version"],
        fingerprint=data["fingerprint"],
        capabilities=data["capabilities"],
        signature=data["signature"],
    )
