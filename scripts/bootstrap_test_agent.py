from pathlib import Path
import json

from core.identity import Identity
from core.manifest import Manifest

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agents" / "TEST_0001"
identity_path = AGENT / "identity" / "private_key.pem"
manifest_path = AGENT / "manifest" / "manifest.json"

identity = Identity.generate()
identity.save(identity_path)

manifest = Manifest(
    agent_id="TEST-0001",
    name="HAEP Test Agent",
    domain="test",
    haep_version="0.1",
    agent_version="0.1.0",
    fingerprint=identity.fingerprint,
    capabilities=[
        {"name": "test.status", "version": "1", "access": "READ"},
        {"name": "test.read", "version": "1", "access": "READ"},
        {"name": "test.echo", "version": "1", "access": "WRITE"},
        {"name": "test.deny_me", "version": "1", "access": "READ"},
    ],
)
manifest.sign(identity)
manifest_path.parent.mkdir(parents=True, exist_ok=True)
manifest_path.write_text(json.dumps(manifest.to_dict(), indent=2) + "\n")
print(f"Generated TEST_0001 identity: {identity.fingerprint}")
print(f"Private key: {identity_path}")
