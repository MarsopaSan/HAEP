from dataclasses import dataclass

from .authorization import AuthorizationAssertion
from .grant import GrantRegistry
from .identity import Identity


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    confirmation: str = "NONE"


class PolicyEngine:
    """
    Autoridad determinista de autorización de HAEP.

    Hermes puede interpretar una intención, pero esta autoridad es la que
    decide si una operación concreta está permitida. El resultado se
    convierte en una AuthorizationAssertion firmada para que el Agent pueda
    verificar la decisión sin acceder al GrantRegistry.
    """

    def __init__(self, grant_registry: GrantRegistry, authority_identity: Identity):
        self.grant_registry = grant_registry
        self.authority_identity = authority_identity

    @property
    def authority_fingerprint(self) -> str:
        return self.authority_identity.fingerprint

    def evaluate(
        self,
        agent_fingerprint: str,
        capability: str,
        resource_id: str,
    ) -> PolicyDecision:
        grant = self.grant_registry.get(
            agent_fingerprint=agent_fingerprint,
            capability=capability,
            resource_id=resource_id,
        )

        if grant is None:
            return PolicyDecision(False, "NO_GRANT")
        if not grant.allowed:
            return PolicyDecision(False, "GRANT_DENIED", grant.confirmation)
        if not grant.is_valid():
            return PolicyDecision(False, "GRANT_EXPIRED", grant.confirmation)

        return PolicyDecision(True, "AUTHORIZED", grant.confirmation)

    def authorize(
        self,
        *,
        request_id: str,
        controller_fingerprint: str,
        agent_fingerprint: str,
        capability: str,
        resource_id: str,
        parameters: dict,
        nonce: str,
        issued_at: str,
        ttl: int,
    ) -> AuthorizationAssertion:
        decision = self.evaluate(agent_fingerprint, capability, resource_id)
        if not decision.allowed:
            raise PermissionError(
                f"REQUEST rechazado por Policy Engine: {decision.reason}"
            )

        return AuthorizationAssertion.issue(
            authority_identity=self.authority_identity,
            request_id=request_id,
            controller_fingerprint=controller_fingerprint,
            agent_fingerprint=agent_fingerprint,
            capability=capability,
            resource_id=resource_id,
            nonce=nonce,
            issued_at=issued_at,
            ttl=ttl,
            parameters=parameters,
            allowed=True,
            confirmation=decision.confirmation,
        )
