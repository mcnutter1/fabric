"""Node role modules.

Each role encapsulates the data-plane responsibilities of a node type:

  * :class:`~fabric_agent.roles.egress.EgressRole`     internet gateway + inspection
  * :class:`~fabric_agent.roles.ingress.IngressRole`   client tunnel + DNS filtering
  * :class:`~fabric_agent.roles.connector.ConnectorRole` private network inbound/outbound
  * :class:`~fabric_agent.roles.relay.RelayRole`       transit-only fabric hop

The agent builds the set of roles it was assigned and drives their
``setup``/``tick``/``teardown`` lifecycle.
"""
from __future__ import annotations

from .base import Role
from .egress import EgressRole
from .ingress import IngressRole
from .connector import ConnectorRole
from .relay import RelayRole

_REGISTRY = {
    "egress": EgressRole,
    "ingress": IngressRole,
    "private_connector": ConnectorRole,
    "relay": RelayRole,
}


def build_roles(agent, role_names) -> list:
    roles = []
    for name in role_names or []:
        cls = _REGISTRY.get(name)
        if cls:
            roles.append(cls(agent))
    return roles


__all__ = ["Role", "EgressRole", "IngressRole", "ConnectorRole", "RelayRole", "build_roles"]
