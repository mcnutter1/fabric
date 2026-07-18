"""Fabric node agent.

A *dumb* data-plane agent. All intelligence (topology, policy, PKI) lives in the
management plane; the agent simply pairs, pulls its config, programs the local
data plane (WireGuard mesh, policy routing, NAT, DNS filtering, TLS inspection)
and streams telemetry back.
"""

__version__ = "0.1.0"
