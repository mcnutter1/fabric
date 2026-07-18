"""Base class for node roles."""
from __future__ import annotations

import logging


class Role:
    name: str = "role"

    def __init__(self, agent):
        self.agent = agent
        self.log = logging.getLogger(f"fabric.agent.role.{self.name}")

    # Convenience accessors onto the owning agent.
    @property
    def dp(self):
        return self.agent.dp

    @property
    def manager(self):
        return self.agent.manager

    @property
    def state(self):
        return self.agent.state

    @property
    def telemetry(self):
        return self.agent.telemetry

    @property
    def policy(self):
        return self.agent.policy

    @property
    def classifier(self):
        return self.agent.classifier

    # Lifecycle -------------------------------------------------------
    def setup(self, config: dict) -> None:
        """Program the data plane for this role. Called on every config apply."""

    def tick(self) -> None:
        """Periodic work (flow observation, egress rotation, health checks)."""

    def teardown(self) -> None:
        """Clean up data-plane state on shutdown."""
