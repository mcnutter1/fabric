"""Bootstrap the database, PKI, and a starter topology + policy.

Run:  python -m app.seed
"""
from __future__ import annotations

from sqlalchemy import select

from .config import settings
from .database import SessionLocal, init_db
from .models import Node, Policy, PolicyRule
from .models.enums import NodeRole, NodeStatus, PolicyAction
from .services.pki import PKIService
from .services.fabric import FabricOrchestrator
from .services.wireguard import AddressAllocator
from .util import new_id


STARTER_NODES = [
    dict(name="aws-egress-1", roles=[NodeRole.egress.value], region="us-east-1",
         egress_ip_pool=["203.0.113.10", "203.0.113.11"]),
    dict(name="aws-ingress-1", roles=[NodeRole.ingress.value], region="us-east-1",
         endpoint_pool_cidr="100.64.0.0/16"),
    dict(name="corp-connector-a", roles=[NodeRole.private_connector.value], region="dc-a",
         private_routes=["10.10.0.0/16"]),
    dict(name="corp-connector-b", roles=[NodeRole.private_connector.value], region="dc-b",
         private_routes=["10.20.0.0/16"]),
]


def _alloc_addr(db, used: set[str]) -> str:
    addr = AddressAllocator(settings.node_cidr).allocate(used)
    used.add(addr)
    return addr


def seed() -> None:
    init_db()
    db = SessionLocal()
    try:
        print("• bootstrapping PKI ...")
        cas = PKIService(db).bootstrap()
        for name, cert in cas.items():
            print(f"    {name:9s} {cert.subject_cn} ({cert.serial})")

        used = {n.fabric_addr for n in db.scalars(select(Node)) if n.fabric_addr}
        for spec in STARTER_NODES:
            if db.scalar(select(Node).where(Node.name == spec["name"])):
                continue
            node = Node(
                id=new_id("node_"),
                status=NodeStatus.pending.value,
                fabric_addr=_alloc_addr(db, used),
                wg_listen_port=settings.wg_port,
                **spec,
            )
            db.add(node)
            print(f"• node {spec['name']:18s} {node.fabric_addr}  roles={spec['roles']}")
        db.commit()

        FabricOrchestrator(db).compute_links()

        if not db.scalar(select(Policy)):
            policy = Policy(
                id=new_id("pol_"),
                name="Default Corporate Policy",
                description="Baseline identity + device policy: inspect web, block malware/adult, "
                            "allow corp, deny anonymizers.",
                enabled=True, priority=10, default_action=PolicyAction.allow.value,
            )
            policy.rules = [
                PolicyRule(order=0, name="Block malware & phishing",
                           match_categories=["malware", "phishing", "command-and-control"],
                           action=PolicyAction.block_page.value,
                           action_params={"message": "Blocked by Fabric: security threat category."}),
                PolicyRule(order=1, name="Deny anonymizers/VPN",
                           match_categories=["anonymizer", "proxy-avoidance"],
                           action=PolicyAction.deny.value),
                PolicyRule(order=2, name="Bypass inspection for banking",
                           match_categories=["financial-services", "health"],
                           action=PolicyAction.bypass.value),
                PolicyRule(order=3, name="Steer corp traffic to connector A",
                           match_dst_cidrs=["10.10.0.0/16"],
                           action=PolicyAction.steer.value,
                           action_params={"via_role": "private_connector", "route": "10.10.0.0/16"}),
                PolicyRule(order=4, name="Inspect all web",
                           match_ports=[443, 80],
                           action=PolicyAction.inspect.value),
            ]
            db.add(policy)
            db.commit()
            print(f"• policy '{policy.name}' with {len(policy.rules)} rules")

        print("\n✓ seed complete. Start with: uvicorn app.main:app --reload --port 8080")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
