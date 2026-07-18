"""Management CLI — operational commands for the fabric control plane.

Runs in-process against the same database the web service uses, so it needs no
API token. Intended to be run on the management host, e.g. via the `fabric`
wrapper installed in PATH, or directly:

    python3 -m app.cli update-nodes           # update every node, show results
    python3 -m app.cli update-nodes --online  # only nodes currently online
    python3 -m app.cli update-nodes --wait 180

`update-nodes` flags each node to self-update on its next heartbeat, then polls
for the outcome the agents report back after restarting.
"""
from __future__ import annotations

import argparse
import time

from sqlalchemy import select

from .database import SessionLocal
from .models import Node
from .models.enums import NodeStatus
from .util import utcnow, audit


def _row(name: str, status: str, state: str, version: str, message: str = "") -> str:
    return f"{name[:24]:24} {status[:10]:10} {state[:10]:10} {(version or '')[:12]:12} {message}"


def cmd_update_nodes(args) -> int:
    db = SessionLocal()
    try:
        q = select(Node)
        if args.online:
            q = q.where(Node.status == NodeStatus.online.value)
        nodes = list(db.scalars(q.order_by(Node.name)))
        if not nodes:
            print("no matching nodes")
            return 0

        now = int(utcnow().timestamp())
        for node in nodes:
            upd = dict((node.meta or {}).get("update") or {})
            upd.update({"state": "requested", "requested_at": now, "from_version": node.version})
            node.meta = {**(node.meta or {}), "update_requested": True, "update": upd}
        audit(db, actor="cli", actor_type="system", action="node.update_all",
              target="*", detail={"count": len(nodes), "online_only": args.online})
        db.commit()

        ids = [n.id for n in nodes]
        print(f"requested update on {len(ids)} node(s); waiting up to {args.wait}s for results...\n")
        print(_row("NODE", "STATUS", "STATE", "VERSION", "MESSAGE"))

        deadline = time.time() + args.wait
        done: set[str] = set()
        while time.time() < deadline and len(done) < len(ids):
            time.sleep(3)
            db.expire_all()
            for node in db.scalars(select(Node).where(Node.id.in_(ids))):
                upd = (node.meta or {}).get("update") or {}
                state = upd.get("state") or "pending"
                if state in ("completed", "failed") and node.id not in done:
                    done.add(node.id)
                    print(_row(node.name, node.status, state,
                               upd.get("to_version") or node.version,
                               upd.get("message", "")))

        # Report any nodes that never came back with a result.
        db.expire_all()
        for node in db.scalars(select(Node).where(Node.id.in_(ids)).order_by(Node.name)):
            if node.id not in done:
                upd = (node.meta or {}).get("update") or {}
                print(_row(node.name, node.status, upd.get("state") or "pending",
                           node.version, "(no result yet)"))

        ok = 0
        for node in db.scalars(select(Node).where(Node.id.in_(ids))):
            if ((node.meta or {}).get("update") or {}).get("ok"):
                ok += 1
        print(f"\n{ok}/{len(ids)} node(s) reported a successful update.")
        return 0 if ok == len(ids) else 1
    finally:
        db.close()


def main(argv=None) -> int:
    p = argparse.ArgumentParser("fabric", description="Fabric management CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    up = sub.add_parser("update-nodes", help="trigger all nodes to self-update and show results")
    up.add_argument("--online", action="store_true", help="only nodes currently online")
    up.add_argument("--wait", type=int, default=120, help="seconds to wait for results (default 120)")
    up.set_defaults(func=cmd_update_nodes)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
