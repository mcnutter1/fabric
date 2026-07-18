"""Policy CRUD and evaluation routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import Principal, require_admin
from ..database import get_db
from ..models import Policy, PolicyRule
from ..schemas import PolicyCreate, PolicyOut, PolicyEvalRequest, DecisionOut
from ..services.policy_engine import PolicyEngine, PolicyContext
from ..realtime import hub
from ..util import new_id, audit

router = APIRouter(prefix="/policies", tags=["policies"])


def _apply_rules(policy: Policy, rules_in: list) -> None:
    policy.rules.clear()
    for idx, r in enumerate(rules_in):
        policy.rules.append(PolicyRule(
            order=r.order or idx,
            name=r.name,
            enabled=r.enabled,
            match_roles=r.match_roles, match_users=r.match_users,
            match_src_cidrs=r.match_src_cidrs, match_endpoints=r.match_endpoints,
            match_node_roles=r.match_node_roles, match_dst_cidrs=r.match_dst_cidrs,
            match_domains=r.match_domains, match_categories=r.match_categories,
            match_ports=r.match_ports, match_protocols=r.match_protocols,
            match_countries=r.match_countries, match_asns=r.match_asns,
            match_time=r.match_time,
            action=r.action, action_params=r.action_params,
        ))


@router.get("", response_model=list[PolicyOut])
def list_policies(db: Session = Depends(get_db), _: Principal = Depends(require_admin)):
    return list(db.scalars(select(Policy).order_by(Policy.priority)))


@router.post("", response_model=PolicyOut, status_code=201)
async def create_policy(body: PolicyCreate, db: Session = Depends(get_db),
                        admin: Principal = Depends(require_admin)):
    if db.scalar(select(Policy).where(Policy.name == body.name)):
        raise HTTPException(409, "policy name already exists")
    policy = Policy(
        id=new_id("pol_"), name=body.name, description=body.description,
        enabled=body.enabled, priority=body.priority, default_action=body.default_action,
    )
    _apply_rules(policy, body.rules)
    db.add(policy)
    db.commit()
    db.refresh(policy)
    audit(db, actor=admin.email, actor_type="user", action="policy.create", target=policy.id)
    await hub.publish("policy.changed", {"policy_id": policy.id})
    return policy


@router.put("/{policy_id}", response_model=PolicyOut)
async def update_policy(policy_id: str, body: PolicyCreate, db: Session = Depends(get_db),
                        admin: Principal = Depends(require_admin)):
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(404, "policy not found")
    policy.name = body.name
    policy.description = body.description
    policy.enabled = body.enabled
    policy.priority = body.priority
    policy.default_action = body.default_action
    _apply_rules(policy, body.rules)
    db.commit()
    db.refresh(policy)
    audit(db, actor=admin.email, actor_type="user", action="policy.update", target=policy.id)
    await hub.publish("policy.changed", {"policy_id": policy.id})
    return policy


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(policy_id: str, db: Session = Depends(get_db), admin: Principal = Depends(require_admin)):
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(404, "policy not found")
    db.delete(policy)
    db.commit()
    audit(db, actor=admin.email, actor_type="user", action="policy.delete", target=policy_id)
    await hub.publish("policy.changed", {"policy_id": policy_id})


@router.post("/evaluate", response_model=DecisionOut)
def evaluate(body: PolicyEvalRequest, db: Session = Depends(get_db), _: Principal = Depends(require_admin)):
    ctx = PolicyContext(**body.model_dump())
    decision = PolicyEngine(db).evaluate(ctx)
    return DecisionOut(
        action=decision.action, params=decision.params, policy_id=decision.policy_id,
        rule_id=decision.rule_id, rule_name=decision.rule_name, reason=decision.reason,
        allowed=decision.allowed,
    )
