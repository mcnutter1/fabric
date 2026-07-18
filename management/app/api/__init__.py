"""API router registry."""
from fastapi import APIRouter

from . import auth as auth_routes
from . import nodes, enroll, endpoints, policy, pki, fabric, telemetry, ws

api_router = APIRouter()
api_router.include_router(auth_routes.router)
api_router.include_router(nodes.router)
api_router.include_router(enroll.router)
api_router.include_router(endpoints.router)
api_router.include_router(policy.router)
api_router.include_router(pki.router)
api_router.include_router(fabric.router)
api_router.include_router(telemetry.router)

__all__ = ["api_router", "ws"]
