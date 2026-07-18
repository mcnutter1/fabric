"""Application configuration, loaded from environment / .env."""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FABRIC_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core
    env: str = "dev"
    secret_key: str = "change-me-in-production-please-32bytes-min"
    public_url: str = "http://localhost:8080"
    domain: str = "fabric.mcnutt.cloud"

    # Database
    database_url: str = "sqlite:///./fabric.db"

    # Realtime
    eventbus_url: str = "inproc"

    # Auth (McNutt Cloud)
    auth_login_base: str = "https://login.mcnutt.cloud"
    auth_app_id: str = "fabric-console"
    auth_app_secret: str = "replace_with_strong_shared_secret"
    auth_cookie_name: str = "fabric_auth"
    auth_cookie_domain: str = ".mcnutt.cloud"
    auth_ttl_sec: int = 7200
    auth_refresh_sec: int = 1200
    auth_admin_roles: str = "admin,fabric_admin"

    # PKI
    pki_passphrase: str = "change-me-pki-passphrase"
    pki_dir: str = "./pki_store"

    # Fabric addressing
    node_cidr: str = "100.96.0.0/12"
    endpoint_cidr: str = "100.64.0.0/12"
    wg_port: int = 51820

    # AWS Route53
    route53_zone_id: str = ""

    @property
    def admin_roles(self) -> List[str]:
        return [r.strip() for r in self.auth_admin_roles.split(",") if r.strip()]

    @property
    def is_dev(self) -> bool:
        return self.env.lower() in ("dev", "development", "local")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
