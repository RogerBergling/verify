from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer") from exc


@dataclass(frozen=True)
class Config:
    auth_mode: str
    data_dir: Path
    database_path: Path
    secret_key: str
    pn_encryption_key: str | None
    cookie_secure: bool
    proxy_shared_secret: str | None
    base_url: str | None
    proxy_logout_url: str | None
    github_url: str
    allowed_origins: tuple[str, ...] = ()
    app_name: str = "Verify"
    version: str = "0.2.0"
    app_theme: str = "dark"
    host: str = "0.0.0.0"
    port: int = 8080
    verification_ttl_seconds: int = 600
    auth_session_ttl_seconds: int = 43200
    max_body_bytes: int = 65536
    rate_create_per_hour: int = 20
    rate_join_per_hour: int = 60
    rate_confirm_per_minute: int = 60
    rate_reveal_per_minute: int = 20
    cookie_name: str = "verify_sid"
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_env(cls) -> "Config":
        auth_mode = os.getenv("AUTH_MODE", "proxy").strip().lower()
        if auth_mode not in {"proxy", "dev"}:
            raise SystemExit("AUTH_MODE must be 'proxy' or 'dev'")

        data_dir = Path(os.getenv("DATA_DIR", "./data")).expanduser().resolve()
        data_dir.mkdir(parents=True, exist_ok=True)
        # Keep the legacy database filename so an existing installation keeps its data.
        database_path = Path(
            os.getenv("DATABASE_PATH", str(data_dir / "samsyn.db"))
        ).expanduser().resolve()

        warnings: list[str] = []
        secret_key = os.getenv("SECRET_KEY", "").strip()
        if not secret_key:
            if auth_mode == "dev":
                secret_key = secrets.token_urlsafe(48)
                warnings.append(
                    "SECRET_KEY was not set; generated an ephemeral development key. "
                    "Sessions and encrypted personal numbers will not survive a restart."
                )
            else:
                raise SystemExit("SECRET_KEY is required when AUTH_MODE=proxy")

        if len(secret_key) < 32:
            raise SystemExit("SECRET_KEY must be at least 32 characters")

        pn_encryption_key = os.getenv("PN_ENCRYPTION_KEY", "").strip() or None
        if pn_encryption_key and len(pn_encryption_key) < 32:
            raise SystemExit("PN_ENCRYPTION_KEY must be at least 32 characters")

        proxy_shared_secret = os.getenv("PROXY_SHARED_SECRET", "").strip() or None
        if auth_mode == "proxy" and not proxy_shared_secret:
            warnings.append(
                "PROXY_SHARED_SECRET is not set. The app will trust X-User-Id and "
                "related headers from any caller that can reach it. Network isolation "
                "and proxy header stripping are mandatory."
            )

        base_url = os.getenv("BASE_URL", "").strip().rstrip("/") or None
        allowed_origins = tuple(
            origin.strip().rstrip("/")
            for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
            if origin.strip()
        )
        if not base_url:
            raise SystemExit(
                "BASE_URL is required. It is the public address used in invitation "
                "links, for example https://verify.example.se"
            )
        if base_url:
            parsed_base = urlparse(base_url)
            if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
                raise SystemExit("BASE_URL must be an absolute http:// or https:// URL")
            if auth_mode == "proxy" and parsed_base.hostname in {
                "localhost",
                "127.0.0.1",
                "::1",
            }:
                warnings.append(
                    "BASE_URL points to localhost. Invitation links will only work on "
                    "this machine; set it to the public address in production."
                )

        app_theme = os.getenv("APP_THEME", "dark").strip().lower()
        app_theme = {"auto": "system", "white": "light"}.get(app_theme, app_theme)
        if app_theme not in {"dark", "light", "system"}:
            app_theme = "dark"

        cookie_secure = _env_bool("COOKIE_SECURE", auth_mode == "proxy")
        cookie_name = os.getenv("COOKIE_NAME", "").strip() or (
            "__Host-verify_sid" if cookie_secure else "verify_sid"
        )

        return cls(
            auth_mode=auth_mode,
            data_dir=data_dir,
            database_path=database_path,
            secret_key=secret_key,
            pn_encryption_key=pn_encryption_key,
            cookie_secure=cookie_secure,
            cookie_name=cookie_name,
            proxy_shared_secret=proxy_shared_secret,
            base_url=base_url,
            proxy_logout_url=os.getenv("PROXY_LOGOUT_URL", "").strip() or None,
            github_url=os.getenv("GITHUB_URL", "https://github.com/RogerBergling/verify").strip(),
            allowed_origins=allowed_origins,
            app_theme=app_theme,
            host=os.getenv("HOST", "0.0.0.0").strip(),
            port=_env_int("PORT", 8080),
            verification_ttl_seconds=_env_int("VERIFICATION_TTL_SECONDS", 600),
            auth_session_ttl_seconds=_env_int("AUTH_SESSION_TTL_SECONDS", 43200),
            max_body_bytes=_env_int("MAX_BODY_BYTES", 65536),
            rate_create_per_hour=_env_int("RATE_CREATE_PER_HOUR", 20),
            rate_join_per_hour=_env_int("RATE_JOIN_PER_HOUR", 60),
            rate_confirm_per_minute=_env_int("RATE_CONFIRM_PER_MINUTE", 60),
            rate_reveal_per_minute=_env_int("RATE_REVEAL_PER_MINUTE", 20),
            warnings=tuple(warnings),
        )
