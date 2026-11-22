from __future__ import annotations

import json
import mimetypes
import re
import sys
import threading
import time
from collections import defaultdict, deque
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import auth, db, i18n, security, verification
from .config import Config
from .verification import VerificationError

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_ENV = Environment(
    loader=FileSystemLoader(BASE_DIR / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
MONTHS = {
    "en": ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
    "sv": ("jan", "feb", "mar", "apr", "maj", "jun", "jul", "aug", "sep", "okt", "nov", "dec"),
}


def _format_datetime(value: Any, lang: str = "en") -> str:
    try:
        dt = security.parse_iso(str(value))
        month = MONTHS.get(lang, MONTHS["en"])[dt.month - 1]
        return f"{dt.day:02d} {month} {dt.year}, {dt:%H:%M} UTC"
    except Exception:
        return str(value)


TEMPLATE_ENV.globals.update(
    initials=security.initials,
    kind_label=security.kind_label,
    state_label=security.state_label,
    assurance_label=security.assurance_label,
    role_label=security.role_label,
)
TEMPLATE_ENV.filters["format_dt"] = _format_datetime


def _normalize_origin(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urlparse(value.strip())
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    return f"{scheme}://{netloc}"


class AppError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class RateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._events[key]
            cutoff = now - window_seconds
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True


RATE_LIMITER = RateLimiter()


def create_server(
    config: Config, *, host: str | None = None, port: int | None = None
) -> ThreadingHTTPServer:
    db.init_db(config)
    handler = make_handler(config)
    server = ThreadingHTTPServer(
        (host if host is not None else config.host, port if port is not None else config.port),
        handler,
    )
    server.daemon_threads = True
    return server


def make_handler(config: Config) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "Verify"
        sys_version = ""
        timeout = 30  # slow-client guard

        def handle_one_request(self) -> None:
            # Browsers, mobile clients, and health probes routinely close a
            # connection before sending a full request line/body. That is not
            # an application error; suppress the default socketserver traceback.
            try:
                super().handle_one_request()
            except (ConnectionError, TimeoutError):
                self.close_connection = True

        def handle(self) -> None:
            try:
                super().handle()
            except (ConnectionError, TimeoutError):
                pass

        def finish(self) -> None:
            try:
                super().finish()
            except (ConnectionError, TimeoutError):
                pass

        def do_GET(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

        def do_HEAD(self) -> None:  # noqa: N802
            self._handle("HEAD")

        def log_request(self, code: Any = "-", size: Any = "-") -> None:
            path = re.sub(r"/join/[^/]+", "/join/[redacted]", self.path.split("?", 1)[0])
            sys.stderr.write(f"{self.command} {path} {code}\n")

        def log_message(self, format: str, *args: Any) -> None:
            # Deliberately silent: default logging can include paths and user agents.
            return

        # ------------------------------------------------------------------
        # Request pipeline
        # ------------------------------------------------------------------

        def _handle(self, method: str) -> None:
            self._pending_cookies: list[str] = []
            parsed = urlparse(self.path)
            path = parsed.path
            self._query = parse_qs(parsed.query)
            self._method = method
            try:
                if path == "/healthz" or path == "/readyz":
                    return self._send_json(
                        200,
                        {
                            "ok": True,
                            "service": config.app_name,
                            "version": config.version,
                            "auth_mode": config.auth_mode,
                        },
                    )
                if path == "/robots.txt":
                    return self._send(
                        200,
                        b"User-agent: *\nDisallow: /\n",
                        "text/plain; charset=utf-8",
                        cache="no-store",
                    )
                if path == "/favicon.ico":
                    return self._static("favicon.svg")
                if path.startswith("/static/"):
                    return self._static(path[len("/static/") :])
                if path == "/login":
                    return self._login_page()
                if path.startswith("/dev/"):
                    return self._dev_route(method, path)
                if path.startswith("/lang/"):
                    return self._set_language(path.rsplit("/", 1)[-1])

                conn = db.connect(config)
                try:
                    auth_ctx = auth.resolve_identity(self, config, conn)
                    if auth_ctx is None:
                        if config.auth_mode == "dev":
                            if path == "/":
                                return self._login_page()
                            return self._redirect(f"/login?next={quote(path)}")
                        return self._unauthorized()

                    if auth_ctx.set_cookie_sid:
                        self._pending_cookies.append(
                            auth.cookie_header(config, auth_ctx.set_cookie_sid)
                        )

                    if method == "GET":
                        return self._get_route(path, auth_ctx, conn)
                    if method == "POST":
                        return self._post_route(path, auth_ctx, conn)
                    return self._send_error_page(405, "Method not allowed")
                finally:
                    conn.close()
            except VerificationError as exc:
                self._handle_error(exc.status, exc.code, exc.message, path)
            except AppError as exc:
                self._handle_error(exc.status, exc.code, exc.message, path)
            except ValueError as exc:
                self._handle_error(400, "invalid_input", str(exc), path)
            except Exception:
                sys.stderr.write("unhandled error while processing request\n")
                self._handle_error(500, "internal_error", "Something went wrong.", path)

        def _get_route(self, path: str, auth_ctx: auth.AuthContext, conn: Any) -> None:
            if path == "/":
                return self._home(auth_ctx)
            if path == "/security":
                return self._security(auth_ctx)
            if path == "/how-it-works":
                return self._how_it_works(auth_ctx)
            if path == "/logout":
                return self._logout(auth_ctx)
            if path.startswith("/join/"):
                return self._join(auth_ctx, path[len("/join/") :])
            if path.startswith("/session/"):
                return self._session(auth_ctx, path[len("/session/") :])
            if path.startswith("/receipts/"):
                return self._receipt(auth_ctx, path[len("/receipts/") :])
            if path == "/api/me":
                return self._api_me(auth_ctx)
            if path == "/api/sessions":
                return self._api_recent(auth_ctx)
            if path == "/api/security-check":
                return self._api_security_check(auth_ctx)
            if path.startswith("/api/sessions/"):
                return self._api_session_get(auth_ctx, path[len("/api/sessions/") :])
            if path.startswith("/api/receipts/"):
                return self._api_receipt(auth_ctx, path[len("/api/receipts/") :])
            return self._send_error_page(404, "Not found")

        def _post_route(self, path: str, auth_ctx: auth.AuthContext, conn: Any) -> None:
            self._require_csrf(auth_ctx)
            if path == "/api/sessions":
                return self._api_create(auth_ctx)
            if path.startswith("/api/sessions/"):
                parts = path[len("/api/sessions/") :].split("/")
                if len(parts) == 2 and parts[1] in {"join", "confirm", "cancel", "reveal"}:
                    return self._api_session_action(auth_ctx, parts[0], parts[1])
            return self._send_error_page(404, "Not found")

        # ------------------------------------------------------------------
        # Pages
        # ------------------------------------------------------------------

        def _login_page(self) -> None:
            if config.auth_mode != "dev":
                return self._unauthorized()
            next_url = security.safe_next(self._query.get("next", ["/"])[0])
            return self._render(
                "login.html",
                200,
                user=None,
                csrf_token="",
                auth_ctx=None,
                next_url=next_url,
                dev_users=auth.DEV_USERS,
                error=None,
            )

        def _unauthorized(self) -> None:
            return self._render("unauthorized.html", 401, user=None, csrf_token="", auth_ctx=None)

        def _home(self, auth_ctx: auth.AuthContext) -> None:
            recent = verification.recent(config, auth_ctx.user["id"])
            return self._render(
                "home.html",
                200,
                user=auth_ctx.user,
                csrf_token=auth_ctx.csrf_token,
                auth_ctx=auth_ctx,
                recent=recent,
            )

        def _security(self, auth_ctx: auth.AuthContext) -> None:
            return self._render(
                "security.html",
                200,
                user=auth_ctx.user,
                csrf_token=auth_ctx.csrf_token,
                auth_ctx=auth_ctx,
            )

        def _how_it_works(self, auth_ctx: auth.AuthContext) -> None:
            return self._render(
                "how_it_works.html",
                200,
                user=auth_ctx.user,
                csrf_token=auth_ctx.csrf_token,
                auth_ctx=auth_ctx,
            )

        def _join(self, auth_ctx: auth.AuthContext, token: str) -> None:
            invite = verification.get_invite(config, token, auth_ctx.user["id"])
            if invite.get("already_joined"):
                return self._redirect(f"/session/{invite['verification_id']}")
            return self._render(
                "join.html",
                200,
                user=auth_ctx.user,
                csrf_token=auth_ctx.csrf_token,
                auth_ctx=auth_ctx,
                invite=invite,
                token=token,
            )

        def _session(self, auth_ctx: auth.AuthContext, session_id: str) -> None:
            view = verification.get_view(
                config, session_id, auth_ctx.user["id"], base_url=self._base_url()
            )
            return self._render(
                "session.html",
                200,
                user=auth_ctx.user,
                csrf_token=auth_ctx.csrf_token,
                auth_ctx=auth_ctx,
                view=view,
                session_id=session_id,
            )

        def _receipt(self, auth_ctx: auth.AuthContext, receipt_id: str) -> None:
            receipt = verification.receipt_view(config, receipt_id, auth_ctx.user["id"])
            return self._render(
                "receipt.html",
                200,
                user=auth_ctx.user,
                csrf_token=auth_ctx.csrf_token,
                auth_ctx=auth_ctx,
                receipt=receipt,
            )

        def _set_language(self, value: str) -> None:
            code = i18n.normalize_language(value)
            if code:
                self._pending_cookies.append(i18n.cookie_header(config, code))
            next_url = security.safe_next(self._query.get("next", ["/"])[0])
            return self._redirect(next_url)

        def _logout(self, auth_ctx: auth.AuthContext) -> None:
            sid = auth._cookie_sid(self, config)
            if sid:
                conn = db.connect(config)
                try:
                    auth.logout(conn, config, sid)
                finally:
                    conn.close()
            self._pending_cookies.append(auth.clear_cookie_header(config))
            if config.auth_mode == "dev":
                return self._redirect("/login")
            if config.proxy_logout_url:
                return self._redirect(config.proxy_logout_url)
            return self._redirect("/")

        # ------------------------------------------------------------------
        # API
        # ------------------------------------------------------------------

        def _api_me(self, auth_ctx: auth.AuthContext) -> None:
            self._send_json(
                200,
                {
                    "id": auth_ctx.user["id"],
                    "subject": auth_ctx.user["subject"],
                    "name": auth_ctx.user["display_name"],
                    "first_name": auth_ctx.user["first_name"],
                    "last_name": auth_ctx.user["last_name"],
                    "assurance": auth_ctx.user["assurance"],
                    "assurance_label": security.assurance_label(
                        auth_ctx.user["assurance"], mock=config.auth_mode == "dev"
                    ),
                    "org": auth_ctx.user.get("org"),
                    "pn_masked": auth_ctx.user.get("pn_masked") or "—",
                    "auth_mode": config.auth_mode,
                    "source": auth_ctx.source,
                    "is_dev": config.auth_mode == "dev",
                },
            )

        def _api_recent(self, auth_ctx: auth.AuthContext) -> None:
            self._send_json(200, {"sessions": verification.recent(config, auth_ctx.user["id"])})

        def _api_create(self, auth_ctx: auth.AuthContext) -> None:
            key = f"create:{auth_ctx.user['subject']}"
            if not RATE_LIMITER.allow(key, config.rate_create_per_hour, 3600):
                raise AppError(429, "rate_limited", "Too many verification sessions; try again later")
            body = self._read_json()
            verification_id, token = verification.create_verification(
                config,
                auth_ctx,
                kind=str(body.get("kind", "one_to_one")),
                context=str(body.get("context", "")),
                pn_mode=str(body.get("pn_mode", "full")),
                duration_minutes=int(body.get("duration_minutes", 10) or 10),
                ip_hash=security.hash_ip(config.secret_key, self.client_address[0]),
                ua_hash=security.hash_ua(config.secret_key, self.headers.get("User-Agent")),
            )
            view = verification.get_view(
                config, verification_id, auth_ctx.user["id"], base_url=self._base_url()
            )
            self._send_json(
                201,
                {
                    "id": verification_id,
                    "join_url": security.join_url(self._base_url(), token),
                    "view": view,
                },
            )

        def _api_session_get(self, auth_ctx: auth.AuthContext, session_id: str) -> None:
            view = verification.get_view(
                config, session_id, auth_ctx.user["id"], base_url=self._base_url()
            )
            self._send_json(200, {"session": view})

        def _api_session_action(
            self, auth_ctx: auth.AuthContext, session_id: str, action: str
        ) -> None:
            body = self._read_json()
            if action == "join":
                if not RATE_LIMITER.allow(
                    f"join:{auth_ctx.user['subject']}", config.rate_join_per_hour, 3600
                ):
                    raise AppError(429, "rate_limited", "Too many join attempts")
                token = security.extract_join_token(str(body.get("token", "")))
                if not token:
                    raise AppError(400, "invalid_token", "A join token is required")
                view = verification.join_verification(
                    config,
                    auth_ctx,
                    session_id,
                    token,
                    base_url=self._base_url(),
                    ip_hash=security.hash_ip(config.secret_key, self.client_address[0]),
                    ua_hash=security.hash_ua(config.secret_key, self.headers.get("User-Agent")),
                )
                return self._send_json(200, {"session": view})
            if action == "confirm":
                if not RATE_LIMITER.allow(
                    f"confirm:{auth_ctx.user['subject']}",
                    config.rate_confirm_per_minute,
                    60,
                ):
                    raise AppError(429, "rate_limited", "Too many confirmation attempts")
                view = verification.confirm(
                    config,
                    auth_ctx,
                    session_id,
                    decision=str(body.get("decision", "")),
                    roster_version=body.get("roster_version"),
                    code=str(body.get("code", "")),
                    base_url=self._base_url(),
                    ip_hash=security.hash_ip(config.secret_key, self.client_address[0]),
                    ua_hash=security.hash_ua(config.secret_key, self.headers.get("User-Agent")),
                )
                return self._send_json(200, {"session": view})
            if action == "cancel":
                view = verification.cancel(
                    config, auth_ctx, session_id, base_url=self._base_url()
                )
                return self._send_json(200, {"session": view})
            if action == "reveal":
                if not RATE_LIMITER.allow(
                    f"reveal:{auth_ctx.user['subject']}",
                    config.rate_reveal_per_minute,
                    60,
                ):
                    raise AppError(429, "rate_limited", "Too many reveal attempts")
                view = verification.reveal(
                    config, auth_ctx, session_id, base_url=self._base_url()
                )
                return self._send_json(200, {"session": view})
            raise AppError(404, "not_found", "Unknown action")

        def _api_receipt(self, auth_ctx: auth.AuthContext, receipt_id: str) -> None:
            receipt = verification.receipt_view(config, receipt_id, auth_ctx.user["id"])
            self._send_json(
                200,
                receipt,
                headers={
                    "Content-Disposition": f'attachment; filename="verify-{receipt["payload"]["reference"]}.json"'
                },
            )

        def _api_security_check(self, auth_ctx: auth.AuthContext) -> None:
            forged = self.headers.get("X-User-Id")
            ignored = config.auth_mode == "dev"
            if ignored:
                note = (
                    "The dev session is the identity source. A client-supplied X-User-Id "
                    "is ignored by the application."
                )
            else:
                note = (
                    "The app trusts the identity headers from the proxy. If a client can "
                    "reach the app directly, it can forge them. The proxy must strip "
                    "client-supplied X-User-Id/X-Name/X-Last-Name/X-Person-Id and the app "
                    "must not be reachable except through the proxy."
                )
            self._send_json(
                200,
                {
                    "identity": {
                        "subject": auth_ctx.user["subject"],
                        "name": auth_ctx.user["display_name"],
                        "source": auth_ctx.source,
                    },
                    "forged_user_id_header": forged,
                    "ignored": ignored,
                    "auth_mode": config.auth_mode,
                    "note": note,
                },
            )

        # ------------------------------------------------------------------
        # CSRF, body parsing and rate limits
        # ------------------------------------------------------------------

        def _require_csrf(self, auth_ctx: auth.AuthContext) -> None:
            supplied = self.headers.get("X-CSRF-Token", "")
            if not supplied or not security.constant_time_equal(
                supplied, auth_ctx.csrf_token
            ):
                raise AppError(403, "csrf", "Invalid or missing CSRF token")
            origin = self.headers.get("Origin")
            if origin:
                normalized = _normalize_origin(origin)
                if not normalized or normalized not in self._origin_candidates():
                    raise AppError(
                        403,
                        "origin",
                        "Request origin is not allowed. Check BASE_URL or ALLOWED_ORIGINS.",
                    )

        def _origin_candidates(self) -> set[str]:
            candidates: set[str] = set()
            for value in (config.base_url, *config.allowed_origins):
                normalized = _normalize_origin(value)
                if normalized:
                    candidates.add(normalized)
            forwarded_host = (
                self.headers.get("X-Forwarded-Host") or ""
            ).split(",")[0].strip()
            host = forwarded_host or (self.headers.get("Host") or "").split(",")[0].strip()
            proto = (self.headers.get("X-Forwarded-Proto") or "http").split(",")[0].strip()
            if host:
                normalized = _normalize_origin(f"{proto}://{host}")
                if normalized:
                    candidates.add(normalized)
            return candidates

        def _origin(self) -> str | None:
            if config.base_url:
                return config.base_url
            forwarded_host = (
                self.headers.get("X-Forwarded-Host") or ""
            ).split(",")[0].strip()
            host = forwarded_host or self.headers.get("Host")
            if not host:
                return None
            proto = (self.headers.get("X-Forwarded-Proto") or "http").split(",")[0].strip()
            return f"{proto}://{host.split(',')[0].strip()}"

        def _base_url(self) -> str:
            return self._origin() or f"http://127.0.0.1:{config.port}"

        def _read_json(self) -> dict[str, Any]:
            length_raw = self.headers.get("Content-Length", "0")
            try:
                length = int(length_raw)
            except ValueError as exc:
                raise AppError(400, "invalid_body", "Invalid Content-Length") from exc
            if length < 0 or length > config.max_body_bytes:
                raise AppError(413, "body_too_large", "Request body is too large")
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return {}
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AppError(400, "invalid_json", "Request body must be valid JSON") from exc
            if not isinstance(value, dict):
                raise AppError(400, "invalid_json", "Request body must be a JSON object")
            return value

        # ------------------------------------------------------------------
        # Dev routes
        # ------------------------------------------------------------------

        def _dev_route(self, method: str, path: str) -> None:
            if config.auth_mode != "dev":
                return self._send_error_page(404, "Not found")
            if method != "GET":
                return self._send_error_page(405, "Method not allowed")
            if path == "/dev/login":
                user_key = self._query.get("user", [""])[0]
                next_url = security.safe_next(self._query.get("next", ["/"])[0])
                conn = db.connect(config)
                try:
                    result = auth.dev_login(conn, config, user_key)
                finally:
                    conn.close()
                if not result:
                    return self._render(
                        "login.html",
                        400,
                        user=None,
                        csrf_token="",
                        auth_ctx=None,
                        next_url=next_url,
                        dev_users=auth.DEV_USERS,
                        error="Unknown mock identity.",
                    )
                _, _, sid = result
                self._pending_cookies.append(auth.cookie_header(config, sid))
                return self._redirect(next_url)
            if path == "/dev/logout":
                sid = auth._cookie_sid(self, config)
                if sid:
                    conn = db.connect(config)
                    try:
                        auth.logout(conn, config, sid)
                    finally:
                        conn.close()
                self._pending_cookies.append(auth.clear_cookie_header(config))
                return self._redirect("/login")
            return self._send_error_page(404, "Not found")

        # ------------------------------------------------------------------
        # Response helpers
        # ------------------------------------------------------------------

        def _language(self) -> str:
            raw = self.headers.get("Cookie")
            cookie_value = None
            if raw:
                jar = SimpleCookie()
                try:
                    jar.load(raw)
                    morsel = jar.get(i18n.COOKIE_NAME)
                    cookie_value = morsel.value if morsel else None
                except Exception:
                    cookie_value = None
            return i18n.detect_language(cookie_value, self.headers.get("Accept-Language"))

        def _render(self, template: str, status: int, **context: Any) -> None:
            lang = context.pop("lang", None) or self._language()
            context.setdefault("lang", lang)
            context.setdefault("t", lambda key, **kwargs: i18n.translate(lang, key, **kwargs))
            context.setdefault("t_kind", lambda code: i18n.label(lang, "kind", code))
            context.setdefault("t_state", lambda code: i18n.label(lang, "state", code))
            context.setdefault("t_role", lambda code: i18n.label(lang, "role", code))
            context.setdefault(
                "t_assurance",
                lambda code, mock=False: i18n.assurance(lang, code, mock),
            )
            context.setdefault("i18n_payload", i18n.payload(lang))
            context.setdefault("current_path", self.path)
            context.setdefault("auth_mode", config.auth_mode)
            context.setdefault("is_dev", config.auth_mode == "dev")
            context.setdefault("app_name", config.app_name)
            context.setdefault("version", config.version)
            context.setdefault("theme_default", config.app_theme)
            context.setdefault("github_url", config.github_url)
            context.setdefault("year", security.utcnow().year)
            context.setdefault("proxy_logout_url", config.proxy_logout_url)
            html = TEMPLATE_ENV.get_template(template).render(**context)
            self._send(
                status,
                html.encode("utf-8"),
                "text/html; charset=utf-8",
                cache="no-store",
            )

        def _send_json(
            self,
            status: int,
            payload: Any,
            *,
            headers: dict[str, str] | None = None,
        ) -> None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
            self._send(
                status,
                body,
                "application/json; charset=utf-8",
                cache="no-store",
                headers=headers,
            )

        def _send_error_page(self, status: int, message: str) -> None:
            if self._is_api():
                return self._send_json(
                    status,
                    {"error": {"code": "error", "message": message}},
                )
            return self._render(
                "error.html",
                status,
                user=None,
                csrf_token="",
                auth_ctx=None,
                status=status,
                message=message,
            )

        def _handle_error(self, status: int, code: str, message: str, path: str) -> None:
            if path.startswith("/api/"):
                return self._send_json(
                    status, {"error": {"code": code, "message": message}}
                )
            if status == 403:
                message = "Access denied."
            elif status == 404:
                message = "Not found."
            elif status == 410:
                message = "Expired."
            return self._render(
                "error.html",
                status,
                user=None,
                csrf_token="",
                auth_ctx=None,
                status=status,
                message=message,
            )

        def _is_api(self) -> bool:
            return self.path.split("?", 1)[0].startswith("/api/")

        def _send(
            self,
            status: int,
            body: bytes,
            content_type: str,
            *,
            cache: str = "no-store",
            headers: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self._security_headers()
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            if content_type.startswith("text/html"):
                self.send_header("Vary", "Accept-Language, Cookie")
            for cookie in self._pending_cookies:
                self.send_header("Set-Cookie", cookie)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _security_headers(self) -> None:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
                "object-src 'none'; base-uri 'none'; form-action 'self'; "
                "frame-ancestors 'none'; worker-src 'none'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Permissions-Policy",
                "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
            )
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("X-Permitted-Cross-Domain-Policies", "none")
            if config.cookie_secure:
                self.send_header(
                    "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
                )

        def _redirect(self, location: str) -> None:
            self._send(303, b"", "text/plain; charset=utf-8", headers={"Location": location})

        def _static(self, name: str) -> None:
            candidate = (STATIC_DIR / name).resolve()
            try:
                candidate.relative_to(STATIC_DIR)
            except ValueError:
                return self._send_error_page(404, "Not found")
            if not candidate.is_file():
                return self._send_error_page(404, "Not found")
            content_type = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
            if candidate.suffix == ".svg":
                content_type = "image/svg+xml"
            if candidate.suffix in {".js", ".css"}:
                content_type += "; charset=utf-8"
            data = candidate.read_bytes()
            self._send(
                200,
                data,
                content_type,
                cache="no-cache",
            )

    return Handler
