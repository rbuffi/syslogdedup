"""OIDC (Keycloak) login routes and optional auth middleware for the Web UI."""
import logging
import os
from collections.abc import Hashable
from typing import Optional

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from config import OidcConfig

logger = logging.getLogger(__name__)


class _OAuthStateCache:
    """Store OAuth/PKCE state outside the session cookie (Authlib async cache API).

    Long authorize URLs + PKCE + a long redirect_uri (e.g. with WEB_BASE_PATH) can
    exceed cookie/header limits when state is kept only in SessionMiddleware.
    For multiple replicas or workers, replace with a shared cache (e.g. Redis).
    """

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def get(self, key: Hashable) -> Optional[str]:
        return self._store.get(str(key))

    async def set(self, key: Hashable, value: str, expires_in: Optional[int] = None) -> None:
        self._store[str(key)] = value

    async def delete(self, key: Hashable) -> None:
        self._store.pop(str(key), None)


oauth = OAuth(cache=_OAuthStateCache())
_oidc_cfg: Optional[OidcConfig] = None
_web_base_path: str = ""

router = APIRouter(prefix="/auth", tags=["oidc"])


def _url_with_base(path: str) -> str:
    """Build absolute path for redirects. path must start with /."""
    if not path.startswith("/"):
        path = "/" + path
    if not _web_base_path:
        return path
    return _web_base_path.rstrip("/") + path


def init_oidc(cfg: OidcConfig, web_base_path: str = "") -> None:
    """Register the OIDC client (Keycloak realm discovery). Call once at startup."""
    global _oidc_cfg, _web_base_path
    _oidc_cfg = cfg
    _web_base_path = web_base_path or ""
    issuer = cfg.issuer.rstrip("/")
    client_kwargs: dict = {"scope": cfg.scope}
    if not cfg.ssl_verify:
        client_kwargs["verify"] = False
    oauth.register(
        name="keycloak",
        client_id=cfg.client_id,
        client_secret=cfg.client_secret,
        server_metadata_url=f"{issuer}/.well-known/openid-configuration",
        client_kwargs=client_kwargs,
    )


def _strip_web_base(raw: str) -> str:
    """Normalize to inner-app path: /api/..., /auth/..., /."""
    raw = raw or "/"
    base = _web_base_path.rstrip("/") if _web_base_path else ""
    if not base:
        return raw
    if raw == base or raw == base + "/":
        return "/"
    if raw.startswith(base + "/"):
        return raw[len(base) :]
    return raw


def _inner_path_for_auth(request: Request) -> str:
    """Path relative to the mounted app (/api/..., /) for auth checks.

    Prefer scope['path'] (correct after Starlette Mount). Strip WEB_BASE_PATH when the
    path still includes the public prefix (some proxies or misconfigured mounts).
    """
    scope_path = request.scope.get("path")
    if scope_path is not None and scope_path != "":
        p = scope_path if scope_path.startswith("/") else "/" + scope_path
        if not p:
            p = "/"
        return _strip_web_base(p)
    return _strip_web_base(request.url.path or "/")


def is_oidc_public_path(path: str) -> bool:
    """Paths that do not require an authenticated session when OIDC is enabled."""
    if path in ("/", "/favicon.ico", "/api/auth/status"):
        return True
    if path.startswith("/static"):
        return True
    if path.startswith("/auth"):
        return True
    return False


class OIDCAuthMiddleware(BaseHTTPMiddleware):
    """When enabled, require a session except /, /static, /auth/*, and /api/auth/status."""

    def __init__(self, app, oidc_enabled: bool = False):
        super().__init__(app)
        self.oidc_enabled = oidc_enabled

    async def dispatch(self, request, call_next):
        if not self.oidc_enabled:
            return await call_next(request)
        path = _inner_path_for_auth(request)
        if is_oidc_public_path(path):
            return await call_next(request)
        user = request.session.get("user")
        if user:
            return await call_next(request)
        if path.startswith("/api"):
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)
        return RedirectResponse(url=_url_with_base("/"), status_code=302)


@router.get("/login")
async def oidc_login(request: Request):
    if _oidc_cfg is None:
        raise RuntimeError("OIDC is not initialized")
    try:
        return await oauth.keycloak.authorize_redirect(request, _oidc_cfg.redirect_uri)
    except Exception as e:
        logger.exception("OIDC authorize_redirect failed: %s", e)
        body = {
            "detail": "OIDC login failed",
            "error": str(e),
            "error_type": type(e).__name__,
        }
        if os.getenv("OIDC_DEBUG", "").lower() in ("1", "true", "yes"):
            import traceback

            body["traceback"] = traceback.format_exc()
        return JSONResponse(status_code=502, content=body)


@router.get("/callback")
async def oidc_callback(request: Request):
    if _oidc_cfg is None:
        raise RuntimeError("OIDC is not initialized")
    try:
        token = await oauth.keycloak.authorize_access_token(request)
    except Exception as e:
        logger.error("OIDC token exchange failed: %s", e)
        return JSONResponse(
            {"detail": "Authentication failed", "error": str(e)},
            status_code=400,
        )
    userinfo = token.get("userinfo")
    if userinfo:
        request.session["user"] = dict(userinfo)
    else:
        request.session["user"] = {"sub": token.get("sub") or ""}
    if token.get("id_token"):
        request.session["id_token"] = token["id_token"]
    return RedirectResponse(url=_url_with_base("/"), status_code=302)


@router.get("/logout")
async def oidc_logout(request: Request):
    request.session.clear()
    return RedirectResponse(url=_url_with_base("/"), status_code=302)
