"""Optional access-token middleware and /api/auth/* handlers."""
from __future__ import annotations

import os
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from cmcc_cloud_alive.webui.common import (
    _access_token_path,
    _clear_access_token,
    _extract_request_token,
    _read_access_token,
    _token_ok,
    _write_access_token,
    api_error,
)

class OptionalTokenMiddleware(BaseHTTPMiddleware):
    """Gate business APIs behind access token (file or env).

    Open always: shell HTML, static, health, system/info, auth setup/login/status.
    gate6:
    - no token configured → open access (auth disabled)
    - token configured → require valid Bearer / x-api-token / ?token=
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Always open: health aliases (compose/X2/T3) + static + root shell + auth bootstrap
        # FLAG#59: /api/health must match docker HEALTHCHECK
        open_exact = {
            "/",
            "/index.html",
            "/health",
            "/api/health",
            "/api/system/health",
            # X9: allow FE to discover tokenRequired / setupRequired before Bearer set
            "/api/system/info",
            "/api/info",
            "/api/auth/status",
            "/api/auth/setup",
            "/api/auth/login",
        }
        open_prefixes = ("/static/", "/favicon")
        if path in open_exact or path.startswith(open_prefixes):
            return await call_next(request)

        expected = _read_access_token()
        # gate6: no token configured → open access (auth disabled)
        if not expected:
            return await call_next(request)

        token = _extract_request_token(request)
        if not _token_ok(token, expected):
            return api_error(
                "TOKEN_INVALID",
                "访问密钥无效或缺失",
                401,
                next_step="请在登录门输入正确访问密钥，或在请求头携带 Bearer / x-api-token",
            )
        return await call_next(request)


# ---------------------------------------------------------------------------
# Fake orchestrator (stable shape for J2 swap)
# ---------------------------------------------------------------------------


async def auth_status(request: Request) -> JSONResponse:
    """Public: whether setup/login is needed (no secret leaked)."""
    expected = _read_access_token()
    provided = _extract_request_token(request)
    authed = (not expected) or _token_ok(provided, expected)
    return JSONResponse(
        {
            "ok": True,
            # gate6: no forced first-run; empty token = auth off
            "setupRequired": False,
            "tokenRequired": bool(expected),
            "authEnabled": bool(expected),
            "authenticated": authed,
            "version": "0.1.0-webui-871d-access-gate19",
        }
    )


async def auth_setup(request: Request) -> JSONResponse:
    """First-run: create durable access token when none configured yet."""
    if _read_access_token():
        return api_error(
            "ALREADY_CONFIGURED",
            "访问密钥已存在，请使用登录或「设置令牌」修改",
            409,
            next_step="在登录页输入现有密钥；修改请点顶栏「设置令牌」",
        )
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    generate = bool(body.get("generate"))
    token = str(body.get("token") or body.get("accessToken") or "").strip()
    if generate or not token:
        token = secrets.token_urlsafe(18)
    try:
        path = _write_access_token(token)
    except ValueError as e:
        return api_error("VALIDATION", str(e), 400, next_step="请提供 4–256 位无空格密钥，或使用 generate")
    except OSError as e:
        return api_error("IO_ERROR", f"写入密钥失败: {e}", 500, next_step="检查数据目录写权限")
    return JSONResponse(
        {
            "ok": True,
            "setup": True,
            "token": token,
            "path": str(path),
            "message": "访问密钥已写入数据目录，请妥善保存；后续登录需此密钥",
        }
    )


async def auth_login(request: Request) -> JSONResponse:
    """Validate access token (does not create sessions server-side; FE stores Bearer)."""
    expected = _read_access_token()
    if not expected:
        # gate6: auth disabled — treat as success so FE can enter console
        return JSONResponse(
            {
                "ok": True,
                "authenticated": True,
                "authEnabled": False,
                "message": "未启用访问密钥，已直接进入控制台",
            }
        )
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    token = str(body.get("token") or body.get("accessToken") or "").strip()
    if not token:
        token = _extract_request_token(request)
    if not _token_ok(token, expected):
        return api_error(
            "TOKEN_INVALID",
            "访问密钥错误",
            401,
            next_step="请检查密钥是否与服务器一致（数据目录 webui_access_token 或 CMCC_WEBUI_TOKEN）",
        )
    return JSONResponse({"ok": True, "authenticated": True, "token": token})


async def auth_change(request: Request) -> JSONResponse:
    """Change access token (requires current valid Bearer; writes file).

    gate6: when no token configured yet, allow first enable without currentToken.
    """
    expected = _read_access_token()
    current = _extract_request_token(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    # allow body.currentToken as alternative to Authorization
    body_current = str(body.get("currentToken") or body.get("oldToken") or "").strip()
    if body_current:
        current = body_current
    if expected and not _token_ok(current, expected):
        return api_error(
            "TOKEN_INVALID",
            "当前访问密钥错误，无法修改",
            401,
            next_step="请输入正确的当前密钥后再改密",
        )
    generate = bool(body.get("generate"))
    new_token = str(body.get("token") or body.get("newToken") or body.get("accessToken") or "").strip()
    if generate or not new_token:
        new_token = secrets.token_urlsafe(18)
    try:
        path = _write_access_token(new_token)
    except ValueError as e:
        return api_error("VALIDATION", str(e), 400, next_step="新密钥需 4–256 位且无空格")
    except OSError as e:
        return api_error("IO_ERROR", f"写入密钥失败: {e}", 500, next_step="检查数据目录写权限")
    return JSONResponse(
        {
            "ok": True,
            "changed": True,
            "authEnabled": True,
            "token": new_token,
            "path": str(path),
            "message": "访问密钥已更新（写入数据目录，优先于环境变量）",
        }
    )


async def auth_disable(request: Request) -> JSONResponse:
    """Disable access-token gate by deleting file token (env CMCC_WEBUI_TOKEN still wins)."""
    expected = _read_access_token()
    has_env = bool((os.environ.get("CMCC_WEBUI_TOKEN") or "").strip())
    if has_env and not _access_token_path().is_file():
        return api_error(
            "ENV_TOKEN",
            "当前密钥来自环境变量 CMCC_WEBUI_TOKEN，无法通过本接口关闭",
            400,
            next_step="请取消环境变量或改用文件密钥后再关闭鉴权",
        )
    if expected:
        current = _extract_request_token(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        body_current = str(body.get("currentToken") or body.get("oldToken") or body.get("token") or "").strip()
        if body_current:
            current = body_current
        if not _token_ok(current, expected):
            return api_error(
                "TOKEN_INVALID",
                "当前访问密钥错误，无法关闭鉴权",
                401,
                next_step="请输入正确的当前密钥后再关闭",
            )
    try:
        path = _clear_access_token()
    except OSError as e:
        return api_error("IO_ERROR", str(e), 500, next_step="检查数据目录写权限")
    # If env still set, report residual auth
    still = _read_access_token()
    return JSONResponse(
        {
            "ok": True,
            "disabled": not bool(still),
            "authEnabled": bool(still),
            "path": str(path),
            "message": (
                "已关闭访问鉴权（删除文件密钥）"
                if not still
                else "已删除文件密钥，但仍受环境变量 CMCC_WEBUI_TOKEN 约束"
            ),
        }
    )


