"""Starlette WebUI for multi-profile keepalive orchestration (J3).

Parent process only: REST + SSE + static shell. Does NOT run keepalive loops
on the ASGI event-loop thread. Handlers live in split modules (D1 R4).
"""
from __future__ import annotations

import asyncio
import contextlib
import os

from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from cmcc_cloud_alive.webui.common import _STATIC_DIR
from cmcc_cloud_alive.webui.auth_gate import (
    OptionalTokenMiddleware,
    auth_change,
    auth_disable,
    auth_login,
    auth_setup,
    auth_status,
)
from cmcc_cloud_alive.webui.handlers import (
    events_global,
    global_logs_clear,
    global_logs_get,
    global_logs_post,
    health,
    index,
    jobs_create,
    jobs_events,
    jobs_get,
    jobs_list,
    jobs_stop,
    logs_batch,
    logs_global,
    profiles_create,
    profiles_delete,
    profiles_desktop_logout,
    profiles_desktops,
    profiles_events,
    profiles_get,
    profiles_list,
    profiles_login,
    profiles_logs,
    profiles_logs_clear,
    profiles_patch,
    profiles_select_desktop,
    profiles_start_job,
    profiles_stop_job,
    system_info,
)
# ensure ORCH loaded at import
from cmcc_cloud_alive.webui.orch_runtime import ORCH  # noqa: F401

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

routes = [
    Route("/", endpoint=index),
    Route("/index.html", endpoint=index),
    # health aliases: X2 `/api/health`, T3 `/health`, PM `/api/system/health`
    Route("/health", endpoint=health),
    Route("/api/health", endpoint=health),
    Route("/api/system/health", endpoint=health),
    Route("/api/system/info", endpoint=system_info),
    # X8 alias: OPEN gates mention /api/info
    Route("/api/info", endpoint=system_info),
    # Access gate (8317-style): public status/setup/login; change requires current token
    Route("/api/auth/status", endpoint=auth_status, methods=["GET"]),
    Route("/api/auth/setup", endpoint=auth_setup, methods=["POST"]),
    Route("/api/auth/login", endpoint=auth_login, methods=["POST"]),
    Route("/api/auth/change", endpoint=auth_change, methods=["POST"]),
    Route("/api/auth/disable", endpoint=auth_disable, methods=["POST"]),
    # X2 §3 profiles
    Route("/api/profiles", endpoint=profiles_list, methods=["GET"]),
    Route("/api/profiles", endpoint=profiles_create, methods=["POST"]),
    Route("/api/profiles/{profile_id}", endpoint=profiles_get, methods=["GET"]),
    Route("/api/profiles/{profile_id}", endpoint=profiles_patch, methods=["PATCH"]),
    Route("/api/profiles/{profile_id}", endpoint=profiles_delete, methods=["DELETE"]),
    Route("/api/profiles/{profile_id}/login", endpoint=profiles_login, methods=["POST"]),
    Route("/api/profiles/{profile_id}/desktops", endpoint=profiles_desktops, methods=["GET"]),
    Route("/api/profiles/{profile_id}/select-desktop", endpoint=profiles_select_desktop, methods=["POST"]),
    Route("/api/profiles/{profile_id}/jobs", endpoint=profiles_start_job, methods=["POST"]),
    Route("/api/profiles/{profile_id}/jobs/current", endpoint=profiles_stop_job, methods=["DELETE"]),
    Route("/api/profiles/{profile_id}/desktop-logout", endpoint=profiles_desktop_logout, methods=["POST"]),
    Route("/api/profiles/{profile_id}/logs", endpoint=profiles_logs, methods=["GET"]),
    Route("/api/profiles/{profile_id}/logs", endpoint=profiles_logs_clear, methods=["DELETE"]),
    Route("/api/profiles/{profile_id}/events", endpoint=profiles_events, methods=["GET"]),
    # Global SSE for FE EventSource("/api/events") — X7
    Route("/api/events", endpoint=events_global, methods=["GET"]),
    # T_PM-compatible jobs collection (poll fallback)
    Route("/api/jobs", endpoint=jobs_list, methods=["GET"]),
    Route("/api/jobs", endpoint=jobs_create, methods=["POST"]),
    Route("/api/jobs/{job_id}", endpoint=jobs_get, methods=["GET"]),
    Route("/api/jobs/{job_id}/stop", endpoint=jobs_stop, methods=["POST"]),
    Route("/api/jobs/{job_id}/events", endpoint=jobs_events, methods=["GET"]),
    Route("/api/logs", endpoint=logs_global, methods=["GET"]),
    Route("/api/logs/batch", endpoint=logs_batch, methods=["GET"]),
    # HARD_GATE#global-run-log: page-level run log (survives FE reload / tunnel)
    Route("/api/global-logs", endpoint=global_logs_get, methods=["GET"]),
    Route("/api/global-logs", endpoint=global_logs_post, methods=["POST"]),
    Route("/api/global-logs", endpoint=global_logs_clear, methods=["DELETE"]),
]

if _STATIC_DIR.is_dir():
    routes.append(Mount("/static", app=StaticFiles(directory=str(_STATIC_DIR)), name="static"))


@contextlib.asynccontextmanager
async def _lifespan(_app):
    """Bind the running ASGI loop so ORCH._emit can wake SSE consumers from
    worker threads via call_soon_threadsafe (otherwise events lag ~15s)."""
    if hasattr(ORCH, "bind_loop"):
        ORCH.bind_loop(asyncio.get_running_loop())
    yield


app = Starlette(
    debug=os.environ.get("CMCC_WEBUI_DEBUG") == "1",
    routes=routes,
    lifespan=_lifespan,
)
app.add_middleware(OptionalTokenMiddleware)


def main() -> None:
    import uvicorn

    host = os.environ.get("CMCC_WEBUI_HOST", "127.0.0.1")
    port = int(os.environ.get("CMCC_WEBUI_PORT", "8080"))
    uvicorn.run("cmcc_cloud_alive.webui.app:app", host=host, port=port, factory=False)


if __name__ == "__main__":
    main()
