"""Shared WebUI helpers (paths, redact, errors, timing, access-token IO)."""
from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from starlette.requests import Request
from starlette.responses import JSONResponse

_STATIC_DIR = Path(__file__).resolve().parent / "static"

def _data_dir() -> Path:
    """Unified durable root shared with CLI (X8).

    Priority:
    1. CMCC_DATA_DIR if set (explicit override; may point at either the
       package root or the final data root)
    2. else ``$CMCC_ALIVE_HOME|HOME|~/.cmcc-cloud-alive`` — always the
       ``.cmcc-cloud-alive`` package dir so Docker HOME=/data matches
       entrypoint + core DEFAULT_DATA_DIR (``/data/.cmcc-cloud-alive``).
    """
    explicit = os.environ.get("CMCC_DATA_DIR")
    if explicit:
        p = Path(explicit)
        # Accept either the package root or the volume root.
        if p.name == ".cmcc-cloud-alive":
            return p
        # Common Docker mistake: CMCC_DATA_DIR=/data — nest under package dir.
        return p / ".cmcc-cloud-alive"
    raw = os.environ.get("CMCC_ALIVE_HOME") or os.environ.get("HOME") or str(Path.home())
    home = Path(raw)
    if home.name == ".cmcc-cloud-alive":
        return home
    return home / ".cmcc-cloud-alive"


_LEGACY_PROFILES_MIGRATED = False


def _legacy_profiles_dirs(unified: Path) -> List[Path]:
    """Pre-X8 WebUI wrote profiles under /data/profiles when HOME=/data."""
    candidates: List[Path] = []
    # Sibling of package root: /data/profiles next to /data/.cmcc-cloud-alive
    sibling = unified.parent / "profiles"
    if sibling != (unified / "profiles"):
        candidates.append(sibling)
    # Bare CMCC_DATA_DIR=/data historical
    bare = Path("/data/profiles")
    if bare not in candidates:
        candidates.append(bare)
    return candidates


def _migrate_legacy_profiles(dest: Path) -> int:
    """Copy missing profile JSON from legacy roots into unified profiles/.

    Never overwrites a newer/same-name file already in dest. Returns count
    of files copied. Best-effort; failures are non-fatal.
    """
    global _LEGACY_PROFILES_MIGRATED
    moved = 0
    try:
        dest.mkdir(parents=True, exist_ok=True)
        for legacy in _legacy_profiles_dirs(dest.parent):
            if not legacy.is_dir():
                continue
            if legacy.resolve() == dest.resolve():
                continue
            for src in legacy.glob("*.json"):
                target = dest / src.name
                if target.exists():
                    continue
                try:
                    target.write_bytes(src.read_bytes())
                    try:
                        os.chmod(target, 0o600)
                    except OSError:
                        pass
                    moved += 1
                except OSError:
                    continue
    finally:
        _LEGACY_PROFILES_MIGRATED = True
    return moved


def profiles_dir() -> Path:
    d = _data_dir() / "profiles"
    d.mkdir(parents=True, exist_ok=True)
    # One-shot best-effort migration so old /data/profiles stay visible.
    if not _LEGACY_PROFILES_MIGRATED:
        _migrate_legacy_profiles(d)
    return d


def _now_iso() -> str:
    # HARD_GATE#861: force Asia/Shanghai so API/orch timestamps match child short_time
    try:
        from zoneinfo import ZoneInfo

        return datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(timespec="seconds")
    except Exception:
        return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

try:
    from cmcc_cloud_alive.core import SENSITIVE_REPORT_KEYS as _CORE_SENSITIVE
except Exception:  # pragma: no cover — package may be partial in unit smoke
    _CORE_SENSITIVE = {
        "accessToken",
        "authorization",
        "authPayload",
        "clientId",
        "connectStr",
        "cpsid",
        "jwt",
        "password",
        "sohoToken",
        "token",
    }

_SENSITIVE_LOWER = {k.lower() for k in _CORE_SENSITIVE} | {
    "refreshtoken",
    "accesstoken",
    "sohotoken",
    "authorization",
}


def _mask_username(u: Optional[str]) -> str:
    if not u:
        return ""
    s = str(u)
    if len(s) <= 4:
        return "*" * len(s)
    return s[:3] + "****" + s[-2:]


def redact_obj(value: Any, key: str = "") -> Any:
    if key and key.lower() in _SENSITIVE_LOWER:
        return "<redacted>"
    if isinstance(value, dict):
        return {k: redact_obj(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_obj(v, key) for v in value]
    return value


def api_error(code: str, message: str, status: int = 400, next_step: str = "") -> JSONResponse:
    body: Dict[str, Any] = {
        "ok": False,
        "error": {"code": code, "message": message},
    }
    if next_step:
        body["error"]["nextStep"] = next_step
    return JSONResponse(body, status_code=status)


# WAVE7 frozen contract: intervalSec/trafficSec/durationSec -> CLI flags
_DEFAULT_INTERVAL_SEC = 300
_DEFAULT_TRAFFIC_SEC = 60
_DEFAULT_DURATION_SEC = 0


def _parse_positive_int(raw: Any, field: str, *, allow_zero: bool = False) -> int:
    """Parse body field as int. allow_zero=True for durationSec (0=forever)."""
    try:
        if isinstance(raw, bool):
            raise ValueError
        val = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be an integer")
    if allow_zero:
        if val < 0:
            raise ValueError(f"{field} must be >= 0")
    elif val <= 0:
        raise ValueError(f"{field} must be > 0")
    return val


def parse_job_timing_fields(body: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Parse optional timing fields; missing -> defaults. Returns fields + extraArgs.

    Accepts FE alias ``intervalMin`` (minutes) when ``intervalSec`` is absent.
    """
    body = body or {}
    if "intervalSec" in body and body.get("intervalSec") is not None:
        interval = _parse_positive_int(body.get("intervalSec"), "intervalSec")
    elif "intervalMin" in body and body.get("intervalMin") is not None:
        # FE draft uses minutes; convert to seconds for orchestrator/CLI.
        minutes = _parse_positive_int(body.get("intervalMin"), "intervalMin")
        interval = minutes * 60
    else:
        interval = _DEFAULT_INTERVAL_SEC
    if "trafficSec" in body and body.get("trafficSec") is not None:
        traffic = _parse_positive_int(body.get("trafficSec"), "trafficSec")
    else:
        traffic = _DEFAULT_TRAFFIC_SEC
    if "durationSec" in body and body.get("durationSec") is not None:
        duration = _parse_positive_int(body.get("durationSec"), "durationSec", allow_zero=True)
    else:
        duration = _DEFAULT_DURATION_SEC
    # simple-keepalive argv (align Python menu): minutes + traffic seconds + mode
    # mode "1"=单轮, "2"=永久. durationSec==0 => forever; >0 => single round.
    interval_minutes = max(1, int(interval) // 60)
    simple_mode = "2" if int(duration) == 0 else "1"
    body_mode = str((body or {}).get("mode") or "").lower()
    if body_mode in ("once", "single", "dry-run", "dryrun"):
        simple_mode = "1"
    elif body_mode in ("live", "forever", "permanent", "loop"):
        if int(duration) == 0:
            simple_mode = "2"
    extra_args = [
        "--interval-minutes",
        str(interval_minutes),
        "--traffic-seconds",
        str(traffic),
        "--mode",
        simple_mode,
    ]
    return {
        "intervalSec": interval,
        "trafficSec": traffic,
        "durationSec": duration,
        "extraArgs": extra_args,
    }


# ---------------------------------------------------------------------------
# Access token gate (file > env; 8317-style login shell)
# ---------------------------------------------------------------------------

_ACCESS_TOKEN_FILENAME = "webui_access_token"


def _access_token_path() -> Path:
    return _data_dir() / _ACCESS_TOKEN_FILENAME


def _read_access_token() -> str:
    """Resolve expected WebUI access token.

    Priority:
    1. durable file under data dir (UI setup / change)
    2. CMCC_WEBUI_TOKEN env (.env / compose)
    """
    try:
        p = _access_token_path()
        if p.is_file():
            raw = p.read_text(encoding="utf-8", errors="replace").strip()
            # accept single-line token only; ignore comments/blank
            for line in raw.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                return s
    except OSError:
        pass
    return (os.environ.get("CMCC_WEBUI_TOKEN") or "").strip()


def _write_access_token(token: str) -> Path:
    """Persist access token to data dir (mode 0600). Returns path."""
    token = (token or "").strip()
    if not token:
        raise ValueError("empty token")
    if len(token) < 4:
        raise ValueError("token too short (min 4)")
    if len(token) > 256:
        raise ValueError("token too long (max 256)")
    # reject whitespace / control chars
    if any(c.isspace() for c in token):
        raise ValueError("token must not contain whitespace")
    root = _data_dir()
    root.mkdir(parents=True, exist_ok=True)
    path = _access_token_path()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(token + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def _clear_access_token() -> Path:
    """Remove file-based access token (disable gate). Env CMCC_WEBUI_TOKEN still wins if set."""
    path = _access_token_path()
    try:
        if path.is_file():
            path.unlink()
    except OSError as e:
        raise OSError(f"无法删除访问密钥文件: {e}") from e
    return path


def _extract_request_token(request: Request) -> str:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (
        request.headers.get("x-api-token")
        or request.query_params.get("token")
        or ""
    ).strip()


def _token_ok(provided: str, expected: str) -> bool:
    if not expected or not provided:
        return False
    # secrets.compare_digest requires equal length; pad-safe via hmac style length check
    try:
        return secrets.compare_digest(provided, expected)
    except (TypeError, ValueError):
        return False


