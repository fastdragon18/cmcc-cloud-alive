"""Orchestrator singleton (real Orchestrator or FakeOrchestrator fallback)."""
from __future__ import annotations

import asyncio
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from cmcc_cloud_alive.webui.common import _now_iso

class FakeOrchestrator:
    """In-memory job table. Method names match planned J2 orchestrator."""

    _GLOBAL_LOG_LIMIT = 500

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._jobs: Dict[str, Dict[str, Any]] = {}  # job_id -> job
        self._by_profile: Dict[str, str] = {}  # profile_id -> job_id
        self._log_buffers: Dict[str, List[Dict[str, str]]] = {}
        # HARD_GATE#global-run-log: page-level run log (not card/job scoped)
        self._global_log: List[Dict[str, str]] = []
        self._subscribers: List[asyncio.Queue] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    @staticmethod
    def _deliver(subs: List[asyncio.Queue], payload: Dict[str, Any]) -> None:
        for q in subs:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    def _emit(self, event: str, data: Dict[str, Any]) -> None:
        payload = {"event": event, "data": data}
        subs = list(self._subscribers)
        if not subs:
            return
        loop = self._loop
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        # See Orchestrator._emit: cross-thread put_nowait won't wake the loop.
        if loop is not None and running is not loop:
            try:
                loop.call_soon_threadsafe(self._deliver, subs, payload)
                return
            except RuntimeError:
                pass
        self._deliver(subs, payload)

    def list_jobs(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(j) for j in self._jobs.values()]

    def get_status(self, profile_id: str) -> Dict[str, Any]:
        with self._lock:
            jid = self._by_profile.get(profile_id)
            if not jid:
                return {"profileId": profile_id, "status": "idle", "jobId": None}
            j = self._jobs.get(jid) or {}
            return {
                "profileId": profile_id,
                "status": j.get("status", "unknown"),
                "jobId": jid,
                "protocol": j.get("protocol"),
                "pid": j.get("pid"),
                "startedAt": j.get("startedAt"),
            }

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            j = self._jobs.get(job_id)
            return dict(j) if j else None

    def start_job(
        self,
        profile_id: str,
        state_path: Path,
        protocol: str = "ZTE",
        extra_args: Optional[List[str]] = None,
        mode: str = "live",
        interval_sec: Optional[int] = None,
        traffic_sec: Optional[int] = None,
        duration_sec: Optional[int] = None,
        user_service_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        protocol = (protocol or "ZTE").upper()
        if protocol not in ("ZTE", "SCG"):
            raise ValueError("protocol must be ZTE or SCG")
        with self._lock:
            existing = self._by_profile.get(profile_id)
            if existing and self._jobs.get(existing, {}).get("status") == "running":
                raise RuntimeError("PROFILE_IN_USE")
            job_id = uuid.uuid4().hex[:12]
            job = {
                "id": job_id,
                "jobId": job_id,
                "profileId": profile_id,
                "statePath": str(state_path),
                "protocol": protocol,
                "mode": mode or "live",
                "status": "running",
                "pid": None,  # fake: no subprocess yet (J2)
                "startedAt": _now_iso(),
                "stoppedAt": None,
                "detail": "fake orchestrator dry-run (no LIVE child)",
                "extraArgs": list(extra_args or []),
                "intervalSec": interval_sec,
                "trafficSec": traffic_sec,
                "durationSec": duration_sec,
                "backend": "fake",
                "userServiceId": (user_service_id or "").strip() or None,
            }
            self._jobs[job_id] = job
            self._by_profile[profile_id] = job_id
            self._log_buffers.setdefault(job_id, []).append(
                {"at": _now_iso(), "line": f"[fake] start {protocol} mode={job['mode']} state={state_path.name}"}
            )
            self._emit(
                "job_status",
                {
                    "jobId": job_id,
                    "profileId": profile_id,
                    "status": "running",
                    "at": job["startedAt"],
                    "detail": job["detail"],
                },
            )
            return dict(job)

    def stop_job(self, profile_id: str) -> Dict[str, Any]:
        with self._lock:
            jid = self._by_profile.get(profile_id)
            if not jid or jid not in self._jobs:
                raise KeyError("NOT_FOUND")
            job = self._jobs[jid]
            if job.get("status") != "running":
                return dict(job)
            job["status"] = "stopped"
            job["stoppedAt"] = _now_iso()
            job["detail"] = "stopped by API"
            self._log_buffers.setdefault(jid, []).append(
                {"at": job["stoppedAt"], "line": "[fake] stop requested"}
            )
            self._emit(
                "job_status",
                {
                    "jobId": jid,
                    "profileId": profile_id,
                    "status": "stopped",
                    "at": job["stoppedAt"],
                },
            )
            return dict(job)

    def recent_logs(self, job_id: Optional[str] = None, profile_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, str]]:
        """Return job/card logs only when scoped.

        HARD_GATE#768-B / ASSIGN#785#4: unscoped /api/logs must not flatten
        job buffers into page-level global log. Card logs stay profile/job scoped.
        """
        with self._lock:
            if not job_id and profile_id:
                job_id = self._by_profile.get(profile_id)
            if not job_id:
                return []
            return list(self._log_buffers.get(job_id, []))[-limit:]

    def recent_logs_batch(
        self, profile_ids: List[str], limit: int = 100
    ) -> Dict[str, List[Dict[str, str]]]:
        """Multi-profile card logs for /api/logs/batch (Fake parity)."""
        out: Dict[str, List[Dict[str, str]]] = {}
        for raw in profile_ids or []:
            pid = str(raw or "").strip()
            if not pid:
                continue
            out[pid] = self.recent_logs(profile_id=pid, limit=limit)
        return out

    def clear_logs(self, job_id: Optional[str] = None, profile_id: Optional[str] = None) -> Dict[str, Any]:
        """Clear a card/job log buffer (parity with real Orchestrator.clear_logs)."""
        with self._lock:
            if not job_id and profile_id:
                job_id = self._by_profile.get(profile_id)
            cleared = 0
            if job_id and job_id in self._log_buffers:
                cleared = len(self._log_buffers[job_id])
                self._log_buffers[job_id] = []
        return {"ok": True, "cleared": cleared, "jobId": job_id}

    def append_global_log(
        self, line: str, level: str = "info", emit: bool = True
    ) -> Dict[str, str]:
        """Append one page-level run-log line (ring buffer, optional SSE)."""
        entry = {
            "at": _now_iso(),
            "line": str(line or "")[:2000],
            "level": str(level or "info")[:32],
        }
        if not entry["line"]:
            return entry
        with self._lock:
            self._global_log.append(entry)
            if len(self._global_log) > self._GLOBAL_LOG_LIMIT:
                self._global_log = self._global_log[-self._GLOBAL_LOG_LIMIT :]
        if emit:
            self._emit("global_log", dict(entry))
        return dict(entry)

    def recent_global_logs(self, limit: int = 300) -> List[Dict[str, str]]:
        try:
            n = max(1, min(int(limit), self._GLOBAL_LOG_LIMIT))
        except Exception:
            n = 300
        with self._lock:
            return [dict(x) for x in self._global_log[-n:]]

    def clear_global_logs(self) -> Dict[str, Any]:
        with self._lock:
            cleared = len(self._global_log)
            self._global_log = []
        self._emit(
            "global_log_cleared",
            {"cleared": cleared, "at": _now_iso()},
        )
        return {"ok": True, "cleared": cleared}


def _load_orchestrator() -> Any:
    try:
        from cmcc_cloud_alive.webui.orchestrator import Orchestrator  # type: ignore

        return Orchestrator()
    except Exception:
        return FakeOrchestrator()


ORCH: Any = _load_orchestrator()
