"""Regression tests for the 2026-07-26 WebUI bug sweep.

Each test pins a specific defect found during the audit so it cannot silently
regress. Kept dependency-light: real Orchestrator + Starlette TestClient only.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path


def _fresh_home() -> str:
    # CMCC_DATA_DIR outranks CMCC_ALIVE_HOME in _data_dir(); a sibling test may
    # have left it set, so clear it for a clean, isolated data root.
    os.environ.pop("CMCC_DATA_DIR", None)
    home = tempfile.mkdtemp()
    os.environ["CMCC_ALIVE_HOME"] = os.path.join(home, ".cmcc-cloud-alive")
    os.makedirs(os.path.join(os.environ["CMCC_ALIVE_HOME"], "profiles"), exist_ok=True)
    # Reset the process-wide one-shot legacy-migration flag so we neither depend
    # on nor poison it for other (ordering-sensitive) tests in the same run.
    import cmcc_cloud_alive.webui.common as _common

    _common._LEGACY_PROFILES_MIGRATED = False
    return os.environ["CMCC_ALIVE_HOME"]


def tearDownModule() -> None:
    # Don't leak our env/flag state into ordering-sensitive tests (e.g.
    # test_dual_profile_via_api relies on the one-shot migration running).
    import cmcc_cloud_alive.webui.common as _common

    _common._LEGACY_PROFILES_MIGRATED = False
    os.environ.pop("CMCC_ALIVE_HOME", None)
    os.environ.pop("CMCC_DATA_DIR", None)


class TestP0Crashers(unittest.TestCase):
    def setUp(self) -> None:
        os.environ.pop("CMCC_WEBUI_TOKEN", None)
        self.data_dir = _fresh_home()
        from starlette.testclient import TestClient
        import cmcc_cloud_alive.webui.app as appmod

        self.appmod = appmod
        self.TestClient = TestClient

    def test_profiles_list_no_500_when_updatedAt_missing(self) -> None:
        # Legacy/migrated profile files carry no updatedAt; the list must not 500.
        Path(self.data_dir, "profiles", "legacy.json").write_text(
            '{"displayName":"L","username":"u12345678"}', encoding="utf-8"
        )
        with self.TestClient(self.appmod.app, raise_server_exceptions=False) as c:
            r = c.get("/api/profiles")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["ok"])
        self.assertEqual(len(r.json()["profiles"]), 1)

    def test_auth_disable_env_token_returns_400_not_500(self) -> None:
        os.environ["CMCC_WEBUI_TOKEN"] = "envsecret"
        try:
            with self.TestClient(self.appmod.app, raise_server_exceptions=False) as c:
                r = c.post(
                    "/api/auth/disable", headers={"Authorization": "Bearer envsecret"}
                )
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.json()["error"]["code"], "ENV_TOKEN")
        finally:
            os.environ.pop("CMCC_WEBUI_TOKEN", None)

    def test_auth_disable_file_token_succeeds(self) -> None:
        with self.TestClient(self.appmod.app, raise_server_exceptions=False) as c:
            c.post("/api/auth/setup", json={"token": "filesecret"})
            r = c.post(
                "/api/auth/disable",
                headers={"Authorization": "Bearer filesecret"},
                json={"currentToken": "filesecret"},
            )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["disabled"])


class TestStopPaths(unittest.TestCase):
    def setUp(self) -> None:
        os.environ.pop("CMCC_WEBUI_TOKEN", None)
        _fresh_home()
        from starlette.testclient import TestClient
        import cmcc_cloud_alive.webui.app as appmod

        self.appmod = appmod
        self.TestClient = TestClient

    def test_stale_job_id_stop_does_not_kill_current_job(self) -> None:
        with self.TestClient(self.appmod.app, raise_server_exceptions=False) as c:
            c.post("/api/profiles", json={"displayName": "A", "username": "u1"})
            j1 = c.post(
                "/api/profiles/A/jobs", json={"protocol": "ZTE", "mode": "dry-run"}
            ).json()["job"]["jobId"]
            c.delete("/api/profiles/A/jobs/current")
            j2 = c.post(
                "/api/profiles/A/jobs", json={"protocol": "ZTE", "mode": "dry-run"}
            ).json()["job"]["jobId"]
            self.assertNotEqual(j1, j2)
            # stopping the STALE j1 must return j1's snapshot, not touch j2
            rs = c.post(f"/api/jobs/{j1}/stop")
            self.assertEqual(rs.status_code, 200)
            self.assertEqual(rs.json()["job"]["jobId"], j1)
            prof = c.get("/api/profiles/A").json()["profile"]
            self.assertEqual(prof["jobId"], j2)
            self.assertEqual(prof["jobStatus"], "running")
            c.delete("/api/profiles/A/jobs/current")


class TestSSECrossThread(unittest.TestCase):
    def test_worker_thread_emit_wakes_consumer_immediately(self) -> None:
        from cmcc_cloud_alive.webui.orchestrator import Orchestrator

        async def run() -> float:
            o = Orchestrator()
            o.bind_loop(asyncio.get_running_loop())
            q = o.subscribe()

            def worker() -> None:
                time.sleep(0.15)
                o._emit("job_log", {"jobId": "j", "line": "round1"})

            threading.Thread(target=worker, daemon=True).start()
            t0 = time.time()
            await asyncio.wait_for(q.get(), timeout=5.0)
            return time.time() - t0

        _fresh_home()
        dt = asyncio.run(run())
        # buggy path only wakes on the 5s timeout; fixed path ~0.15s
        self.assertLess(dt, 1.0)


class TestFakeParity(unittest.TestCase):
    def test_fake_has_clear_logs_and_usid_param(self) -> None:
        _fresh_home()
        from cmcc_cloud_alive.webui.orch_runtime import FakeOrchestrator

        f = FakeOrchestrator()
        sp = Path(tempfile.mkdtemp()) / "p.json"
        sp.write_text("{}", encoding="utf-8")
        job = f.start_job("p1", sp, protocol="ZTE", mode="dry-run", user_service_id="u9")
        self.assertEqual(job["userServiceId"], "u9")
        self.assertTrue(hasattr(f, "clear_logs"))
        self.assertTrue(f.clear_logs(profile_id="p1")["ok"])


class TestFlockLeak(unittest.TestCase):
    def test_lock_released_after_build_cmd_failure(self) -> None:
        _fresh_home()
        from cmcc_cloud_alive.webui.orchestrator import Orchestrator

        o = Orchestrator()
        sp = Path(tempfile.mkdtemp()) / "p1.json"
        sp.write_text("{}", encoding="utf-8")  # no userServiceId -> _build_cmd raises
        with self.assertRaises(RuntimeError):
            o.start_job("p1", sp, protocol="ZTE", mode="live")
        # after the failure the flock must be free so a fixed profile can start
        sp.write_text(json.dumps({"userServiceId": "u1"}), encoding="utf-8")
        job = o.start_job("p1", sp, protocol="ZTE", mode="live", user_service_id="u1")
        try:
            self.assertEqual(job["status"], "running")
        finally:
            o.stop_job("p1")


class TestContractFixes(unittest.TestCase):
    def setUp(self) -> None:
        os.environ.pop("CMCC_WEBUI_TOKEN", None)
        _fresh_home()
        from starlette.testclient import TestClient
        import cmcc_cloud_alive.webui.app as appmod

        self.appmod = appmod
        self.TestClient = TestClient

    def test_select_desktop_rejects_empty_body(self) -> None:
        with self.TestClient(self.appmod.app, raise_server_exceptions=False) as c:
            c.post("/api/profiles", json={"displayName": "D", "username": "u1"})
            self.assertEqual(c.post("/api/profiles/D/select-desktop", json={}).status_code, 400)
            r = c.post(
                "/api/profiles/D/select-desktop",
                json={"userServiceId": "2663816", "protocol": "SCG"},
            )
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["profile"]["userServiceId"], "2663816")
            self.assertEqual(r.json()["profile"]["protocol"], "SCG")


class TestSharedToken(unittest.TestCase):
    def test_non_login_sync_does_not_clobber_newer_shared_token(self) -> None:
        _fresh_home()
        from cmcc_cloud_alive.webui import handlers as H

        H._sync_shared_account(
            {"username": "acct1", "sohoToken": "OLD"}, allow_token_overwrite=True
        )
        H._sync_shared_account(
            {"username": "acct1", "sohoToken": "NEW"}, allow_token_overwrite=True
        )
        # a later non-login start/patch with a stale token must NOT overwrite NEW
        H._sync_shared_account({"username": "acct1", "sohoToken": "OLD"})
        shared = H._read_state(H._shared_account_path("acct1"))
        self.assertEqual(shared.get("sohoToken"), "NEW")


if __name__ == "__main__":
    unittest.main()
