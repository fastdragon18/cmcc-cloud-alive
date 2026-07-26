"""J2 orchestrator unit + TestClient dual-profile dry-run (no LIVE)."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Ensure package importable from repo root
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class TestOrchestratorUnit(unittest.TestCase):
    def setUp(self) -> None:
        os.environ.pop("CMCC_WEBUI_ALLOW_LIVE", None)
        from cmcc_cloud_alive.webui.orchestrator import Orchestrator

        self.Orchestrator = Orchestrator
        self.orch = Orchestrator()

    def test_import_and_class_name(self) -> None:
        self.assertEqual(type(self.orch).__name__, "Orchestrator")

    def test_dry_run_start_stop(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "p1.json"
            state.write_text(
                json.dumps({"userServiceId": "fixture-zte-d9"}, ensure_ascii=False),
                encoding="utf-8",
            )
            job = self.orch.start_job(
                "p1",
                state,
                protocol="ZTE",
                mode="dry-run",
                traffic_sec=90,
            )
            self.assertEqual(job["status"], "running")
            self.assertEqual(job["mode"], "dry-run")
            self.assertEqual(job["backend"], "fake")
            self.assertIsNone(job.get("pid"))
            st = self.orch.get_status("p1")
            self.assertEqual(st["status"], "running")
            self.assertEqual(st["jobId"], job["jobId"])
            # wait for full OPS#497 product markers (OPEN#555 / ACK#560)
            deadline = time.time() + 4.0
            lines = []
            while time.time() < deadline:
                lines = self.orch.recent_logs(job_id=job["jobId"])
                text_so_far = "\n".join(x.get("line") or "" for x in lines)
                if (
                    "手选" in text_so_far
                    and "kind=" in text_so_far
                    and "云桌面状态" in text_so_far
                ):
                    break
                time.sleep(0.05)
            text = "\n".join(x.get("line") or "" for x in lines)
            self.assertIn("爱家移动云电脑", text, lines)
            self.assertIn("手选", text, lines)
            self.assertIn("userServiceId=fixture-zte-d9", text, lines)
            self.assertIn("duration=", text, lines)
            self.assertIn("kind=zte", text, lines)
            self.assertIn("ok=", text, lines)
            self.assertIn("stage=", text, lines)
            self.assertIn("云桌面状态", text, lines)
            self.assertTrue(
                any("进入保活循环" in (x.get("line") or "") for x in lines)
                or any("保活连接#" in (x.get("line") or "") for x in lines),
                lines,
            )
            self.assertNotIn("[live]", text, lines)
            # tick spam removed; meta may still mention dry-run once
            self.assertFalse(
                any((x.get("line") or "").startswith("[dry-run] tick=") for x in lines),
                lines,
            )
            stopped = self.orch.stop_job("p1")
            self.assertEqual(stopped["status"], "stopped")
            # _mark_stopped intentionally drops the profile->job mapping so a card
            # doesn't keep showing a long-dead job as its live status; get_status
            # therefore reports idle (not "stopped") once a job is stopped.
            st2 = self.orch.get_status("p1")
            self.assertEqual(st2["status"], "idle")
            self.assertIsNone(st2["jobId"])

    def test_live_watch_multiline_passthrough_no_live_prefix(self) -> None:
        """Simulated child log: multi-line burst must all pass; no [live] prefix."""
        from cmcc_cloud_alive.webui.orchestrator import SubprocessBackend

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            state = td_path / "p1.json"
            state.write_text("{}", encoding="utf-8")
            log_path = td_path / "child.log"
            lock_path = td_path / "p1.lock"
            stop_evt = __import__("threading").Event()
            be = SubprocessBackend(
                self.orch,
                job_id="job-test-ml",
                state_path=state,
                protocol="ZTE",
                extra_args=[],
                stop_evt=stop_evt,
                log_path=log_path,
                lock_path=lock_path,
            )
            # seed multi-line file as if child wrote a burst
            payload = (
                "移动云电脑保活工具\n"
                "  协议：ZTE\n"
                "  状态：running\n"
                "heartbeat ok\n"
            )
            log_path.write_text(payload, encoding="utf-8")
            # exercise drain from offset 0 (full file)
            offset, pending = be._drain_log(0, "", final=True)
            self.assertEqual(pending, "")
            self.assertEqual(offset, len(payload.encode("utf-8")))
            lines = self.orch.recent_logs(job_id="job-test-ml")
            texts = [x.get("line") or "" for x in lines]
            self.assertEqual(
                texts,
                [
                    "移动云电脑保活工具",
                    "  协议：ZTE",
                    "  状态：running",
                    "heartbeat ok",
                ],
            )
            self.assertTrue(all(not t.startswith("[live]") for t in texts), texts)

    def test_profile_mutex(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "p1.json"
            state.write_text("{}", encoding="utf-8")
            self.orch.start_job("p1", state, protocol="ZTE", mode="dry-run")
            with self.assertRaises(RuntimeError) as ctx:
                self.orch.start_job("p1", state, protocol="SCG", mode="dry-run")
            self.assertEqual(str(ctx.exception), "PROFILE_IN_USE")
            self.orch.stop_job("p1")

    def test_dual_profile_parallel(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            s1 = Path(td) / "a.json"
            s2 = Path(td) / "b.json"
            s1.write_text("{}", encoding="utf-8")
            s2.write_text("{}", encoding="utf-8")
            j1 = self.orch.start_job("alpha", s1, protocol="ZTE", mode="dry-run")
            j2 = self.orch.start_job("beta", s2, protocol="SCG", mode="dry-run")
            self.assertNotEqual(j1["jobId"], j2["jobId"])
            jobs = self.orch.list_jobs()
            running = [j for j in jobs if j["status"] == "running"]
            self.assertGreaterEqual(len(running), 2)
            self.orch.stop_job("alpha")
            self.orch.stop_job("beta")

    def test_live_is_never_gated(self) -> None:
        """#862: the LIVE gate was intentionally removed — live keepalive is
        always allowed. The only barrier to spawning is a resolvable desktop, so
        a state without userServiceId fails with that specific error, NOT a
        LIVE_DISABLED gate (which must no longer exist)."""
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "p1.json"
            state.write_text("{}", encoding="utf-8")
            with self.assertRaises(RuntimeError) as ctx:
                self.orch.start_job("p1", state, protocol="ZTE", mode="live")
            msg = str(ctx.exception)
            self.assertNotIn("LIVE_DISABLED", msg)
            self.assertIn("userServiceId", msg)

    def test_live_allowed_with_userservice(self) -> None:
        """A live start with a resolvable desktop spawns a real child (no gate)."""
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "p1.json"
            state.write_text(
                json.dumps({"userServiceId": "u-live-1"}), encoding="utf-8"
            )
            job = self.orch.start_job(
                "p1", state, protocol="ZTE", mode="live", user_service_id="u-live-1"
            )
            try:
                self.assertEqual(job["status"], "running")
                self.assertEqual(job["backend"], "subprocess")
            finally:
                self.orch.stop_job("p1")


class TestWebUIOrchestratorLoad(unittest.TestCase):
    def test_app_loads_real_orchestrator(self) -> None:
        # fresh import path
        import importlib

        # ensure no leftover env forces weird paths
        os.environ.pop("CMCC_WEBUI_ALLOW_LIVE", None)
        import cmcc_cloud_alive.webui.app as appmod

        importlib.reload(appmod)
        self.assertEqual(type(appmod.ORCH).__name__, "Orchestrator")
        # health payload
        try:
            from starlette.testclient import TestClient
        except Exception as e:  # pragma: no cover
            self.skipTest(f"starlette missing: {e}")
        client = TestClient(appmod.app)
        r = client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body.get("orchestrator"), "Orchestrator")

    def test_dual_profile_via_api(self) -> None:
        import importlib
        import cmcc_cloud_alive.webui.app as appmod

        try:
            from starlette.testclient import TestClient
        except Exception as e:  # pragma: no cover
            self.skipTest(f"starlette missing: {e}")

        with tempfile.TemporaryDirectory() as td:
            os.environ["CMCC_DATA_DIR"] = td
            # re-import so profiles_dir uses temp + fresh ORCH
            importlib.reload(appmod)
            client = TestClient(appmod.app)
            # profiles are filesystem-backed; write known ids
            pdir = Path(td) / "profiles"
            pdir.mkdir(parents=True, exist_ok=True)
            (pdir / "alice.json").write_text(
                json.dumps({"displayName": "alice", "protocol": "ZTE"}), encoding="utf-8"
            )
            (pdir / "bob.json").write_text(
                json.dumps({"displayName": "bob", "protocol": "SCG"}), encoding="utf-8"
            )
            # start both dry-run (API returns 202 Accepted)
            r1 = client.post("/api/profiles/alice/jobs", json={"protocol": "ZTE", "mode": "dry-run"})
            r2 = client.post("/api/profiles/bob/jobs", json={"protocol": "SCG", "mode": "dry-run"})
            self.assertIn(r1.status_code, (200, 202), r1.text)
            self.assertIn(r2.status_code, (200, 202), r2.text)
            j1 = r1.json().get("job") or {}
            j2 = r2.json().get("job") or {}
            self.assertEqual(j1.get("status"), "running")
            self.assertEqual(j2.get("status"), "running")
            self.assertEqual(j1.get("backend"), "fake")
            self.assertNotEqual(j1.get("jobId"), j2.get("jobId"))
            # mutex
            r3 = client.post("/api/profiles/alice/jobs", json={"protocol": "ZTE", "mode": "dry-run"})
            self.assertEqual(r3.status_code, 409, r3.text)
            # stop via DELETE current + POST job stop
            d1 = client.delete("/api/profiles/alice/jobs/current")
            self.assertIn(d1.status_code, (200, 404), d1.text)
            jid2 = j2.get("jobId")
            if jid2:
                s2 = client.post(f"/api/jobs/{jid2}/stop")
                self.assertIn(s2.status_code, (200, 404), s2.text)


if __name__ == "__main__":
    unittest.main()
