"""End-to-end WebUI chain over the real app + real Orchestrator (dry-run only,
no network). Walks the path a real user takes and asserts each hop, including
the linux/windows/mac client profiles and the SSE stream.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest


def tearDownModule() -> None:
    import cmcc_cloud_alive.webui.common as _common

    _common._LEGACY_PROFILES_MIGRATED = False
    os.environ.pop("CMCC_ALIVE_HOME", None)
    os.environ.pop("CMCC_WEBUI_TOKEN", None)


class TestFullChain(unittest.TestCase):
    def setUp(self) -> None:
        os.environ.pop("CMCC_WEBUI_TOKEN", None)
        os.environ.pop("CMCC_DATA_DIR", None)
        home = tempfile.mkdtemp()
        os.environ["CMCC_ALIVE_HOME"] = os.path.join(home, ".cmcc-cloud-alive")
        os.makedirs(os.path.join(os.environ["CMCC_ALIVE_HOME"], "profiles"), exist_ok=True)
        import cmcc_cloud_alive.webui.common as common

        common._LEGACY_PROFILES_MIGRATED = False
        from starlette.testclient import TestClient
        import cmcc_cloud_alive.webui.app as appmod

        self.appmod = appmod
        self.client = TestClient(appmod.app, raise_server_exceptions=False)

    def test_happy_path_chain(self) -> None:
        c = self.client
        with c:  # trigger lifespan (binds ORCH loop for SSE)
            # 1. health + info are open (no token yet)
            self.assertEqual(c.get("/api/health").status_code, 200)
            info = c.get("/api/system/info").json()
            self.assertTrue(info["ok"])
            self.assertEqual(info["orchestrator"], "Orchestrator")

            # 2. enable access gate, then log in
            self.assertTrue(c.post("/api/auth/setup", json={"token": "sk-abc123"}).json()["ok"])
            self.assertEqual(
                c.get("/api/profiles").status_code, 401  # gated now
            )
            hdr = {"Authorization": "Bearer sk-abc123"}
            self.assertTrue(c.post("/api/auth/login", json={"token": "sk-abc123"}).json()["ok"])
            c.headers.update(hdr)  # carry the Bearer on every subsequent call

            # 3. create a main-account profile
            r = c.post("/api/profiles", json={"displayName": "家用", "username": "13800000000"}, headers=hdr)
            self.assertEqual(r.status_code, 201)
            pid = r.json()["profile"]["id"]

            # 4. client profile round-trips for all three OSes
            for osname in ("linux", "windows", "mac"):
                pr = c.patch(f"/api/profiles/{pid}", json={"clientProfile": osname}, headers=hdr)
                self.assertEqual(pr.status_code, 200, pr.text)
                self.assertEqual(pr.json()["profile"]["clientProfile"], osname)

            # 5. bind a desktop + user protocol (empty body rejected)
            self.assertEqual(
                c.post(f"/api/profiles/{pid}/select-desktop", json={}, headers=hdr).status_code, 400
            )
            sd = c.post(
                f"/api/profiles/{pid}/select-desktop",
                json={"userServiceId": "us-1", "desktopLabel": "家庭云", "protocol": "ZTE"},
                headers=hdr,
            )
            self.assertEqual(sd.status_code, 200)
            self.assertEqual(sd.json()["profile"]["userServiceId"], "us-1")
            self.assertEqual(sd.json()["profile"]["protocol"], "ZTE")

            # 6. start a dry-run job (no network), confirm running
            sj = c.post(f"/api/profiles/{pid}/jobs", json={"protocol": "ZTE", "mode": "dry-run"}, headers=hdr)
            self.assertEqual(sj.status_code, 202, sj.text)
            job_id = sj.json()["job"]["jobId"]
            self.assertEqual(c.get(f"/api/profiles/{pid}").json()["profile"]["jobStatus"], "running")

            # 7. logs stream in
            import time

            deadline = time.time() + 4.0
            got_logs = False
            while time.time() < deadline:
                lg = c.get(f"/api/profiles/{pid}/logs", headers=hdr).json()
                if lg.get("lines"):
                    got_logs = True
                    break
                time.sleep(0.1)
            self.assertTrue(got_logs, "no card logs streamed")

            # 8. stop the job -> profile goes idle
            self.assertEqual(
                c.delete(f"/api/profiles/{pid}/jobs/current", headers=hdr).status_code, 200
            )
            self.assertEqual(c.get(f"/api/profiles/{pid}").json()["profile"]["jobStatus"], "idle")

            # 9. clear card logs (would 500 on the Fake fallback before the parity fix)
            self.assertEqual(
                c.delete(f"/api/profiles/{pid}/logs", headers=hdr).status_code, 200
            )

            # 10. stale job_id stop must not error/kill anything now-idle
            self.assertEqual(c.post(f"/api/jobs/{job_id}/stop", headers=hdr).status_code, 200)

            # 11. delete the profile
            self.assertTrue(c.delete(f"/api/profiles/{pid}", headers=hdr).json()["deleted"])

            # 12. disable the access gate (file token) -> 200
            self.assertTrue(
                c.post("/api/auth/disable", json={"currentToken": "sk-abc123"}, headers=hdr).json()["disabled"]
            )


if __name__ == "__main__":
    unittest.main()
