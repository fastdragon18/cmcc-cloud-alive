#!/usr/bin/env python3
"""全链路保活长测 — 一键跑。40/60/120分钟三节点验收。

用法：
  python tests/long_keepalive_test.py

凭据从环境变量 CMCC_USERNAME/CMCC_PASSWORD 读取，自动跑 120 分钟。
每 5 分钟发 60 秒保活流量，每分钟检测是否关机。
40min / 60min / 120min 三节点全过 → 合格。
"""

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import threading
import time
import tempfile
import urllib.request
from pathlib import Path

# ── 凭据从环境变量读取（绝不落盘明文） ───────────────
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
CLI = str(REPO_ROOT / "bin" / "cmcc_cloud_alive.py")
USERNAME = os.environ.get("CMCC_USERNAME", "")
PASSWORD = os.environ.get("CMCC_PASSWORD", "")
DEFAULT_STATE_PATH = Path.home() / ".cmcc-cloud-alive" / "state.json"
STATE_PATH = os.environ.get(
    "CMCC_STATE_PATH",
    str(DEFAULT_STATE_PATH if DEFAULT_STATE_PATH.exists() else Path(tempfile.gettempdir()) / "long_keepalive_state.json"),
)

KEEPALIVE_INTERVAL = int(os.environ.get("CMCC_KEEPALIVE_INTERVAL", "30"))     # T4-C: HTTP heartbeat 30秒
KEEPALIVE_BURST = int(os.environ.get("CMCC_KEEPALIVE_BURST", "60"))            # 每次60秒流量
POWER_INTERVAL = int(os.environ.get("CMCC_POWER_INTERVAL", "60"))              # 每分钟检测
MILESTONES = [int(v) for v in os.environ.get("CMCC_LONGTEST_MILESTONES", "40,60,120").split(",") if v.strip()]
TOTAL_MIN = int(os.environ.get("CMCC_LONGTEST_TOTAL_MIN", str(max(MILESTONES or [120]))))
DEFAULT_REPORT_DIR = Path("/home/demo/.local/opt/GenericAgent-Desktop-Linux-Portable-v0.1.4/runtime/app/temp/hive_interactive_8h/reports")
REPORT_DIR = Path(os.environ.get("CMCC_LONGTEST_REPORT_DIR", str(DEFAULT_REPORT_DIR)))
REPORT_PREFIX = os.environ.get("CMCC_LONGTEST_REPORT_PREFIX", "T4-C_longtest")
REPORT_JSON = REPORT_DIR / f"{REPORT_PREFIX}_result.json"
REPORT_EXEC_MD = REPORT_DIR / f"{REPORT_PREFIX}_exec.md"
REPORT_CHECKPOINT_JSON = REPORT_DIR / f"{REPORT_PREFIX}_checkpoint.json"
MQTT_REPORT_JSON = REPORT_DIR / f"{REPORT_PREFIX}_mqtt.json"
MQTT_PING_INTERVAL = int(os.environ.get("CMCC_MQTT_PING_INTERVAL", "30"))
KEEPALIVE_ROUNDS = []
DISCONNECT_CODES = []
POWER_SAMPLES = []
MQTT_STATUS = {"enabled": False, "started": False, "finished": False, "ok": False, "error": "", "report": None}

# BBS 上报（如果可用）
BBS_URL = os.environ.get("BBS_URL", "http://127.0.0.1:5762")
BBS_KEY = os.environ.get("BBS_API_KEY", "")
BBS_TOKEN = os.environ.get("BBS_MASTER_TOKEN", "")


def log(msg, tag="INFO"):
    ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{tag}] {msg}", flush=True)


def bbs_post(content, title=None):
    """尝试把消息推送到 BBS（失败不影响主流程）。"""
    if not BBS_KEY or not BBS_TOKEN:
        return
    try:
        payload = {"token": BBS_TOKEN, "content": content}
        if title:
            payload["title"] = title
        body = json.dumps(payload).encode()
        url = f"{BBS_URL.rstrip('/')}/post?key={BBS_KEY}"
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=8).read()
    except Exception:
        pass  # BBS 不可用不阻塞


def display_cmd(cmd):
    """返回脱敏后的命令文本。"""
    safe = list(cmd)
    if "login" in safe:
        idx = safe.index("login")
        if len(safe) > idx + 2:
            safe[idx + 2] = "<password>"
    return " ".join(safe)


def run_cli(args_list, timeout=None):
    """调用 cmcc_cloud_alive CLI。"""
    cmd = [sys.executable, CLI, "--state", STATE_PATH] + [str(a) for a in args_list]
    log(f"$ {display_cmd(cmd)}", "CMD")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, cwd=str(REPO_ROOT))
        if r.stdout:
            print(r.stdout[-1500:], flush=True)
        if r.returncode != 0 and r.stderr:
            print(r.stderr[-500:], flush=True)
        return r
    except subprocess.TimeoutExpired:
        log("命令超时", "WARN")
        return None


def parse_usid(out):
    """从 list 输出中提取 userServiceId。"""
    try:
        data = json.loads(out)
    except Exception:
        import re
        m = re.search(r'"userServiceId"\s*:\s*(\d+)|userServiceId=(\d+)', out)
        return int(next(g for g in m.groups() if g)) if m else None
    items = data if isinstance(data, list) else data.get("list", data.get("items", []))
    for it in items:
        uid = it.get("userServiceId") or it.get("id")
        if uid:
            return int(uid)
    return None


def check_power(usid, elapsed_min=None):
    """检测云电脑是否 running。"""
    r = run_cli(["power-monitor", str(usid),
                 "--interval", "1", "--duration", "1",
                 "--no-stop-on-error"],
                timeout=30)
    if r is None:
        POWER_SAMPLES.append({"minute": elapsed_min, "status": "timeout"})
        return False
    out = r.stdout + r.stderr
    running = re.search(r'"running"\s*:\s*(true|false)', out, re.I)
    status_show = re.search(r'"vmStatusShow"\s*:\s*"([^"]+)"', out)
    status = "running" if running and running.group(1).lower() == "true" else "off"
    if status_show:
        status = status_show.group(1)
    POWER_SAMPLES.append({"minute": elapsed_min, "status": status, "returncode": r.returncode})
    return bool(running and running.group(1).lower() == "true") or "运行" in status


def extract_disconnect_codes(text):
    """从 keepalive 输出中提取 accepted/disconnect 关键信号。"""
    signals = []
    for line in text.splitlines():
        if "disconnect" not in line.lower() and "accepted" not in line.lower():
            continue
        signal = {"line": line[-300:]}
        code = re.search(r'"(?:code|resultCode|status)"\s*:\s*"?([\w.-]+)"?', line)
        if code:
            signal["code"] = code.group(1)
        accepted = re.search(r'"accepted"\s*:\s*(true|false)', line, re.I)
        if accepted:
            signal["accepted"] = accepted.group(1).lower() == "true"
        signals.append(signal)
    return signals


def build_report(account_label, usid, milestone_results, verdict=None, finished=False):
    return {
        "username": account_label,
        "statePath": STATE_PATH,
        "userServiceId": usid,
        "totalMinutes": TOTAL_MIN,
        "keepaliveIntervalSeconds": KEEPALIVE_INTERVAL,
        "keepaliveBurstSeconds": KEEPALIVE_BURST,
        "powerIntervalSeconds": POWER_INTERVAL,
        "milestones": milestone_results,
        "keepaliveRounds": KEEPALIVE_ROUNDS,
        "disconnectSignals": DISCONNECT_CODES,
        "powerSamples": POWER_SAMPLES,
        "mqttKeepalive": MQTT_STATUS,
        "verdict": verdict or "RUNNING",
        "finished": finished,
        "timestamp": dt.datetime.now().isoformat(),
    }


def write_checkpoint(account_label, usid, milestone_results):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report = build_report(account_label, usid, milestone_results)
    REPORT_CHECKPOINT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str))


def start_mqtt_keepalive(duration_seconds):
    MQTT_STATUS.update({"enabled": True, "started": True, "finished": False, "ok": False, "error": ""})

    def _run():
        try:
            from cmcc_cloud_alive import mqtt_keepalive

            report = mqtt_keepalive.smoke(
                duration_seconds=int(duration_seconds),
                report_file=str(MQTT_REPORT_JSON),
                ping_interval_seconds=MQTT_PING_INTERVAL,
                allow_long_run=True,
            )
            MQTT_STATUS["report"] = report
            MQTT_STATUS["ok"] = bool(report.get("mqttKeepaliveProven"))
        except Exception as exc:
            MQTT_STATUS["error"] = f"{type(exc).__name__}: {exc}"
            log(f"MQTT 保活线程失败: {MQTT_STATUS['error']}", "ERROR")
        finally:
            MQTT_STATUS["finished"] = True

    thread = threading.Thread(target=_run, name="mqtt-keepalive", daemon=True)
    thread.start()
    return thread


def parse_args():
    parser = argparse.ArgumentParser(description="全链路保活长测")
    parser.add_argument("--state", default=STATE_PATH, help="复用已有 cmcc-cloud-alive state 文件")
    parser.add_argument(
        "--confirm-long-run",
        action="store_true",
        help="确认执行真实 120 分钟长测；也可设置 CMCC_CONFIRM_LONG_RUN=1",
    )
    return parser.parse_args()


def require_long_run_confirmation(args):
    """Block accidental 120-minute real-device runs."""
    env_confirmed = os.environ.get("CMCC_CONFIRM_LONG_RUN") == "1"
    if args.confirm_long_run or env_confirmed:
        return
    log("长测默认会占用真实云电脑约120分钟，当前缺少显式确认。", "ERROR")
    log("确认执行请追加 --confirm-long-run，或设置 CMCC_CONFIRM_LONG_RUN=1。", "ERROR")
    sys.exit(2)


# ═══════════════════════════════════════════════════════
def main():
    global STATE_PATH
    args = parse_args()
    require_long_run_confirmation(args)
    STATE_PATH = str(Path(args.state).expanduser())
    print()
    print("╔══════════════════════════════════════════════╗")
    print("║      全链路保活长测 — 一键运行              ║")
    print("║  自动登录 → 自动保活 → 自动检测            ║")
    print("║  40/60/120 分钟三节点验收                   ║")
    print("╚══════════════════════════════════════════════╝")
    print()

    # ── 凭据守卫：优先复用已有 state；没有 state 才要求环境变量 ──
    state_exists = Path(STATE_PATH).exists()
    if not state_exists and (not USERNAME or not PASSWORD):
        log("缺少可复用 state，且缺少环境变量 CMCC_USERNAME / CMCC_PASSWORD，无法运行长测。", "ERROR")
        log("请提供 CMCC_STATE_PATH 或设置 CMCC_USERNAME/CMCC_PASSWORD。", "ERROR")
        sys.exit(2)

    account_label = USERNAME or "<state-session>"
    log(f"账号: {account_label}")
    log(f"状态文件: {STATE_PATH}")
    log(f"保活: 每 {KEEPALIVE_INTERVAL}秒 发 {KEEPALIVE_BURST}秒 屏幕流量")
    log(f"检测: 每 {POWER_INTERVAL}秒 检查是否关机")
    log(f"节点: {MILESTONES} 分钟, 全过才合格")
    log(f"总时长: {TOTAL_MIN} 分钟")
    print()

    # ── 1. 登录/复用会话 ──
    if USERNAME and PASSWORD:
        log(">>> [1/3] 登录云电脑…")
        run_cli(["login", USERNAME, PASSWORD, "--save-password"])
    else:
        log(">>> [1/3] 复用已有登录态…")

    # ── 2. 获取桌面列表 ──
    log(">>> [2/3] 获取桌面列表…")
    r = run_cli(["list"], timeout=60)
    usid = parse_usid(r.stdout) if r and r.stdout else None
    if not usid:
        log("【失败】无法自动获取桌面 ID", "ERROR")
        bbs_post(f"【长测失败】{account_label} 无法获取桌面 ID")
        sys.exit(1)
    log(f"桌面 ID: {usid}")
    run_cli(["select", str(usid)])

    bbs_post(f"【长测启动】账号={account_label} 桌面ID={usid} 总时长={TOTAL_MIN}min "
             f"节点={MILESTONES}min")

    # ── 3. 主循环 ──
    log(">>> [3/3] 进入保活+检测循环（120分钟）…")
    print()

    milestone_results = {m: None for m in MILESTONES}
    write_checkpoint(account_label, usid, milestone_results)
    t0 = time.time()
    next_power = 0.0
    next_keepalive = 0.0
    mqtt_thread = start_mqtt_keepalive(TOTAL_MIN * 60)
    log(f"MQTT TLS 保活线程已启动：PINGREQ 间隔约 {MQTT_PING_INTERVAL}s，报告 {MQTT_REPORT_JSON}")

    while True:
        elapsed = time.time() - t0
        if elapsed >= TOTAL_MIN * 60:
            break
        elapsed_min = elapsed / 60.0

        # ---- 保活触发 ----
        if elapsed >= next_keepalive:
            log(f"━━━ [{elapsed_min:.0f}min] 保活中: 发送 {KEEPALIVE_BURST}秒屏幕流量 ━━━")
            # T7-C-fix: route via `product-keepalive` (mode-2) so the ZTE
            # SPICE keepalive path fires. cmd_product_keepalive loads
            # firmAuth from state (core.get_firm_auth), classifies route
            # (product_router.classify_firm_auth_route) and, for family-cloud
            # (RouteKind.ZTE), dispatches to _run_zte_keepalive ->
            # run_zte_keepalive_session -> keepaliveRawSpiceLoop, which
            # injects BuildZTERawDisplayInit + BuildZTERawInputInit +
            # auto-reply every 25s (real SPICE channel traffic that keeps
            # the desktop powered). The legacy `keepalive` subcommand only
            # hits HTTP heartbeat/infoReport/point routes which "do not keep
            # desktop powered" (desktop_keepalive.py ~line 150) -> FAIL
            # ~30min in the T5 40min long test. args.state is satisfied by
            # the top-level parser global --state (default None -> default
            # state dir); auth is recovered from state, no extra creds.
            r = run_cli(["product-keepalive",
                         "--duration", str(KEEPALIVE_BURST),
                         "--user-service-id", str(usid)],
                        timeout=KEEPALIVE_BURST + 90)
            signals = extract_disconnect_codes((r.stdout + r.stderr) if r else "")
            round_info = {
                "minute": round(elapsed_min, 2),
                "returncode": r.returncode if r else None,
                "signals": signals,
            }
            KEEPALIVE_ROUNDS.append(round_info)
            DISCONNECT_CODES.extend(signals)
            log(f"保活轮次记录: returncode={round_info['returncode']} disconnect_signals={len(signals)}")
            write_checkpoint(account_label, usid, milestone_results)
            next_keepalive = elapsed + KEEPALIVE_INTERVAL
            continue

        # ---- 关机检测 ----
        if elapsed >= next_power:
            running = check_power(usid, round(elapsed_min, 2))
            status = "✅ 运行中" if running else "❌ 已关机/离线"
            log(f"[{elapsed_min:.0f}min] 电源状态: {status}")
            if not running:
                for m in MILESTONES:
                    if elapsed_min >= m and milestone_results[m] is None:
                        milestone_results[m] = f"FAIL(关机@ {elapsed_min:.0f}min)"
            write_checkpoint(account_label, usid, milestone_results)
            next_power = elapsed + POWER_INTERVAL

        # ---- 节点判定 ----
        for m in MILESTONES:
            if milestone_results[m] is None and elapsed_min >= m:
                running = check_power(usid, round(elapsed_min, 2))
                milestone_results[m] = {
                    "result": "PASS" if running else "FAIL",
                    "status": "running" if running else "off_or_unknown",
                    "minute": round(elapsed_min, 2),
                    "time": dt.datetime.now().isoformat(),
                    "keepaliveRounds": len(KEEPALIVE_ROUNDS),
                    "recentDisconnectSignals": KEEPALIVE_ROUNDS[-3:],
                }
                log(f"◆◆◆ 节点 {m}min: {milestone_results[m]['result']} ◆◆◆", "MILE")
                bbs_post(f"【T4-C长测节点】{m}min {milestone_results[m]['result']} "
                         f"状态={milestone_results[m]['status']} "
                         f"保活轮次={len(KEEPALIVE_ROUNDS)} disconnect信号={len(DISCONNECT_CODES)} "
                         f"mqtt_ok={MQTT_STATUS.get('ok')}")
                write_checkpoint(account_label, usid, milestone_results)

        time.sleep(5)

    # ── 4. 汇总报告 ──
    print()
    print("╔══════════════════════════════════════════════╗")
    print("║              测试报告                        ║")
    print("╚══════════════════════════════════════════════╝")
    mqtt_thread.join(timeout=15)
    if not MQTT_STATUS.get("finished"):
        MQTT_STATUS["error"] = "MQTT keepalive thread did not finish before report cutoff"
    all_pass = bool(MQTT_STATUS.get("ok"))
    for m in MILESTONES:
        res = milestone_results.get(m)
        ok = isinstance(res, dict) and res.get("result") == "PASS"
        all_pass = all_pass and ok
        icon = "✅" if ok else "❌"
        printable = res if res is not None else "未到达"
        print(f"  节点 {m:>3}分钟 : {printable}  {icon}")
    verdict = "合格 (QUALIFIED)" if all_pass else "不合格 (FAILED)"
    print(f"  ─────────────────────────────")
    print(f"  最终判定: {verdict}")
    print()

    log(f"判定: {verdict}", "VERDICT")
    bbs_post(f"【长测完成】账号={account_label} 桌面ID={usid} "
             f"节点结果={milestone_results} 判定={verdict}",
             title=f"长测报告: {verdict}")

    # 写本地报告
    report = build_report(account_label, usid, milestone_results, finished=True, verdict=verdict)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    REPORT_CHECKPOINT_JSON.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    exec_md = "\n".join([
        "# T4-C Long Keepalive Execution",
        "",
        f"- Started/finished at: {report['timestamp']}",
        f"- State path: {STATE_PATH}",
        f"- Desktop ID: {usid}",
        f"- Total minutes: {TOTAL_MIN}",
        f"- Keepalive rounds: {len(KEEPALIVE_ROUNDS)}",
        f"- Disconnect signals: {len(DISCONNECT_CODES)}",
        f"- Power samples: {len(POWER_SAMPLES)}",
        f"- Verdict: {verdict}",
        f"- Result JSON: {REPORT_JSON}",
        "",
    ])
    REPORT_EXEC_MD.write_text(exec_md)
    log(f"报告已保存: {REPORT_JSON}")
    log(f"执行记录已保存: {REPORT_EXEC_MD}")

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
