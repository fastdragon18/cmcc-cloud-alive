#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────────────────
#  一键启动「爱家移动云电脑」保活 WebUI —— 不需要 Docker
#
#  用法：把下面这一整行复制到终端，回车即可
#      bash scripts/run-webui.sh
#
#  想换端口就在前面加（默认 8080）：
#      CMCC_WEBUI_PORT=9000 bash scripts/run-webui.sh
# ───────────────────────────────────────────────────────────────────────────
set -e
cd "$(dirname "$0")/.."

PORT="${CMCC_WEBUI_PORT:-8080}"
HOST="${CMCC_WEBUI_HOST:-127.0.0.1}"
VENV=".venv-webui"

# 选 python：优先 python3，其次 python
PYBIN="$(command -v python3 || command -v python || true)"
if [ -z "$PYBIN" ]; then
  echo "✗ 没找到 Python。请先安装 Python 3.10 及以上： https://www.python.org/downloads/"
  exit 1
fi

# 1) 建一个独立运行环境（不弄乱系统 Python）
if [ ! -x "$VENV/bin/python" ]; then
  echo "[1/3] 正在创建运行环境（首次需要一点时间）…"
  "$PYBIN" -m venv "$VENV"
fi
PY="$VENV/bin/python"

# 2) 安装依赖：优先用随附离线包（Linux 免联网），装不上再联网
if ! "$PY" -c "import starlette, uvicorn, cryptography" >/dev/null 2>&1; then
  echo "[2/3] 正在安装依赖…"
  "$PY" -m pip install -q --upgrade pip >/dev/null 2>&1 || true
  if ! "$PY" -m pip install -q --no-index --find-links=docker/wheels ".[web]" >/dev/null 2>&1; then
    echo "      （离线包不适用本机，改为联网安装，请保持网络畅通）"
    "$PY" -m pip install -q ".[web]"
  fi
fi

# 3) 启动
echo "[3/3] 启动完成 ✅"
echo ""
echo "  ┌────────────────────────────────────────────┐"
echo "  │  在浏览器打开：  http://127.0.0.1:${PORT}"
echo "  │  停止服务：      在本窗口按 Ctrl+C           │"
echo "  └────────────────────────────────────────────┘"
echo ""
exec env CMCC_WEBUI_HOST="$HOST" CMCC_WEBUI_PORT="$PORT" "$PY" -m cmcc_cloud_alive.webui.app
