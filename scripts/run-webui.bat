@echo off
REM ==========================================================================
REM   一键启动「爱家移动云电脑」保活 WebUI —— 不需要 Docker（Windows 版）
REM
REM   用法：双击本文件，或在命令行里运行：
REM       scripts\run-webui.bat
REM ==========================================================================
setlocal
cd /d "%~dp0.."

if not defined CMCC_WEBUI_PORT set CMCC_WEBUI_PORT=8080
if not defined CMCC_WEBUI_HOST set CMCC_WEBUI_HOST=127.0.0.1

where python >nul 2>nul
if errorlevel 1 (
  echo X 没找到 Python。请先安装 Python 3.10 及以上： https://www.python.org/downloads/
  echo   安装时请勾选 "Add Python to PATH"。
  pause
  exit /b 1
)

if not exist ".venv-webui\Scripts\python.exe" (
  echo [1/3] 正在创建运行环境（首次需要一点时间）...
  python -m venv .venv-webui
)
set "PY=.venv-webui\Scripts\python.exe"

"%PY%" -c "import starlette, uvicorn, cryptography" >nul 2>nul
if errorlevel 1 (
  echo [2/3] 正在联网安装依赖，请保持网络畅通...
  "%PY%" -m pip install -q --upgrade pip
  "%PY%" -m pip install -q ".[web]"
)

echo [3/3] 启动完成
echo.
echo   在浏览器打开：  http://127.0.0.1:%CMCC_WEBUI_PORT%
echo   停止服务：      在本窗口按 Ctrl+C
echo.
"%PY%" -m cmcc_cloud_alive.webui.app
