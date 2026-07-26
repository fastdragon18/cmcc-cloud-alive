  function randomToken(len) {
    const n = Math.max(8, Math.min(64, len || 16));
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let out = "";
    try {
      const arr = new Uint8Array(n);
      crypto.getRandomValues(arr);
      for (let i = 0; i < n; i++) out += alphabet[arr[i] % alphabet.length];
      return out;
    } catch (_) {
      for (let i = 0; i < n; i++) {
        out += alphabet[Math.floor(Math.random() * alphabet.length)];
      }
      return out;
    }
  }

  function setGateErr(msg, which) {
    // which: "setup" | "login" | undefined (both clear / login preferred for display)
    const setupEl = $("#gate-setup-err");
    const loginEl = $("#gate-login-err") || $("#gate-error");
    if (which === "setup") {
      if (setupEl) setupEl.textContent = msg || "";
      if (loginEl && !msg) loginEl.textContent = "";
      return;
    }
    if (which === "login") {
      if (loginEl) loginEl.textContent = msg || "";
      if (setupEl && !msg) setupEl.textContent = "";
      return;
    }
    if (setupEl) setupEl.textContent = msg || "";
    if (loginEl) loginEl.textContent = msg || "";
  }

  function showAccessGate(mode) {
    const gate = $("#access-gate");
    const app = $("#app");
    if (!gate) return;
    state.gateMode = mode || (state.setupRequired ? "setup" : "login");
    // Align with showTokenModal: clear class + attr + property so [hidden] CSS never sticks
    gate.classList.remove("hidden");
    gate.removeAttribute("hidden");
    gate.hidden = false;
    gate.setAttribute("aria-hidden", "false");
    if (app) {
      app.classList.add("gate-locked");
      app.setAttribute("aria-hidden", "true");
    }
    const title = $("#gate-title");
    const sub = $("#gate-sub");
    const setupPane = $("#gate-setup-panel");
    const loginPane = $("#gate-login-panel");
    const isSetup = state.gateMode === "setup";
    if (title) title.textContent = isSetup ? "设置访问密钥" : "输入访问密钥";
    if (sub) {
      sub.textContent = isSetup
        ? "首次部署可选：保护控制台，之后也可在顶栏修改。"
        : "此控制台已启用鉴权，输入密钥后进入。";
    }
    if (setupPane) {
      setupPane.classList.toggle("hidden", !isSetup);
      if (isSetup) {
        setupPane.removeAttribute("hidden");
        setupPane.hidden = false;
      }
    }
    if (loginPane) {
      loginPane.classList.toggle("hidden", isSetup);
      if (!isSetup) {
        loginPane.removeAttribute("hidden");
        loginPane.hidden = false;
      }
    }
    setGateErr("");
    const focusEl = isSetup ? $("#gate-setup-input") : $("#gate-login-input");
    if (focusEl) {
      try {
        focusEl.focus();
      } catch (_) { logCatch("catch", _); }
    }
    updateTokenBtn();
  }

  function hideAccessGate() {
    const gate = $("#access-gate");
    const app = $("#app");
    if (gate) {
      gate.classList.add("hidden");
      gate.setAttribute("hidden", "");
      gate.hidden = true;
      gate.setAttribute("aria-hidden", "true");
    }
    if (app) {
      app.classList.remove("gate-locked");
      app.setAttribute("aria-hidden", "false");
    }
    state.gateMode = "";
    setGateErr("");
    updateTokenBtn();
  }

  async function refreshAuthStatus() {
    try {
      const st = await api("/api/auth/status");
      state.setupRequired = !!(st && st.setupRequired);
      state.tokenRequired = !!(st && st.tokenRequired);
      state.authEnabled = !!(st && (st.authEnabled != null ? st.authEnabled : st.tokenRequired));
      state.authSource = (st && (st.tokenSource || st.source)) || state.authSource || "";
      updateTokenBtn();
      return st;
    } catch (e) {
      return null;
    }
  }

  async function enterConsoleAfterAuth() {
    hideAccessGate();
    try {
      await loadSys();
    } catch (_) { logCatch("catch", _); }
    try {
      await loadProfiles(true);
    } catch (_) { logCatch("catch", _); }
    try {
      connectSSE();
    } catch (_) { logCatch("catch", _); }
    try {
      startPolling();
    } catch (_) { logCatch("catch", _); }
    updateTokenBtn();
  }

  async function submitGateSetup() {
    setGateErr("", "setup");
    const input = $("#gate-setup-input");
    let token = (input && input.value || "").trim();
    if (!token) {
      setGateErr("请输入要设置的访问密钥，或点「生成」", "setup");
      return;
    }
    if (token.length < 4) {
      setGateErr("密钥至少 4 位", "setup");
      return;
    }
    const btn = $("#gate-setup-ok");
    if (btn) btn.disabled = true;
    try {
      const res = await api("/api/auth/setup", {
        method: "POST",
        body: JSON.stringify({ token: token }),
      });
      const saved = (res && (res.token || token)) || token;
      setToken(saved);
      state.setupRequired = false;
      state.tokenRequired = true;
      state.authSource = "file";
      updateTokenBtn();
      hideAccessGate();
      toast("访问密钥已设置");
      pushGlobal("访问密钥首次设置完成");
      try {
        await enterConsoleAfterAuth();
      } catch (e2) {
        toast(humanError(e2, "进入控制台失败"), true);
      }
    } catch (e) {
      setGateErr(humanError(e, "设置密钥失败"), "setup");
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function submitGateLogin() {
    setGateErr("", "login");
    const input = $("#gate-login-input");
    const token = (input && input.value || "").trim();
    if (!token) {
      setGateErr("请输入访问密钥", "login");
      return;
    }
    const btn = $("#gate-login-ok");
    if (btn) btn.disabled = true;
    try {
      await api("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ token: token }),
      });
      setToken(token);
      state.tokenRequired = true;
      updateTokenBtn();
      hideAccessGate();
      toast("已进入控制台");
      pushGlobal("访问密钥验证通过");
      // Must also connectSSE()+startPolling(); a bare loadProfiles left the
      // console static (no live logs/status) until a manual F5.
      try {
        await enterConsoleAfterAuth();
      } catch (e2) {
        toast(humanError(e2, "加载账号失败"), true);
      }
    } catch (e) {
      setGateErr(humanError(e, "访问密钥错误"), "login");
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function setTokenModalErr(msg) {
    const el = $("#token-modal-err");
    if (el) el.textContent = msg || "";
  }

  function hideTokenModal() {
    const m = $("#token-modal");
    if (!m) return;
    m.classList.add("hidden");
    m.hidden = true;
    m.setAttribute("aria-hidden", "true");
    setTokenModalErr("");
  }

  function showTokenModal() {
    const m = $("#token-modal");
    if (!m) {
      // fallback: if HTML not deployed yet
      toast("令牌管理面板未加载，请刷新页面", true);
      return;
    }
    m.classList.remove("hidden");
    m.hidden = false;
    m.setAttribute("aria-hidden", "false");
    const cur = getToken() || "";
    const curIn = $("#token-modal-current");
    const newIn = $("#token-modal-new");
    if (curIn) curIn.value = cur;
    if (newIn) newIn.value = "";
    const authOn = !!(state.authEnabled || state.tokenRequired);
    const st = $("#token-modal-status");
    if (st) {
      if (authOn) {
        st.textContent =
          "服务器鉴权：已启用" +
          (state.authSource ? "（" + state.authSource + "）" : "") +
          (cur ? " · 本机已保存密钥" : " · 本机无密钥") +
          "。改密请填「新密钥」。";
      } else {
        st.textContent =
          "服务器鉴权：已关闭。" +
          (cur
            ? "本机已有密钥，点「启用密钥」即可打开服务器鉴权（不必再填新密钥）。"
            : "在「当前密钥」填入要启用的密钥后点「启用密钥」；若要换成别的再填「新密钥」并用「修改密钥」。");
      }
    }
    // 两个按钮始终可见：启用=开鉴权；修改=改成新密钥
    const enBtn = $("#token-modal-enable");
    const chBtn = $("#token-modal-change");
    if (enBtn) {
      enBtn.hidden = false;
      enBtn.style.display = "";
      enBtn.disabled = authOn; // 已启用时只能改密/关闭
      enBtn.title = authOn ? "服务器已启用鉴权，请用「修改密钥」或先关闭鉴权" : "用「当前密钥」启用服务器鉴权";
    }
    if (chBtn) {
      chBtn.hidden = false;
      chBtn.style.display = "";
      chBtn.disabled = false;
      chBtn.title = authOn ? "校验当前密钥后写入新密钥" : "写入新密钥并启用服务器鉴权";
    }
    setTokenModalErr("");
  }

  async function tokenModalSubmit(mode) {
    setTokenModalErr("");
    const curIn = $("#token-modal-current");
    const newIn = $("#token-modal-new");
    const cur = ((curIn && curIn.value) || getToken() || "").trim();
    const tNew = ((newIn && newIn.value) || "").trim();
    const authOn = !!(state.authEnabled || state.tokenRequired);

    // 启用 = 打开服务器鉴权：优先用「当前密钥」/本机已存密钥，不要求填新密钥
    // 修改 = 改成「新密钥」（鉴权已开时要校验当前密钥；未开时等同设定并启用）
    let writeToken = "";
    if (mode === "enable") {
      if (authOn) {
        setTokenModalErr("服务器已启用鉴权，请用「修改密钥」或先「关闭服务器鉴权」");
        return;
      }
      writeToken = cur;
      if (!writeToken || writeToken.length < 4 || /\s/.test(writeToken)) {
        setTokenModalErr("启用鉴权请在「当前密钥」填入至少 4 位无空格密钥（本机已保存会自动填充）");
        return;
      }
    } else {
      // change
      writeToken = tNew;
      if (!writeToken || writeToken.length < 4 || /\s/.test(writeToken)) {
        setTokenModalErr("修改密钥请在「新密钥」填入至少 4 位无空格密钥");
        return;
      }
      if (authOn && !cur) {
        setTokenModalErr("修改密钥需要填写当前密钥");
        return;
      }
    }
    try {
      await api("/api/auth/change", {
        method: "POST",
        body: JSON.stringify({
          currentToken: cur || undefined,
          oldToken: cur || undefined,
          newToken: writeToken,
          token: writeToken,
        }),
      });
      setToken(writeToken);
      state.tokenRequired = true;
      state.authEnabled = true;
      state.setupRequired = false;
      updateTokenBtn();
      hideTokenModal();
      // The live SSE URL embeds the old token; reconnect so it doesn't 401 at
      // the next retry and silently stop streaming keepalive logs.
      reconnectSSE();
      toast(mode === "enable" ? "服务器访问鉴权已启用" : "服务器访问密钥已修改");
      pushGlobal(mode === "enable" ? "访问鉴权已启用" : "访问密钥已修改");
      await refreshAuthStatus();
    } catch (e) {
      setTokenModalErr(humanError(e, mode === "enable" ? "启用密钥失败" : "修改密钥失败"));
    }
  }

  function tokenModalClearLocal() {
    setToken("");
    updateTokenBtn();
    hideTokenModal();
    toast("已清除本机密钥");
    if (state.authEnabled || state.tokenRequired) {
      showAccessGate("login");
    }
  }

  async function tokenModalDisable() {
    setTokenModalErr("");
    const curIn = $("#token-modal-current");
    const cur = ((curIn && curIn.value) || getToken() || "").trim();
    if (!window.confirm("确认关闭服务器访问鉴权？关闭后任何人可打开控制台。")) {
      return;
    }
    try {
      await api("/api/auth/disable", {
        method: "POST",
        body: JSON.stringify({
          currentToken: cur || undefined,
          oldToken: cur || undefined,
          token: cur || undefined,
        }),
      });
      setToken("");
      state.tokenRequired = false;
      state.authEnabled = false;
      state.setupRequired = false;
      updateTokenBtn();
      hideTokenModal();
      hideAccessGate();
      toast("已关闭服务器鉴权");
      pushGlobal("访问鉴权已关闭");
      await refreshAuthStatus();
      try {
        await loadSys();
        await loadProfiles(true);
      } catch (_) { logCatch("catch", _); }
    } catch (e) {
      setTokenModalErr(humanError(e, "关闭鉴权失败"));
    }
  }

  function wireTokenModal() {
    const close = $("#token-modal-close");
    if (close && !close.dataset.bound) {
      close.dataset.bound = "1";
      close.addEventListener("click", hideTokenModal);
    }
    const enable = $("#token-modal-enable");
    if (enable && !enable.dataset.bound) {
      enable.dataset.bound = "1";
      enable.addEventListener("click", function () {
        tokenModalSubmit("enable").catch(function (err) { logCatch("promise", err); });
      });
    }
    const change = $("#token-modal-change");
    if (change && !change.dataset.bound) {
      change.dataset.bound = "1";
      change.addEventListener("click", function () {
        tokenModalSubmit("change").catch(function (err) { logCatch("promise", err); });
      });
    }
    const clearBtn = $("#token-modal-clear");
    if (clearBtn && !clearBtn.dataset.bound) {
      clearBtn.dataset.bound = "1";
      clearBtn.addEventListener("click", tokenModalClearLocal);
    }
    const dis = $("#token-modal-disable");
    if (dis && !dis.dataset.bound) {
      dis.dataset.bound = "1";
      dis.addEventListener("click", function () {
        tokenModalDisable().catch(function (err) { logCatch("promise", err); });
      });
    }
    const modal = $("#token-modal");
    if (modal && !modal.dataset.boundBackdrop) {
      modal.dataset.boundBackdrop = "1";
      modal.addEventListener("click", function (ev) {
        if (ev.target === modal) hideTokenModal();
      });
    }
  }

  async function openTokenDialog() {
    // gate6: need login gate when server auth on but no local token
    await refreshAuthStatus();
    if ((state.authEnabled || state.tokenRequired) && !getToken()) {
      showAccessGate("login");
      return;
    }
    showTokenModal();
  }

  
  async function submitGateSetupSkip() {
    // Leave auth disabled: no token file, enter console without forcing setup.
    setGateErr("", "setup");
    try {
      // Leave auth disabled server-side (no token file). /api/auth/disable is
      // the real route; already-no-token just returns a benign 400/200.
      try {
        await api("/api/auth/disable", { method: "POST", body: "{}" });
      } catch (e1) {
        /* ok: already no token on server */
      }
      setToken("");
      state.setupRequired = false;
      state.tokenRequired = false;
      state.authEnabled = false;
      updateTokenBtn && updateTokenBtn();
      // toast(msg, isError): second arg is a boolean; "ok" is truthy and would
      // paint this success message red. Enter the console for real (SSE+poll).
      if (typeof toast === "function") toast("已跳过访问密钥，控制台可直接使用");
      try { await enterConsoleAfterAuth(); } catch (e) { logCatch("catch", e); }
    } catch (err) {
      setGateErr((err && err.message) || String(err), "setup");
    }
  }


  function bindPasswordReveal(btnId, inputId) {
    const btn = document.getElementById(btnId);
    const input = document.getElementById(inputId);
    if (!btn || !input || btn.dataset.bound) return;
    btn.dataset.bound = "1";
    // token-modal 用短文案；向导/门控保持「显示密钥」
    const short = String(btnId || "").indexOf("token-modal-show") === 0;
    const setLabel = function (visible) {
      const hideTxt = short ? "隐藏" : "隐藏密钥";
      const showTxt = short ? "显示" : "显示密钥";
      btn.textContent = visible ? hideTxt : showTxt;
      btn.setAttribute("aria-pressed", visible ? "true" : "false");
      btn.setAttribute("aria-label", visible ? hideTxt : showTxt);
    };
    setLabel(input.type !== "password");
    btn.addEventListener("click", function () {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      setLabel(show);
    });
  }

function wireAccessGate() {
    bindPasswordReveal("gate-setup-show", "gate-setup-input");
    bindPasswordReveal("gate-login-show", "gate-login-input");
    bindPasswordReveal("token-modal-show-current", "token-modal-current");
    bindPasswordReveal("token-modal-show-new", "token-modal-new");

    const gen = $("#gate-setup-gen");
    if (gen && !gen.dataset.bound) {
      gen.dataset.bound = "1";
      gen.addEventListener("click", function () {
        const input = $("#gate-setup-input");
        if (!input) return;
        const arr = new Uint8Array(18);
        crypto.getRandomValues(arr);
        let s = "";
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (let i = 0; i < arr.length; i++) s += alphabet[arr[i] % alphabet.length];
        input.value = s;
        setGateErr("", "setup");
      });
    }
    const setupSkip = $("#gate-setup-skip");
    if (setupSkip && !setupSkip.dataset.bound) {
      setupSkip.dataset.bound = "1";
      setupSkip.addEventListener("click", function () {
        submitGateSetupSkip().catch(function (err) { logCatch("promise", err); });
      });
    }
    const setupOk = $("#gate-setup-ok");
    if (setupOk && !setupOk.dataset.bound) {
      setupOk.dataset.bound = "1";
      setupOk.addEventListener("click", function () {
        submitGateSetup().catch(function (err) { logCatch("promise", err); });
      });
    }
    const loginOk = $("#gate-login-ok");
    if (loginOk && !loginOk.dataset.bound) {
      loginOk.dataset.bound = "1";
      loginOk.addEventListener("click", function () {
        submitGateLogin().catch(function (err) { logCatch("promise", err); });
      });
    }
    ["gate-setup-input", "gate-login-input"].forEach(function (id) {
      const el = document.getElementById(id);
      if (!el || el.dataset.bound) return;
      el.dataset.bound = "1";
      el.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter") {
          ev.preventDefault();
          if (id === "gate-setup-input") submitGateSetup().catch(function (err) { logCatch("promise", err); });
          else submitGateLogin().catch(function (err) { logCatch("promise", err); });
        }
      });
    });
    ["gate-setup-show", "gate-login-show"].forEach(function (id) {
      const el = document.getElementById(id);
      if (!el || el.dataset.bound) return;
      el.dataset.bound = "1";
      el.addEventListener("change", function () {
        const inputId = id.indexOf("setup") >= 0 ? "gate-setup-input" : "gate-login-input";
        const input = document.getElementById(inputId);
        if (input) input.type = el.checked ? "text" : "password";
      });
    });
  }

