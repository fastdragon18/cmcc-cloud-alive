  function cardHtml(p) {
    const pid = p.id;
    const st = statusOf(p);
    const open = state.configPid === pid;
    const d = ensureDraft(pid, p);
    const busy = !!state.busy[pid];
    const job = jobOf(p);
    const name = p.displayName || pid;
    const user = p.usernameMasked || "未设置账号";
    const usid = d.userServiceId || p.userServiceId || "";
    let deskLabel = d.desktopLabel || p.desktopLabel || "";
    /* resolve label from cached list for card-meta only; never spu on surface */
    if (usid && !deskLabel) {
      const dlist = state.desktops[pid] || [];
      for (let i = 0; i < dlist.length; i++) {
        const x = dlist[i];
        const xid = x.userServiceId || x.id || "";
        if (xid === usid) {
          deskLabel = x.desktopLabel || x.name || x.label || "";
          break;
        }
      }
    }
    /* HARD_GATE#736: surface id-only; no long desk/spu string */
    const deskIdText = usid || "未选";
    const deskShort = deskLabel || usid || "未选桌面";
    const client = d.clientProfile || p.clientProfile || "linux";
    const protocol =
      resolveUserProtocol(d.protocol, p && p.protocol, p && p.lastOfficialProtocol, p && p.protocolHint, job && job.protocol);
    const mode = d.mode || (p && p.mode) || (job && job.mode) || "live";
    /* HARD_GATE#871: 云桌面状态 = 桌面列表 / job / 日志「云桌面状态：xxx」缓存 */
    let deskStatus = "—";
    if (usid) {
      const dlist = state.desktops[pid] || [];
      for (let i = 0; i < dlist.length; i++) {
        const x = dlist[i];
        const xid = x.userServiceId || x.id || "";
        if (String(xid) === String(usid)) {
          deskStatus = desktopStatusText(x);
          break;
        }
      }
    }
    if (deskStatus === "—" || !deskStatus) {
      const jst =
        (job &&
          (job.desktopStatus ||
            job.vmStatusShow ||
            job.statusText ||
            job.cloudStatus)) ||
        "";
      if (jst) deskStatus = String(jst);
    }
    if ((deskStatus === "—" || !deskStatus) && state.desktopStatusByPid[pid]) {
      deskStatus = String(state.desktopStatusByPid[pid]);
    }
    if (deskStatus === "—" || !deskStatus) {
      const fromLog = extractDesktopStatusFromLogs(pid);
      if (fromLog) deskStatus = fromLog;
    }
    if ((deskStatus === "—" || !deskStatus) && (st === "running" || (job && job.status === "running"))) {
      deskStatus = "查询中…";
    }
    const errLine = String(state.cardMsg[pid] || "").trim();
    const running = st === "running";

    return (
      '<article class="card status-' +
      esc(st) +
      (open ? " is-configuring" : "") +
      '" data-id="' +
      esc(pid) +
      '">' +
      '<header class="card-head">' +
      '<div class="card-title">' +
      '<span class="status-dot" aria-hidden="true"></span>' +
      "<div>" +
      '<p class="card-name">' +
      esc(name) +
      "</p>" +
      '<p class="card-meta">' +
      esc(user) +
      " · " +
      esc(protocolLabel(protocol)) +
      " · " +
      esc(deskShort) +
      "</p>" +
      "</div></div>" +
      '<span class="badge badge-' +
      esc(st) +
      '">' +
      esc(statusLabel(st)) +
      "</span>" +
      "</header>" +
      '<div class="card-summary">' +
      /* HARD_GATE#869: 3×2 left-aligned columns
         云桌面↔模式 | 用户协议↔间隔 | 客户端↔云桌面状态 */
      "<div>云桌面<strong title=\"" +
      esc(deskIdText) +
      '">' +
      esc(deskIdText) +
      "</strong></div>" +
      "<div>用户协议<strong>" +
      esc(protocolLabel(protocol)) +
      "</strong></div>" +
      "<div>客户端<strong>" +
      esc(clientLabel(client)) +
      "</strong></div>" +
      "<div>模式<strong>" +
      esc(modeLabel(mode)) +
      "</strong></div>" +
      "<div>间隔<strong>" +
      esc(String(d.intervalMin || 5)) +
      " 分钟</strong></div>" +
      "<div>云桌面状态<strong data-desk-status title=\"" +
      esc(deskStatus) +
      "\">" +
      esc(deskStatus) +
      "</strong></div>" +
      "</div>" +
      '<div class="card-surface">' +
      (errLine
        ? '<p class="card-error">' + esc(errLine) + "</p>"
        : "") +
      '<div class="card-actions">' +
      (running
        ? '<button type="button" class="btn btn-stop" data-act="stop" ' +
          (busy ? "disabled" : "") +
          ">停止保活</button>"
        : '<button type="button" class="btn btn-primary" data-act="start" ' +
          (busy ? "disabled" : "") +
          ">开始保活</button>") +
      '<button type="button" class="btn btn-ghost" data-act="config" ' +
      (busy ? "disabled" : "") +
      (open ? ' aria-expanded="true"' : ' aria-expanded="false"') +
      ">配置</button>" +
      '<button type="button" class="btn btn-ghost" data-act="refresh-logs" ' +
      (busy ? "disabled" : "") +
      ' title="清空本卡片日志显示（不影响保活任务）">刷新日志</button>' +
      '<button type="button" class="btn btn-ghost" data-act="clear-logs" ' +
      (busy ? "disabled" : "") +
      ">清空日志</button>" +
      "</div>" +
      /* HARD_GATE#736: logs-only dual surface; desktop box removed */
      /* HARD_GATE#810: dblclick whole log panel (head+box) → full modal */
      '<div class="card-surface-dual card-surface-log-only">' +
      '<div class="log-panel surface-log card-log-expanded" title="双击日志查看完整记录">' +
      '<div class="log-panel-head"><span>日志（常显最近 6 条；双击看全部）</span></div>' +
      '<div class="log-box log-viewport" data-log="' +
      esc(pid) +
      '" title="双击查看完整日志">' +
      profileLogsHtml(pid) +
      "</div></div>" +
      "</div>" +
      "</div></article>"
    );
  }

  function configFormHtml(p) {
    const pid = p.id;
    const d = ensureDraft(pid, p);
    const busy = !!state.busy[pid];
    const job = jobOf(p);
    const user = p.usernameMasked || "未设置账号";
    const client = d.clientProfile || p.clientProfile || "linux";
    const protocol =
      resolveUserProtocol(d.protocol, p && p.protocol, p && p.lastOfficialProtocol, p && p.protocolHint, job && job.protocol);
    const mode = d.mode || (p && p.mode) || (job && job.mode) || "live";
    const errLine = String(state.cardMsg[pid] || "").trim();
    const usid = d.userServiceId || (p && p.userServiceId) || "";
    const selectedDesk = usid || d.desktopLabel || "";
    const spu =
      d.spuCode ||
      (p && (p.spuCode || p.spu_code)) ||
      "";
    return (
      (errLine
        ? '<p class="card-error" id="config-modal-error" role="alert">' + esc(errLine) + "</p>"
        : "") +
      '<div class="card-fields config-modal-fields">' +
      '<label class="field span-2"><span>显示名</span>' +
      '<input type="text" data-pid="' +
      esc(pid) +
      '" data-key="displayName" value="' +
      esc(d.displayName || "") +
      '" /></label>' +
      '<label class="field"><span>账号</span>' +
      '<input type="text" data-pid="' +
      esc(pid) +
      '" data-key="username" placeholder="' +
      esc(user) +
      '" value="' +
      esc(d.username || "") +
      '" /></label>' +
      '<label class="field"><span>密码</span>' +
      '<input type="text" autocomplete="new-password" data-pid="' +
      esc(pid) +
      '" data-key="password" placeholder="' +
      (p.hasPassword ? "已保存，不改请留空" : "请输入密码") +
      '" value="" /></label>' +
      /* HARD_GATE#layout_fix LOGIN_WITH_SAVE: 登录迁到底部与保存并列；保留轻提示 */
      '<p class="field-hint login-hint-inline span-2">登录后加载云桌面列表，不会启动保活（底部「登录」）</p>' +
      '<div class="field span-2 desktop-field config-desktop-field">' +      "<span>云桌面</span>" +
      '<div class="desk-seg-wrap">' +
      /* HARD_GATE#747: CTA button inside segmented html (empty + after list) */
      desktopSegmentedHtml(pid, selectedDesk, false) +
      "</div>" +
      "</div>" +
      /* HARD_GATE#729: form-pair only 保活间隔 || 单次流量持续; duration field removed */
      '<div class="form-pair span-2" role="group" aria-label="保活间隔 / 单次流量持续">' +
      '<label class="field"><span>保活间隔（分钟）</span>' +
      '<input type="number" min="1" max="1440" data-pid="' +
      esc(pid) +
      '" data-key="intervalMin" value="' +
      esc(String(d.intervalMin || 5)) +
      '" /></label>' +
      '<label class="field"><span>单次流量持续（秒）</span>' +
      '<input type="number" min="5" max="3600" data-pid="' +
      esc(pid) +
      '" data-key="trafficSec" value="' +
      esc(String(d.trafficSec || 60)) +
      '" /></label>' +
      "</div>" +
      '<div class="form-bottom-3 span-2" role="group" aria-label="客户端 / 模式 / 用户协议">' +
      '<div class="field"><span>客户端类型</span>' +
      '<div class="seg" role="group" aria-label="客户端类型">' +
      '<button type="button" class="seg-btn' +
      (client === "linux" ? " active" : "") +
      '" data-pid="' +
      esc(pid) +
      '" data-key="clientProfile" data-val="linux">Linux</button>' +
      '<button type="button" class="seg-btn' +
      (client === "windows" ? " active" : "") +
      '" data-pid="' +
      esc(pid) +
      '" data-key="clientProfile" data-val="windows">Windows</button>' +
      '<button type="button" class="seg-btn' +
      (client === "mac" ? " active" : "") +
      '" data-pid="' +
      esc(pid) +
      '" data-key="clientProfile" data-val="mac">Mac</button>' +
      "</div></div>" +
      '<div class="field"><span>模式</span>' +
      '<div class="seg" role="group" aria-label="保活模式">' +
      '<button type="button" class="seg-btn' +
      (!modeIsOnce(d.mode) ? " active" : "") +
      '" data-pid="' +
      esc(pid) +
      '" data-key="mode" data-val="live">永久</button>' +
      '<button type="button" class="seg-btn' +
      (modeIsOnce(d.mode) ? " active" : "") +
      '" data-pid="' +
      esc(pid) +
      '" data-key="mode" data-val="once">单轮</button>' +
      "</div></div>" +
      '<div class="field"><span>用户协议</span>' +
      '<div class="seg" role="group" aria-label="用户协议">' +
      '<button type="button" class="seg-btn' +
      (String(protocol).toUpperCase() === "ZTE" ? " active" : "") +
      '" data-pid="' +
      esc(pid) +
      '" data-key="protocol" data-val="ZTE">ZTE</button>' +
      '<button type="button" class="seg-btn' +
      (String(protocol).toUpperCase() === "SCG" || String(protocol).toUpperCase() === "SANGFOR" ? " active" : "") +
      '" data-pid="' +
      esc(pid) +
      '" data-key="protocol" data-val="SCG">SCG</button>' +
      "</div></div>" +
      "</div>" +
      "</div>" +
      '<div class="card-config-actions config-modal-actions">' +
      '<button type="button" class="btn btn-primary" data-act="save-start" data-pid="' +
      esc(pid) +
      '" ' +
      (busy || !usid ? "disabled" : "") +
      (usid ? "" : ' title="请先选择云桌面"') +
      ">保存并保活</button>" +
      '<button type="button" class="btn btn-ghost" data-act="save" data-pid="' +
      esc(pid) +
      '" ' +
      (busy ? "disabled" : "") +
      ">保存配置</button>" +
      '<button type="button" class="btn btn-danger" data-act="delete" data-pid="' +
      esc(pid) +
      '" ' +
      (busy ? "disabled" : "") +
      ">删除账号</button>" +
      '<button type="button" class="btn btn-secondary btn-login-inline" data-act="login" data-id="' +
      esc(pid) +
      '"' +
      (busy ? " disabled" : "") +
      ' title="登录并加载官方云桌面列表（不启动保活）">登录</button>' +
      "</div>"
    );
  }

  function openConfigModal(pid) {
    const modal = $("#config-modal");
    const body = $("#config-modal-body");
    const title = $("#config-modal-title");
    if (!modal || !body) return;
    const p = state.profiles.find(function (x) {
      return x.id === pid;
    });
    if (!p) return;
    state.configPid = pid;
    ensureDraft(pid, p);
    const name = p.displayName || pid;
    if (title) title.textContent = "配置 · " + name;
    body.innerHTML = configFormHtml(p);
    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
    renderCards();
    setTimeout(function () {
      const first = body.querySelector('input:not([type="radio"]), select, input[type="radio"]');
      if (first) {
        try {
          first.focus();
        } catch (_) { logCatch("catch", _); }
      }
    }, 0);
  }

  function refreshConfigModal() {
    const pid = state.configPid;
    if (!pid) return;
    const modal = $("#config-modal");
    const body = $("#config-modal-body");
    if (!modal || !body || modal.classList.contains("hidden")) return;
    const p = state.profiles.find(function (x) {
      return x.id === pid;
    });
    if (!p) return;
    const active = document.activeElement;
    const keepKey =
      active && active.getAttribute ? active.getAttribute("data-key") : null;
    const keepVal = active && "value" in active ? active.value : null;
    body.innerHTML = configFormHtml(p);
    if (keepKey) {
      // Desktop radios all share data-key="desktop"; a bare querySelector would
      // return the FIRST radio and (below) overwrite its fixed value with the
      // focused radio's usid → the wrong desktop gets bound. Disambiguate by
      // value in JS, and never rewrite a radio/checkbox value.
      const cands = body.querySelectorAll('[data-key="' + keepKey + '"]');
      let el = null;
      if (keepVal != null) {
        for (let i = 0; i < cands.length; i++) {
          if (cands[i].value === keepVal) { el = cands[i]; break; }
        }
      }
      if (!el) el = cands[0] || null;
      if (el) {
        const t = el.type;
        if (keepVal != null && t !== "password" && t !== "radio" && t !== "checkbox") {
          try {
            el.value = keepVal;
          } catch (_) { logCatch("catch", _); }
        }
        try {
          el.focus();
        } catch (_) { logCatch("catch", _); }
      }
    }
  }

  function closeConfigModal() {
    const modal = $("#config-modal");
    state.configPid = null;
    if (modal) {
      modal.classList.add("hidden");
      modal.setAttribute("aria-hidden", "true");
    }
    const body = $("#config-modal-body");
    if (body) body.innerHTML = "";
    renderCards();
  }

  function renderCards() {
    const root = $("#timeline");
    const empty = $("#empty-state");
    if (!root) return;
    renderStats();
    /* HARD_GATE#851: belt-and-suspenders draft hide */
    const visible = (state.profiles || []).filter(function (p) {
      return p && !p.draft && p.draft !== true && p.draft !== 1 && p.draft !== "1";
    });
    if (!visible.length) {
      root.innerHTML = "";
      if (empty) empty.hidden = false;
      return;
    }
    if (empty) empty.hidden = true;
    root.innerHTML = visible.map(cardHtml).join("");
    // HARD_GATE#838: after rebuild, pin each card log to latest 6
    state.profiles.forEach(function (p) {
      if (!p || !p.id) return;
      const panel =
        $('.log-viewport[data-log="' + p.id + '"]') ||
        $('.log-box[data-log="' + p.id + '"]');
      if (panel) panel.scrollTop = panel.scrollHeight;
      if (!state.logs[p.id] || !state.logs[p.id].length) {
        loadLogs(p.id).catch(function (err) { logCatch("promise", err); });
      } else {
        applyLogsToDom(p.id, true);
      }
    });
    refreshConfigModal();
  }

  
  function setConfigError(pid, msg) {
    const text = String(msg || "").trim();
    if (text) state.cardMsg[pid] = text;
    else delete state.cardMsg[pid];
    const el = document.getElementById("config-modal-error");
    if (!el) return;
    if (!text) {
      el.remove();
      return;
    }
    el.classList.remove("hidden");
    el.textContent = text;
    el.setAttribute("role", "alert");
  }

function setComposerMsg(text, kind) {
    const el = $("#composer-msg");
    if (!el) return;
    el.textContent = text || "";
    el.classList.remove("error", "ok");
    if (kind) el.classList.add(kind);
  }

  function readComposer() {
    return {
      displayName: ($("#c-displayName") && $("#c-displayName").value.trim()) || "",
      username: ($("#c-username") && $("#c-username").value.trim()) || "",
      password: ($("#c-password") && $("#c-password").value) || "",
      protocol: resolveUserProtocol(state.composer.protocol, state.composer.lastOfficialProtocol),
      clientProfile: state.composer.clientProfile || "linux",
      mode: modeApi(state.composer.mode || "live"),
      intervalMin: Number(($("#c-intervalMin") && $("#c-intervalMin").value) || 5),
      trafficSec: Number(($("#c-trafficSec") && $("#c-trafficSec").value) || 60),
      /* #848: once -> trafficSec; live forever -> 0 */
      durationSec: durationForMode(
        state.composer.mode || "live",
        Number(($("#c-trafficSec") && $("#c-trafficSec").value) || 60)
      ),
      userServiceId:
        state.composer.userServiceId ||
        ($("#c-userServiceId") && $("#c-userServiceId").value) ||
        "",
      desktopLabel:
        state.composer.desktopLabel ||
        ($("#c-desktopLabel") && $("#c-desktopLabel").value) ||
        "",
    };
  }

  function clearComposer() {
    ["c-displayName", "c-username", "c-password"].forEach(function (id) {
      const el = $("#" + id);
      if (el) el.value = "";
    });
    if ($("#c-intervalMin")) $("#c-intervalMin").value = "5";
    if ($("#c-trafficSec")) $("#c-trafficSec").value = "60";
    if ($("#c-userServiceId")) $("#c-userServiceId").value = "";
    if ($("#c-desktopLabel")) $("#c-desktopLabel").value = "";
    if ($("#c-desktop")) {
      /* HARD_GATE#842: empty table state */
      $("#c-desktop").innerHTML = composerDeskEmptyHtml();
      $("#c-desktop").classList.add("is-locked");
      $("#c-desktop").setAttribute("aria-disabled", "true");
    }
    state.composer = {
      protocol: "ZTE",
      clientProfile: "linux",
      mode: "live",
      userServiceId: "",
      desktopLabel: "",
      profileId: "",
    };
    $$(".composer .seg-btn").forEach(function (btn) {
      const p = btn.getAttribute("data-protocol");
      const c = btn.getAttribute("data-client");
      const m = btn.getAttribute("data-mode");
      if (p) btn.classList.toggle("active", p === "ZTE");
      if (c) btn.classList.toggle("active", c === "linux");
      if (m) btn.classList.toggle("active", m === "live");
    });
    setComposerMsg("");
    setComposerDesktopLock(false);
    setComposerOfficial("未登录");
  }


