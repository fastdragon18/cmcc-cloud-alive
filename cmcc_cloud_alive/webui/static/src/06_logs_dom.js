  function pushGlobalLocal(line, level, at) {
    const entry = {
      at: at || new Date().toISOString(),
      line: String(line || ""),
      level: level || "info",
    };
    if (!entry.line) return entry;
    // de-dupe last identical line (SSE echo of our own POST)
    const last = state.globalLog[state.globalLog.length - 1];
    if (
      last &&
      last.line === entry.line &&
      (last.level || "info") === (entry.level || "info") &&
      String(last.at || "") === String(entry.at || "")
    ) {
      return entry;
    }
    state.globalLog.push(entry);
    if (state.globalLog.length > 500) {
      state.globalLog = state.globalLog.slice(-500);
    }
    renderGlobalLog();
    return entry;
  }

  function pushGlobal(line, level) {
    const text = String(line || "");
    if (!text) return;
    const lvl = level || "info";
    // optimistic local paint so UI is snappy; backend is source of truth
    const localAt = new Date().toISOString();
    pushGlobalLocal(text, lvl, localAt);
    api("/api/global-logs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ line: text, level: lvl }),
    })
      .then(function (res) {
        const e = res && res.entry;
        if (!e || !e.line) return;
        // replace optimistic tail if same text and backend returned canonical stamp
        const last = state.globalLog[state.globalLog.length - 1];
        if (last && last.line === e.line && String(last.at) === localAt) {
          last.at = e.at || last.at;
          last.level = e.level || last.level;
          renderGlobalLog();
        }
      })
      .catch(function () {
        /* offline/tunnel: keep local mirror only */
      });
  }

  async function loadGlobalLogs() {
    try {
      const res = await api("/api/global-logs?limit=500");
      const lines = (res && res.lines) || [];
      state.globalLog = lines.map(function (x) {
        return {
          at: x.at || "",
          line: String(x.line || ""),
          level: x.level || "info",
        };
      });
      if (state.globalLog.length > 500) {
        state.globalLog = state.globalLog.slice(-500);
      }
      renderGlobalLog();
      return state.globalLog;
    } catch (e) {
      return state.globalLog || [];
    }
  }

  async function clearGlobalLogs() {
    state.globalLog = [];
    renderGlobalLog();
    try {
      await api("/api/global-logs", { method: "DELETE" });
    } catch (e) {
      /* keep local cleared; next load may restore if backend failed */
    }
  }

  /* HARD_GATE#768-B: card-only keepalive/job log sink (never global) */
  function patchCardStatus(pid) {
    // HARD_GATE#784: update status chrome only; leave log DOM untouched
    if (!pid) return;
    const p = state.profiles.find(function (x) {
      return x.id === pid;
    });
    if (!p) return;
    const st = statusOf(p);
    const card = document.querySelector('article.card[data-id="' + pid + '"]');
    if (!card) return;
    card.className = card.className
      .split(/\s+/)
      .filter(function (c) {
        return c && c.indexOf("status-") !== 0;
      })
      .concat(["status-" + st])
      .join(" ");
    if (card.className.indexOf("card") < 0) card.className = "card " + card.className;
    // ensure base card class retained
    if (!/\bcard\b/.test(card.className)) card.className = "card " + card.className;
    const badge = card.querySelector(".status-badge, .card-status, [data-status-label]");
    if (badge) badge.textContent = statusLabel(st);
    const open = state.configPid === pid;
    if (open) card.classList.add("is-configuring");
    else card.classList.remove("is-configuring");
    // busy buttons
    const busy = !!state.busy[pid];
    const acts = card.querySelectorAll("[data-act]");
    for (let i = 0; i < acts.length; i++) {
      if (busy) acts[i].setAttribute("disabled", "disabled");
      else acts[i].removeAttribute("disabled");
    }
    // start/stop visibility if present
    const startBtn = card.querySelector('[data-act="start"]');
    const stopBtn = card.querySelector('[data-act="stop"]');
    if (startBtn && stopBtn) {
      if (st === "running") {
        startBtn.hidden = true;
        stopBtn.hidden = false;
      } else {
        startBtn.hidden = false;
        stopBtn.hidden = true;
      }
    }
  }

  function pushCard(pid, line, at) {
    // HARD_GATE#854: buffer + immediate paint (SSE must reappear after clear; 6s poll is backup)
    if (!pid || !line) return;
    const arr = state.logs[pid] || (state.logs[pid] = []);
    try { patchCardDeskStatus(pid); } catch (_e) { logCatch("catch", _e); }
    const entry = { at: at || new Date().toISOString(), line: String(line) };
    arr.push(entry);
    if (arr.length > 300) state.logs[pid] = arr.slice(-300);
    try { patchCardDeskStatus(pid); } catch (_e) { logCatch("catch", _e); }
    applyLogsToDom(pid, false);
  }

  function shanghaiHms(isoOrDate) {
    /* HARD_GATE#871c: full Asia/Shanghai [YYYY-MM-DD HH:mm:ss] like CLI */
    try {
      const d = isoOrDate instanceof Date ? isoOrDate : new Date(isoOrDate || Date.now());
      if (isNaN(d.getTime())) return "";
      const parts = new Intl.DateTimeFormat("en-CA", {
        timeZone: "Asia/Shanghai",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      }).formatToParts(d);
      const get = (t) => (parts.find((p) => p.type === t) || {}).value || "";
      return get("year") + "-" + get("month") + "-" + get("day") + " " + get("hour") + ":" + get("minute") + ":" + get("second");
    } catch (e) {
      try {
        const d2 = new Date(isoOrDate || Date.now());
        const t = d2.getTime() + 8 * 3600 * 1000;
        const x = new Date(t);
        const y = x.getUTCFullYear();
        const mo = String(x.getUTCMonth() + 1).padStart(2, "0");
        const da = String(x.getUTCDate()).padStart(2, "0");
        const hh = String(x.getUTCHours()).padStart(2, "0");
        const mm = String(x.getUTCMinutes()).padStart(2, "0");
        const ss = String(x.getUTCSeconds()).padStart(2, "0");
        return y + "-" + mo + "-" + da + " " + hh + ":" + mm + ":" + ss;
      } catch (e2) {
        return "";
      }
    }
  }

  function extractDesktopStatusFromLogs(pid) {
    /* HARD_GATE#871: parse "云桌面状态：xxx" from recent log lines */
    const arr = state.logs[pid] || [];
    for (let i = arr.length - 1; i >= 0; i--) {
      const raw = String((arr[i] && (arr[i].line || arr[i].text)) || arr[i] || "");
      const m = raw.match(/云桌面状态[：:]\s*([^\s\|\[\]，,；;]+(?:\s*[^\s\|\[\]，,；;]+){0,4})/);
      if (m && m[1]) {
        const v = m[1].trim();
        if (v && v !== "—" && v !== "-") {
          state.desktopStatusByPid[pid] = v;
          return v;
        }
      }
      if (/开机运行中|运行中|已开机|关机|已关机|休眠|启动中/.test(raw)) {
        if (/开机运行中/.test(raw)) {
          state.desktopStatusByPid[pid] = "开机运行中";
          return "开机运行中";
        }
        if (/已关机|关机/.test(raw) && !/开机/.test(raw)) {
          state.desktopStatusByPid[pid] = "已关机";
          return "已关机";
        }
      }
    }
    return state.desktopStatusByPid[pid] || "";
  }

  function patchCardDeskStatus(pid) {
    /* HARD_GATE#871_PATCH_LOG_STATUS: never leave em-dash while keepalive running */
    const card = document.querySelector('.card[data-id="' + pid + '"]');
    if (!card) return;
    const el = card.querySelector("[data-desk-status]");
    if (!el) return;
    let v = extractDesktopStatusFromLogs(pid);
    if (!v) {
      // state.profiles is an Array (index-by-id yields undefined) and state.jobs
      // does not exist — the correct shapes are .find(id) and jobsByProfile.
      const prof = (state.profiles && state.profiles.find)
        ? state.profiles.find(function (x) { return x && x.id === pid; })
        : null;
      const st = (prof && (prof.jobStatus || prof.status)) || "";
      const job = (state.jobsByProfile && state.jobsByProfile[pid]) || {};
      const running = /run|alive|keep|active|ing/i.test(String(st)) ||
        /run|alive|active/i.test(String(job.status || job.state || ""));
      const cardRun = card.classList.contains("is-running") || card.getAttribute("data-running") === "1";
      if (running || cardRun) v = "保活中";
    }
    if (!v) return;
    el.textContent = v;
    el.setAttribute("title", v);
    state.desktopStatusByPid = state.desktopStatusByPid || {};
    state.desktopStatusByPid[pid] = v;
  }


  // HARD_GATE#871d-proto-serial-globallog: global run-log HTML (viewport last-N or full modal)
  function globalLogsHtml(opts) {
    opts = opts || {};
    const full = !!opts.full;
    const lines = state.globalLog || [];
    const slice = full ? lines.slice() : lines.slice(-200);
    if (!slice.length) {
      return '<div class="log-empty">暂无日志</div>';
    }
    return slice
      .map(function (x) {
        const t = shanghaiHms(x.at) || shanghaiHms(Date.now()) || "";
        return (
          '<div class="log-line ' +
          esc(x.level || "") +
          '"><time>' +
          esc(t) +
          "</time><span>" +
          esc(x.line) +
          "</span></div>"
        );
      })
      .join("");
  }

  function renderGlobalLog() {
    const box = $("#global-log");
    if (!box) return;
    box.innerHTML = globalLogsHtml({ full: false });
    box.scrollTop = box.scrollHeight;
    // keep full modal in sync when open on global log
    if (state.logModalPid === "__global__") {
      const body = $("#log-full-body");
      const modal = $("#log-modal") || $("#log-full-modal");
      if (
        body &&
        modal &&
        !modal.classList.contains("hidden") &&
        modal.getAttribute("aria-hidden") !== "true"
      ) {
        const mfp = "full:g:" + String((state.globalLog || []).length);
        if (body.getAttribute("data-log-fp") !== mfp) {
          body.innerHTML = globalLogsHtml({ full: true });
          body.setAttribute("data-log-fp", mfp);
          body.scrollTop = body.scrollHeight;
        }
      }
    }
  }

  function renderStats() {
    const counts = { total: 0, running: 0, idle: 0, error: 0 };
    for (let i = 0; i < state.profiles.length; i++) {
      const p = state.profiles[i];
      counts.total += 1;
      const st = statusOf(p);
      if (st === "running") counts.running += 1;
      else if (st === "error") counts.error += 1;
      else counts.idle += 1;
    }
    const root = $("#top-stats");
    if (!root) return;
    const map = {
      total: "账号 " + counts.total,
      running: "保活 " + counts.running,
      idle: "空闲 " + counts.idle,
      error: "异常 " + counts.error,
    };
    $$("[data-k]", root).forEach(function (el) {
      const k = el.getAttribute("data-k");
      if (map[k] != null) el.textContent = map[k];
    });
  }

  function classifyLogLine(line) {
    const s = String(line || "").toLowerCase();
    if (
      s.indexOf("token") >= 0 ||
      s.indexOf("refreshtoken") >= 0 ||
      s.indexOf("refresh token") >= 0 ||
      s.indexOf("刷新令牌") >= 0 ||
      s.indexOf("令牌刷新") >= 0
    ) {
      return "token";
    }
    if (
      s.indexOf("5xx") >= 0 ||
      s.indexOf(" http 5") >= 0 ||
      s.indexOf("status=5") >= 0 ||
      s.indexOf("soft recover") >= 0 ||
      s.indexOf("soft-recover") >= 0 ||
      s.indexOf("软恢复") >= 0 ||
      /\b5\d\d\b/.test(s)
    ) {
      return "warn";
    }
    if (
      s.indexOf("error") >= 0 ||
      s.indexOf("fail") >= 0 ||
      s.indexOf("exception") >= 0 ||
      s.indexOf("失败") >= 0 ||
      s.indexOf("异常") >= 0
    ) {
      return "error";
    }
    return "";
  }

  function formatLogDisplayLine(x) {
    // Backend product lines already embed [YYYY-MM-DD HH:MM:SS]; keep exact Python style.
    // For raw/orch lines without stamp, synthesize Shanghai wall stamp from entry.at.
    // HARD_GATE#861: parse ISO/Z/offset via Date so UTC "...Z" shows as Asia/Shanghai.
    const raw = String((x && x.line) || "");
    if (!raw) return "";
    if (/^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]/.test(raw)) return raw;
    const at = String((x && x.at) || "");
    let stamp = "";
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(at)) {
      try {
        const d = new Date(at);
        if (!isNaN(d.getTime())) {
          stamp = d.toLocaleString("sv-SE", {
            timeZone: "Asia/Shanghai",
            hour12: false,
          }).replace("T", " ").slice(0, 19);
        }
      } catch (e) {
        stamp = "";
      }
      if (!stamp) stamp = at.slice(0, 19).replace("T", " ");
    } else if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(at)) {
      stamp = at.slice(0, 19);
    }
    return stamp ? "[" + stamp + "] " + raw : raw;
  }

  function profileLogsHtml(pid, opts) {
    // HARD_GATE#841: card = last 6 complete entries only (no empty slots);
    // modal (full) keeps entire history. Height follows content.
    opts = opts || {};
    const full = !!opts.full;
    const all = state.logs[pid] || [];
    const lines = full ? all : all.slice(-6);
    if (!lines.length) {
      if (full) {
        return '<div class="log-empty log-empty-fill">暂无日志。启动保活后这里会实时滚动。</div>';
      }
      // HARD_GATE#853: empty placeholder fills fixed viewport (no card shrink)
      return (
        '<div class="log-line log-line-py log-line-card log-line-empty log-empty-fill">' +
        '<span class="log-text">暂无日志。启动保活后这里会实时滚动。</span></div>'
      );
    }
    return lines
      .map(function (x) {
        const raw = formatLogDisplayLine(x);
        const level = classifyLogLine(raw);
        const rowCls = full
          ? 'log-line log-line-py log-line-full ' + level
          : 'log-line log-line-py log-line-card ' + level;
        const titleAttr = full ? '' : ' title="' + esc(raw) + '"';
        return (
          '<div class="' +
          rowCls +
          '"' +
          titleAttr +
          '><span class="log-text">' +
          esc(raw) +
          '</span></div>'
        );
      })
      .join('');
  }

  
  function ensureLogModal() {
    // HARD_GATE#768-C: log-modal alias + CSS shell .log-full-modal / .log-full-dialog
    // HARD_GATE#827: static #log-full-modal must still bind close/backdrop once
    let el = $("#log-modal") || $("#log-full-modal");
    if (!el) {
      el = document.createElement("div");
      el.id = "log-modal";
      el.className = "log-modal log-full-modal modal hidden";
      el.setAttribute("aria-hidden", "true");
      el.setAttribute("role", "dialog");
      el.setAttribute("aria-modal", "true");
      el.setAttribute("aria-labelledby", "log-full-title");
      el.innerHTML =
        '<div class="log-full-dialog modal-card log-modal-card">' +
        '<div class="log-full-head modal-head">' +
        '<h3 id="log-full-title" class="log-full-title">完整日志</h3>' +
        '<button type="button" class="btn btn-ghost modal-x" id="log-full-close" aria-label="关闭">×</button>' +
        "</div>" +
        '<div class="log-box log-full-body log-full-box card-log" id="log-full-body" data-log-modal-body="1"></div>' +
        "</div>";
      document.body.appendChild(el);
    }
    // HARD_GATE#833: bind close once; also re-hook static close button if recreated
    if (!el.dataset.closeBound) {
      el.dataset.closeBound = "1";
      el.addEventListener("click", function (ev) {
        if (ev.target === el || (ev.target && ev.target.getAttribute && ev.target.getAttribute("data-close-log-modal") != null)) {
          closeLogModal();
        }
      });
    }
    const closeBtn =
      el.querySelector("#log-full-close") ||
      el.querySelector("[data-close-log-modal], .modal-x, .log-full-close, .btn-log-close");
    if (closeBtn && closeBtn.dataset.boundClose !== "1") {
      closeBtn.dataset.boundClose = "1";
      closeBtn.addEventListener("click", function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
        closeLogModal();
      });
    }
    return el;
  }

  function openLogModal(pid) {
    if (!pid) return;
    const el = ensureLogModal();
    const title = el.querySelector("#log-full-title");
    const body = el.querySelector("#log-full-body");
    // HARD_GATE#871d-proto-serial-globallog: pid === "__global__" → 运行日志全量
    if (pid === "__global__") {
      if (title) title.textContent = "完整日志 · 运行日志";
      if (body) {
        body.innerHTML = globalLogsHtml({ full: true });
        body.setAttribute(
          "data-log-fp",
          "full:g:" + String((state.globalLog || []).length)
        );
      }
      state.logModalReturnFocus =
        document.activeElement && document.activeElement !== document.body
          ? document.activeElement
          : document.querySelector("#global-log") ||
            document.querySelector(".global-log-panel") ||
            null;
    } else {
      const p = (state.profiles || []).find(function (x) {
        return x && x.id === pid;
      });
      const d = ensureDraft(pid, p || {});
      const name =
        (p && (p.displayName || p.usernameMasked || p.username)) || pid;
      const usid = (d && d.userServiceId) || (p && p.userServiceId) || "";
      if (title) {
        title.textContent =
          "完整日志 · " + name + (usid ? " · 桌面 " + usid : "");
      }
      if (body) body.innerHTML = profileLogsHtml(pid, { full: true });
      // HARD_GATE#810: force visible vs CSS .log-full-modal / [hidden] / .is-hidden
      // HARD_GATE#827: scroll lock + return focus; close must reverse cleanly
      state.logModalReturnFocus =
        document.activeElement && document.activeElement !== document.body
          ? document.activeElement
          : document.querySelector('.log-panel[data-pid="' + pid + '"]') ||
            document.querySelector('.card[data-pid="' + pid + '"] .log-panel') ||
            null;
    }
    el.classList.remove("hidden", "is-hidden");
    el.classList.add("open", "is-open");
    el.removeAttribute("hidden");
    el.setAttribute("aria-hidden", "false");
    el.style.display = "flex";
    el.style.visibility = "visible";
    el.style.opacity = "1";
    el.style.pointerEvents = "auto";
    el.style.zIndex = "1200";
    el.setAttribute("data-pid", String(pid));
    document.body.classList.add("log-modal-open", "modal-open");
    document.body.style.overflow = "hidden";
    document.body.style.pointerEvents = "";
    state.logModalPid = pid;
    const closeBtn = el.querySelector("#log-full-close");
    if (closeBtn && typeof closeBtn.focus === "function") {
      try {
        closeBtn.focus();
      } catch (_) { logCatch("catch", _); }
    }
  }

  function closeLogModal() {
    // HARD_GATE#831 CARD_LOG_MODAL_CLOSE: X/backdrop/Esc clean close, no residual mask
    const el = $("#log-modal") || $("#log-full-modal");
    if (!el) return;
    el.classList.add("hidden", "is-hidden");
    el.classList.remove("open", "is-open", "show");
    el.setAttribute("hidden", "");
    el.setAttribute("aria-hidden", "true");
    el.style.display = "none";
    el.style.visibility = "hidden";
    el.style.opacity = "0";
    el.style.pointerEvents = "none";
    el.style.zIndex = "";
    document.body.classList.remove("log-modal-open", "modal-open");
    document.body.style.overflow = "";
    document.body.style.pointerEvents = "";
    el.removeAttribute("data-pid");
    state.logModalPid = null;
  }


  function desktopRowText(d) {
    const id = (d && (d.userServiceId || d.id)) || "";
    const label = (d && (d.desktopLabel || d.skuName || d.sku || d.name || d.label || d.vmName)) || id || "未命名";
    const spu = (d && (d.spuCode || d.spu_code)) || "—";
    return label + " / " + id + " | spuCode：" + spu;
  }

  function deskRefreshCtaHtml(pid, composer, loading) {
    /* HARD_GATE#781: centered text-link CTA (CLI Proxy style), not thick bordered btn.
       Do NOT use class desk-refresh-cta alone under old CSS (thick secondary btn).
       Keep data-act + desk-refresh-link; inline style guarantees text-link look without CSS ownership. */
    const act = composer ? "composer-desktops" : "desktops";
    const pidAttr = composer
      ? ""
      : ' data-pid="' + esc(pid || "") + '"';
    const label = loading ? "刷新中…" : "点击此处刷新云桌面列表";
    const disabled = loading ? " disabled aria-busy=\"true\"" : "";
    const busyCls = loading ? " is-loading" : "";
    const color = loading ? "var(--muted, #8b90a5)" : "var(--accent, #625fff)";
    const style =
      "display:block;width:100%;margin:6px 0 0;padding:4px 0;border:0;background:transparent;" +
      "box-shadow:none;border-radius:0;min-height:auto;height:auto;font:inherit;font-size:13px;" +
      "font-weight:500;letter-spacing:0;text-align:center;text-decoration:underline;" +
      "text-underline-offset:3px;cursor:" +
      (loading ? "wait" : "pointer") +
      ";color:" +
      color +
      ";";
    return (
      '<div class="desk-refresh-wrap" style="width:100%;text-align:center;">' +
      '<button type="button" class="desk-refresh-link desk-refresh-cta' +
      busyCls +
      '" data-act="' +
      act +
      '"' +
      pidAttr +
      ' title="刷新云桌面列表" aria-label="刷新云桌面列表" style="' +
      style +
      '"' +
      disabled +
      ">" +
      label +
      "</button></div>"
    );
  }

  function desktopSegmentedHtml(pid, selected, surface) {
    const list = state.desktops[pid] || [];
    const surfaceAttr = surface ? ' data-surface="1"' : "";
    const name = "desktop-" + pid + (surface ? "-surface" : "-modal");
    if (!list.length) {
      /* HARD_GATE#747: empty = real CTA button; keep selected id chip if any */
      const chip = selected
        ? '<span class="desk-selected-chip">' + esc(String(selected)) + "</span>"
        : "";
      return (
        '<div class="desk-seg is-empty desk-seg-refresh" role="group" aria-label="云桌面刷新">' +
        chip +
        deskRefreshCtaHtml(pid, false, !!state.busy[pid]) +
        "</div>"
      );
    }
    let html =
      '<div class="desk-seg" role="radiogroup" aria-label="云桌面">';
    for (let i = 0; i < list.length; i++) {
      const d = list[i] || {};
      const id = d.userServiceId || d.id || "";
      const label = d.desktopLabel || d.skuName || d.sku || d.name || d.label || d.vmName || id;
      const val = id + "||" + label;
      const checked = id === selected || label === selected;
      const text = desktopRowText(d);
      html +=
        '<label class="desk-seg-item' +
        (checked ? " is-active" : "") +
        '">' +
        '<input type="radio" name="' +
        esc(name) +
        '" data-pid="' +
        esc(pid) +
        '" data-key="desktop"' +
        surfaceAttr +
        ' value="' +
        esc(val) +
        '"' +
        (checked ? " checked" : "") +
        " />" +
        '<span class="desk-dot" aria-hidden="true"></span>' +
        '<span class="desk-seg-text">' +
        esc(text) +
        "</span></label>";
    }
    /* HARD_GATE#747: keep refresh after selected / list loaded */
    return html + "</div>" + deskRefreshCtaHtml(pid, false, !!state.busy[pid]);
  }

  /* compat alias — no native select options */
  function desktopOptionsHtml(pid, selected) {
    return desktopSegmentedHtml(pid, selected, false);
  }

