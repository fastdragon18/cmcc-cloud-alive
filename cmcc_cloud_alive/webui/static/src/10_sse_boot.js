  function applyJobEvent(data) {
    if (!data || typeof data !== "object") return;
    const jid = data.jobId || data.job_id || data.id || null;
    const pid = data.profileId || data.profile_id || null;
    if (!jid && !pid) {
      if (data.detail && data.detail !== "global-sse" && data.detail !== "snapshot") {
        pushGlobal(String(data.detail), data.status === "error" ? "error" : "info");
      }
      return;
    }
    const prev =
      (jid && state.jobsById[jid]) ||
      (pid && state.jobsByProfile[pid]) ||
      null;
    // HARD_GATE#R3: maps + profile.job* only via upsertJob
    const merged = upsertJob(data) || Object.assign({}, prev || {}, data);
    const status = merged.status || data.status || "";
    const label = pid || jid || "?";
    // HARD_GATE#768-B: job status meta may hit global; keepalive round/detail stays card-only via pushCard
    const detail = data.detail ? String(data.detail) : "";
    const looksKeepalive =
      /保活|keepalive|SCG|第\s*\d+\s*轮|round/i.test(detail) ||
      /保活|keepalive|SCG|第\s*\d+\s*轮|round/i.test(status);
    if (looksKeepalive && pid) {
      if (detail) pushCard(pid, detail, data.at || new Date().toISOString());
    } else if (status && (!prev || prev.status !== status)) {
      pushGlobal(
        "[" + label + "] job " + status + (detail && !looksKeepalive ? " — " + detail : ""),
        status === "error" ? "error" : "info"
      );
    } else if (detail && detail !== "snapshot" && !looksKeepalive) {
      pushGlobal("[" + label + "] " + detail, status === "error" ? "error" : "info");
    }
    try {
      // HARD_GATE#784: status-only patch; do not rebuild log panels
      if (pid) patchCardStatus(pid);
      else if (jid) {
        const p = state.profiles.find(function (x) {
          const j = jobOf(x);
          return j && String(j.id || j.jobId || "") === String(jid);
        });
        if (p) patchCardStatus(p.id);
      }
    } catch (_) { logCatch("catch", _); }
  }

  function applyJobLogEvent(data) {
    if (!data || typeof data !== "object") return;
    const line = data.line || data.message || "";
    if (!line) return;
    const pid = data.profileId || data.profile_id || "";
    // HARD_GATE#854: SSE buffers + paints via pushCard→applyLogsToDom (clear后新日志立即可见)
    if (pid) pushCard(pid, line, data.at || new Date().toISOString());
  }

  // Reopen the SSE stream with the current token (connectSSE already closes the
  // old EventSource first). Used after an access-key change so the embedded
  // ?token= is refreshed instead of 401-ing on the next retry.
  function reconnectSSE() {
    try { connectSSE(); } catch (_) { logCatch("catch", _); }
  }

  function connectSSE() {
    if (typeof EventSource === "undefined") return;
    try {
      if (state.es) {
        try {
          state.es.close();
        } catch (_) { logCatch("catch", _); }
        state.es = null;
      }
      // EventSource cannot set Authorization headers; BE accepts ?token= (and Bearer on fetch).
      const token = getToken();
      if (state.tokenRequired && !token) {
        if (!state.sseNeedTokenLogged) {
          pushGlobal(
            "需要访问令牌才能连接事件流 · 请在顶部填写并保存，或使用 ?token=…",
            "error"
          );
          state.sseNeedTokenLogged = true;
        }
        return;
      }
      state.sseNeedTokenLogged = false;
      let url = "/api/events";
      if (token) {
        url +=
          (url.indexOf("?") >= 0 ? "&" : "?") +
          "token=" +
          encodeURIComponent(token);
      }
      const es = new EventSource(url);
      state.es = es;
      // BE emits named events (event: job_status / job_log); onmessage only gets unnamed.
      es.addEventListener("job_status", function (ev) {
        try {
          applyJobEvent(JSON.parse(ev.data));
        } catch (_) { logCatch("catch", _); }
      });
      es.addEventListener("job_log", function (ev) {
        try {
          applyJobLogEvent(JSON.parse(ev.data));
        } catch (_) { logCatch("catch", _); }
      });
      es.addEventListener("job_log_cleared", function (ev) {
        try {
          const d = JSON.parse(ev.data) || {};
          const pid = d.profileId || d.profile_id || "";
          if (!pid) return;
          state.logs[pid] = [];
    try { patchCardDeskStatus(pid); } catch (_e) { logCatch("catch", _e); }
          applyLogsToDom(pid, true);
        } catch (_) { logCatch("catch", _); }
      });
      // HARD_GATE#global-run-log: backend page log fan-out (tunnel / multi-tab)
      es.addEventListener("global_log", function (ev) {
        try {
          const d = JSON.parse(ev.data) || {};
          if (!d.line) return;
          pushGlobalLocal(d.line, d.level || "info", d.at || "");
        } catch (_) { logCatch("catch", _); }
      });
      es.addEventListener("global_log_cleared", function () {
        state.globalLog = [];
        renderGlobalLog();
      });
      es.onmessage = function (ev) {
        try {
          const data = JSON.parse(ev.data);
          if (data && data.line) {
            applyJobLogEvent(data);
          } else if (data && (data.status || data.jobId || data.profileId)) {
            applyJobEvent(data);
          } else if (data && data.detail) {
            pushGlobal(String(data.detail), data.level || "info");
          }
        } catch (_) { logCatch("catch", _); }
      };
      es.onerror = function () {
        /* quiet reconnect by browser */
      };
    } catch (_) { logCatch("catch", _); }
  }


  // HARD_GATE#831 CARD_LOG_DBLCLICK: double-click card log viewport opens full modal
  // HARD_GATE#871d-proto-serial-globallog: double-click 运行日志 (#global-log) → full modal
  document.addEventListener(
    "dblclick",
    function (ev) {
      const t = ev.target;
      if (!t || !t.closest) return;
      // global run-log panel first (do not require data-log / card)
      const gbox = t.closest(
        "#global-log, .global-log-panel .log-box, .global-log-panel .log-viewport, .global-log-panel"
      );
      if (gbox) {
        // avoid treating card log that might nest (none expected)
        const inCard = t.closest(".card, .account-card, [data-pid]");
        if (!inCard || gbox.id === "global-log" || gbox.closest(".global-log-panel")) {
          if (!inCard || (gbox.closest && gbox.closest(".global-log-panel"))) {
            ev.preventDefault();
            openLogModal("__global__");
            return;
          }
        }
      }
      const box = t.closest('[data-log], .log-panel, .card-surface-log-only, .log-viewport');
      if (!box) return;
      // skip if this is the global log box without a profile id
      if (box.id === "global-log" || (box.closest && box.closest(".global-log-panel") && !box.getAttribute("data-log"))) {
        ev.preventDefault();
        openLogModal("__global__");
        return;
      }
      let pid = box.getAttribute("data-log");
      if (!pid) {
        const card = box.closest("[data-pid], .account-card, .card");
        if (card) pid = card.getAttribute("data-pid") || (card.dataset && card.dataset.pid);
      }
      if (!pid && box.querySelector) {
        const inner = box.querySelector("[data-log]");
        if (inner) pid = inner.getAttribute("data-log");
      }
      if (!pid) return;
      ev.preventDefault();
      openLogModal(pid);
      loadLogs(pid).catch(function (err) { logCatch("promise", err); });
    },
    false
  );

  function startPolling() {
    // HARD_GATE#831: profile/status poll 4s; card logs poll 6s (HARD_GATE#852)
    setInterval(async function () {
      try {
        await loadJobs();
        const data = await api("/api/profiles");
        const next = ((data && data.profiles) || []).filter(function (p) {
          return p && !p.draft && p.draft !== true && p.draft !== 1 && p.draft !== "1";
        });
        const prevMap = Object.create(null);
        for (let i = 0; i < state.profiles.length; i++) {
          prevMap[state.profiles[i].id] = statusOf(state.profiles[i]);
        }
        // HARD_GATE#784: only full-render when membership/status set changes
        let needFull = next.length !== state.profiles.length;
        if (!needFull) {
          for (let i = 0; i < next.length; i++) {
            const id = next[i].id;
            if (!prevMap[id]) {
              needFull = true;
              break;
            }
            if (prevMap[id] !== statusOf(next[i])) {
              // status change handled below via patch; still need profile data swap
            }
          }
        }
        const idSetPrev = state.profiles
          .map(function (x) {
            return x.id;
          })
          .join("\0");
        const idSetNext = next
          .map(function (x) {
            return x.id;
          })
          .join("\0");
        if (idSetPrev !== idSetNext) needFull = true;
        state.profiles = next;
        const active = document.activeElement;
        const keepPid =
          active && active.getAttribute ? active.getAttribute("data-pid") : null;
        const keepKey =
          active && active.getAttribute ? active.getAttribute("data-key") : null;
        const selStart = active && active.selectionStart;
        const selEnd = active && active.selectionEnd;
        /* HARD_GATE#851: NEVER full-render while config panel open (kills flicker) */
        if (state.configPid) {
          for (let i = 0; i < next.length; i++) {
            patchCardStatus(next[i].id);
          }
        } else if (needFull) {
          renderCards();
        } else {
          for (let i = 0; i < next.length; i++) {
            patchCardStatus(next[i].id);
          }
        }
        if (keepPid && keepKey) {
          const el = $(
            'input[data-pid="' +
              keepPid +
              '"][data-key="' +
              keepKey +
              '"], select[data-pid="' +
              keepPid +
              '"][data-key="' +
              keepKey +
              '"]'
          );
          if (el) {
            el.focus();
            if (typeof selStart === "number" && el.setSelectionRange) {
              try {
                el.setSelectionRange(selStart, selEnd);
              } catch (_) { logCatch("catch", _); }
            }
          }
        }
        next.forEach(function (p) {
          if (!p || !p.id) return;
          const pid = p.id;
          const prev = prevMap[pid];
          const now = statusOf(p);
          if (prev && now && prev !== now) {
            pushGlobal(
              "[" +
                (p.displayName || pid) +
                "] 状态 " +
                statusLabel(prev) +
                " → " +
                statusLabel(now)
            );
          }
        });
      } catch (_) { logCatch("catch", _); }
    }, 4000);

        setInterval(async function () {
      try {
        // HARD_GATE#855 / #852 / R2: 6s log poll — single batch + applyLogsToDom (fingerprint), never full-render
        const list = state.profiles || [];
        const ids = list.map(function (p) { return p.id; }).filter(Boolean);
        if (ids.length) await loadLogsBatch(ids, false);
      } catch (_) { logCatch("catch", _); }
    }, 6000); /* HARD_GATE#856/#855/#852: card log poll 6s */
  }

  function wireChrome() {
    $("#btn-refresh") &&
      $("#btn-refresh").addEventListener("click", async function () {
        // HARD_GATE#843: top refresh reloads profiles + jobs + all card logs (minute paint path)
        const btn = $("#btn-refresh");
        if (btn) btn.disabled = true;
        try {
          await loadJobs();
          await loadProfiles(false);
          const ids = state.profiles.map(function (p) { return p.id; });
          // HARD_GATE#R2: batch card logs (one request)
          await loadLogsBatch(ids, false);
          await loadGlobalLogs().catch(function (err) { logCatch("promise", err); });
          toast("已刷新账号与日志");
          pushGlobal("整页刷新完成 · " + ids.length + " 个账号");
        } catch (e) {
          toast(humanError(e, "刷新失败"), true);
        } finally {
          if (btn) btn.disabled = false;
        }
      });
    $("#btn-token") &&
      $("#btn-token").addEventListener("click", function () {
        openTokenDialog();
      });
    updateTokenBtn();
    $("#btn-clear-log") &&
      $("#btn-clear-log").addEventListener("click", function () {
        clearGlobalLogs();
      });
    $("#c-clear") &&
      $("#c-clear").addEventListener("click", function () {
        clearComposer();
      });
    ensureComposerLoginBtn();
    $("#c-login") &&
      $("#c-login").addEventListener("click", function (ev) {
        composerLoginOnly(ev, "main");
      });
    $("#c-login-sub") &&
      $("#c-login-sub").addEventListener("click", function (ev) {
        composerLoginOnly(ev, "sub");
      });
    $("#composer-form") &&
      $("#composer-form").addEventListener("submit", composerSaveAndStart);

    $$(".composer .seg-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const protocol = btn.getAttribute("data-protocol");
        const client = btn.getAttribute("data-client");
        const mode = btn.getAttribute("data-mode");
        if (protocol) {
          state.composer.protocol = protocol;
          $$('.composer .seg-btn[data-protocol]').forEach(function (b) {
            b.classList.toggle(
              "active",
              b.getAttribute("data-protocol") === protocol
            );
          });
        }
        if (client) {
          state.composer.clientProfile = client;
          $$('.composer .seg-btn[data-client]').forEach(function (b) {
            b.classList.toggle(
              "active",
              b.getAttribute("data-client") === client
            );
          });
        }
        if (mode) {
          state.composer.mode = mode;
          $$('.composer .seg-btn[data-mode]').forEach(function (b) {
            b.classList.toggle("active", b.getAttribute("data-mode") === mode);
          });
        }
      });
    });

    $("#c-desk-refresh") &&
      $("#c-desk-refresh").addEventListener("click", function (ev) {
        ev.preventDefault();
        const fake = { target: ev.currentTarget, preventDefault: function () {} };
        const box = $("#c-desktop");
        if (box) {
          // reuse same path as in-panel refresh by synthesizing event on box listener
        }
        const pid = state.composer.profileId;
        if (!pid) {
          setComposerMsg("请先登录以加载官方云桌面列表", "error");
          return;
        }
        (async function () {
          const hit = $("#c-desk-refresh");
          try {
            state.busy[pid] = true;
            setComposerMsg("正在刷新官方云桌面列表…");
            setComposerDeskRefreshEnabled(true);
            const deskData = await api(
              "/api/profiles/" + encodeURIComponent(pid) + "/desktops"
            );
            const list =
              (deskData && (deskData.desktops || deskData.items || deskData.list)) ||
              (Array.isArray(deskData) ? deskData : []) ||
              [];
            state.desktops[pid] = list;
            fillComposerDesktopSelect(list, state.composer.userServiceId || "");
            setComposerMsg(
              list.length
                ? "已刷新官方云桌面 " + list.length + " 台"
                : "官方列表为空",
              list.length ? "ok" : "warn"
            );
          } catch (err) {
            setComposerMsg((err && err.message) || "刷新云桌面失败", "error");
          } finally {
            state.busy[pid] = false;
            fillComposerDesktopSelect(
              state.desktops[pid] || [],
              state.composer.userServiceId || ""
            );
          }
        })();
      });

    $("#c-desktop") &&
      $("#c-desktop").addEventListener("click", function (ev) {
        /* HARD_GATE#842: row 操作「选择」*/
        const sel = ev.target && ev.target.closest
          ? ev.target.closest("[data-desk-select]")
          : null;
        if (sel) {
          const lab = sel.closest("label");
          const input = lab && lab.querySelector('input[type="radio"]');
          if (input && !input.disabled) {
            input.checked = true;
            input.dispatchEvent(new Event("change", { bubbles: true }));
          }
          return;
        }
        /* HARD_GATE#707-2: legacy in-panel refresh control */
        const hit = ev.target && ev.target.closest
          ? ev.target.closest('[data-act="composer-desktops"]')
          : null;
        if (!hit) return;
        ev.preventDefault();
        const pid = state.composer.profileId;
        if (!pid) {
          setComposerMsg("请先登录以加载官方云桌面列表", "error");
          return;
        }
        (async function () {
          try {
            state.busy[pid] = true;
            setComposerMsg("正在刷新官方云桌面列表…");
            if (hit) {
              hit.disabled = true;
              hit.classList.add("is-loading");
              hit.textContent = "刷新中…";
            }
            const deskData = await api(
              "/api/profiles/" + encodeURIComponent(pid) + "/desktops"
            );
            const list =
              (deskData && (deskData.desktops || deskData.items || deskData.list)) ||
              (Array.isArray(deskData) ? deskData : []) ||
              [];
            state.desktops[pid] = list;
            fillComposerDesktopSelect(
              list,
              state.composer.userServiceId || ""
            );
            setComposerMsg(
              list.length
                ? "已刷新官方云桌面 " + list.length + " 台"
                : "官方列表为空",
              list.length ? "ok" : "warn"
            );
          } catch (err) {
            setComposerMsg(
              (err && err.message) || "刷新云桌面失败",
              "error"
            );
          } finally {
            state.busy[pid] = false;
            // rebuild CTA if list still empty / restore label
            fillComposerDesktopSelect(
              state.desktops[pid] || [],
              state.composer.userServiceId || ""
            );
          }
        })();
      });

    $("#c-desktop") &&
      $("#c-desktop").addEventListener("change", function (ev) {
        const t = ev.target;
        if (!t || t.name !== "c-desktop") return;
        const id = t.value || "";
        const label = t.getAttribute("data-label") || id;
        state.composer.userServiceId = id;
        state.composer.desktopLabel = label;
        var spuPick = t.getAttribute("data-spu") || "";
        if (!spuPick) {
          var pid0 = state.composer.profileId;
          var list0 = (pid0 && state.desktops[pid0]) || [];
          for (var si = 0; si < list0.length; si++) {
            var dd = list0[si] || {};
            if (String(dd.userServiceId || dd.id || "") === String(id)) {
              spuPick = String(dd.spuCode || dd.spu || "");
              break;
            }
          }
        }
        state.composer.spuCode = spuPick;
        if ($("#c-userServiceId")) $("#c-userServiceId").value = id;
        if ($("#c-desktopLabel")) $("#c-desktopLabel").value = label;
        if ($("#c-spuCode")) $("#c-spuCode").value = spuPick;
        $$("#c-desktop tbody tr").forEach(function (tr) {
          tr.classList.toggle("is-selected", tr.contains(t));
        });
        $$("#c-desktop .desk-select-btn").forEach(function (btn) {
          const on = btn.closest("label") && btn.closest("label").contains(t);
          btn.classList.toggle("is-active", !!on);
          btn.textContent = on ? "已选" : "选择";
        });
        const pid = state.composer.profileId;
        const list = (pid && state.desktops[pid]) || [];
        for (let i = 0; i < list.length; i++) {
          const d = list[i] || {};
          if (String(d.userServiceId || d.id || "") === String(id)) {
            applyOfficialFromDesktop(state.composer, d);
            break;
          }
        }
      });

    const help = $("#help-modal");
    $("#btn-help") &&
      $("#btn-help").addEventListener("click", function () {
        if (!help) return;
        help.classList.remove("hidden");
        help.setAttribute("aria-hidden", "false");
      });
    $("#help-close") &&
      $("#help-close").addEventListener("click", function () {
        if (!help) return;
        help.classList.add("hidden");
        help.setAttribute("aria-hidden", "true");
      });


    $("#config-modal-close") &&
      $("#config-modal-close").addEventListener("click", function () {
        closeConfigModal();
      });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" || ev.key === "Esc") {
        // HARD_GATE#827: Esc closes full-log modal before config/help
        const lm = $("#log-modal") || $("#log-full-modal");
        if (
          lm &&
          state.logModalPid &&
          !lm.classList.contains("hidden") &&
          lm.getAttribute("aria-hidden") !== "true"
        ) {
          closeLogModal();
          return;
        }
        const cm = $("#config-modal");
        if (cm && !cm.classList.contains("hidden")) {
          closeConfigModal();
          return;
        }
        const help = $("#help-modal");
        if (help && !help.classList.contains("hidden")) {
          help.classList.add("hidden");
          help.setAttribute("aria-hidden", "true");
        }
      }
    });

    try {
      const u = new URL(location.href);
      const t = u.searchParams.get("token");
      if (t) {
        setToken(t);
        u.searchParams.delete("token");
        history.replaceState({}, "", u.pathname + u.search + u.hash);
        // Token arrived after boot path may have skipped SSE; reconnect with ?token=.
        state.sseNeedTokenLogged = false;
        connectSSE();
      }
    } catch (_) { logCatch("catch", _); }
  }

  async function boot() {
    bindCardEvents();
    wireChrome();
    wireAccessGate();
    wireTokenModal();
    await loadSys();
    // Access gate: no server key → setup; has key but no local token → login.
    if (state.setupRequired) {
      showAccessGate("setup");
      updateTokenBtn();
      return;
    }
    if (state.tokenRequired && !getToken()) {
      showAccessGate("login");
      updateTokenBtn();
      return;
    }
    // HARD_GATE#global-run-log: hydrate page log from backend (survives FE reload / tunnel)
    try {
      await loadGlobalLogs();
    } catch (_) { logCatch("catch", _); }
    pushGlobal("爱家移动云电脑就绪 · 多账户保活控制台");
    try {
      await loadProfiles(true);
    } catch (e) {
      const code = (e && (e.code || (e.error && e.error.code))) || "";
      if (
        e &&
        (e.status === 401 ||
          code === "AUTH_REQUIRED" ||
          code === "TOKEN_REQUIRED" ||
          code === "SETUP_REQUIRED")
      ) {
        if (code === "SETUP_REQUIRED" || state.setupRequired) showAccessGate("setup");
        else showAccessGate("login");
        updateTokenBtn();
        return;
      }
    }
    connectSSE();
    startPolling();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
