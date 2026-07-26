  function confirmModal(title, body, okText) {
    return new Promise(function (resolve) {
      const modal = $("#modal");
      const t = $("#modal-title");
      const b = $("#modal-body");
      const ok = $("#modal-ok");
      const cancel = $("#modal-cancel");
      if (!modal || !ok || !cancel) {
        resolve(window.confirm(body || title));
        return;
      }
      t.textContent = title || "确认";
      b.textContent = body || "";
      ok.textContent = okText || "确定删除";
      // HARD_GATE#843: tertiary confirm above config modal
      modal.style.zIndex = "1300";
      modal.classList.remove("hidden");
      modal.setAttribute("aria-hidden", "false");
      setTimeout(function () {
        try {
          cancel.focus();
        } catch (_) { logCatch("catch", _); }
      }, 0);
      const done = function (v) {
        modal.classList.add("hidden");
        modal.setAttribute("aria-hidden", "true");
        ok.onclick = null;
        cancel.onclick = null;
        resolve(v);
      };
      ok.onclick = function () {
        done(true);
      };
      cancel.onclick = function () {
        done(false);
      };
    });
  }

  async function onSave(pid) {
    // HARD_GATE#save-login: always pull open form fields first — otherwise
    // password/username typed in modal never land in draft (input event may
    // miss when user clicks 保存 immediately after typing).
    const form =
      $("#config-form") ||
      document.querySelector('[data-id="' + pid + '"]') ||
      document.querySelector('.config-modal [data-pid="' + pid + '"]');
    if (form) {
      const inputs = form.querySelectorAll("[data-key]");
      for (let i = 0; i < inputs.length; i++) {
        applyDraftFromEl(inputs[i]);
      }
    }
    const d = ensureDraft(pid);
    state.busy[pid] = true;
    renderCards();
    try {
      // gate6: only POST /login when password present (username-only must not force re-auth)
      // HARD_GATE#ye4: must pass mode/isSubAccount — sub accounts reject main passwordLogin (4119)
      // HARD_GATE#save-login: /login is the ONLY endpoint that persists password
      // into profile state (profiles_patch rejects password). Always login when
      // password present so 保存 = 写 state + 上游鉴权.
      if (d.password) {
        const p = state.profiles.find(function (x) {
          return x.id === pid;
        });
        const loginMode = resolveLoginMode(d, p);
        await api("/api/profiles/" + encodeURIComponent(pid) + "/login", {
          method: "POST",
          body: {
            username: d.username || undefined,
            password: d.password,
            mode: loginMode,
            isSubAccount: loginMode === "sub",
            clientProfile: d.clientProfile || undefined,
          },
        });
      }
      if (d.userServiceId) {
        await api(
          "/api/profiles/" + encodeURIComponent(pid) + "/select-desktop",
          {
            method: "POST",
            body: {
              userServiceId: d.userServiceId || undefined,
              desktopLabel: d.desktopLabel || undefined,
              protocol: resolveUserProtocol(d.protocol, d.lastOfficialProtocol),
              protocolHint: (d.protocol || "").toUpperCase() || undefined,
              spuCode: d.spuCode || undefined,
            },
          }
        );
      }
      d.password = "";
      state.cardMsg[pid] = "";
      toast("配置已保存");
      pushGlobal("[" + pid + "] 配置已保存");
      closeConfigModal();
      await loadProfiles();
    } catch (e) {
      const msg = humanError(e, "保存失败");
      state.cardMsg[pid] = msg;
      toast(msg, true);
      pushGlobal("[" + pid + "] 保存失败: " + msg, "error");
      renderCards();
    } finally {
      state.busy[pid] = false;
      renderCards();
    }
  }

  async function onStart(pid) {
    const d = ensureDraft(pid);
    const p = state.profiles.find(function (x) {
      return x.id === pid;
    });
    if (!(d.userServiceId || d.desktopLabel || (p && (p.userServiceId || p.desktopLabel)))) {
      const msg = "请先选择云桌面";
      state.cardMsg[pid] = msg;
      toast(msg, true);
      renderCards();
      return;
    }
    state.busy[pid] = true;
    state.cardMsg[pid] = "";
    renderCards();
    try {
      // gate6: only POST /login when password is present (avoid "username only" → 401 AUTH_FAILED)
      // HARD_GATE#ye4: pass mode/isSubAccount so sub-account re-login uses sub_password_login
      if (d.password) {
        const loginMode = resolveLoginMode(d, p);
        await api("/api/profiles/" + encodeURIComponent(pid) + "/login", {
          method: "POST",
          body: {
            username: d.username || undefined,
            password: d.password,
            mode: loginMode,
            isSubAccount: loginMode === "sub",
          },
        });
      }
      // 登录后尽量刷新桌面列表 / 协议提示（refresh=1：绕过缓存重新拉取官方列表）
      try {
        const deskData = await api(
          "/api/profiles/" + encodeURIComponent(pid) + "/desktops?refresh=1"
        );
        const list =
          (deskData && (deskData.desktops || deskData.items || deskData.list)) ||
          (Array.isArray(deskData) ? deskData : []) ||
          [];
        state.desktops[pid] = list;
        if (d.userServiceId) {
          for (let i = 0; i < list.length; i++) {
            const x = list[i] || {};
            const xid = x.userServiceId || x.id || "";
            if (xid === d.userServiceId) {
              applyOfficialFromDesktop(d, x);
              break;
            }
          }
        } else if (list.length === 1) {
          const only = list[0] || {};
          d.userServiceId = only.userServiceId || only.id || "";
          d.desktopLabel =
            only.desktopLabel || only.name || only.label || d.userServiceId;
          applyOfficialFromDesktop(d, only);
        }
      } catch (_) {
        /* 桌面刷新失败不阻断启动；AUTH 等由后续 select/jobs 暴露 */
      }
      if (d.userServiceId) {
        await api(
          "/api/profiles/" + encodeURIComponent(pid) + "/select-desktop",
          {
            method: "POST",
            body: {
              userServiceId: d.userServiceId || undefined,
              desktopLabel: d.desktopLabel || undefined,
              protocol: resolveUserProtocol(d.protocol, d.lastOfficialProtocol),
              protocolHint: (d.protocol || "").toUpperCase() || undefined,
              spuCode: d.spuCode || undefined,
            },
          }
        );
      }
      const mode = modeApi(d.mode);
      const trafficSec = Number(d.trafficSec || 60);
      const durationSec = durationForMode(mode, trafficSec);
      const data = await api(
        "/api/profiles/" + encodeURIComponent(pid) + "/jobs",
        {
          method: "POST",
          body: {
            protocol: resolveUserProtocol(d.protocol, d.lastOfficialProtocol),
            mode: mode,
            clientProfile: d.clientProfile || "linux",
            intervalSec: Math.max(60, Number(d.intervalMin || 5) * 60),
            trafficSec: trafficSec,
            /* #848: once uses trafficSec; live forever uses 0 */
            durationSec: durationSec,
          },
        }
      );
      toast(modeIsOnce(mode) ? "已启动单轮保活" : "已开始保活");
      pushGlobal(
        "[" +
          ((p && p.displayName) || pid) +
          "] 开始保活 · " +
          protocolLabel(d.protocol) +
          " · " +
          modeLabel(mode)
      );
      d.password = "";
      /* no card expand */
      closeConfigModal();
      await loadProfiles();
      await loadLogs(pid);
      return data;
    } catch (e) {
      const msg = humanError(e, "启动失败");
      state.cardMsg[pid] = msg;
      toast(msg, true);
      pushGlobal("[" + pid + "] 启动失败: " + msg, "error");
      renderCards();
    } finally {
      state.busy[pid] = false;
      renderCards();
    }
  }

  async function onStop(pid) {
    state.busy[pid] = true;
    renderCards();
    try {
      await api(
        "/api/profiles/" + encodeURIComponent(pid) + "/jobs/current",
        { method: "DELETE" }
      );
      toast("已停止保活");
      pushGlobal("[" + pid + "] 已停止保活");
      state.cardMsg[pid] = "";
      await loadProfiles();
      await loadLogs(pid);
    } catch (e) {
      const msg = humanError(e, "停止失败");
      state.cardMsg[pid] = msg;
      toast(msg, true);
      pushGlobal("[" + pid + "] 停止失败: " + msg, "error");
      renderCards();
    } finally {
      state.busy[pid] = false;
      renderCards();
    }
  }

  function onRefreshLogs(pid) {
    // Card button: clear local log display only; does NOT stop job / logout.
    if (!pid) return;
    state.logs = state.logs || {};
    state.logs[pid] = [];
    state._logClearedAt = state._logClearedAt || {};
    state._logClearedAt[pid] = Date.now();
    try { applyLogsToDom(pid, true); } catch (_e) { logCatch("catch", _e); }
    if (state.logModalPid === pid) {
      const full =
        document.querySelector("#log-full-body") ||
        document.querySelector("#log-modal-body");
      if (full) full.textContent = "";
    }
    toast("已刷新日志");
    pushGlobal("[" + pid + "] 已刷新日志显示");
  }

  async function onClearThread(pid) {
    // Card button: stop/clear local keepalive worker for this profile.
    // Replaces upstream desktop-logout; user evidence shows orphan local
    // threads (not SOHO logout) were what blocked restart after fail.
    if (!pid) return;
    const p = state.profiles.find(function (x) {
      return x.id === pid;
    });
    const name = (p && p.displayName) || pid;
    const ok = await confirmModal(
      "清除线程",
      "确定清除「" +
        name +
        "」的当前保活线程？将先调用桌面登出释放远端会话，再停止本机任务；账号登录态保留。",
      "确定清除"
    );
    if (!ok) return;
    state.busy[pid] = true;
    renderCards();
    try {
      await api(
        "/api/profiles/" + encodeURIComponent(pid) + "/jobs/current",
        { method: "DELETE" }
      );
      toast("已清除保活线程");
      pushGlobal("[" + pid + "] 已清除保活线程");
      state.cardMsg[pid] = "";
      await loadProfiles();
      await loadLogs(pid).catch(function (err) { logCatch("promise", err); });
    } catch (e) {
      // No running job is still a successful "clear" from user POV.
      const code = e && (e.code || e.status);
      const msgRaw = String((e && (e.message || e.detail)) || "");
      if (
        code === "NOT_FOUND" ||
        code === 404 ||
        /not.?found|no.+job|无.+任务|没有.+任务/i.test(msgRaw)
      ) {
        toast("当前无运行中的保活线程");
        pushGlobal("[" + pid + "] 清除线程：当前无运行任务");
        state.cardMsg[pid] = "";
        await loadProfiles().catch(function (err) { logCatch("promise", err); });
      } else {
        const msg = humanError(e, "清除线程失败");
        state.cardMsg[pid] = msg;
        toast(msg, true);
        pushGlobal("[" + pid + "] 清除线程失败: " + msg, "error");
        renderCards();
      }
    } finally {
      state.busy[pid] = false;
      renderCards();
    }
  }

  // Backward-compat alias (old handlers / residual callers).
  async function onDesktopLogout(pid) {
    return onClearThread(pid);
  }

  async function onDelete(pid) {
    const p = state.profiles.find(function (x) {
      return x.id === pid;
    });
    const name = (p && p.displayName) || pid;
    const ok = await confirmModal(
      "删除账号",
      "确定删除该账号？删除后无法恢复",
      "确定删除"
    );
    if (!ok) return;
    state.busy[pid] = true;
    renderCards();
    try {
      await api("/api/profiles/" + encodeURIComponent(pid), {
        method: "DELETE",
      });
      delete state.drafts[pid];
      delete state.logs[pid];
      delete state.cardMsg[pid];
      delete state.desktops[pid];
      if (state.configPid === pid) closeConfigModal();
      toast("已删除 " + name);
      pushGlobal("已删除账号 " + name);
      await loadProfiles();
    } catch (e) {
      const msg = humanError(e, "删除失败");
      state.cardMsg[pid] = msg;
      toast(msg, true);
      pushGlobal("[" + pid + "] 删除失败: " + msg, "error");
      renderCards();
    } finally {
      state.busy[pid] = false;
      renderCards();
    }
  }


  async function onDesktops(pid) {
    state.busy[pid] = true;
    renderCards();
    try {
      // Explicit user refresh must bypass the server-side cloudList cache,
      // otherwise added/removed desktops and power state never update.
      const data = await api(
        "/api/profiles/" + encodeURIComponent(pid) + "/desktops?refresh=1"
      );
      const list =
        (data && (data.desktops || data.items || data.list)) ||
        (Array.isArray(data) ? data : []) ||
        [];
      state.desktops[pid] = list;
      const d = ensureDraft(pid);
      if (d.userServiceId) {
        for (let i = 0; i < list.length; i++) {
          const x = list[i] || {};
          const xid = x.userServiceId || x.id || "";
          if (xid === d.userServiceId) {
            applyOfficialFromDesktop(d, x);
            break;
          }
        }
      } else if (list.length === 1) {
        const only = list[0] || {};
        d.userServiceId = only.userServiceId || only.id || "";
        d.desktopLabel =
          only.desktopLabel || only.name || only.label || d.userServiceId;
        applyOfficialFromDesktop(d, only);
      }
      // A12: success/info stays in toast+global log; cardMsg is error-only (red)
      state.cardMsg[pid] = "";
      const info = list.length
        ? "已加载 " + list.length + " 个云桌面"
        : "未返回云桌面，请确认已登录";
      toast(info);
      pushGlobal("[" + pid + "] " + info);
      renderCards();
    } catch (e) {
      const msg = humanError(e, "刷新桌面失败");
      state.cardMsg[pid] = msg;
      toast(msg, true);
      pushGlobal("[" + pid + "] 刷新桌面失败: " + msg, "error");
      renderCards();
    } finally {
      state.busy[pid] = false;
      renderCards();
    }
  }

  
  async function onConfigLogin(pid) {
    // HARD_GATE#784 + #save-login: modal 登录 = POST /login (写 password+sohoToken
    // 到 state) then refresh official desktops (no keepalive).
    // BUGFIX: previously used PUT /api/profiles/{id} which does not exist
    // (only PATCH, and patch rejects password) → silent no-op, state never
    // got new password → later 启动 showed AUTH_FAILED / 4119.
    if (!pid) return;
    state.busy[pid] = true;
    patchCardStatus(pid);
    // if config form open, keep form; avoid full card wipe of inputs
    try {
      // pull latest draft from open form fields
      const form =
        $("#config-form") ||
        document.querySelector('[data-id="' + pid + '"]') ||
        document.querySelector('.config-modal [data-pid="' + pid + '"]');
      if (form) {
        const inputs = form.querySelectorAll("[data-key]");
        for (let i = 0; i < inputs.length; i++) {
          applyDraftFromEl(inputs[i]);
        }
      }
      const d = ensureDraft(pid);
      const p = state.profiles.find(function (x) {
        return x.id === pid;
      });
      const loginMode = resolveLoginMode(d, p);
      if (!d.password && !(p && (p.sessionEstablished || p.hasPassword))) {
        throw new Error("请先填写密码再登录");
      }
      // ALWAYS go through /login so password lands in state file.
      await api("/api/profiles/" + encodeURIComponent(pid) + "/login", {
        method: "POST",
        body: {
          username: d.username || undefined,
          password: d.password || undefined,
          mode: loginMode,
          isSubAccount: loginMode === "sub",
          clientProfile: d.clientProfile || undefined,
        },
      });
      // clear password from draft after successful write (matches onSave)
      d.password = "";
      toast("登录成功，正在刷新云桌面");
      pushGlobal("[" + pid + "] 配置登录成功，已写 state");
      await loadProfiles();
      await onDesktops(pid);
    } catch (e) {
      const msg = humanError(e, "登录失败");
      state.cardMsg[pid] = msg;
      toast(msg, true);
      pushGlobal("[" + pid + "] " + msg, "error");
    } finally {
      state.busy[pid] = false;
      // refresh modal desktop list without nuking logs if possible
      if (state.configPid === pid) {
        try {
          refreshConfigModal();
        } catch (_) {
          renderCards();
        }
      } else {
        patchCardStatus(pid);
      }
    }
  }

  function setComposerOfficial(text) {
    /* HARD_GATE#707-3/4: drop 协议提示 / 官方协议 independent UI; keep data-only no-op */
    const el = $("#c-official-protocol");
    if (el) {
      el.textContent = text || "未登录";
      const wrap = el.closest(".official-protocol-field") || el.parentElement;
      if (wrap && wrap.style) wrap.style.display = "none";
      el.style.display = "none";
    }
  }

  function composerDeskEmptyHtml() {
    /* HARD_GATE#842: table empty state matching reference layout */
    return (
      '<div class="desk-table-wrap"><table class="desk-table" aria-label="云桌面">' +
      "<thead><tr>" +
      '<th class="col-idx">序号</th>' +
      '<th class="col-name">名称</th>' +
      '<th class="col-id">ID</th>' +
      '<th class="col-proto">协议</th>' +
      '<th class="col-act">操作</th>' +
      "</tr></thead>" +
      '<tbody id="c-desktop-tbody">' +
      '<tr class="desk-empty-row"><td colspan="5">' +
      '<div class="desk-empty"><div class="desk-empty-title">暂无数据</div>' +
      '<div class="desk-empty-hint">登录后自动获取云桌面列表</div></div>' +
      "</td></tr></tbody></table></div>"
    );
  }

  function desktopSpecText(d) {
    d = d || {};
    const spu = d.spuCode || d.spu_code || "";
    if (spu) return String(spu);
    const cpu = d.cpu || d.cpuNum || d.cpuCore || "";
    const mem = d.memory || d.mem || d.ram || "";
    if (cpu || mem) return String(cpu || "—") + "C / " + String(mem || "—") + "G";
    const spec = d.spec || d.productName || d.packageName || d.resourceName || "";
    return spec ? String(spec) : "—";
  }

  function desktopStatusText(d) {
    d = d || {};
    const st =
      d.vmStatusShow ||
      d.statusName ||
      d.statusText ||
      d.desktopStatusName ||
      d.pcStatusName ||
      d.runStatusName ||
      d.status ||
      d.desktopStatus ||
      d.pcStatus ||
      d.runStatus ||
      "";
    if (st === 0 || st === "0") return "未知";
    return st ? String(st) : "—";
  }

  function desktopProtocolText(d) {
    /* HARD_GATE#846: protocol col = spuCode (python CLI: | spuCode：xxx) */
    d = d || {};
    const spu = d.spuCode || d.spu_code || d.spu || "";
    if (spu) return String(spu);
    const hint = d.protocolHint || d.protocol || d.clientProtocol || "";
    return hint ? String(hint) : "—";
  }


  function setComposerDeskRefreshEnabled(unlocked) {
    const btn = $("#c-desk-refresh");
    if (!btn) return;
    const pid = state.composer && state.composer.profileId;
    const busy = !!(pid && state.busy[pid]);
    btn.disabled = !unlocked || busy;
    btn.textContent = busy ? "刷新中…" : "刷新列表";
    btn.classList.toggle("is-loading", busy);
  }

  function setComposerDesktopLock(unlocked) {
    const box = $("#c-desktop");
    if (box) {
      box.classList.toggle("is-locked", !unlocked);
      box.setAttribute("aria-disabled", unlocked ? "false" : "true");
      const radios = box.querySelectorAll('input[type="radio"]');
      for (let i = 0; i < radios.length; i++) {
        radios[i].disabled = !unlocked;
      }
      const acts = box.querySelectorAll(".desk-select-btn");
      for (let i = 0; i < acts.length; i++) {
        acts[i].disabled = !unlocked;
      }
    }
    setComposerDeskRefreshEnabled(unlocked);
    const sub = $("#c-desktop-sub");
    if (sub) {
      sub.textContent = unlocked ? "已加载，可选择云桌面" : "登录后自动获取";
    }
    const note = $("#c-desktop-note");
    if (note) {
      note.textContent = unlocked
        ? "官方 list_clouds 已加载；在操作列点击「选择」"
        : "登录成功后展示官方 list_clouds（名称 / id | spuCode：xxx）";
    }
  }

  function desktopOptionLabel(d) {
    /* HARD_GATE#781: 名称 / id | spuCode：xxx */
    return desktopRowText(d || {});
  }

  function fillComposerDesktopSelect(list, selectedId) {
    /* HARD_GATE#842: composer desktop = full-width table */
    const box = $("#c-desktop");
    if (!box) return;
    list = Array.isArray(list) ? list : [];
    if (!list.length) {
      box.innerHTML = composerDeskEmptyHtml();
      state.composer.userServiceId = "";
      state.composer.desktopLabel = "";
      if ($("#c-userServiceId")) $("#c-userServiceId").value = "";
      if ($("#c-desktopLabel")) $("#c-desktopLabel").value = "";
      setComposerDesktopLock(!!(state.composer && state.composer.profileId));
      return;
    }
    let matched = false;
    let rows = "";
    for (let i = 0; i < list.length; i++) {
      const d = list[i] || {};
      const id = String(d.userServiceId || d.id || "");
      const spu = String(d.spuCode || d.spu || "");
      const label = d.desktopLabel || d.skuName || d.sku || d.vmName || d.name || d.labelName || id || "未命名";
      const active =
        selectedId && String(selectedId) === id
          ? true
          : !selectedId && list.length === 1;
      if (active) matched = true;
      const rid = "c-desk-" + i + "-" + id.replace(/[^a-zA-Z0-9_-]/g, "_");
      const proto = desktopProtocolText(d);
      const seq = String(i + 1);
      rows +=
        '<tr class="' +
        (active ? "is-selected" : "") +
        '">' +
        '<td class="col-idx">' +
        esc(seq) +
        "</td>" +
        '<td class="col-name" title="' +
        esc(label) +
        '">' +
        esc(label) +
        "</td>" +
        '<td class="col-id" title="' +
        esc(id) +
        '">' +
        esc(id || "—") +
        "</td>" +
        '<td class="col-proto" title="' +
        esc(proto) +
        '">' +
        esc(proto) +
        "</td>" +
        '<td class="col-act">' +
        '<label class="desk-select-wrap" for="' +
        rid +
        '">' +
        '<input type="radio" class="sr-only" name="c-desktop" id="' +
        rid +
        '" value="' +
        esc(id) +
        '" data-label="' +
        esc(label) +
        '" data-spu="' +
        esc(proto) +
        '"' +
        (active ? " checked" : "") +
        " />" +
        '<span class="btn btn-secondary desk-select-btn' +
        (active ? " is-active" : "") +
        '" data-desk-select="1">' +
        (active ? "已选" : "选择") +
        "</span></label></td></tr>";
    }
    box.innerHTML =
      '<div class="desk-table-wrap"><table class="desk-table" aria-label="云桌面">' +
      "<thead><tr>" +
      '<th class="col-idx">序号</th>' +
      '<th class="col-name">名称</th>' +
      '<th class="col-id">ID</th>' +
      '<th class="col-proto">协议</th>' +
      '<th class="col-act">操作</th>' +
      "</tr></thead>" +
      '<tbody id="c-desktop-tbody">' +
      rows +
      "</tbody></table></div>";
    if (matched) {
      const act = box.querySelector('input[name="c-desktop"]:checked');
      if (act) {
        state.composer.userServiceId = act.value || "";
        state.composer.desktopLabel =
          act.getAttribute("data-label") || act.value || "";
        if ($("#c-userServiceId")) $("#c-userServiceId").value = act.value || "";
        if ($("#c-desktopLabel"))
          $("#c-desktopLabel").value =
            act.getAttribute("data-label") || act.value || "";
      }
    }
    setComposerDesktopLock(true);
  }

  function applyOfficialFromDesktop(target, d) {
    /* gate6: never overwrite user-selected protocol; only record official hint */
    if (!target || !d) return;
    const hint = (
      d.protocolHint ||
      d.protocol_hint ||
      d.protocol ||
      ""
    )
      .toString()
      .toUpperCase();
    let off = "";
    if (hint === "ZX" || hint === "ZHONGXING") off = "ZTE";
    else if (hint === "SANGFOR") off = "SCG";
    else if (hint === "ZTE" || hint === "SCG") off = hint;
    const spu = d.spuCode || d.spu_code || "";
    if (off) {
      target.lastOfficialProtocol = off;
      target.protocolHint = off;
      if (!target.protocol) target.protocol = off;
    }
    if (spu) target.spuCode = spu;
    if (off || spu) {
      setComposerOfficial(
        (off || "未知") + (spu ? " · spu " + spu : "") +
          (target.protocol && off && target.protocol !== off
            ? "（用户选 " + target.protocol + "）"
            : "")
      );
    }
  }

  function ensureComposerLoginBtn() {
    // HTML already has dual login buttons; keep as no-op fallback.
    if ($("#c-login") && $("#c-login-sub")) return;
    const actions = $(".composer-actions") || $(".field-login-cta");
    if (!actions) return;
    if (!$("#c-login")) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-primary btn-login-cta";
      btn.id = "c-login";
      btn.textContent = "主帐号获取云桌面";
      btn.title = "主帐号登录并加载官方云桌面列表（不启动保活）";
      actions.appendChild(btn);
    }
    if (!$("#c-login-sub")) {
      const btn2 = document.createElement("button");
      btn2.type = "button";
      btn2.className = "btn btn-secondary btn-login-cta";
      btn2.id = "c-login-sub";
      btn2.textContent = "子帐号获取云桌面";
      btn2.title = "子帐号登录并加载官方云桌面列表（不启动保活）";
      actions.appendChild(btn2);
    }
  }

  async function composerLoginOnly(ev, modeOpt) {
    if (ev) ev.preventDefault();
    const mode = modeOpt === "sub" ? "sub" : "main";
    const isSub = mode === "sub";
    const c = readComposer();
    if (!c.username) {
      setComposerMsg("请填写账号", "error");
      return;
    }
    if (!c.password) {
      setComposerMsg("请填写密码", "error");
      return;
    }
    const loginBtn = $("#c-login");
    const loginSubBtn = $("#c-login-sub");
    const submitBtn = $("#c-submit");
    if (loginBtn) loginBtn.disabled = true;
    if (loginSubBtn) loginSubBtn.disabled = true;
    if (submitBtn) submitBtn.disabled = true;
    setComposerMsg("正在登录…");
    try {
      let pid = state.composer.profileId || "";
      if (!pid) {
        const created = await api("/api/profiles", {
          method: "POST",
          body: {
            displayName: c.displayName || undefined,
            username: c.username,
            password: c.password,
            clientProfile: c.clientProfile || "linux",
            protocol: resolveUserProtocol(c.protocol),
            draft: true,
          },
        });
        const p = created && created.profile;
        if (!p || !p.id) throw new Error("创建账号失败");
        pid = p.id;
        state.composer.profileId = pid;
        ensureDraft(pid, p);
      } else {
        ensureDraft(pid);
      }
      state.drafts[pid].username = c.username;
      state.drafts[pid].password = c.password;
      state.drafts[pid].protocol = resolveUserProtocol(c.protocol);
      state.drafts[pid].lastOfficialProtocol = state.drafts[pid].protocol;
      state.drafts[pid].clientProfile = c.clientProfile;
      state.drafts[pid].mode = c.mode;
      state.drafts[pid].intervalMin = c.intervalMin;
      state.drafts[pid].trafficSec = c.trafficSec;
      state.drafts[pid].durationSec = 0;
      state.drafts[pid].loginMode = mode;
      state.drafts[pid].isSubAccount = isSub;
      state.composer.loginMode = mode;
      state.composer.isSubAccount = isSub;

      await api("/api/profiles/" + encodeURIComponent(pid) + "/login", {
        method: "POST",
        body: {
          username: c.username,
          password: c.password,
          mode: mode,
          isSubAccount: isSub,
        },
      });
      setComposerMsg("登录成功，正在加载官方云桌面列表…", "ok");
      setComposerDesktopLock(true);
      pushGlobal(
        "[" + (c.displayName || c.username) + "] 登录成功，加载云桌面列表"
      );

      let list = [];
      try {
        const deskData = await api(
          "/api/profiles/" + encodeURIComponent(pid) + "/desktops?refresh=1"
        );
        list =
          (deskData && (deskData.desktops || deskData.items || deskData.list)) ||
          (Array.isArray(deskData) ? deskData : []) ||
          [];
        state.desktops[pid] = list;
        fillComposerDesktopSelect(list, c.userServiceId || "");
        if (!c.userServiceId && list.length === 1) {
          const only = list[0] || {};
          c.userServiceId = only.userServiceId || only.id || "";
          c.desktopLabel =
            only.desktopLabel || only.name || only.label || c.userServiceId;
          applyOfficialFromDesktop(c, only);
          applyOfficialFromDesktop(state.drafts[pid], only);
          fillComposerDesktopSelect(list, c.userServiceId);
        } else if (c.userServiceId) {
          const hit = list.find(function (d) {
            const id = d.userServiceId || d.id || "";
            return id === c.userServiceId;
          });
          if (hit) {
            applyOfficialFromDesktop(c, hit);
            applyOfficialFromDesktop(state.drafts[pid], hit);
          }
        }
        if (list.length) {
          setComposerMsg(
            "登录成功 · 已加载 " + list.length + " 台云桌面，请选择后点「保存并保活」",
            "ok"
          );
        } else {
          setComposerMsg("登录成功，但官方云桌面列表为空", "error");
        }
      } catch (de) {
        const dmsg = humanError(de, "云桌面列表加载失败");
        pushGlobal(
          "[" + (c.displayName || c.username) + "] 刷新桌面: " + dmsg,
          "error"
        );
        setComposerMsg("登录成功，但桌面列表失败: " + dmsg, "error");
      }
      /* HARD_GATE#850: login-only must not push draft into timeline */
        } catch (e) {
      const msg = humanError(e, "登录失败");
      setComposerMsg(msg, "error");
      toast(msg, true);
      pushGlobal("Composer 登录失败: " + msg, "error");
      /* HARD_GATE#850: login-only must not push draft into timeline */
        } finally {
      if (loginBtn) loginBtn.disabled = false;
      if (loginSubBtn) loginSubBtn.disabled = false;
      if (submitBtn) submitBtn.disabled = false;
    }
  }

  async function composerSaveAndStart(ev) {
    if (ev) ev.preventDefault();
    const c = readComposer();
    if (!c.username) {
      setComposerMsg("请填写账号", "error");
      return;
    }
    if (!c.password) {
      setComposerMsg("请填写密码", "error");
      return;
    }
    const btn = $("#c-submit");
    const loginBtn = $("#c-login");
    if (btn) btn.disabled = true;
    if (loginBtn) loginBtn.disabled = true;
    setComposerMsg("正在保存并启动保活…");
    try {
      let pid = state.composer.profileId || "";
      if (!pid) {
        // Not yet logged via 登录: create profile first (still require desktop)
        const created = await api("/api/profiles", {
          method: "POST",
          body: {
            displayName: c.displayName || undefined,
            username: c.username,
            password: c.password,
            clientProfile: c.clientProfile || "linux",
            protocol: resolveUserProtocol(c.protocol),
          },
        });
        const p = created && created.profile;
        if (!p || !p.id) throw new Error("创建账号失败");
        pid = p.id;
        state.composer.profileId = pid;
        ensureDraft(pid, p);
        await api("/api/profiles/" + encodeURIComponent(pid) + "/login", {
          method: "POST",
          body: { username: c.username, password: c.password },
        });
        setComposerDesktopLock(true);
        try {
          const deskData = await api(
            "/api/profiles/" + encodeURIComponent(pid) + "/desktops"
          );
          const list =
            (deskData &&
              (deskData.desktops || deskData.items || deskData.list)) ||
            (Array.isArray(deskData) ? deskData : []) ||
            [];
          state.desktops[pid] = list;
          fillComposerDesktopSelect(list, c.userServiceId || "");
          if (!c.userServiceId && list.length === 1) {
            const only = list[0] || {};
            c.userServiceId = only.userServiceId || only.id || "";
            c.desktopLabel =
              only.desktopLabel || only.name || only.label || c.userServiceId;
            applyOfficialFromDesktop(c, only);
            applyOfficialFromDesktop(state.drafts[pid], only);
            fillComposerDesktopSelect(list, c.userServiceId);
          }
        } catch (_) { logCatch("catch", _); }
      }
      ensureDraft(pid);
      state.drafts[pid].username = c.username;
      state.drafts[pid].password = c.password;
      state.drafts[pid].protocol = resolveUserProtocol(c.protocol);
      state.drafts[pid].lastOfficialProtocol = state.drafts[pid].protocol;
      state.drafts[pid].clientProfile = c.clientProfile;
      state.drafts[pid].mode = c.mode;
      state.drafts[pid].intervalMin = c.intervalMin;
      state.drafts[pid].trafficSec = c.trafficSec;
      state.drafts[pid].durationSec = 0;

      // re-read desktop selection from DOM after possible fill
      const c2 = readComposer();
      c.userServiceId = c2.userServiceId || c.userServiceId;
      c.desktopLabel = c2.desktopLabel || c.desktopLabel;
      c.protocol = c2.protocol || c.protocol;

      const list = state.desktops[pid] || [];
      if (!c.userServiceId) {
        if (list.length > 1) {
          setComposerMsg("请选择云桌面后再点「保存并保活」", "error");
          toast("请先选择云桌面", true);
          await loadProfiles();
          return;
        }
        if (!list.length) {
          setComposerMsg(
            "请先点「登录」加载官方云桌面列表，再选择桌面后保存并保活",
            "error"
          );
          toast("请先登录并选择云桌面", true);
          await loadProfiles();
          return;
        }
        if (list.length === 1) {
          const only = list[0] || {};
          c.userServiceId = only.userServiceId || only.id || "";
          c.desktopLabel =
            only.desktopLabel || only.name || only.label || c.userServiceId;
          applyOfficialFromDesktop(c, only);
          applyOfficialFromDesktop(state.drafts[pid], only);
        }
      }

      if (c.userServiceId) {
        await api(
          "/api/profiles/" + encodeURIComponent(pid) + "/select-desktop",
          {
            method: "POST",
            body: {
              userServiceId: c.userServiceId || undefined,
              desktopLabel: c.desktopLabel || undefined,
              protocol: (
                resolveUserProtocol(c.protocol, state.drafts[pid] && state.drafts[pid].protocol, state.drafts[pid] && state.drafts[pid].lastOfficialProtocol)
              ).toUpperCase(),
              protocolHint:
                (c.protocol || state.drafts[pid].protocol || "").toUpperCase() ||
                undefined,
              spuCode: state.drafts[pid].spuCode || undefined,
            },
          }
        );
        state.drafts[pid].userServiceId = c.userServiceId || "";
        state.drafts[pid].desktopLabel = c.desktopLabel || "";
      }

      setComposerMsg("正在启动保活…", "ok");
      const mode = modeApi(c.mode);
      const trafficSec = Number(c.trafficSec || 60);
      await api("/api/profiles/" + encodeURIComponent(pid) + "/jobs", {
        method: "POST",
        body: {
          protocol: (
            resolveUserProtocol(c.protocol, state.drafts[pid] && state.drafts[pid].protocol, state.drafts[pid] && state.drafts[pid].lastOfficialProtocol)
          ).toUpperCase(),
          mode: mode,
          clientProfile: c.clientProfile || "linux",
          intervalSec: Math.max(60, Number(c.intervalMin || 5) * 60),
          trafficSec: trafficSec,
          durationSec: durationForMode(mode, trafficSec),
        },
      });
      toast("保存并保活成功");
      setComposerMsg("保存并保活成功", "ok");
      pushGlobal(
        "[" +
          (c.displayName || c.username) +
          "] 保存并保活 · " +
          protocolLabel(c.protocol || state.drafts[pid].protocol) +
          " · " +
          modeLabel(mode)
      );
      clearComposer();
      await loadProfiles();
      await loadLogs(pid);
    } catch (e) {
      const msg = humanError(e, "保存并保活失败");
      setComposerMsg(msg, "error");
      toast(msg, true);
      pushGlobal("Composer 失败: " + msg, "error");
      await loadProfiles();
    } finally {
      if (btn) btn.disabled = false;
      if (loginBtn) loginBtn.disabled = false;
    }
  }

  // legacy alias (submit handler name used in older wires)
  async function composerLoginAndStart(ev) {
    return composerSaveAndStart(ev);
  }


  function applyDraftFromEl(el) {
    const pid = el.getAttribute("data-pid");
    const key = el.getAttribute("data-key");
    if (!pid || !key) return;
    const d = ensureDraft(pid);
    if (key === "desktop") {
      const parts = String(el.value || "").split("||");
      d.userServiceId = parts[0] || "";
      d.desktopLabel = parts[1] || parts[0] || "";
      const list = state.desktops[pid] || [];
      let matched = null;
      for (let i = 0; i < list.length; i++) {
        const x = list[i];
        const xid = x.userServiceId || x.id || "";
        if (xid === d.userServiceId) {
          matched = x;
          break;
        }
      }
      if (matched) {
        applyOfficialFromDesktop(d, matched);
      }
      const root = el.closest(".desk-seg");
      if (root) {
        const items = root.querySelectorAll(".desk-seg-item");
        for (let i = 0; i < items.length; i++) {
          items[i].classList.toggle(
            "is-active",
            items[i].contains(el) || (items[i].querySelector("input") || {}).checked
          );
        }
      }
      if (el.getAttribute("data-surface") === "1") {
        renderCards();
      } else if (state.configPid === pid) {
        refreshConfigModal();
      }
      return;
    }
    if (key === "intervalMin" || key === "trafficSec") {
      const raw = el.getAttribute("data-val");
      d[key] = Number(raw != null ? raw : el.value || 0);
    } else if (key === "durationSec") {
      /* HARD_GATE#729: ignore duration UI if residual HTML still present */
      d.durationSec = 0;
    } else {
      const raw = el.getAttribute("data-val");
      const val = raw != null ? raw : el.value;
      d[key] = val;
      if (key === "protocol" && val) {
        d.lastOfficialProtocol = val;
      }
      if (key === "clientProfile") {
        d.clientProfile = String(val || "linux").toLowerCase();
        persistClientProfile(pid, d.clientProfile);
      }
    }
    // seg-btn active state in config modal / cards
    if (el.classList && el.classList.contains("seg-btn")) {
      const group = el.closest(".seg");
      if (group) {
        const btns = group.querySelectorAll(".seg-btn");
        for (let i = 0; i < btns.length; i++) {
          btns[i].classList.toggle("active", btns[i] === el);
        }
      }
    }
  }

  function bindCardEvents() {
    const root = $("#timeline");
    if (!root || root._bound) return;
    root._bound = true;

    root.addEventListener("click", function (ev) {
      const segBtn = ev.target.closest(".seg-btn[data-key]");
      if (segBtn) {
        applyDraftFromEl(segBtn);
        return;
      }
      const actEl = ev.target.closest("[data-act]");
      const card = ev.target.closest(".card");
      if (!card) return;
      const pid = card.getAttribute("data-id");
      if (!pid) return;
      const act = actEl ? actEl.getAttribute("data-act") : "";
      // 配置入口：居中 Modal（OPS#337）；卡面保持紧凑不展开
      if (act === "config" || act === "config-close") {
        ev.preventDefault();
        if (act === "config-close") {
          closeConfigModal();
        } else if (state.configPid === pid) {
          closeConfigModal();
        } else {
          openConfigModal(pid);
          loadLogs(pid).catch(function (err) { logCatch("promise", err); });
        }
        return;
      }
      if (!act) return;
      ev.preventDefault();
      if (act === "start") onStart(pid);
      else if (act === "stop") onStop(pid);
      else if (act === "save") onSave(pid);
      else if (act === "delete") onDelete(pid);
      else if (act === "desktops") onDesktops(pid);
      else if (act === "login") onConfigLogin(pid);
      else if (act === "desktop-logout") onClearThread(pid);
      else if (act === "refresh-logs" || act === "clear-thread") onRefreshLogs(pid);
      else if (act === "clear-logs") {
        // HARD_GATE#853: real backend clear (not FE-only fake clear)
        if (!pid) return;
        const btn = ev.target.closest("[data-act]");
        if (btn) btn.disabled = true;
        api("/api/profiles/" + encodeURIComponent(pid) + "/logs", { method: "DELETE" })
          .then(function (data) {
            state.logs[pid] = [];
    try { patchCardDeskStatus(pid); } catch (_e) { logCatch("catch", _e); }
            state._logClearedAt = state._logClearedAt || {};
            state._logClearedAt[pid] = Date.now();
            applyLogsToDom(pid, true);
            if (state.logModalPid === pid) {
              const full =
                $("#log-full-body") ||
                $("#log-full .log-box") ||
                $(".log-full .log-box");
              if (full) full.innerHTML = profileLogsHtml(pid, { full: true });
            }
            const n = data && data.cleared != null ? data.cleared : 0;
            toast("已清空该账号日志" + (n ? "（" + n + "）" : ""));
            pushGlobal("[" + pid + "] 卡片日志已清空（后端缓冲 " + n + "）");
          })
          .catch(function (err) {
            toast((err && err.message) || "清空日志失败", "error");
            pushGlobal("[" + pid + "] 清空日志失败: " + ((err && err.message) || err), "error");
          })
          .finally(function () {
            if (btn) btn.disabled = false;
          });
      }
    });

    root.addEventListener("input", function (ev) {
      applyDraftFromEl(ev.target);
    });

    root.addEventListener("change", function (ev) {
      applyDraftFromEl(ev.target);
    });

    // HARD_GATE#768-C / HARD_GATE#810: double-click card log panel → full history modal
    root.addEventListener("dblclick", function (ev) {
      const t = ev.target;
      if (!t || !t.closest) return;
      // hit head / empty / line / box / whole panel (not only .log-box)
      const hit = t.closest(
        ".log-panel, .log-panel-head, .log-box, .log-viewport, .log-line, .log-empty, [data-log]"
      );
      if (!hit) return;
      const card = hit.closest(".card");
      const holder =
        (hit.getAttribute && hit.getAttribute("data-log") && hit) ||
        hit.closest("[data-log]") ||
        card;
      const pid =
        (holder && holder.getAttribute && holder.getAttribute("data-log")) ||
        (holder && holder.getAttribute && holder.getAttribute("data-id")) ||
        (card && card.getAttribute("data-id")) ||
        "";
      if (!pid) return;
      ev.preventDefault();
      if (ev.stopPropagation) ev.stopPropagation();
      openLogModal(pid);
      loadLogs(pid).catch(function (err) { logCatch("promise", err); });
    });

    // Modal is outside #timeline — bind separately (OPS#337)
    const modal = $("#config-modal");
    if (modal && !modal._bound) {
      modal._bound = true;
      modal.addEventListener("click", function (ev) {
        if (ev.target === modal) {
          closeConfigModal();
          return;
        }
        const segBtn = ev.target.closest(".seg-btn[data-key]");
        if (segBtn) {
          applyDraftFromEl(segBtn);
          return;
        }
        const actEl = ev.target.closest("[data-act]");
        if (!actEl) return;
        const act = actEl.getAttribute("data-act");
        // login button inside the modal carries data-id (not data-pid); fall
        // back to it and to the open modal's configPid.
        const pid = actEl.getAttribute("data-pid") || actEl.getAttribute("data-id") || state.configPid || "";
        if (act === "config-close") {
          ev.preventDefault();
          closeConfigModal();
          return;
        }
        // The inline 登录 button (config-modal is outside #timeline, so the
        // timeline delegate never saw it) — wire it here.
        if (act === "login" && pid) {
          ev.preventDefault();
          onConfigLogin(pid);
          return;
        }
        if (act === "save" && pid) {
          ev.preventDefault();
          onSave(pid);
          return;
        }
        if (act === "save-start" && pid) {
          ev.preventDefault();
          onStart(pid);
          return;
        }
        if (act === "desktops" && pid) {
          ev.preventDefault();
          onDesktops(pid);
          return;
        }
        // HARD_GATE#665 D: delete account from config modal (modal is outside #timeline)
        if (act === "delete" && pid) {
          ev.preventDefault();
          onDelete(pid);
          return;
        }
      });
      modal.addEventListener("input", function (ev) {
        applyDraftFromEl(ev.target);
      });
      modal.addEventListener("change", function (ev) {
        applyDraftFromEl(ev.target);
      });
    }
  }


