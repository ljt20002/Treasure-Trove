(() => {
  "use strict";

  const KDF_ITERATIONS = 600000;
  const API_BASE_STORAGE_KEY = "personalVault.apiBaseUrl";
  const DEFAULT_API_BASE_URL = "https://cangbaoge-api.1027900565.workers.dev";
  const OFFLINE_GUESSES_PER_SECOND = 100000;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const state = {
    envelope: null,
    vault: null,
    key: null,
    selectedId: null,
    dirty: false,
    modelDirty: false,
    draftDirty: false,
    touchedThisSession: false,
    saving: false,
    toastTimer: 0,
  };

  const $ = (id) => document.getElementById(id);

  const elements = {
    connectionBadge: $("connectionBadge"),
    lockButton: $("lockButton"),
    resetVaultButton: $("resetVaultButton"),
    apiBaseInput: $("apiBaseInput"),
    saveApiBaseButton: $("saveApiBaseButton"),
    connectButton: $("connectButton"),
    setupPanel: $("setupPanel"),
    setupForm: $("setupForm"),
    setupPassword: $("setupPassword"),
    setupPasswordStrength: $("setupPasswordStrength"),
    setupPasswordConfirm: $("setupPasswordConfirm"),
    setupToken: $("setupToken"),
    unlockPanel: $("unlockPanel"),
    unlockForm: $("unlockForm"),
    unlockPassword: $("unlockPassword"),
    vaultPanel: $("vaultPanel"),
    entriesList: $("entriesList"),
    searchInput: $("searchInput"),
    newEntryButton: $("newEntryButton"),
    editorPanel: $("editorPanel"),
    entryForm: $("entryForm"),
    entryId: $("entryId"),
    entryApp: $("entryApp"),
    addCredentialButton: $("addCredentialButton"),
    credentialsList: $("credentialsList"),
    saveEntryButton: $("saveEntryButton"),
    deleteEntryButton: $("deleteEntryButton"),
    dirtyBadge: $("dirtyBadge"),
    resetDialog: $("resetDialog"),
    resetForm: $("resetForm"),
    resetConfirmText: $("resetConfirmText"),
    resetPassword: $("resetPassword"),
    resetPasswordStrength: $("resetPasswordStrength"),
    resetPasswordConfirm: $("resetPasswordConfirm"),
    cancelResetButton: $("cancelResetButton"),
    toast: $("toast"),
  };

  window.addEventListener("DOMContentLoaded", () => {
    elements.apiBaseInput.value =
      localStorage.getItem(API_BASE_STORAGE_KEY) ?? DEFAULT_API_BASE_URL;
    bindEvents();
    connectToApi();
  });

  function bindEvents() {
    elements.saveApiBaseButton.addEventListener("click", () => {
      localStorage.setItem(API_BASE_STORAGE_KEY, elements.apiBaseInput.value.trim());
      showToast("API 地址已保存");
    });

    elements.connectButton.addEventListener("click", () => {
      localStorage.setItem(API_BASE_STORAGE_KEY, elements.apiBaseInput.value.trim());
      connectToApi();
    });

    elements.setupPassword.addEventListener("input", () => {
      renderPasswordStrength(elements.setupPassword.value, elements.setupPasswordStrength);
    });
    elements.resetPassword.addEventListener("input", () => {
      renderPasswordStrength(elements.resetPassword.value, elements.resetPasswordStrength);
    });
    elements.lockButton.addEventListener("click", lockVault);
    elements.resetVaultButton.addEventListener("click", openResetDialog);
    elements.setupForm.addEventListener("submit", setupVault);
    elements.unlockForm.addEventListener("submit", unlockVault);
    elements.newEntryButton.addEventListener("click", createEntry);
    elements.searchInput.addEventListener("input", () => {
      renderVault();
    });
    elements.entryForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!syncEditorToState()) {
        return;
      }
      await saveVault({ successMessage: "已保存并更新" });
    });
    elements.entryApp.addEventListener("input", markEditorDraftDirty);
    elements.addCredentialButton.addEventListener("click", () => {
      const row = appendCredentialRow({ id: crypto.randomUUID(), account: "", secret: "" });
      markEditorDraftDirty({ force: true });
      row.querySelector(".credential-account").focus();
    });
    elements.credentialsList.addEventListener("input", markEditorDraftDirty);
    elements.credentialsList.addEventListener("click", handleCredentialAction);
    elements.deleteEntryButton.addEventListener("click", deleteSelectedEntry);
    elements.cancelResetButton.addEventListener("click", closeResetDialog);
    elements.resetForm.addEventListener("submit", resetVault);
    window.addEventListener("beforeunload", (event) => {
      if (!state.touchedThisSession || !state.dirty) {
        return;
      }
      event.preventDefault();
      event.returnValue = "";
    });
  }

  async function connectToApi() {
    setBusy(true);
    lockVault({ keepEnvelope: false, quiet: true });
    setStatus("正在连接 Worker API", "warn");

    try {
      const healthResponse = await apiFetch("/api/health", { method: "GET" });
      if (!healthResponse.ok) {
        throw new Error(await responseText(healthResponse));
      }

      const health = await healthResponse.json();
      if (!health.initialized) {
        state.envelope = null;
        showSetup();
        setStatus("未初始化", "warn");
        return;
      }

      const response = await apiFetch("/api/vault", { method: "GET" });
      if (!response.ok) {
        throw new Error(await responseText(response));
      }

      state.envelope = await response.json();
      showUnlock();
      setStatus("已连接", "ok");
    } catch (error) {
      hideAuthAndVault();
      setStatus("连接失败", "error");
      showToast(error instanceof Error ? error.message : "连接失败");
    } finally {
      setBusy(false);
    }
  }

  async function setupVault(event) {
    event.preventDefault();

    const password = elements.setupPassword.value;
    const confirmation = elements.setupPasswordConfirm.value;
    if (password !== confirmation) {
      showToast("两次输入的主密钥不一致");
      return;
    }
    if (password.length < 12) {
      showToast("主密钥至少需要 12 个字符");
      return;
    }

    setBusy(true);
    try {
      const writeToken = randomBase64Url(32);
      const salt = randomBytes(16);
      const key = await deriveKey(password, salt, KDF_ITERATIONS);
      const vault = {
        vaultVersion: 1,
        writeToken,
        entries: [],
      };
      const envelope = await encryptVault(key, vault, {
        kdf: "PBKDF2-HMAC-SHA256",
        iterations: KDF_ITERATIONS,
        salt: bytesToBase64Url(salt),
        cipher: "AES-256-GCM",
      });

      const headers = { "Content-Type": "application/json" };
      const setupToken = elements.setupToken.value.trim();
      if (setupToken) {
        headers["X-Setup-Token"] = setupToken;
      }

      const response = await apiFetch("/api/setup", {
        method: "POST",
        headers,
        body: JSON.stringify(envelope),
      });
      if (!response.ok) {
        throw new Error(await responseText(response));
      }

      state.envelope = envelope;
      state.vault = vault;
      state.key = key;
      state.selectedId = null;
      state.dirty = false;
      state.modelDirty = false;
      state.draftDirty = false;
      state.touchedThisSession = false;
      clearSetupInputs();
      showVault();
      showToast("密钥库已创建");
      setStatus("已解锁", "ok");
    } catch (error) {
      showToast(error instanceof Error ? error.message : "初始化失败");
    } finally {
      setBusy(false);
    }
  }

  async function unlockVault(event) {
    event.preventDefault();
    if (!state.envelope) {
      showToast("还没有获取到密钥库数据");
      return;
    }

    setBusy(true);
    try {
      const salt = base64UrlToBytes(state.envelope.crypto.salt);
      const key = await deriveKey(
        elements.unlockPassword.value,
        salt,
        state.envelope.crypto.iterations,
      );
      const decryptedVault = await decryptVault(key, state.envelope);
      const vault = normalizeVault(decryptedVault);

      state.key = key;
      state.vault = vault;
      state.selectedId = vault.entries[0]?.id ?? null;
      state.dirty = false;
      state.modelDirty = false;
      state.draftDirty = false;
      state.touchedThisSession = false;
      elements.unlockPassword.value = "";
      showVault();
      showToast("已解锁");
      setStatus("已解锁", "ok");
    } catch {
      showToast("主密钥错误或数据损坏");
    } finally {
      setBusy(false);
    }
  }

  async function saveVault(options = {}) {
    if (!state.vault || !state.key || !state.envelope) {
      return;
    }
    if (state.saving) {
      return;
    }

    state.saving = true;
    renderDirtyState();
    syncEditorToState({ silent: true });
    if (!state.dirty) {
      state.saving = false;
      renderDirtyState();
      showToast("没有需要保存的修改");
      return;
    }

    setBusy(true);
    try {
      const nextEnvelope = await encryptVault(state.key, state.vault, {
        kdf: state.envelope.crypto.kdf,
        iterations: state.envelope.crypto.iterations,
        salt: state.envelope.crypto.salt,
        cipher: state.envelope.crypto.cipher,
      });

      const response = await apiFetch("/api/vault", {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${state.vault.writeToken}`,
          "Content-Type": "application/json",
          "If-Match": state.envelope.rev,
        },
        body: JSON.stringify(nextEnvelope),
      });

      if (response.status === 409) {
        throw new Error("其他设备已修改，请重新连接 API 后再处理本地修改");
      }
      if (!response.ok) {
        throw new Error(await responseText(response));
      }

      await refreshUnlockedVault({ preferredEnvelope: nextEnvelope });
      showToast(options.successMessage ?? "已保存并更新");
    } catch (error) {
      showToast(error instanceof Error ? error.message : "保存失败");
    } finally {
      state.saving = false;
      setBusy(false);
      renderDirtyState();
    }
  }

  async function refreshUnlockedVault(options = {}) {
    const preferredEnvelope = options.preferredEnvelope;
    let envelope = preferredEnvelope;

    try {
      const response = await apiFetch("/api/vault", { method: "GET" });
      if (!response.ok) {
        throw new Error(await responseText(response));
      }

      const remoteEnvelope = await response.json();
      envelope = shouldUseRemoteEnvelope(remoteEnvelope, preferredEnvelope)
        ? remoteEnvelope
        : preferredEnvelope;
    } catch (error) {
      if (!preferredEnvelope) {
        throw error;
      }
    }

    if (!envelope || !state.key) {
      return;
    }

    const previousSelectedId = state.selectedId;
    const vault = normalizeVault(await decryptVault(state.key, envelope));
    state.envelope = envelope;
    state.vault = vault;
    state.selectedId =
      previousSelectedId && vault.entries.some((entry) => entry.id === previousSelectedId)
        ? previousSelectedId
        : vault.entries[0]?.id ?? null;
    state.dirty = false;
    state.modelDirty = false;
    state.draftDirty = false;
    state.touchedThisSession = false;
    renderVault();
    setStatus("已解锁", "ok");
  }

  function shouldUseRemoteEnvelope(remoteEnvelope, preferredEnvelope) {
    if (!preferredEnvelope || remoteEnvelope.rev === preferredEnvelope.rev) {
      return true;
    }

    const remoteUpdatedAt = Date.parse(remoteEnvelope.updatedAt);
    const preferredUpdatedAt = Date.parse(preferredEnvelope.updatedAt);
    if (!Number.isFinite(remoteUpdatedAt) || !Number.isFinite(preferredUpdatedAt)) {
      return false;
    }

    return remoteUpdatedAt >= preferredUpdatedAt;
  }

  async function resetVault(event) {
    event.preventDefault();

    if (!state.vault || !state.key || !state.envelope) {
      showToast("请先解锁密钥库");
      return;
    }

    if (elements.resetConfirmText.value.trim() !== "RESET") {
      showToast("请输入 RESET 确认重置");
      return;
    }

    const password = elements.resetPassword.value;
    const confirmation = elements.resetPasswordConfirm.value;
    if (password !== confirmation) {
      showToast("两次输入的新主密钥不一致");
      return;
    }
    if (password.length < 12) {
      showToast("新主密钥至少需要 12 个字符");
      return;
    }

    setBusy(true);
    try {
      const oldWriteToken = state.vault.writeToken;
      const salt = randomBytes(16);
      const nextKey = await deriveKey(password, salt, KDF_ITERATIONS);
      const nextVault = {
        vaultVersion: 1,
        writeToken: randomBase64Url(32),
        entries: [],
      };
      const nextEnvelope = await encryptVault(nextKey, nextVault, {
        kdf: "PBKDF2-HMAC-SHA256",
        iterations: KDF_ITERATIONS,
        salt: bytesToBase64Url(salt),
        cipher: "AES-256-GCM",
      });

      const response = await apiFetch("/api/vault", {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${oldWriteToken}`,
          "Content-Type": "application/json",
          "If-Match": state.envelope.rev,
        },
        body: JSON.stringify(nextEnvelope),
      });

      if (response.status === 409) {
        throw new Error("其他设备已修改，请重新连接 API 后再重置");
      }
      if (!response.ok) {
        throw new Error(await responseText(response));
      }

      state.envelope = nextEnvelope;
      state.vault = nextVault;
      state.key = nextKey;
      state.selectedId = null;
      state.dirty = false;
      state.modelDirty = false;
      state.draftDirty = false;
      state.touchedThisSession = false;
      clearEntryForm();
      closeResetDialog();
      renderVault();
      setStatus("已重置", "ok");
      showToast("系统已重置，所有密钥已清空，主密钥已更换");
    } catch (error) {
      showToast(error instanceof Error ? error.message : "重置失败");
    } finally {
      setBusy(false);
    }
  }

  function createEntry() {
    if (!state.vault) {
      return;
    }

    const entry = {
      id: crypto.randomUUID(),
      app: "未命名应用",
      credentials: [
        {
          id: crypto.randomUUID(),
          account: "",
          secret: "",
        },
      ],
      updatedAt: new Date().toISOString(),
    };
    state.vault.entries.unshift(entry);
    state.selectedId = entry.id;
    elements.searchInput.value = "";
    markDirty({ userChange: true });
    renderVault();
    elements.entryApp.focus();
    elements.entryApp.select();
  }

  function syncEditorToState(options = {}) {
    const entry = getSelectedEntry();
    if (!entry) {
      return false;
    }

    const next = readEntryForm(entry.id);
    if (!next.app.trim()) {
      if (!options.silent) {
        showToast("应用不能为空");
      }
      return false;
    }

    if (!hasEntryChanged(entry, next)) {
      return true;
    }

    Object.assign(entry, next, { updatedAt: new Date().toISOString() });
    state.draftDirty = false;
    markDirty({ userChange: true });
    renderEntries();
    return true;
  }

  function markEditorDraftDirty(options = {}) {
    if (!state.vault || !state.selectedId || state.saving) {
      return;
    }

    state.draftDirty = options.force === true || hasUnsavedEditorDraft();
    state.dirty = state.modelDirty || state.draftDirty;
    state.touchedThisSession = state.dirty;
    renderDirtyState();
  }

  function hasUnsavedEditorDraft() {
    const entry = getSelectedEntry();
    return Boolean(entry && hasEntryChanged(entry, readEntryForm(entry.id)));
  }

  function getSelectedEntry() {
    if (!state.vault || !state.selectedId) {
      return null;
    }
    return state.vault.entries.find((item) => item.id === state.selectedId) ?? null;
  }

  function hasEntryChanged(entry, next) {
    return (
      entry.app !== next.app ||
      JSON.stringify(entry.credentials) !== JSON.stringify(next.credentials)
    );
  }

  function readEntryForm(id) {
    return {
      id,
      app: elements.entryApp.value.trim(),
      credentials: readCredentialRows(),
    };
  }

  function readCredentialRows() {
    return Array.from(elements.credentialsList.querySelectorAll(".credential-row"))
      .map((row) => ({
        id: row.dataset.credentialId || crypto.randomUUID(),
        account: row.querySelector(".credential-account").value.trim(),
        secret: row.querySelector(".credential-secret").value,
      }))
      .filter((credential) => credential.account || credential.secret);
  }

  function deleteSelectedEntry() {
    if (!state.vault || !state.selectedId) {
      return;
    }

    const entry = state.vault.entries.find((item) => item.id === state.selectedId);
    if (!entry || !confirm(`删除「${entry.app}」？`)) {
      return;
    }

    state.vault.entries = state.vault.entries.filter((item) => item.id !== state.selectedId);
    state.selectedId = state.vault.entries[0]?.id ?? null;
    markDirty({ userChange: true });
    renderVault();
  }

  function handleCredentialAction(event) {
    const button = event.target.closest("button[data-action]");
    if (!button) {
      return;
    }

    const row = button.closest(".credential-row");
    if (!row) {
      return;
    }

    if (button.dataset.action === "copy") {
      copyCredentialSecret(row);
      return;
    }

    if (button.dataset.action === "remove" && confirm("删除这组账户密码？")) {
      row.remove();
      markEditorDraftDirty();
    }
  }

  async function copyCredentialSecret(row) {
    const secret = row.querySelector(".credential-secret").value;
    if (!secret) {
      showToast("当前账户没有密钥内容");
      return;
    }

    try {
      await navigator.clipboard.writeText(secret);
      showToast("已复制密钥");
      window.setTimeout(async () => {
        try {
          const current = await navigator.clipboard.readText();
          if (current === secret) {
            await navigator.clipboard.writeText("");
          }
        } catch {
          // Some browsers block clipboard reads without a user gesture.
        }
      }, 30000);
    } catch {
      showToast("浏览器拒绝了剪贴板访问");
    }
  }

  function lockVault(options = {}) {
    state.vault = null;
    state.key = null;
    state.selectedId = null;
    state.dirty = false;
    state.modelDirty = false;
    state.draftDirty = false;
    state.touchedThisSession = false;
    state.saving = false;
    clearEntryForm();
    renderDirtyState();

    if (!options.keepEnvelope) {
      state.envelope = null;
    }

    if (!options.quiet) {
      if (state.envelope) {
        showUnlock();
        setStatus("已锁定", "warn");
      } else {
        hideAuthAndVault();
        setStatus("已锁定", "warn");
      }
    }
  }

  function showSetup() {
    elements.setupPanel.hidden = false;
    elements.unlockPanel.hidden = true;
    elements.vaultPanel.hidden = true;
    elements.lockButton.hidden = true;
    elements.resetVaultButton.hidden = true;
  }

  function showUnlock() {
    elements.setupPanel.hidden = true;
    elements.unlockPanel.hidden = false;
    elements.vaultPanel.hidden = true;
    elements.lockButton.hidden = true;
    elements.resetVaultButton.hidden = true;
  }

  function showVault() {
    elements.setupPanel.hidden = true;
    elements.unlockPanel.hidden = true;
    elements.vaultPanel.hidden = false;
    elements.lockButton.hidden = false;
    elements.resetVaultButton.hidden = false;
    renderVault();
  }

  function hideAuthAndVault() {
    elements.setupPanel.hidden = true;
    elements.unlockPanel.hidden = true;
    elements.vaultPanel.hidden = true;
    elements.lockButton.hidden = true;
    elements.resetVaultButton.hidden = true;
  }

  function renderVault() {
    renderEntries();
    renderEditor();
    renderDirtyState();
  }

  function renderEntries() {
    if (!state.vault) {
      elements.entriesList.innerHTML = "";
      return;
    }

    const entries = getFilteredEntries();

    if (entries.length === 0 && elements.searchInput.value.trim()) {
      elements.entriesList.innerHTML = `<div class="empty-state">没有匹配的应用</div>`;
      return;
    }

    elements.entriesList.innerHTML = "";
    for (const entry of entries) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `entry-card${entry.id === state.selectedId ? " active" : ""}`;
      button.innerHTML = `
        <span class="entry-title"></span>
        <span class="entry-meta"></span>
      `;
      button.querySelector(".entry-title").textContent = entry.app || "未命名应用";
      button.querySelector(".entry-meta").textContent = formatCredentialSummary(entry);
      button.addEventListener("click", () => {
        if (
          hasUnsavedEditorDraft() &&
          !confirm("当前详情有未保存修改，切换应用会丢弃这些修改。继续吗？")
        ) {
          return;
        }
        if (hasUnsavedEditorDraft()) {
          state.draftDirty = false;
          state.dirty = state.modelDirty;
          state.touchedThisSession = state.dirty;
        }
        state.selectedId = entry.id;
        renderVault();
      });
      elements.entriesList.appendChild(button);
    }
  }

  function renderEditor() {
    if (!state.vault || !state.selectedId) {
      elements.editorPanel.hidden = true;
      clearEntryForm();
      setEditorDisabled(true);
      return;
    }

    const entry = state.vault.entries.find((item) => item.id === state.selectedId);
    if (!entry || !entryMatchesSearch(entry)) {
      elements.editorPanel.hidden = true;
      clearEntryForm();
      setEditorDisabled(true);
      return;
    }

    elements.editorPanel.hidden = false;
    setEditorDisabled(false);
    elements.entryId.value = entry.id;
    elements.entryApp.value = entry.app;
    renderCredentialRows(entry.credentials);
  }

  function formatCredentialSummary(entry) {
    const accounts = entry.credentials.map((credential) => credential.account).filter(Boolean);
    if (accounts.length > 0) {
      const summary = accounts.slice(0, 3).join("、");
      return accounts.length > 3 ? `${summary} 等 ${accounts.length} 个账户` : summary;
    }
    return entry.credentials.length > 0 ? `${entry.credentials.length} 个账户` : "未添加账户";
  }

  function getFilteredEntries() {
    if (!state.vault) {
      return [];
    }
    return state.vault.entries.filter(entryMatchesSearch);
  }

  function entryMatchesSearch(entry) {
    const query = elements.searchInput.value.trim().toLowerCase();
    const haystack = [
      entry.app,
      ...entry.credentials.map((credential) => credential.account),
    ].join(" ").toLowerCase();
    return !query || haystack.includes(query);
  }

  function renderCredentialRows(credentials) {
    elements.credentialsList.innerHTML = "";
    const rows =
      credentials.length > 0
        ? credentials
        : [{ id: crypto.randomUUID(), account: "", secret: "" }];
    for (const credential of rows) {
      appendCredentialRow(credential);
    }
  }

  function appendCredentialRow(credential) {
    const row = document.createElement("div");
    row.className = "credential-row";
    row.dataset.credentialId = credential.id || crypto.randomUUID();
    row.innerHTML = `
      <label class="field">
        <span>账户</span>
        <input class="credential-account" type="text" autocomplete="off" />
      </label>
      <label class="field">
        <span>密钥</span>
        <input class="credential-secret" type="text" autocomplete="off" spellcheck="false" />
      </label>
      <div class="credential-actions">
        <button type="button" class="secondary compact" data-action="copy">复制</button>
        <button type="button" class="danger compact" data-action="remove">删除</button>
      </div>
    `;
    row.querySelector(".credential-account").value = credential.account ?? "";
    row.querySelector(".credential-secret").value = credential.secret ?? "";
    elements.credentialsList.appendChild(row);
    return row;
  }

  function setEditorDisabled(disabled) {
    for (const control of elements.entryForm.elements) {
      control.disabled = disabled;
    }
  }

  function clearEntryForm() {
    elements.entryForm.reset();
    elements.entryId.value = "";
    elements.credentialsList.innerHTML = "";
  }

  function markDirty(options = {}) {
    state.modelDirty = true;
    state.dirty = true;
    const isUserChange = options.userChange !== false;
    if (isUserChange) {
      state.touchedThisSession = true;
    }
    renderDirtyState();
  }

  function renderDirtyState() {
    elements.dirtyBadge.hidden = !state.dirty && !state.saving;
    elements.dirtyBadge.textContent = state.saving ? "保存中" : "待保存";
  }

  function setStatus(text, level) {
    elements.connectionBadge.textContent =
      level === "ok" ? "已连接" : level === "error" ? "异常" : "等待";
    elements.connectionBadge.classList.toggle("warn", level === "warn");
    elements.connectionBadge.classList.toggle("error", level === "error");
  }

  function setBusy(isBusy) {
    for (const button of document.querySelectorAll("button")) {
      button.disabled = isBusy;
    }
    if (!isBusy && state.vault) {
      setEditorDisabled(!state.selectedId);
    }
    renderDirtyState();
  }

  function showToast(message) {
    window.clearTimeout(state.toastTimer);
    elements.toast.textContent = message;
    elements.toast.hidden = false;
    state.toastTimer = window.setTimeout(() => {
      elements.toast.hidden = true;
    }, 1800);
  }

  function openResetDialog() {
    if (!state.vault || !state.key) {
      showToast("请先解锁密钥库");
      return;
    }
    clearResetInputs();
    elements.resetDialog.hidden = false;
    elements.resetConfirmText.focus();
  }

  function closeResetDialog() {
    elements.resetDialog.hidden = true;
    clearResetInputs();
  }

  function clearResetInputs() {
    elements.resetForm.reset();
    elements.resetPasswordStrength.replaceChildren();
  }

  function clearSetupInputs() {
    elements.setupPassword.value = "";
    elements.setupPasswordConfirm.value = "";
    elements.setupToken.value = "";
    elements.setupPasswordStrength.replaceChildren();
  }

  function renderPasswordStrength(password, target) {
    if (!password) {
      target.replaceChildren();
      return;
    }

    const strength = estimatePasswordStrength(password);
    target.innerHTML = `
      <div class="strength-summary">
        <span></span>
        <span></span>
      </div>
      <div class="strength-bar" aria-hidden="true">
        <div class="strength-bar-fill"></div>
      </div>
      <div class="strength-detail"></div>
      <div class="strength-note"></div>
    `;

    target.querySelector(".strength-summary span:first-child").textContent = strength.label;
    target.querySelector(".strength-summary span:last-child").textContent =
      `${strength.bits} bits`;
    target.querySelector(".strength-bar-fill").style.setProperty(
      "--strength-percent",
      `${strength.percent}%`,
    );
    target.querySelector(".strength-bar-fill").style.setProperty(
      "--strength-color",
      strength.color,
    );
    target.querySelector(".strength-detail").textContent =
      `估算搜索空间约 ${strength.searchSpaceText}；按 PBKDF2 ${formatNumber(
        KDF_ITERATIONS,
      )} 次迭代后的离线攻击 ${formatNumber(
        OFFLINE_GUESSES_PER_SECOND,
      )} 次/秒估算，平均攻破时间约 ${strength.timeText}。`;
    target.querySelector(".strength-note").textContent = strength.note;
  }

  function estimatePasswordStrength(password) {
    const length = Array.from(password).length;
    const poolSize = estimatePoolSize(password);
    const rawBits = length * Math.log2(poolSize);
    const penalty = estimatePasswordPenalty(password);
    const bits = Math.max(0, Math.round(rawBits - penalty));
    const percent = Math.min(100, Math.round((bits / 100) * 100));
    const medianSeconds = bits <= 1 ? 0 : 2 ** (bits - 1) / OFFLINE_GUESSES_PER_SECOND;
    const level = passwordStrengthLevel(bits);

    return {
      bits,
      percent,
      label: level.label,
      color: level.color,
      searchSpaceText: formatPowerOfTwo(bits),
      timeText: formatDuration(medianSeconds),
      note: passwordStrengthNote(password, bits, penalty),
    };
  }

  function estimatePoolSize(password) {
    let size = 0;
    if (/[a-z]/.test(password)) size += 26;
    if (/[A-Z]/.test(password)) size += 26;
    if (/[0-9]/.test(password)) size += 10;
    if (/[^A-Za-z0-9\s]/.test(password)) size += 32;
    if (/\s/.test(password)) size += 1;
    if (/[^\x00-\x7F]/.test(password)) size += 80;
    return Math.max(size, 1);
  }

  function estimatePasswordPenalty(password) {
    const lower = password.toLowerCase();
    let penalty = 0;

    if (/(.)\1{2,}/.test(lower)) penalty += 18;
    if (/0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf|zxcv/.test(lower)) {
      penalty += 18;
    }
    if (/password|admin|letmein|welcome|qwerty|iloveyou|github|openai/.test(lower)) {
      penalty += 24;
    }
    if (/^[A-Za-z]+[0-9]{1,4}[!@#$%^&*._-]?$/.test(password)) penalty += 14;
    if (new Set(Array.from(password)).size <= Math.max(2, Math.floor(password.length / 3))) {
      penalty += 12;
    }

    return penalty;
  }

  function passwordStrengthLevel(bits) {
    if (bits < 40) return { label: "很弱", color: "#b42318" };
    if (bits < 60) return { label: "偏弱", color: "#c2410c" };
    if (bits < 80) return { label: "可用", color: "#b7791f" };
    if (bits < 100) return { label: "较强", color: "#0f766e" };
    return { label: "很强", color: "#166534" };
  }

  function passwordStrengthNote(password, bits, penalty) {
    const length = Array.from(password).length;
    if (length < 16) {
      return "建议至少 16 位；更推荐 4 到 6 个随机词或 20 位以上随机字符。";
    }
    if (penalty > 0) {
      return "检测到重复、顺序、常见词或常见格式，实际强度可能低于字符种类估算。";
    }
    if (bits < 80) {
      return "可以继续增加长度。长度通常比简单混合大小写和符号更有效。";
    }
    return "这是基于字符空间的本地估算，不包含密码泄露库、社工和设备被控等风险。";
  }

  function formatPowerOfTwo(bits) {
    if (bits <= 0) return "1 次猜测";
    const log10 = bits * Math.LOG10E * Math.LN2;
    if (log10 < 6) {
      return `${formatNumber(Math.round(10 ** log10))} 次猜测`;
    }
    return `10^${Math.floor(log10)} 次猜测`;
  }

  function formatDuration(seconds) {
    if (!Number.isFinite(seconds)) return "远超可估算范围";
    if (seconds <= 0) return "不到 1 秒";
    if (seconds < 1) return "不到 1 秒";
    const units = [
      ["年", 365 * 24 * 60 * 60],
      ["天", 24 * 60 * 60],
      ["小时", 60 * 60],
      ["分钟", 60],
      ["秒", 1],
    ];
    for (const [unit, unitSeconds] of units) {
      if (seconds >= unitSeconds) {
        const value = seconds / unitSeconds;
        if (unit === "年" && value >= 1e6) return `${formatScientific(value)} 年`;
        return `${formatCompact(value)} ${unit}`;
      }
    }
    return "不到 1 秒";
  }

  function formatCompact(value) {
    if (value >= 100) return formatNumber(Math.round(value));
    if (value >= 10) return value.toFixed(1);
    return value.toFixed(2);
  }

  function formatScientific(value) {
    const exponent = Math.floor(Math.log10(value));
    const mantissa = value / 10 ** exponent;
    return `${mantissa.toFixed(1)}e${exponent}`;
  }

  function formatNumber(value) {
    return new Intl.NumberFormat("zh-CN").format(value);
  }

  async function apiFetch(path, options = {}) {
    const base = elements.apiBaseInput.value.trim().replace(/\/+$/, "");
    const url = base ? `${base}${path}` : path;
    const timeoutMs = options.timeoutMs ?? 12000;
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeoutMs);

    try {
      return await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          ...(options.headers ?? {}),
        },
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new Error("连接超时，请确认 Worker API 已启动且 KV 远程绑定可用");
      }
      throw error;
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function deriveKey(password, saltBytes, iterations) {
    const material = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations,
        hash: "SHA-256",
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  async function encryptVault(key, vault, cryptoConfig) {
    const iv = randomBytes(12);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoder.encode(JSON.stringify(vault)),
    );

    return {
      schemaVersion: 1,
      rev: crypto.randomUUID(),
      updatedAt: new Date().toISOString(),
      auth: {
        tokenHashAlg: "SHA-256",
        tokenHash: await sha256Base64Url(vault.writeToken),
      },
      crypto: {
        ...cryptoConfig,
        iv: bytesToBase64Url(iv),
      },
      ciphertext: bytesToBase64Url(new Uint8Array(ciphertext)),
    };
  }

  async function decryptVault(key, envelope) {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64UrlToBytes(envelope.crypto.iv) },
      key,
      base64UrlToBytes(envelope.ciphertext),
    );
    return JSON.parse(decoder.decode(plaintext));
  }

  async function sha256Base64Url(value) {
    const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
    return bytesToBase64Url(new Uint8Array(digest));
  }

  function normalizeVault(vault) {
    validatePlainVault(vault);
    return {
      vaultVersion: 1,
      writeToken: vault.writeToken,
      entries: vault.entries.map(normalizeEntry),
    };
  }

  function normalizeEntry(entry) {
    const source = entry && typeof entry === "object" ? entry : {};
    const credentials = Array.isArray(source.credentials)
      ? source.credentials.map(normalizeCredential).filter(Boolean)
      : normalizeLegacyCredential(source);

    return {
      id: typeof source.id === "string" && source.id ? source.id : crypto.randomUUID(),
      app:
        typeof source.app === "string"
          ? source.app
          : typeof source.title === "string"
            ? source.title
            : "未命名应用",
      credentials,
      updatedAt:
        typeof source.updatedAt === "string" && !Number.isNaN(Date.parse(source.updatedAt))
          ? source.updatedAt
          : new Date().toISOString(),
    };
  }

  function normalizeCredential(credential) {
    const source = credential && typeof credential === "object" ? credential : {};
    const account = typeof source.account === "string" ? source.account : "";
    const secret = typeof source.secret === "string" ? source.secret : "";

    if (!account && !secret) {
      return null;
    }

    return {
      id: typeof source.id === "string" && source.id ? source.id : crypto.randomUUID(),
      account,
      secret,
    };
  }

  function normalizeLegacyCredential(source) {
    const account = typeof source.account === "string" ? source.account : "";
    const secret = typeof source.secret === "string" ? source.secret : "";
    return account || secret
      ? [
          {
            id: crypto.randomUUID(),
            account,
            secret,
          },
        ]
      : [];
  }

  function validatePlainVault(vault) {
    if (
      !vault ||
      vault.vaultVersion !== 1 ||
      typeof vault.writeToken !== "string" ||
      !Array.isArray(vault.entries)
    ) {
      throw new Error("Invalid vault");
    }
  }

  async function responseText(response) {
    try {
      const data = await response.json();
      return data.message || data.error || `HTTP ${response.status}`;
    } catch {
      return `HTTP ${response.status}`;
    }
  }

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  function randomBase64Url(length) {
    return bytesToBase64Url(randomBytes(length));
  }

  function bytesToBase64Url(bytes) {
    let binary = "";
    const chunkSize = 0x8000;
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
  }

  function base64UrlToBytes(value) {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }
})();
