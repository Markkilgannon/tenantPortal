/**
 * Tenant Portal (Cloudflare Pages)
 * - Auth0 SPA login (Auth0 SPA SDK v2)
 * - Calls Pages Functions (/api/*) with Bearer token
 * - Renders: Home dashboard, Maintenance, Docs
 */

// -------------------------
// DOM helpers (safe)
// -------------------------
const $ = (id) => document.getElementById(id);
const has = (id) => Boolean($(id));

const setText = (id, text) => {
  const el = $(id);
  if (el) el.textContent = text;
};

const setHtml = (id, html) => {
  const el = $(id);
  if (el) el.innerHTML = html;
};

const show = (id, yes, displayStyle = "inline-block") => {
  const el = $(id);
  if (!el) return;
  el.style.display = yes ? displayStyle : "none";
};

const on = (id, evt, fn, opts) => {
  const el = $(id);
  if (!el) return false;
  el.addEventListener(evt, fn, opts);
  return true;
};

// -------------------------
// Config (yours)
// -------------------------
const AUTH0_DOMAIN = "dev-v3g60bdgfjg7walx.us.auth0.com";
const AUTH0_CLIENT_ID = "CXrASdTRNQKhDuJIFNvIR7wPwjAwjtCx";
const AUTH0_AUDIENCE = "https://tenant-portal-api";

// Must match Auth0 Allowed Callback/Logout/Web Origins
const PORTAL_ORIGIN = window.location.origin;

// -------------------------
// State
// -------------------------
let auth0Client = null;
let isBooted = false;
let maintenanceItemsCache = [];
let maintenanceFilter = "all";

// Cache of /api/me response (includes Salesforce context)
let portalContext = null;

// -------------------------
// Utilities
// -------------------------
function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

function safeDate(d) {
  try {
    if (!d) return "";
    const dt = new Date(d);
    if (Number.isNaN(dt.getTime())) return String(d);
    return dt.toLocaleString();
  } catch {
    return String(d || "");
  }
}

function setStatus(message, kind = "info") {
  setText("statusText", `Status: ${message}`);

  const dot = $("statusDot");
  if (!dot) return;

  const color =
    kind === "ok" ? "rgba(124,240,197,0.95)" :
    kind === "warn" ? "rgba(255, 209, 102, 0.95)" :
    kind === "bad" ? "rgba(255, 107, 107, 0.95)" :
    "rgba(255,255,255,0.35)";

  dot.style.background = color;
}

// -------------------------
// Simple panels (Home/Maintenance/Docs)
// -------------------------
function setPanel(name) {
  document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
  const panel = $(`panel-${name}`);
  if (panel) panel.classList.add("active");

  document.querySelectorAll(".tabBtn").forEach((b) => {
    b.classList.toggle("active", b.dataset.panel === name);
  });
}

function initNav() {
  const nav = $("navBar");
  if (!nav) return;

  nav.addEventListener("click", async (e) => {
    const btn = e.target.closest(".tabBtn");
    if (!btn) return;

    const panel = btn.dataset.panel;
    if (!panel) return;

    setPanel(panel);

    // Lazy-load data for panels
    if (panel === "maintenance") {
      await loadMaintenance().catch(console.error);
    } else if (panel === "docs") {
      await loadDocs().catch(console.error);
    }
  });


  function groupDocuments(docs) {
  const groups = {
    Lease: [],
    Property: [],
    Unit: [],
    Other: []
  };

  docs.forEach((doc) => {
    const key = doc.sourceType || "Other";
    if (!groups[key]) groups[key] = [];
    groups[key].push(doc);
  });

  return groups;
}

  // Default
  setPanel("home");
}

// -------------------------
// Auth helpers
// -------------------------
async function requireAuth0Client() {
  const factory =
    (window.auth0 && typeof window.auth0.createAuth0Client === "function")
      ? window.auth0.createAuth0Client
      : null;

  if (!factory) {
    throw new Error("Auth0 SPA SDK not loaded. window.auth0.createAuth0Client is missing.");
  }

  if (!auth0Client) {
    auth0Client = await window.auth0.createAuth0Client({
      domain: AUTH0_DOMAIN,
      clientId: AUTH0_CLIENT_ID,
      authorizationParams: {
        audience: AUTH0_AUDIENCE,
        redirect_uri: PORTAL_ORIGIN,
        scope: "openid profile email"
      },
      cacheLocation: "memory",
      useRefreshTokens: false
    });
  }

  return auth0Client;
}

async function handleAuthRedirectIfPresent() {
  const query = window.location.search;
  if (query.includes("code=") && query.includes("state=")) {
    setStatus("Completing login…", "warn");
    await auth0Client.handleRedirectCallback();
    window.history.replaceState({}, document.title, PORTAL_ORIGIN + window.location.pathname);
  }
}

async function login() {
  await requireAuth0Client();
  setStatus("Redirecting to login…", "warn");
  await auth0Client.loginWithRedirect({
    authorizationParams: {
      redirect_uri: PORTAL_ORIGIN,
      audience: AUTH0_AUDIENCE,
      scope: "openid profile email",
    },
  });
}

async function logout() {
  await requireAuth0Client();
  setStatus("Logging out…", "warn");
  await auth0Client.logout({
    logoutParams: { returnTo: PORTAL_ORIGIN },
  });
}

async function isAuthenticated() {
  await requireAuth0Client();
  return await auth0Client.isAuthenticated();
}

async function getAccessToken() {
  await requireAuth0Client();
  return await auth0Client.getTokenSilently({
    authorizationParams: {
      audience: AUTH0_AUDIENCE,
      scope: "openid profile email",
    },
  });
}

// -------------------------
// API wrapper
// -------------------------
async function api(path, opts = {}) {
  const token = await getAccessToken();
  const headers = { ...(opts.headers || {}) };

  if (opts.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  headers.Authorization = `Bearer ${token}`;

  const res = await fetch(path, {
    ...opts,
    headers
  });

  if (opts.rawResponse) {
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(text || `HTTP ${res.status}`);
    }
    return res;
  }

  const ct = res.headers.get("Content-Type") || "";
  const data = ct.includes("application/json")
    ? await res.json().catch(() => ({}))
    : await res.text();

  if (!res.ok) {
    const msg =
      (data && data.details) ? data.details :
      (data && data.message) ? data.message :
      (data && data.error) ? data.error :
      (typeof data === "string" ? data : `HTTP ${res.status}`);
    throw new Error(msg);
  }

  return data;
}

// -------------------------
// Home dashboard renderer
// -------------------------
function renderHome() {
  const el = $("homeCards");
  if (!el) return;

  const ctx = portalContext?.sf?.ok !== false ? portalContext.sf : null;

  if (!ctx) {
    el.innerHTML = `
      <div class="dashboardCard dashboardCardWide">
        <p class="cardLabel">Welcome</p>
        <p class="cardTitle">Login to access your portal</p>
        <p class="cardText">View your property details, submit maintenance requests and download important documents.</p>
      </div>
    `;
    return;
  }

  const tenant = ctx.tenant || {};
  const unit = ctx.unit || {};
  const lease = ctx.lease || {};
  const tenancy = ctx.tenancy || {};

  const maintenanceItems = Array.isArray(portalContext?.maintenancePreview)
    ? portalContext.maintenancePreview
    : [];

  const docsItems = Array.isArray(portalContext?.docsPreview)
    ? portalContext.docsPreview
    : [];

  const latestMaintenance = maintenanceItems.length ? maintenanceItems[0] : null;

  el.innerHTML = `
    <div class="summaryCard">
      <p class="summaryLabel">Open Requests</p>
      <p class="summaryValue">${maintenanceItems.length}</p>
      <p class="summaryText">Maintenance requests currently visible in your portal.</p>
    </div>

    <div class="summaryCard">
      <p class="summaryLabel">Documents</p>
      <p class="summaryValue">${docsItems.length}</p>
      <p class="summaryText">Files available for download.</p>
    </div>

    <div class="summaryCard">
      <p class="summaryLabel">Tenancy</p>
      <p class="summaryValue summaryValueText">${escapeHtml(tenancy.status || "—")}</p>
      <p class="summaryText">Your current tenancy status.</p>
    </div>

    <div class="dashboardCard">
      <p class="cardLabel">Tenant</p>
      <p class="cardTitle">${escapeHtml(tenant.name || "Tenant")}</p>
      <p class="cardText">${escapeHtml(tenant.email || "No email available")}</p>
      <p class="cardText">${escapeHtml(tenant.phone || "No phone available")}</p>
    </div>

    <div class="dashboardCard">
      <p class="cardLabel">Your Home</p>
      <p class="cardTitle">${escapeHtml(unit.propertyName || "Property")}</p>
      <p class="cardText">Unit: ${escapeHtml(unit.name || "—")}</p>
      <p class="cardText">Tenancy: ${escapeHtml(tenancy.status || "—")}</p>
    </div>

    <div class="dashboardCard">
      <p class="cardLabel">Lease</p>
      <p class="cardTitle">${escapeHtml(lease.name || "Lease")}</p>
      <p class="cardText">${escapeHtml(lease.startDate || "?")} → ${escapeHtml(lease.endDate || "?")}</p>
      <p class="cardText">Status: ${escapeHtml(lease.status || "—")}</p>
    </div>

    <div class="dashboardCard">
      <p class="cardLabel">Quick actions</p>
      <p class="cardTitle">What would you like to do?</p>
      <p class="cardText">Use the shortcuts below to manage your tenancy.</p>

      <div class="quickActionRow">
        <button type="button" class="btn btn-primary" id="homeGoMaintenance">Submit maintenance</button>
        <button type="button" class="btn btn-secondary" id="homeGoDocs">View documents</button>
      </div>
    </div>

    <div class="dashboardCard dashboardCardWide">
      <p class="cardLabel">Latest activity</p>
      ${
        latestMaintenance
          ? `
            <p class="cardTitle">${escapeHtml(latestMaintenance.subject || "Maintenance request")}</p>
            <p class="cardText">Status: ${escapeHtml(latestMaintenance.status || "Open")}</p>
            <p class="cardText">Submitted: ${escapeHtml(safeDate(latestMaintenance.createdDate))}</p>
            ${
              latestMaintenance.portalUpdate
                ? `<p class="cardText">Latest update: ${escapeHtml(latestMaintenance.portalUpdate)}</p>`
                : `<p class="cardText">No update has been added yet.</p>`
            }
          `
          : `
            <p class="cardTitle">No recent activity</p>
            <p class="cardText">Your latest maintenance updates will appear here.</p>
          `
      }
    </div>
  `;

  const btnMaintenance = $("homeGoMaintenance");
  if (btnMaintenance) {
    btnMaintenance.addEventListener("click", async () => {
      setPanel("maintenance");
      await loadMaintenance().catch(console.error);
    });
  }

  const btnDocs = $("homeGoDocs");
  if (btnDocs) {
    btnDocs.addEventListener("click", async () => {
      setPanel("docs");
      await loadDocs().catch(console.error);
    });
  }
}

function setAccountBanner(message = "", type = "") {
  const banner = $("accountBanner");
  if (!banner) return;

  if (!message) {
    banner.style.display = "none";
    banner.className = "accountBanner";
    banner.textContent = "";
    return;
  }

  banner.style.display = "block";
  banner.className = `accountBanner ${type === "error" ? "accountBannerError" : "accountBannerSuccess"}`;
  banner.textContent = message;
}

function setFieldError(fieldId, errorId, message = "") {
  const field = $(fieldId);
  const error = $(errorId);

  if (field) {
    field.classList.toggle("inputError", Boolean(message));
  }

  if (error) {
    error.textContent = message;
  }
}

function validateAccountForm(email, phone) {
  let valid = true;

  setFieldError("accountEmail", "accountEmailError", "");
  setFieldError("accountPhone", "accountPhoneError", "");

  const trimmedEmail = String(email || "").trim();
  const trimmedPhone = String(phone || "").trim();

  if (trimmedEmail) {
    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail);
    if (!emailOk) {
      setFieldError("accountEmail", "accountEmailError", "Enter a valid email address.");
      valid = false;
    }
  }

  if (trimmedPhone) {
    const phoneOk = /^[0-9+()\-\s]{7,20}$/.test(trimmedPhone);
    if (!phoneOk) {
      setFieldError("accountPhone", "accountPhoneError", "Enter a valid phone number.");
      valid = false;
    }
  }

  return valid;
}

function resetAccountFormFromContext() {
  const tenant = portalContext?.sf?.tenant || {};

  if ($("accountEmail")) $("accountEmail").value = tenant.email || "";
  if ($("accountPhone")) $("accountPhone").value = tenant.phone || "";

  setFieldError("accountEmail", "accountEmailError", "");
  setFieldError("accountPhone", "accountPhoneError", "");
  setAccountBanner("", "");
}

function renderAccount() {
  const el = $("accountDetails");
  if (!el) return;

  const ctx = portalContext?.sf?.ok !== false ? portalContext.sf : null;

  if (!ctx) {
    el.innerHTML = `
      <div class="itemCard">
        <p class="itemTitle">Account</p>
        <p class="itemMeta">Login to view your profile details.</p>
      </div>
    `;

    if ($("accountEmail")) $("accountEmail").value = "";
    if ($("accountPhone")) $("accountPhone").value = "";
    setAccountBanner("", "");
    return;
  }

  const tenant = ctx.tenant || {};
  const unit = ctx.unit || {};
  const lease = ctx.lease || {};
  const tenancy = ctx.tenancy || {};

  el.innerHTML = `
    <div class="accountFieldCard">
      <p class="accountFieldLabel">Full name</p>
      <p class="accountFieldValue">${escapeHtml(tenant.name || "—")}</p>
    </div>

    <div class="accountFieldCard">
      <p class="accountFieldLabel">Email</p>
      <p class="accountFieldValue">${escapeHtml(tenant.email || "—")}</p>
    </div>

    <div class="accountFieldCard">
      <p class="accountFieldLabel">Phone</p>
      <p class="accountFieldValue">${escapeHtml(tenant.phone || "—")}</p>
    </div>

    <div class="accountFieldCard">
      <p class="accountFieldLabel">Property</p>
      <p class="accountFieldValue">${escapeHtml(unit.propertyName || "—")}</p>
      <p class="accountFieldSubvalue">Unit: ${escapeHtml(unit.name || "—")}</p>
    </div>

    <div class="accountFieldCard">
      <p class="accountFieldLabel">Lease</p>
      <p class="accountFieldValue">${escapeHtml(lease.name || "—")}</p>
      <p class="accountFieldSubvalue">${escapeHtml(lease.startDate || "?")} → ${escapeHtml(lease.endDate || "?")}</p>
    </div>

    <div class="accountFieldCard">
      <p class="accountFieldLabel">Tenancy status</p>
      <p class="accountFieldValue">${escapeHtml(tenancy.status || "—")}</p>
    </div>
  `;

  resetAccountFormFromContext();
}
// -------------------------
// Loaders
// -------------------------
async function loadMe() {
  setStatus("Loading dashboard…", "warn");
  const me = await api("/api/me");
  portalContext = me;

  // Update unit line headline
  const ctx = me?.sf?.ok !== false ? me.sf : null;
  const headline = ctx
    ? `${ctx.unit?.propertyName || "Property"} • ${ctx.unit?.name || "Unit"}`
    : (me.sub ? `Logged in (${me.sub})` : "Logged in");

  setText("unitLine", headline);

  // Render dashboard cards
  renderHome();
  renderAccount();

  try {
  const [maintenancePreview, docsPreview] = await Promise.all([
    api("/api/maintenance").catch(() => []),
    api("/api/docs").catch(() => [])
  ]);

  portalContext.maintenancePreview = Array.isArray(maintenancePreview) ? maintenancePreview : [];
  portalContext.docsPreview = Array.isArray(docsPreview) ? docsPreview : [];
  renderHome();
} catch (e) {
  console.error("Preview load failed:", e);
}

  renderAccount();

  // Debug output
  setText("output", JSON.stringify(me, null, 2));
  setStatus("Ready", "ok");
}

function statusClass(status) {
  const s = String(status || "").toLowerCase().trim();

  if (s === "completed") return "statusBadge statusCompleted";
  if (s === "in progress") return "statusBadge statusInProgress";
  if (s === "waiting for contractor") return "statusBadge statusWaiting";
  return "statusBadge statusOpen";
}

async function loadMaintenance() {
  const wrap = $("maintenanceList");
  if (!wrap) return;

  setStatus("Loading maintenance…", "warn");
  wrap.innerHTML = "";

  try {
    maintenanceItemsCache = await api("/api/maintenance");

    if (portalContext) {
      portalContext.maintenancePreview = Array.isArray(maintenanceItemsCache)
        ? maintenanceItemsCache
        : [];
    }

    renderMaintenanceList();
    setStatus("Maintenance ready", "ok");
  } catch (e) {
    console.error("Maintenance list unavailable:", e);
    wrap.innerHTML = `
      <div class="maintenanceCard emptyStateCard">
        <div class="maintenanceMain">
          <p class="itemTitle">Maintenance unavailable</p>
          <p class="itemMeta">Maintenance requests aren’t available right now.</p>
        </div>
      </div>
    `;
    setStatus("Maintenance ready", "warn");
  }
}

function renderMaintenanceList() {
  const wrap = $("maintenanceList");
  if (!wrap) return;

  wrap.innerHTML = "";

  let items = Array.isArray(maintenanceItemsCache) ? maintenanceItemsCache : [];

  if (maintenanceFilter !== "all") {
    items = items.filter((i) => i.status === maintenanceFilter);
  }

  if (!items.length) {
    wrap.innerHTML = `
      <div class="maintenanceCard emptyStateCard">
        <div class="maintenanceMain">
          <p class="itemTitle">No maintenance requests found</p>
          <p class="itemMeta">There are no requests for the selected filter.</p>
        </div>
      </div>
    `;
    return;
  }

  items.forEach((i) => {
    const el = document.createElement("div");
    el.className = "maintenanceCard";

    el.innerHTML = `
      <div class="maintenanceHeader">
        <div class="maintenanceMain">
          <p class="itemTitle">${escapeHtml(i.subject || "(No subject)")}</p>
          <p class="itemMeta">Submitted: ${escapeHtml(safeDate(i.createdDate))}</p>
        </div>
        <div class="maintenanceSide">
          <span class="${statusClass(i.status)}">${escapeHtml(i.status || "Open")}</span>
        </div>
      </div>

      ${i.portalUpdate ? `
        <div class="maintenanceUpdateBox">
          <p class="detailLabel">Latest update</p>
          <p class="itemMeta">${escapeHtml(i.portalUpdate)}</p>
        </div>
      ` : ""}

      <div class="maintenanceDescription">
        <p class="detailLabel">Description</p>
        <p class="itemMeta">${escapeHtml(i.description || "No description provided.")}</p>
      </div>
    `;

    wrap.appendChild(el);
  });
}
async function loadDocs() {
  const wrap = $("docsList");
  if (!wrap) return;

  setStatus("Loading documents…", "warn");
  wrap.innerHTML = "";

  try {
    const docs = await api("/api/docs");

    if (portalContext) {
      portalContext.docsPreview = Array.isArray(docs) ? docs : [];
    }

    if (!Array.isArray(docs) || !docs.length) {
      wrap.innerHTML = `
        <div class="documentGroup emptyStateCard">
          <p class="itemTitle">No documents available</p>
          <p class="itemMeta">There are currently no documents linked to your tenancy.</p>
        </div>
      `;
      setStatus("Documents ready", "ok");
      return;
    }

    const groups = {
      Lease: [],
      Property: [],
      Unit: [],
      Other: []
    };

    docs.forEach((doc) => {
      const key = doc.sourceType || "Other";
      if (!groups[key]) groups[key] = [];
      groups[key].push(doc);
    });

    const orderedGroups = [
      { key: "Lease", title: "Lease Documents" },
      { key: "Property", title: "Property Documents" },
      { key: "Unit", title: "Unit Documents" },
      { key: "Other", title: "Other Documents" }
    ];

    orderedGroups.forEach((group) => {
      const items = groups[group.key];
      if (!items || !items.length) return;

      const section = document.createElement("section");
      section.className = "documentGroup";

      const heading = document.createElement("div");
      heading.className = "documentGroupHeader";
      heading.innerHTML = `
        <p class="documentGroupTitle">${escapeHtml(group.title)}</p>
        <p class="documentGroupMeta">${items.length} ${items.length === 1 ? "file" : "files"}</p>
      `;
      section.appendChild(heading);

      const list = document.createElement("div");
      list.className = "documentGroupList";

      items.forEach((d) => {
        const row = document.createElement("div");
        row.className = "documentRow";

        const button = document.createElement("button");
        button.type = "button";
        button.className = "btn btn-secondary documentAction";
        button.textContent = "Download";
        button.addEventListener("click", () => {
          downloadDocument(d);
        });

        row.innerHTML = `
          <div class="documentIcon" aria-hidden="true">📄</div>
          <div class="documentInfo">
            <p class="itemTitle">${escapeHtml(d.title || "Document")}</p>
            <p class="itemMeta">
              ${escapeHtml(d.fileType || "File")} • ${escapeHtml(safeDate(d.lastModified))}
            </p>
            ${d.sourceLabel ? `<p class="itemMeta">${escapeHtml(d.sourceLabel)}</p>` : ""}
          </div>
        `;

        row.appendChild(button);
        list.appendChild(row);
      });

      section.appendChild(list);
      wrap.appendChild(section);
    });

    setStatus("Documents ready", "ok");
  } catch (e) {
    console.error("Docs unavailable:", e);
    wrap.innerHTML = `
      <div class="documentGroup emptyStateCard">
        <p class="itemTitle">Documents unavailable</p>
        <p class="itemMeta">Documents aren’t available right now.</p>
      </div>
    `;
    setStatus("Documents ready", "warn");
  }
}
async function downloadDocument(doc) {
  try {
    setStatus(`Downloading ${doc.title || "document"}…`, "warn");

    const res = await api(
      `/api/docs/download?contentDocumentId=${encodeURIComponent(doc.contentDocumentId)}`,
      {
        method: "GET",
        rawResponse: true
      }
    );

    const blob = await res.blob();
    const blobUrl = window.URL.createObjectURL(blob);

    const ext = doc.fileExtension
  ? `.${doc.fileExtension}`
  : (doc.fileType ? `.${String(doc.fileType).toLowerCase()}` : "");
    const filename = `${doc.title || "document"}${ext}`;

    const a = document.createElement("a");
    a.href = blobUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();

    window.URL.revokeObjectURL(blobUrl);
    setStatus("Documents ready", "ok");
  } catch (e) {
    console.error("Download failed:", e);
    setStatus("Download failed", "bad");
    alert("Failed to download document.");
  }
}

// -------------------------
// Maintenance submit
// -------------------------
function readFileAsBase64Payload(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onerror = () => reject(new Error("Failed to read file"));
    r.onload = () => resolve({
      fileName: file.name,
      contentType: file.type || "application/octet-stream",
      base64: r.result, // data URL
    });
    r.readAsDataURL(file);
  });
}

function initMaintenanceForm() {
  if (!has("maintenanceForm")) return;

  on("maintenanceForm", "submit", async (e) => {
    e.preventDefault();
    setText("maintenanceMsg", "Submitting…");
    setStatus("Submitting maintenance…", "warn");

    try {
      const subject = ($("subject")?.value || "").trim();
      const description = ($("description")?.value || "").trim();

      const files = Array.from($("photos")?.files || []);
      const photos = await Promise.all(files.map(readFileAsBase64Payload));

      await api("/api/maintenance", {
        method: "POST",
        body: JSON.stringify({ subject, description, photos }),
      });

      setText("maintenanceMsg", "Submitted. Thanks — we’ll reach out if we need more info.");
      e.target.reset();

      await loadMaintenance();
      setStatus("Submitted", "ok");
    } catch (err) {
      setText("maintenanceMsg", err?.message || "Something went wrong");
      setStatus("Submit failed", "bad");
    }
  });
}

function initAccountForm() {
  if (!has("accountForm")) return;

  on("accountForm", "submit", async (e) => {
    e.preventDefault();

    const email = ($("accountEmail")?.value || "").trim();
    const phone = ($("accountPhone")?.value || "").trim();

    setAccountBanner("", "");

    if (!validateAccountForm(email, phone)) {
      setAccountBanner("Please fix the highlighted fields and try again.", "error");
      setStatus("Account validation failed", "bad");
      return;
    }

    setAccountBanner("Saving your changes…", "success");
    setStatus("Saving account details…", "warn");

    try {
      const result = await api("/api/profile", {
        method: "POST",
        body: JSON.stringify({ email, phone })
      });

      if (portalContext?.sf?.tenant) {
        portalContext.sf.tenant.email = result.email || "";
        portalContext.sf.tenant.phone = result.phone || "";
      }

      renderAccount();
      renderHome();

      setAccountBanner("Your contact details have been updated successfully.", "success");
      setStatus("Account updated", "ok");
    } catch (err) {
      console.error("Profile update failed:", err);
      setAccountBanner(err?.message || "Failed to update account details.", "error");
      setStatus("Account update failed", "bad");
    }
  });

  on("accountResetBtn", "click", () => {
    resetAccountFormFromContext();
    setStatus("Account form reset", "ok");
  });
}

// -------------------------
// Auth UI wiring
// -------------------------
function initAuthButtons() {
  on("btnLogin", "click", async () => {
    try {
      await login();
    } catch (e) {
      console.error(e);
      setStatus("Login error", "bad");
    }
  });

  on("btnLogout", "click", async () => {
    try {
      await logout();
    } catch (e) {
      console.error(e);
      setStatus("Logout error", "bad");
    }
  });

  on("callApi", "click", async () => {
    try {
      setStatus("Calling /api/me…", "warn");
      const me = await api("/api/me");
      portalContext = me;
      renderHome();
      setText("output", JSON.stringify(me, null, 2));
      setStatus("API ok", "ok");
    } catch (e) {
      console.error(e);
      setText("output", JSON.stringify({ ok: false, error: e?.message || String(e) }, null, 2));
      setStatus("API failed", "bad");
    }
  });
}

async function renderLoggedInState() {
  const authed = await isAuthenticated();
  show("btnLogin", !authed);
  show("btnLogout", authed);
  show("navBar", authed, "flex");

  if (!authed) {
    portalContext = null;
    setText("unitLine", "Please log in to view your unit.");
    renderHome();
    setStatus("Not logged in", "info");
    return;
  }

  await loadMe();
}

    function initMaintenanceFilters() {
  const container = $("maintenanceFilters");
  if (!container) return;

  container.addEventListener("click", (e) => {
    const btn = e.target.closest(".filterBtn");
    if (!btn) return;

    maintenanceFilter = btn.dataset.filter;

    container.querySelectorAll(".filterBtn").forEach(b => {
      b.classList.remove("active");
    });

    btn.classList.add("active");

    renderMaintenanceList();
  });
}

// -------------------------
// Boot
// -------------------------
async function boot() {
  if (isBooted) return;
  isBooted = true;

  initNav();
  initMaintenanceForm();
  initAccountForm();
  initMaintenanceFilters();
  initAuthButtons();

  setStatus("Initialising auth…", "warn");
  await requireAuth0Client();
  await handleAuthRedirectIfPresent();
  await renderLoggedInState();
}

boot().catch((e) => {
  console.error(e);
  setStatus("Auth init error", "bad");
  setText("unitLine", "Auth init error. Check Auth0 URLs + settings.");
});
