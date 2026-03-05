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

  if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  headers.Authorization = `Bearer ${token}`;

  const res = await fetch(path, { ...opts, headers });
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
      <div class="itemCard">
        <p class="itemTitle">Welcome</p>
        <p class="itemMeta">Login to see your unit and lease details.</p>
      </div>
    `;
    return;
  }

  const tenant = ctx.tenant || {};
  const unit = ctx.unit || {};
  const lease = ctx.lease || {};
  const tenancy = ctx.tenancy || {};

  el.innerHTML = `
    <div class="itemCard">
      <p class="itemTitle">Welcome, ${escapeHtml(tenant.name || "Tenant")}</p>
      <p class="itemMeta">${escapeHtml(tenant.email || "")}</p>
      <p class="itemMeta">${escapeHtml(tenant.phone || "")}</p>
    </div>

    <div class="itemCard">
      <p class="itemTitle">${escapeHtml(unit.propertyName || "Property")}</p>
      <p class="itemMeta">Unit: ${escapeHtml(unit.name || "")}</p>
      <p class="itemMeta">Tenancy: ${escapeHtml(tenancy.status || "")}</p>
    </div>

    <div class="itemCard">
      <p class="itemTitle">Lease ${escapeHtml(lease.name || "")}</p>
      <p class="itemMeta">${escapeHtml(lease.startDate || "?")} → ${escapeHtml(lease.endDate || "?")}</p>
      <p class="itemMeta">Status: ${escapeHtml(lease.status || "")}</p>
    </div>

    <div class="itemCard">
      <p class="itemTitle">Quick actions</p>
      <p class="itemMeta">Use the navigation above to submit maintenance or view documents.</p>
    </div>
  `;
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

  // Debug output
  setText("output", JSON.stringify(me, null, 2));
  setStatus("Ready", "ok");
}

async function loadMaintenance() {
  const wrap = $("maintenanceList");
  if (!wrap) return;

  setStatus("Loading maintenance…", "warn");
  wrap.innerHTML = "";

  try {
    const items = await api("/api/maintenance"); // optional list
    if (!Array.isArray(items) || !items.length) {
      wrap.innerHTML = `<div class="itemCard"><p class="itemMeta">No requests yet.</p></div>`;
      setStatus("Maintenance ready", "ok");
      return;
    }

    items.forEach((i) => {
      const el = document.createElement("div");
      el.className = "itemCard";
      el.innerHTML = `
        <p class="itemTitle">${escapeHtml(i.subject || "(No subject)")}</p>
        <p class="itemMeta">${escapeHtml(i.status || "")} • ${escapeHtml(safeDate(i.createdDate))}</p>
        <p class="itemMeta">${escapeHtml(i.description || "")}</p>
      `;
      wrap.appendChild(el);
    });

    setStatus("Maintenance ready", "ok");
  } catch (e) {
    console.error("Maintenance list unavailable:", e);
    wrap.innerHTML = `<div class="itemCard"><p class="itemMeta">Maintenance list isn’t available yet.</p></div>`;
    setStatus("Maintenance ready", "warn");
  }
}

async function loadDocs() {
  const wrap = $("docsList");
  if (!wrap) return;

  setStatus("Loading documents…", "warn");
  wrap.innerHTML = "";

  try {
    const docs = await api("/api/docs");
    if (!Array.isArray(docs) || !docs.length) {
      wrap.innerHTML = `<div class="itemCard"><p class="itemMeta">No documents linked to this unit.</p></div>`;
      setStatus("Documents ready", "ok");
      return;
    }

    docs.forEach((d) => {
      const el = document.createElement("div");
      el.className = "itemCard";
      const url = `/api/docs/download?contentDocumentId=${encodeURIComponent(d.contentDocumentId)}`;
      el.innerHTML = `
        <p class="itemTitle">${escapeHtml(d.title || "Document")}</p>
        <p class="itemMeta">${escapeHtml(d.fileType || "")} • ${escapeHtml(safeDate(d.lastModified))}</p>
        <p class="itemMeta"><a href="${url}">Download</a></p>
      `;
      wrap.appendChild(el);
    });

    setStatus("Documents ready", "ok");
  } catch (e) {
    console.error("Docs unavailable:", e);
    wrap.innerHTML = `<div class="itemCard"><p class="itemMeta">Documents aren’t available yet.</p></div>`;
    setStatus("Documents ready", "warn");
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

// -------------------------
// Boot
// -------------------------
async function boot() {
  if (isBooted) return;
  isBooted = true;

  initNav();
  initMaintenanceForm();
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
