/**
 * Tenant Portal (Cloudflare Pages)
 * - Auth0 SPA login (Auth0 SPA SDK v2)
 * - Calls Pages Functions (/api/*) with Bearer token
 * - Renders: Profile (/api/me), Maintenance (/api/maintenance), Docs (/api/docs)
 *
 * Requirements in your HTML:
 *  - Buttons: #btnLogin, #btnLogout (optional: will gracefully no-op if missing)
 *  - Tabs (optional): .tab[data-tab="..."] and panels: .tabPanel + #tab-<name>
 *  - UI targets (optional):
 *      #unitLine, #profileBox, #maintenanceList, #docsList, #maintenanceMsg
 *  - Maintenance form (optional):
 *      #maintenanceForm with fields #subject #description #photos
 *
 * NOTE: This file is defensive: if a given element isn't present, it won't crash.
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

const show = (id, yes) => {
  const el = $(id);
  if (!el) return;
  el.style.display = yes ? "inline-block" : "none";
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

// -------------------------
// Utilities
// -------------------------
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
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
  // Optional: hook these up in your HTML if you want
  // - #statusText, #statusDot
  setText("statusText", message);

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
// Tabs (optional)
// -------------------------
function setTab(name) {
  document.querySelectorAll(".tab").forEach((t) => {
    t.classList.toggle("active", t.dataset.tab === name);
  });
  document.querySelectorAll(".tabPanel").forEach((p) => {
    p.style.display = "none";
  });
  const panel = $(`tab-${name}`);
  if (panel) panel.style.display = "block";
}

function initTabs() {
  const tabs = Array.from(document.querySelectorAll(".tab"));
  if (!tabs.length) return;

  tabs.forEach((btn) => {
    btn.addEventListener("click", () => setTab(btn.dataset.tab));
  });

  // Default to first tab if no panel is shown
  const first = tabs[0]?.dataset?.tab;
  if (first) setTab(first);
}

// -------------------------
// Auth helpers
// -------------------------
async function requireAuth0Client() {
  const factory =
    (window.auth0 && typeof window.auth0.createAuth0Client === "function")
      ? window.auth0.createAuth0Client
      : null;

  console.log("Auth0 SDK typeof window.auth0.createAuth0Client =", typeof factory);

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
    // Clean URL (remove code/state)
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
  // Uses SPA SDK cache + refresh tokens automatically
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
      (data && data.message) ? data.message :
      (data && data.error) ? data.error :
      (typeof data === "string" ? data : `HTTP ${res.status}`);
    throw new Error(msg);
  }
  return data;
}

// -------------------------
// Loaders
// -------------------------
async function loadMe() {
  setStatus("Loading profile…", "warn");
  const me = await api("/api/me");

  // Until Salesforce mapping is wired, /api/me returns Auth0-ish data. Show something sensible either way.
  const headline =
    me.unitName
      ? `${me.unitName} • Lease ${me.leaseStart || "?"} → ${me.leaseEnd || "?"}`
      : (me.email ? `Logged in as ${me.email}` : (me.sub ? `Logged in (${me.sub})` : "Logged in"));

  setText("unitLine", headline);
  setText("profileBox", JSON.stringify(me, null, 2));
  setStatus("Profile loaded", "ok");
}

async function loadMaintenance() {
  const wrap = $("maintenanceList");
  if (!wrap) return;

  setStatus("Loading maintenance…", "warn");
  const items = await api("/api/maintenance");
  wrap.innerHTML = "";

  if (!Array.isArray(items) || !items.length) {
    wrap.innerHTML = `<div class="item"><p class="itemMeta">No requests yet.</p></div>`;
    setStatus("Maintenance loaded", "ok");
    return;
  }

  items.forEach((i) => {
    const el = document.createElement("div");
    el.className = "item";
    el.innerHTML = `
      <p class="itemTitle">${escapeHtml(i.subject || "(No subject)")}</p>
      <p class="itemMeta">${escapeHtml(i.status || "")} • ${escapeHtml(safeDate(i.createdDate))}</p>
      <p class="itemMeta">${escapeHtml(i.description || "")}</p>
    `;
    wrap.appendChild(el);
  });

  setStatus("Maintenance loaded", "ok");
}

async function loadDocs() {
  const wrap = $("docsList");
  if (!wrap) return;

  setStatus("Loading documents…", "warn");
  const docs = await api("/api/docs");
  wrap.innerHTML = "";

  if (!Array.isArray(docs) || !docs.length) {
    wrap.innerHTML = `<div class="item"><p class="itemMeta">No documents linked to this unit.</p></div>`;
    setStatus("Documents loaded", "ok");
    return;
  }

  docs.forEach((d) => {
    const el = document.createElement("div");
    el.className = "item";
    const url = `/api/docs/download?contentDocumentId=${encodeURIComponent(d.contentDocumentId)}`;
    el.innerHTML = `
      <p class="itemTitle">${escapeHtml(d.title || "Document")}</p>
      <p class="itemMeta">${escapeHtml(d.fileType || "")} • ${escapeHtml(safeDate(d.lastModified))}</p>
      <a href="${url}">Download</a>
    `;
    wrap.appendChild(el);
  });

  setStatus("Documents loaded", "ok");
}

// -------------------------
// Maintenance submit (optional)
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
// Auth0 UI wiring (optional)
// -------------------------
function initAuthButtons() {
  on("btnLogin", "click", async () => {
    try {
      await login();
    } catch (e) {
      console.error(e);
      setStatus("Login error", "bad");
      setText("unitLine", "Login error. Check Auth0 settings.");
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

  // Optional test button if you include it in HTML
  on("callApi", "click", async () => {
    try {
      setStatus("Calling /api/me…", "warn");
      const me = await api("/api/me");
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

  if (!authed) {
    setText("unitLine", "Please log in to view your unit.");
    setStatus("Not logged in", "info");
    return;
  }

  // Load what exists (each loader is safe if its UI container doesn't exist)
  await loadMe();
  await Promise.allSettled([loadMaintenance(), loadDocs()]);
}

// -------------------------
// Boot
// -------------------------
async function boot() {
  if (isBooted) return;
  isBooted = true;

  initTabs();
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
