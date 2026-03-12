/**
 * Tenant Portal (Cloudflare Pages)
 * - Auth0 SPA login (Auth0 SPA SDK v2)
 * - Calls Pages Functions (/api/*) with Bearer token
 * - Stripe-style shell with sidebar navigation
 */

// -------------------------
// DOM helpers
// -------------------------
const $ = (id) => document.getElementById(id);
const has = (id) => Boolean($(id));

const setText = (id, text) => {
  const el = $(id);
  if (el) el.textContent = String(text ?? "");
};

const on = (id, evt, fn, opts) => {
  const el = $(id);
  if (!el) return false;
  el.addEventListener(evt, fn, opts);
  return true;
};

// -------------------------
// Config
// -------------------------
const AUTH0_DOMAIN = "dev-v3g60bdgfjg7walx.us.auth0.com";
const AUTH0_CLIENT_ID = "CXrASdTRNQKhDuJIFNvIR7wPwjAwjtCx";
const AUTH0_AUDIENCE = "https://tenant-portal-api";
const PORTAL_ORIGIN = window.location.origin;

// -------------------------
// State
// -------------------------
let auth0Client = null;
let isBooted = false;
let portalContext = null;
let maintenanceItemsCache = [];
let documentsCache = [];
let announcementsCache = [];
let maintenanceFilter = "all";

// -------------------------
// Utilities
// -------------------------
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[c]));
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";

  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric"
  }).format(date);
}

function safeDateTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";

  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

function getInitials(name) {
  if (!name) return "TP";
  return name
    .trim()
    .split(/\s+/)
    .map((part) => part[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
}

function setStatus(message, kind = "info") {
  const label = $("globalStatusText");
  if (label) {
    label.textContent = String(message || "");
  }

  const dot = $("globalStatusDot");
  if (!dot) return;

  const color =
    kind === "ok" ? "#0f9f6e" :
    kind === "warn" ? "#b7791f" :
    kind === "bad" ? "#d14343" :
    "#94a3b8";

  dot.style.background = color;
}

function showToast(message, kind = "info") {
  const toast = $("toast");
  const toastText = $("toastText");
  if (!toast || !toastText) return;

  toastText.textContent = String(message || "");
  toast.classList.remove("toast--info", "toast--success", "toast--error");
  if (kind === "ok") {
    toast.classList.add("toast--success");
  } else if (kind === "bad") {
    toast.classList.add("toast--error");
  } else {
    toast.classList.add("toast--info");
  }

  toast.classList.add("is-visible");

  window.clearTimeout(showToast._timer);
  showToast._timer = window.setTimeout(() => {
    toast.classList.remove("is-visible");
  }, 3200);
}

function setProfileMessage(message = "", kind = "info") {
  const el = $("profileMessage");
  if (!el) return;

  el.textContent = message;
  el.classList.remove("form-message--info", "form-message--success", "form-message--error");

  if (!message) {
    el.style.display = "none";
    return;
  }

  el.style.display = "block";
  if (kind === "ok") {
    el.classList.add("form-message--success");
  } else if (kind === "bad") {
    el.classList.add("form-message--error");
  } else {
    el.classList.add("form-message--info");
  }
}

function setMaintenanceMessage(message = "", kind = "info") {
  const el = $("maintenanceMsg");
  if (!el) return;

  el.textContent = message;
  el.classList.remove("form-message--info", "form-message--success", "form-message--error");

  if (!message) {
    el.style.display = "none";
    return;
  }

  el.style.display = "block";
  if (kind === "ok") {
    el.classList.add("form-message--success");
  } else if (kind === "bad") {
    el.classList.add("form-message--error");
  } else {
    el.classList.add("form-message--info");
  }
}

function validateEmail(email) {
  if (!email) return true;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePhone(phone) {
  if (!phone) return true;
  return /^[0-9+()\-\s]{7,20}$/.test(phone);
}

// -------------------------
// Page metadata / navigation
// -------------------------
const pageMeta = {
  home: {
    title: "Dashboard",
    subtitle: "Overview of your tenancy and latest activity"
  },
  maintenance: {
    title: "Maintenance",
    subtitle: "Track issues, updates, and request history"
  },
  documents: {
    title: "Documents",
    subtitle: "Download files available through your tenancy"
  },
  announcements: {
    title: "Announcements",
    subtitle: "Important notices and property updates"
  },
  profile: {
    title: "Profile",
    subtitle: "Manage your contact details"
  }
};

function setActiveView(viewName) {
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("active", view.id === `view-${viewName}`);
  });

  document.querySelectorAll(".nav-item").forEach((item) => {
    item.classList.toggle("active", item.dataset.view === viewName);
  });

  const meta = pageMeta[viewName] || pageMeta.home;
  setText("pageTitle", meta.title);
  setText("pageSubtitle", meta.subtitle);

  const sidebar = document.querySelector(".sidebar");
  if (sidebar) sidebar.classList.remove("is-open");
}

function initNavigation() {
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const view = btn.dataset.view;
      setActiveView(view);

      if (view === "maintenance") {
        await loadMaintenance();
      } else if (view === "documents") {
        await loadDocuments();
      } else if (view === "announcements") {
        await loadAnnouncementsAndRender();
      }
    });
  });

  document.querySelectorAll("[data-view-link]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const view = btn.dataset.viewLink;
      setActiveView(view);

      if (view === "maintenance") {
        await loadMaintenance();
      } else if (view === "documents") {
        await loadDocuments();
      } else if (view === "announcements") {
        await loadAnnouncementsAndRender();
      }
    });
  });

  on("mobileNavToggle", "click", () => {
    document.querySelector(".sidebar")?.classList.toggle("is-open");
  });

  on("qaMaintenance", "click", async () => {
    setActiveView("maintenance");
    await loadMaintenance();
  });

  on("qaDocuments", "click", async () => {
    setActiveView("documents");
    await loadDocuments();
  });

  on("qaAnnouncements", "click", async () => {
    setActiveView("announcements");
    await loadAnnouncementsAndRender();
  });

  on("qaProfile", "click", () => {
    setActiveView("profile");
  });

  on("quickMaintenanceBtn", "click", () => {
    openMaintenanceModal();
  });

  on("maintenanceCreateBtn", "click", () => {
    openMaintenanceModal();
  });
}

function initMaintenanceFilters() {
  document.querySelectorAll("[data-maintenance-filter]").forEach((btn) => {
    btn.addEventListener("click", () => {
      maintenanceFilter = btn.dataset.maintenanceFilter || "all";

      document.querySelectorAll("[data-maintenance-filter]").forEach((other) => {
        other.classList.toggle("active", other === btn);
      });

      renderFilteredMaintenance();
    });
  });
}

// -------------------------
// Auth helpers
// -------------------------
async function requireAuth0Client() {
  const factory =
    window.auth0 && typeof window.auth0.createAuth0Client === "function"
      ? window.auth0.createAuth0Client
      : null;

  if (!factory) {
    throw new Error("Auth0 SPA SDK not loaded.");
  }

  if (!auth0Client) {
    auth0Client = await factory({
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
      scope: "openid profile email"
    }
  });
}

async function logout() {
  await requireAuth0Client();
  setStatus("Logging out…", "warn");
  await auth0Client.logout({
    logoutParams: { returnTo: PORTAL_ORIGIN }
  });
}

async function isAuthenticated() {
  await requireAuth0Client();
  return auth0Client.isAuthenticated();
}

async function getAccessToken() {
  await requireAuth0Client();
  return auth0Client.getTokenSilently({
    authorizationParams: {
      audience: AUTH0_AUDIENCE,
      scope: "openid profile email"
    }
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
// Shell population
// -------------------------
function applyTenantProfileToShell(data) {
  const fullName = data?.name || "Tenant";
  const email = data?.email || "—";
  const phone = data?.phone || "—";
  const property = data?.propertyName || "—";
  const unit = data?.unitName || "—";
  const lease = data?.leaseName || "—";
  const tenancyStatus = data?.tenancyStatus || "—";
  const leaseEnd = data?.leaseEndDate || "—";

  setText("profileNameTop", fullName);
  setText("profileEmailTop", email);
  setText("profileInitials", getInitials(fullName));

  setText("tenantName", fullName);
  setText("tenantEmail", email);
  setText("tenantPhone", phone);
  setText("tenantProperty", property);
  setText("tenantUnit", unit);
  setText("tenantLease", lease);

  setText("metricTenancyStatus", tenancyStatus);
  setText("metricLeaseEnd", leaseEnd);
  setText("sidebarTenancyStatus", tenancyStatus);
  setText("sidebarUnitName", unit !== "—" ? unit : "Unit —");

  const profileEmailField = $("profileEmail");
  const profilePhoneField = $("profilePhone");

  if (profileEmailField) profileEmailField.value = email === "—" ? "" : email;
  if (profilePhoneField) profilePhoneField.value = phone === "—" ? "" : phone;
}

function updateDashboardMetrics() {
  const openCount = maintenanceItemsCache.filter(
    (item) => (item.status || "").toLowerCase() !== "completed"
  ).length;

  setText("metricOpenRequests", openCount);
  setText("metricDocuments", documentsCache.length);
}

// -------------------------
// Rendering
// -------------------------
function normaliseStatusClass(status) {
  const value = String(status || "").toLowerCase();
  if (value === "open") return "badge badge--open";
  if (value === "in progress") return "badge badge--in-progress";
  if (value === "waiting for contractor") return "badge badge--waiting";
  if (value === "completed") return "badge badge--completed";
  return "badge badge--neutral";
}

function renderMaintenanceItems(items, targetId) {
  const container = $(targetId);
  if (!container) return;

  if (!items || !items.length) {
    container.innerHTML = `
      <div class="list-item">
        <div class="list-item__body">No maintenance requests found.</div>
      </div>
    `;
    return;
  }

  container.innerHTML = items.map((item, index) => `
    <article class="list-item" data-status="${escapeHtml((item.status || "").toLowerCase())}">
      <div class="list-item__top">
        <div>
          <h3 class="list-item__title">${escapeHtml(item.subject || "Untitled request")}</h3>
          <div class="list-item__meta">
            Submitted ${formatDate(item.createdDate)}
          </div>
        </div>
        <span class="${normaliseStatusClass(item.status)}">${escapeHtml(item.status || "Unknown")}</span>
      </div>
      <div class="list-item__body">
        ${escapeHtml(item.portalUpdate || item.description || "No additional details yet.")}
      </div>
      <div class="list-item__footer">
        <button class="panel__action" type="button" data-maintenance-index="${index}">
          View details
        </button>
      </div>
    </article>
  `).join("");

  container.querySelectorAll("[data-maintenance-index]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.dataset.maintenanceIndex);
      const item = items[idx];
      if (item) openMaintenanceDetail(item);
    });
  });
}

function renderFilteredMaintenance() {
  const value = maintenanceFilter.toLowerCase();
  const filtered = value === "all"
    ? maintenanceItemsCache
    : maintenanceItemsCache.filter(
        (item) => String(item.status || "").toLowerCase() === value
      );

  renderMaintenanceItems(filtered, "maintenanceList");
}

function renderAnnouncements(items, targetId) {
  const container = $(targetId);
  if (!container) return;

  if (!items || !items.length) {
    container.innerHTML = `
      <div class="list-item">
        <div class="list-item__body">No announcements right now.</div>
      </div>
    `;
    return;
  }

  container.innerHTML = items.map((item) => `
    <article class="list-item">
      <div class="list-item__top">
        <div>
          <h3 class="list-item__title">${escapeHtml(item.title || "Announcement")}</h3>
          <div class="list-item__meta">
            ${escapeHtml(item.category || "General")}${item.scope ? ` • ${escapeHtml(item.scope)}` : ""}
          </div>
        </div>
        <span class="badge badge--neutral">${escapeHtml(item.priority || "Info")}</span>
      </div>
      <div class="list-item__body">
        ${escapeHtml(item.message || "")}
      </div>
      <div class="list-item__meta" style="margin-top:10px;">
        ${item.startDateTime || item.endDateTime
          ? `Active ${escapeHtml(safeDateTime(item.startDateTime))}${item.endDateTime ? ` to ${escapeHtml(safeDateTime(item.endDateTime))}` : ""}`
          : ""}
      </div>
    </article>
  `).join("");
}

function renderDocuments(items) {
  const container = $("documentsList");
  if (!container) return;

  if (!items || !items.length) {
    container.innerHTML = `
      <div class="list-item">
        <div class="list-item__body">No documents available.</div>
      </div>
    `;
    return;
  }

  container.innerHTML = items.map((doc, index) => `
    <article class="list-item">
      <div class="list-item__top">
        <div>
          <h3 class="list-item__title">${escapeHtml(doc.title || doc.fileName || "Document")}</h3>
          <div class="list-item__meta">
            ${escapeHtml(doc.fileType || doc.type || "File")}
            ${doc.lastModified ? ` • ${formatDate(doc.lastModified)}` : ""}
          </div>
        </div>
        <button class="panel__action" type="button" data-document-index="${index}">
          Download
        </button>
      </div>
      <div class="list-item__body">
        ${escapeHtml(doc.sourceLabel || doc.scopeLabel || "Available through your tenancy")}
      </div>
    </article>
  `).join("");

  container.querySelectorAll("[data-document-index]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const idx = Number(btn.dataset.documentIndex);
      const doc = items[idx];
      if (doc) await downloadDocument(doc);
    });
  });
}

// -------------------------
// Detail / modal handling
// -------------------------
function openMaintenanceDetail(item) {
  setText("maintenanceDetailTitle", item.subject || "Maintenance request");
  setText("maintenanceDetailStatus", item.status || "Unknown");
  setText("maintenanceDetailSubmitted", safeDateTime(item.createdDate));
  setText("maintenanceDetailDescription", item.description || "No description provided.");
  setText("maintenanceDetailUpdate", item.portalUpdate || "No update has been added yet.");

  const modal = $("maintenanceDetailModal");
  if (modal) modal.classList.add("is-open");
}

function closeMaintenanceDetail() {
  $("maintenanceDetailModal")?.classList.remove("is-open");
}

function openMaintenanceModal() {
  $("maintenanceModal")?.classList.add("is-open");
  setMaintenanceMessage("", "info");
  $("subject")?.focus();
}

function closeMaintenanceModal() {
  $("maintenanceModal")?.classList.remove("is-open");
}

function initModalControls() {
  document.querySelectorAll("[data-close-modal]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.closeModal;
      $(target)?.classList.remove("is-open");
    });
  });

  document.querySelectorAll(".modal").forEach((modal) => {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) {
        modal.classList.remove("is-open");
      }
    });
  });
}

// -------------------------
// Loaders
// -------------------------
async function loadMe() {
  setStatus("Loading dashboard…", "warn");

  const me = await api("/api/me");
  portalContext = me;

  const ctx = me?.sf?.ok !== false ? me.sf : null;

  const shellProfile = {
    name: ctx?.tenant?.name || "Tenant",
    email: ctx?.tenant?.email || "",
    phone: ctx?.tenant?.phone || "",
    propertyName: ctx?.unit?.propertyName || "",
    unitName: ctx?.unit?.name || "",
    leaseName: ctx?.lease?.name || "",
    tenancyStatus: ctx?.tenancy?.status || "",
    leaseEndDate: ctx?.lease?.endDate || ""
  };

  applyTenantProfileToShell(shellProfile);

  await Promise.all([
    loadMaintenance(true),
    loadDocuments(true),
    loadAnnouncementsAndRender(true)
  ]);

  updateDashboardMetrics();
  setStatus("Ready", "ok");
}

async function loadMaintenance(skipStatusMessage = false) {
  if (!skipStatusMessage) setStatus("Loading maintenance…", "warn");

  try {
    const items = await api("/api/maintenance");
    maintenanceItemsCache = Array.isArray(items) ? items : [];

    renderFilteredMaintenance();
    renderMaintenanceItems(maintenanceItemsCache.slice(0, 3), "recentMaintenanceList");
    updateDashboardMetrics();

    if (!skipStatusMessage) setStatus("Maintenance ready", "ok");
  } catch (e) {
    console.error("Maintenance unavailable:", e);
    maintenanceItemsCache = [];
    renderFilteredMaintenance();
    renderMaintenanceItems([], "recentMaintenanceList");

    if (!skipStatusMessage) setStatus("Maintenance unavailable", "warn");
  }
}

async function loadDocuments(skipStatusMessage = false) {
  if (!skipStatusMessage) setStatus("Loading documents…", "warn");

  try {
    const items = await api("/api/docs");
    documentsCache = Array.isArray(items) ? items : [];
    renderDocuments(documentsCache);
    updateDashboardMetrics();

    if (!skipStatusMessage) setStatus("Documents ready", "ok");
  } catch (e) {
    console.error("Documents unavailable:", e);
    documentsCache = [];
    renderDocuments([]);

    if (!skipStatusMessage) setStatus("Documents unavailable", "warn");
  }
}

async function loadAnnouncementsAndRender(skipStatusMessage = false) {
  if (!skipStatusMessage) setStatus("Loading announcements…", "warn");

  try {
    const items = await api("/api/announcements");
    announcementsCache = Array.isArray(items) ? items : [];
    renderAnnouncements(announcementsCache, "announcementsList");
    renderAnnouncements(announcementsCache.slice(0, 3), "homeAnnouncements");

    if (!skipStatusMessage) setStatus("Announcements ready", "ok");
  } catch (e) {
    console.error("Announcements unavailable:", e);
    announcementsCache = [];
    renderAnnouncements([], "announcementsList");
    renderAnnouncements([], "homeAnnouncements");

    if (!skipStatusMessage) setStatus("Announcements unavailable", "warn");
  }
}

// -------------------------
// Downloads
// -------------------------
async function downloadDocument(doc) {
  try {
    setStatus(`Downloading ${doc.title || "document"}…`, "warn");

    const contentDocumentId = doc.contentDocumentId || doc.id;
    if (!contentDocumentId) {
      throw new Error("Document id missing.");
    }

    const res = await api(
      `/api/docs/download?contentDocumentId=${encodeURIComponent(contentDocumentId)}`,
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
    showToast("Failed to download document.", "bad");
  }
}

// -------------------------
// Maintenance submit
// -------------------------
function readFileAsBase64Payload(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Failed to read file"));
    reader.onload = () => resolve({
      fileName: file.name,
      contentType: file.type || "application/octet-stream",
      base64: reader.result
    });
    reader.readAsDataURL(file);
  });
}

function initMaintenanceForm() {
  if (!has("maintenanceForm")) return;

  on("maintenanceForm", "submit", async (e) => {
    e.preventDefault();
    setMaintenanceMessage("Submitting your request…", "info");
    setStatus("Submitting maintenance…", "warn");

    try {
      const subject = ($("subject")?.value || "").trim();
      const description = ($("description")?.value || "").trim();
      const files = Array.from($("photos")?.files || []);

      if (!subject) {
        throw new Error("Please enter a subject.");
      }

      if (!description) {
        throw new Error("Please enter a description.");
      }

      const photos = await Promise.all(files.map(readFileAsBase64Payload));

      await api("/api/maintenance", {
        method: "POST",
        body: JSON.stringify({ subject, description, photos })
      });

      $("maintenanceForm")?.reset();
await loadMaintenance();
closeMaintenanceModal();
showToast("Maintenance request submitted.", "ok");
setStatus("Submitted", "ok");
    } catch (err) {
      console.error(err);
      setMaintenanceMessage(err?.message || "Something went wrong.", "bad");
      setStatus("Submit failed", "bad");
    }
  });
}

// -------------------------
// Profile form
// -------------------------
function initProfileForm() {
  if (!has("profileForm")) return;

  on("profileForm", "submit", async (e) => {
    e.preventDefault();

    const email = ($("profileEmail")?.value || "").trim();
    const phone = ($("profilePhone")?.value || "").trim();

    setProfileMessage("", "info");

    if (!validateEmail(email)) {
      setProfileMessage("Enter a valid email address.", "bad");
      setStatus("Profile validation failed", "bad");
      return;
    }

    if (!validatePhone(phone)) {
      setProfileMessage("Enter a valid phone number.", "bad");
      setStatus("Profile validation failed", "bad");
      return;
    }

    setProfileMessage("Saving your changes…", "info");
    setStatus("Saving profile…", "warn");

    try {
      const result = await api("/api/profile", {
        method: "POST",
        body: JSON.stringify({ email, phone })
      });

      if (portalContext?.sf?.tenant) {
        portalContext.sf.tenant.email = result.email || "";
        portalContext.sf.tenant.phone = result.phone || "";
      }

      applyTenantProfileToShell({
        name: portalContext?.sf?.tenant?.name || "Tenant",
        email: result.email || "",
        phone: result.phone || "",
        propertyName: portalContext?.sf?.unit?.propertyName || "",
        unitName: portalContext?.sf?.unit?.name || "",
        leaseName: portalContext?.sf?.lease?.name || "",
        tenancyStatus: portalContext?.sf?.tenancy?.status || "",
        leaseEndDate: portalContext?.sf?.lease?.endDate || ""
      });

      setProfileMessage("Your contact details have been updated successfully.", "ok");
      setStatus("Profile updated", "ok");
      showToast("Profile updated.", "ok");
    } catch (err) {
      console.error("Profile update failed:", err);
      setProfileMessage(err?.message || "Failed to update profile.", "bad");
      setStatus("Profile update failed", "bad");
    }
  });
}

// -------------------------
// Auth UI
// -------------------------
function initAuthButtons() {
  on("loginBtn", "click", async () => {
    try {
      await login();
    } catch (e) {
      console.error(e);
      setStatus("Login error", "bad");
    }
  });

  on("logoutBtn", "click", async () => {
    try {
      await logout();
    } catch (e) {
      console.error(e);
      setStatus("Logout error", "bad");
    }
  });
}

async function renderLoggedInState() {
  const authed = await isAuthenticated();

  const app = $("app");
  const loading = $("authLoading");
  const guest = $("guestScreen");

  if (!authed) {
    portalContext = null;
    if (app) app.classList.add("hidden");
    if (loading) loading.classList.add("hidden");
    if (guest) guest.classList.remove("hidden");
    setStatus("Not logged in", "info");
    return;
  }

  if (guest) guest.classList.add("hidden");
  if (loading) loading.classList.remove("hidden");

  await loadMe();

  if (loading) loading.classList.add("hidden");
  if (app) app.classList.remove("hidden");
}

// -------------------------
// Boot
// -------------------------
async function boot() {
  if (isBooted) return;
  isBooted = true;

  initNavigation();
  initMaintenanceFilters();
  initMaintenanceForm();
  initProfileForm();
  initAuthButtons();
  initModalControls();

  setStatus("Initialising auth…", "warn");
  await requireAuth0Client();
  await handleAuthRedirectIfPresent();
  await renderLoggedInState();
}

boot().catch((e) => {
  console.error(e);
  setStatus("Auth init error", "bad");
  showToast("Authentication failed. Check Auth0 settings.", "bad");
});
