const $ = (id) => document.getElementById(id);

// ----------- CONFIG (yours) -----------
const AUTH0_DOMAIN = "dev-v3g60bdgfjg7walx.us.auth0.com";
const AUTH0_CLIENT_ID = "CXrASdTRNQKhDuJIFNvIR7wPwjAwjtCx";
const AUTH0_AUDIENCE = "https://tenant-portal-api";

// IMPORTANT: set to your Pages URL (must match Auth0 settings)
// Example: https://tenant-portal-abc.pages.dev
const PORTAL_ORIGIN = window.location.origin;
// -------------------------------------

let auth0Client = null;

function setTab(name) {
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".tabPanel").forEach(p => p.style.display = "none");
  $(`tab-${name}`).style.display = "block";
}
document.querySelectorAll(".tab").forEach(btn => btn.addEventListener("click", () => setTab(btn.dataset.tab)));

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
}

async function getAccessToken() {
  // Uses Auth0 SPA SDK cache/refresh automatically
  return await auth0Client.getTokenSilently({
    authorizationParams: {
      audience: AUTH0_AUDIENCE
    }
  });
}

async function api(path, opts = {}) {
  const token = await getAccessToken();
  const headers = { ...(opts.headers || {}) };

  if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  headers.Authorization = `Bearer ${token}`;

  const res = await fetch(path, { ...opts, headers });
  const ct = res.headers.get("Content-Type") || "";
  const data = ct.includes("application/json") ? await res.json().catch(() => ({})) : await res.text();

  if (!res.ok) {
    const msg = (data && data.message) ? data.message : (typeof data === "string" ? data : `HTTP ${res.status}`);
    throw new Error(msg);
  }
  return data;
}

async function loadMe() {
  const me = await api("/api/me");
  $("unitLine").textContent = `${me.unitName || "Unit"} • Lease ${me.leaseStart || "?"} → ${me.leaseEnd || "?"}`;
  $("profileBox").textContent = JSON.stringify(me, null, 2);
}

async function loadMaintenance() {
  const items = await api("/api/maintenance");
  const wrap = $("maintenanceList");
  wrap.innerHTML = "";

  if (!items.length) {
    wrap.innerHTML = `<div class="item"><p class="itemMeta">No requests yet.</p></div>`;
    return;
  }

  items.forEach(i => {
    const el = document.createElement("div");
    el.className = "item";
    el.innerHTML = `
      <p class="itemTitle">${escapeHtml(i.subject || "(No subject)")}</p>
      <p class="itemMeta">${escapeHtml(i.status || "")} • ${new Date(i.createdDate).toLocaleString()}</p>
      <p class="itemMeta">${escapeHtml(i.description || "")}</p>
    `;
    wrap.appendChild(el);
  });
}

async function loadDocs() {
  const docs = await api("/api/docs");
  const wrap = $("docsList");
  wrap.innerHTML = "";

  if (!docs.length) {
    wrap.innerHTML = `<div class="item"><p class="itemMeta">No documents linked to this unit.</p></div>`;
    return;
  }

  docs.forEach(d => {
    const el = document.createElement("div");
    el.className = "item";
    const url = `/api/docs/download?contentDocumentId=${encodeURIComponent(d.contentDocumentId)}`;
    el.innerHTML = `
      <p class="itemTitle">${escapeHtml(d.title || "Document")}</p>
      <p class="itemMeta">${escapeHtml(d.fileType || "")} • ${new Date(d.lastModified).toLocaleString()}</p>
      <a href="${url}">Download</a>
    `;
    wrap.appendChild(el);
  });
}

function readFileAsBase64Payload(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onerror = () => reject(new Error("Failed to read file"));
    r.onload = () => resolve({
      fileName: file.name,
      contentType: file.type || "application/octet-stream",
      base64: r.result // data URL
    });
    r.readAsDataURL(file);
  });
}

$("maintenanceForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("maintenanceMsg").textContent = "Submitting...";

  try {
    const subject = $("subject").value.trim();
    const description = $("description").value.trim();
    const files = Array.from($("photos").files || []);
    const photos = await Promise.all(files.map(readFileAsBase64Payload));

    await api("/api/maintenance", {
      method: "POST",
      body: JSON.stringify({ subject, description, photos })
    });

    $("maintenanceMsg").textContent = "Submitted. Thanks — we’ll reach out if we need more info.";
    e.target.reset();
    await loadMaintenance();
  } catch (err) {
    $("maintenanceMsg").textContent = err.message || "Something went wrong";
  }
});

// ----- Auth0 UI -----
$("btnLogin").addEventListener("click", async () => {
  await auth0Client.loginWithRedirect({
    authorizationParams: {
      redirect_uri: PORTAL_ORIGIN,
      audience: AUTH0_AUDIENCE,
      scope: "openid profile email"
    }
  });
});

$("btnLogout").addEventListener("click", async () => {
  await auth0Client.logout({
    logoutParams: { returnTo: PORTAL_ORIGIN }
  });
});

async function renderLoggedInState() {
  const isAuth = await auth0Client.isAuthenticated();
  $("btnLogin").style.display = isAuth ? "none" : "inline-block";
  $("btnLogout").style.display = isAuth ? "inline-block" : "none";

  if (!isAuth) {
    $("unitLine").textContent = "Please log in to view your unit.";
    return;
  }

  await loadMe();
  await loadMaintenance();
  await loadDocs();
}

async function boot() {
  // Create Auth0 client
  auth0Client = await createAuth0Client({
    domain: AUTH0_DOMAIN,
    clientId: AUTH0_CLIENT_ID,
    authorizationParams: {
      audience: AUTH0_AUDIENCE,
      redirect_uri: PORTAL_ORIGIN
    },
    cacheLocation: "localstorage", // keeps session between refreshes
    useRefreshTokens: true
  });

  // Handle Auth0 redirect callback (after login)
  const query = window.location.search;
  if (query.includes("code=") && query.includes("state=")) {
    await auth0Client.handleRedirectCallback();
    // Clean URL
    window.history.replaceState({}, document.title, PORTAL_ORIGIN + window.location.pathname);
  }

  await renderLoggedInState();
}

boot().catch((e) => {
  console.error(e);
  $("unitLine").textContent = "Auth init error. Check Auth0 URLs + settings.";
});
