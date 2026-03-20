/* =========================================================
   01. AUTH / APP CONFIG
   ========================================================= */

const AUTH0_DOMAIN = "dev-v3g60bdgfjg7walx.us.auth0.com";
const AUTH0_CLIENT_ID = "CXrASdTRNQKhDuJIFNvIR7wPwjAwjtCx";
const AUTH0_AUDIENCE = "https://tenant-portal-api";

const LAST_VIEW_KEY = "tenant-portal:last-view";
const MAX_FILES = 5;
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024;

/* =========================================================
   02. APP STATE
   ========================================================= */

let auth0Client = null;
let isBooted = false;
let portalContext = null;
let maintenanceItemsCache = [];
let documentsCache = [];
let announcementsCache = [];
let maintenanceFilter = "all";
let activeModalId = null;
let toastTimer = null;
let maintenanceMessagesCache = {};
let activeMaintenanceItem = null;
let isSendingMaintenanceMessage = false;
let maintenanceMessagesPollTimer = null;
let isSidebarCollapsed = false;
let notificationsCache = [];
let isNotificationsDropdownOpen = false;

/* =========================================================
   03. VIEW META
   ========================================================= */

const pageMeta = {
  home: { title: "Home" },
  maintenance: { title: "Maintenance" },
  documents: { title: "Documents" },
  announcements: { title: "Announcements" },
  profile: { title: "Profile" }
};

/* =========================================================
   04. BASIC HELPERS / FORMATTERS
   ========================================================= */

function $(id) {
  return document.getElementById(id);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function safeText(value, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
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
  const raw = String(name || "").trim();
  if (!raw) return "TP";
  const parts = raw.split(/\s+/).slice(0, 2);
  return parts.map((p) => p[0]?.toUpperCase() || "").join("") || "TP";
}

function isMobileViewport() {
  return window.matchMedia("(max-width: 1024px)").matches;
}

function getMockNotifications() {
  return [
    {
      id: "notif-1",
      title: "New message on Sink Repair",
      message: "The property team replied to your maintenance request.",
      type: "Maintenance Message",
      isRead: false,
      createdDate: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
      actionType: "maintenance",
      relatedRecordId: maintenanceItemsCache?.[0]?.id || maintenanceItemsCache?.[0]?.maintenanceId || null
    },
    {
      id: "notif-2",
      title: "New announcement posted",
      message: "A property update has been added for your building.",
      type: "Announcement",
      isRead: false,
      createdDate: new Date(Date.now() - 1000 * 60 * 60 * 3).toISOString(),
      actionType: "announcements"
    },
    {
      id: "notif-3",
      title: "Document available",
      message: "A new tenancy document is available in your portal.",
      type: "Document",
      isRead: true,
      createdDate: new Date(Date.now() - 1000 * 60 * 60 * 7).toISOString(),
      actionType: "documents"
    },
    {
      id: "notif-4",
      title: "Maintenance status updated",
      message: "Your repair request moved to In Progress.",
      type: "Maintenance Update",
      isRead: true,
      createdDate: new Date(Date.now() - 1000 * 60 * 60 * 26).toISOString(),
      actionType: "maintenance",
      relatedRecordId: maintenanceItemsCache?.[0]?.id || maintenanceItemsCache?.[0]?.maintenanceId || null
    },
    {
      id: "notif-5",
      title: "Reminder from property team",
      message: "Please upload an additional photo if possible.",
      type: "Maintenance Message",
      isRead: false,
      createdDate: new Date(Date.now() - 1000 * 60 * 60 * 30).toISOString(),
      actionType: "maintenance",
      relatedRecordId: maintenanceItemsCache?.[0]?.id || maintenanceItemsCache?.[0]?.maintenanceId || null
    },
    {
      id: "notif-6",
      title: "Older document update",
      message: "A historic tenancy file is available in Documents.",
      type: "Document",
      isRead: true,
      createdDate: new Date(Date.now() - 1000 * 60 * 60 * 50).toISOString(),
      actionType: "documents"
    }
  ];
}

function getUnreadNotificationsCount() {
  return notificationsCache.filter((item) => !item.isRead).length;
}

function getRecentNotifications(limit = 5) {
  return [...notificationsCache]
    .sort((a, b) => new Date(b.createdDate).getTime() - new Date(a.createdDate).getTime())
    .slice(0, limit);
}

function notificationTypeBadgeClass(type) {
  const key = String(type || "").trim().toLowerCase();

  if (key.includes("message")) return "badge badge--in-progress";
  if (key.includes("maintenance")) return "badge badge--open";
  if (key.includes("announcement")) return "badge badge--high";
  if (key.includes("document")) return "badge badge--default";

  return "badge badge--default";
}


/* =========================================================
   05. LOCAL STORAGE
   ========================================================= */

function getSavedView() {
  return localStorage.getItem(LAST_VIEW_KEY) || "home";
}

function saveView(viewName) {
  localStorage.setItem(LAST_VIEW_KEY, viewName);
}

/* =========================================================
   06. GLOBAL UI FEEDBACK
   ========================================================= */

function setStatus(state, text) {
  const dot = $("globalStatusDot");
  const label = $("globalStatusText");
  if (!dot || !label) return;

  label.textContent = text || "Connected";

  const colorMap = {
    ok: "var(--success)",
    loading: "var(--warning)",
    error: "var(--danger)"
  };
  dot.style.background = colorMap[state] || "var(--success)";
  dot.style.boxShadow =
    state === "error"
      ? "0 0 0 6px rgba(209, 67, 67, 0.08)"
      : state === "loading"
      ? "0 0 0 6px rgba(183, 121, 31, 0.08)"
      : "0 0 0 6px rgba(15, 159, 110, 0.08)";
}

function showToast(text) {
  const toast = $("toast");
  const toastText = $("toastText");
  if (!toast || !toastText) return;

  toastText.textContent = text;
  toast.classList.remove("hidden");

  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.add("hidden");
  }, 3200);
}

function setFormMessage(elementId, type, text) {
  const el = $(elementId);
  if (!el) return;

  if (!text) {
    el.className = "form-message hidden";
    el.textContent = "";
    return;
  }

  el.className = `form-message form-message--${type}`;
  el.textContent = text;
}

function setProfileMessage(type, text) {
  setFormMessage("profileMessage", type, text);
}

function setMaintenanceMessage(type, text) {
  setFormMessage("maintenanceMsg", type, text);
}

/* =========================================================
   07. SIDEBAR CONTROLS
   ========================================================= */

function applySidebarState() {
  const sidebar = $("sidebar");
  const overlay = $("mobileSidebarOverlay");
  const app = $("app");

  if (!sidebar) return;

  if (isMobileViewport()) {
    sidebar.classList.remove("is-collapsed");
    if (app) app.classList.remove("sidebar-collapsed");
    if (overlay) overlay.classList.remove("is-visible");
    return;
  }

  sidebar.classList.remove("is-open");
  if (overlay) overlay.classList.remove("is-visible");

  sidebar.classList.toggle("is-collapsed", isSidebarCollapsed);
  if (app) {
    app.classList.toggle("sidebar-collapsed", isSidebarCollapsed);
  }
}

function openSidebar() {
  if (!isMobileViewport()) return;

  const sidebar = $("sidebar");
  const overlay = $("mobileSidebarOverlay");
  if (sidebar) sidebar.classList.add("is-open");
  if (overlay) overlay.classList.add("is-visible");
}

function closeSidebar() {
  if (!isMobileViewport()) return;

  const sidebar = $("sidebar");
  const overlay = $("mobileSidebarOverlay");
  if (sidebar) sidebar.classList.remove("is-open");
  if (overlay) overlay.classList.remove("is-visible");
}

function toggleSidebar() {
  const sidebar = $("sidebar");
  if (!sidebar) return;

  if (isMobileViewport()) {
    if (sidebar.classList.contains("is-open")) {
      closeSidebar();
    } else {
      openSidebar();
    }
    return;
  }

  isSidebarCollapsed = !isSidebarCollapsed;
  applySidebarState();
}

function initSidebarControls() {
  const menuBtn = $("sidebarToggle");
  const closeBtn = $("sidebarClose");
  const overlay = $("mobileSidebarOverlay");

  if (menuBtn) menuBtn.addEventListener("click", toggleSidebar);
  if (closeBtn) closeBtn.addEventListener("click", closeSidebar);
  if (overlay) overlay.addEventListener("click", closeSidebar);

  window.addEventListener("resize", applySidebarState);

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && isMobileViewport()) {
      closeSidebar();
    }
  });

  applySidebarState();
}

/* =========================================================
   08. MODAL CONTROLS
   ========================================================= */

function closeAllModals() {
  document.querySelectorAll(".modal").forEach((modal) => {
    modal.classList.add("hidden");
    modal.setAttribute("aria-hidden", "true");
  });

  stopMaintenanceMessagesPolling();
  activeModalId = null;
}

function closeModalById(id) {
  const modal = $(id);
  if (!modal) return;

  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");

  if (id === "maintenanceDetailModal") {
    stopMaintenanceMessagesPolling();
  }

  if (activeModalId === id) activeModalId = null;
}

function openModal(id) {
  const modal = $(id);
  if (!modal) return;
  closeAllModals();
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
  activeModalId = id;
}

function openMaintenanceModal() {
  $("maintenanceForm").reset();
  $("photoSelectionList").innerHTML = "";
  $("photoSelectionMeta").textContent =
    "You can upload up to 5 images, maximum 2MB each.";
  setMaintenanceMessage("", "");
  openModal("maintenanceModal");
  setTimeout(() => $("subject")?.focus(), 50);
}

function openLogoutModal() {
  openModal("logoutModal");
}

function initModalControls() {
  document.querySelectorAll("[data-close-modal]").forEach((btn) => {
    btn.addEventListener("click", () => {
      closeModalById(btn.dataset.closeModal);
    });
  });
}

/* =========================================================
   09. STATUS / BADGE / ANNOUNCEMENT HELPERS
   ========================================================= */

function normaliseStatusClass(status) {
  const key = String(status || "").trim().toLowerCase();
  if (key === "open") return "badge--open";
  if (key === "in progress") return "badge--in-progress";
  if (key === "waiting for contractor") return "badge--waiting-for-contractor";
  if (key === "completed") return "badge--completed";
  if (key === "closed") return "badge--completed";
  if (key === "scheduled") return "badge--in-progress";
  if (key === "under review") return "badge--default";
  if (key === "cancelled") return "badge--default";
  return "badge--default";
}

function announcementItemClass(priority) {
  const value = String(priority || "").trim().toLowerCase();
  if (value === "urgent") return "list-item--announcement-urgent";
  if (value === "high") return "list-item--announcement-high";
  return "";
}

function announcementBadgeClass(priority) {
  const value = String(priority || "").trim().toLowerCase();
  if (value === "urgent") return "badge badge--urgent";
  if (value === "high") return "badge badge--high";
  return "badge badge--default";
}

/* =========================================================
   10. SKELETONS / EMPTY STATES
   ========================================================= */

function renderSkeletonList(targetId, count = 3) {
  const target = $(targetId);
  if (!target) return;

  target.innerHTML = Array.from({ length: count })
    .map(
      () => `
        <div class="skeleton-card">
          <div class="skeleton-line skeleton-line--lg"></div>
          <div class="skeleton-line skeleton-line--md"></div>
          <div class="skeleton-line skeleton-line--sm"></div>
        </div>
      `
    )
    .join("");
}

function renderEmptyState({
  title,
  text,
  actionText,
  actionType,
  targetId,
  icon = ""
}) {
  const target = $(targetId);
  if (!target) return;

  const actionHtml = actionText
    ? `
      <div class="empty-state__actions">
        <button class="btn btn--primary" data-empty-action="${escapeHtml(actionType || "")}" type="button">
          ${escapeHtml(actionText)}
        </button>
      </div>
    `
    : "";

  const iconHtml = icon
    ? `<div class="empty-state__icon">${escapeHtml(icon)}</div>`
    : "";

  target.innerHTML = `
    <div class="empty-state">
      ${iconHtml}
      <p class="empty-state__title">${escapeHtml(title)}</p>
      <p class="empty-state__text">${escapeHtml(text)}</p>
      ${actionHtml}
    </div>
  `;
}

/* =========================================================
   11. VIEW / PAGE STATE
   ========================================================= */

function updateTopbarMeta(viewName) {
  const meta = pageMeta[viewName] || pageMeta.home;
  if ($("pageTitle")) $("pageTitle").textContent = meta.title;
}

function setActiveView(viewName, options = {}) {
  const resolvedView = pageMeta[viewName] ? viewName : "home";

  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("is-active", view.id === `view-${resolvedView}`);
  });

  document.querySelectorAll(".nav__item").forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.view === resolvedView);
  });

  updateTopbarMeta(resolvedView);
  saveView(resolvedView);

  if (isMobileViewport()) {
    closeSidebar();
  }

  if (!options.skipScroll) {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
}

async function openViewAndLoad(viewName) {
  setActiveView(viewName);

  if (viewName === "maintenance") {
    renderSkeletonList("maintenanceList", 4);
    await loadMaintenance(true);
  } else if (viewName === "documents") {
    renderSkeletonList("documentsList", 4);
    await loadDocuments(true);
  } else if (viewName === "announcements") {
    renderSkeletonList("announcementsList", 3);
    await loadAnnouncementsAndRender(true);
  } else if (viewName === "profile") {
    hydrateProfileForm();
  } else if (viewName === "home") {
    updateDashboardMetrics();
  }
}

/* =========================================================
   12. TENANT / PROFILE SHELL HYDRATION
   ========================================================= */

function applyTenantProfileToShell(data) {
  const ctx = data || {};
  portalContext = ctx;

  const tenantName =
    ctx?.tenant?.name ||
    ctx?.tenantName ||
    ctx?.name ||
    "Tenant";

  const email =
    ctx?.tenant?.email ||
    ctx?.email ||
    ctx?.personEmail ||
    "—";

  const phone =
    ctx?.tenant?.phone ||
    ctx?.phone ||
    ctx?.personMobilePhone ||
    "—";

  const property =
    ctx?.unit?.propertyName ||
    ctx?.propertyName ||
    ctx?.property ||
    "—";

  const unit =
    ctx?.unit?.name ||
    ctx?.unitName ||
    ctx?.unit ||
    "—";

  const lease =
    ctx?.lease?.name ||
    ctx?.leaseName ||
    ctx?.lease ||
    "—";

  const initials = getInitials(tenantName);
  const tenantSub = unit !== "—" ? unit : property !== "—" ? property : email;

  if ($("sidebarTenantName")) $("sidebarTenantName").textContent = tenantName;
  if ($("sidebarTenantSub")) $("sidebarTenantSub").textContent = tenantSub;
  if ($("sidebarInitials")) $("sidebarInitials").textContent = initials;

  if ($("topbarTenantName")) $("topbarTenantName").textContent = tenantName;
  if ($("topbarInitials")) $("topbarInitials").textContent = initials;

  if ($("detailTenantName")) $("detailTenantName").textContent = tenantName;
  if ($("detailTenantEmail")) $("detailTenantEmail").textContent = email;
  if ($("detailTenantPhone")) $("detailTenantPhone").textContent = phone;
  if ($("detailProperty")) $("detailProperty").textContent = property;
  if ($("detailUnit")) $("detailUnit").textContent = unit;
  if ($("detailLease")) $("detailLease").textContent = lease;
}

function hydrateProfileForm() {
  const email =
    portalContext?.tenant?.email ||
    portalContext?.email ||
    portalContext?.personEmail ||
    "";

  const phone =
    portalContext?.tenant?.phone ||
    portalContext?.phone ||
    portalContext?.personMobilePhone ||
    "";

  if ($("profileEmail")) $("profileEmail").value = email;
  if ($("profilePhone")) $("profilePhone").value = phone;
}

/* =========================================================
   13. DASHBOARD / HOME RENDERING
   ========================================================= */

function updateDashboardMetrics() {
  const openItems = maintenanceItemsCache.filter((item) => {
    const status = String(item.status || "").toLowerCase();
    return !["completed", "closed", "cancelled"].includes(status);
  });

  const tenancyStatus =
    portalContext?.tenancy?.status ||
    portalContext?.status ||
    "—";

  const leaseEnd =
    portalContext?.lease?.endDate ||
    portalContext?.tenancy?.endDate ||
    portalContext?.leaseEndDate ||
    null;

  $("metricOpenRequests").textContent = String(openItems.length);
  $("metricOpenRequestsMeta").textContent =
    openItems.length === 0
      ? "No open maintenance requests at the moment"
      : openItems.length === 1
      ? "1 request currently needs attention"
      : `${openItems.length} requests currently need attention`;

  $("metricDocuments").textContent = String(documentsCache.length);
  $("metricTenancyStatus").textContent = safeText(tenancyStatus);
  $("metricTenancyStatusMeta").textContent =
    tenancyStatus && tenancyStatus !== "—"
      ? "Status taken from your tenancy record"
      : "No tenancy status was provided";

  $("metricLeaseEnd").textContent = leaseEnd ? formatDate(leaseEnd) : "—";

  if (leaseEnd) {
    const diffDays = Math.ceil(
      (new Date(leaseEnd).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
    );

    if (Number.isFinite(diffDays)) {
      if (diffDays < 0) {
        $("metricLeaseEndMeta").textContent = "Your recorded lease end date has passed";
      } else if (diffDays === 0) {
        $("metricLeaseEndMeta").textContent = "Lease ends today";
      } else if (diffDays === 1) {
        $("metricLeaseEndMeta").textContent = "1 day remaining on the current lease";
      } else {
        $("metricLeaseEndMeta").textContent = `${diffDays} days remaining on the current lease`;
      }
    } else {
      $("metricLeaseEndMeta").textContent = "Remaining time unavailable";
    }
  } else {
    $("metricLeaseEndMeta").textContent = "No lease end date is currently available";
  }

  renderHomeCallout();
  renderMaintenanceItems(maintenanceItemsCache.slice(0, 3), "recentMaintenanceList", {
    emptyTitle: "No maintenance requests yet",
    emptyText:
      "If something in your home needs attention, create a request and we will help you from there.",
    emptyActionText: "Create request",
    emptyActionType: "new-maintenance",
    showViewButton: false
  });

  renderAnnouncements(announcementsCache.slice(0, 3), "homeAnnouncements", {
    emptyTitle: "No announcements right now",
    emptyText:
      "Property updates and notices will appear here when they are available.",
    showFullMessage: false
  });
}

function renderHomeCallout() {
  const target = $("homeCallout");
  if (!target) return;

  const urgentAnnouncement = announcementsCache.find((item) => {
    const priority = String(item.priority || "").toLowerCase();
    return priority === "urgent" || priority === "high";
  });

  const openMaintenance = maintenanceItemsCache.filter((item) => {
    const status = String(item.status || "").toLowerCase();
    return !["completed", "closed", "cancelled"].includes(status);
  });

  const missingProfile =
    !String(portalContext?.tenant?.email || "").trim() ||
    !String(portalContext?.tenant?.phone || "").trim();

  if (urgentAnnouncement) {
    target.innerHTML = `
      <div class="callout-card callout-card--priority">
        <div>
          <p class="eyebrow eyebrow--tight">Priority update</p>
          <h2 class="callout-card__title">${escapeHtml(
            urgentAnnouncement.title || "Important announcement"
          )}</h2>
          <p class="callout-card__text">${escapeHtml(
            urgentAnnouncement.message || "A new announcement needs your attention."
          )}</p>
        </div>
        <div class="callout-card__actions">
          <button class="btn btn--primary" data-open-view="announcements" type="button">
            Review announcements
          </button>
        </div>
      </div>
    `;
    return;
  }

  if (openMaintenance.length > 0) {
    target.innerHTML = `
      <div class="callout-card">
        <div>
          <p class="eyebrow eyebrow--tight">Open maintenance</p>
          <h2 class="callout-card__title">
            ${openMaintenance.length} ${
      openMaintenance.length === 1 ? "request requires" : "requests require"
    } attention
          </h2>
          <p class="callout-card__text">
            Review your current maintenance items or submit another request if a new issue has come up.
          </p>
        </div>
        <div class="callout-card__actions">
          <button class="btn btn--ghost" data-open-view="maintenance" type="button">
            View requests
          </button>
          <button class="btn btn--primary" data-action="new-maintenance" type="button">
            New request
          </button>
        </div>
      </div>
    `;
    return;
  }

  if (missingProfile) {
    target.innerHTML = `
      <div class="callout-card">
        <div>
          <p class="eyebrow eyebrow--tight">Profile update</p>
          <h2 class="callout-card__title">Complete your contact details</h2>
          <p class="callout-card__text">
            Add your current email and phone number so property updates can reach you more easily.
          </p>
        </div>
        <div class="callout-card__actions">
          <button class="btn btn--primary" data-open-view="profile" type="button">
            Update profile
          </button>
        </div>
      </div>
    `;
    return;
  }

  target.innerHTML = `
    <div class="callout-card">
      <div>
        <p class="eyebrow eyebrow--tight">Welcome</p>
        <h2 class="callout-card__title">Everything for your tenancy is now in one place</h2>
        <p class="callout-card__text">
          Use the portal to submit maintenance requests, review documents, and stay up to date with property announcements.
        </p>
      </div>
      <div class="callout-card__actions">
        <button class="btn btn--primary" data-action="new-maintenance" type="button">
          Create request
        </button>
      </div>
    </div>
  `;
}


/* =========================================================
   13B. Notifcation DropDown Functions
   ========================================================= */

function updateNotificationsBell() {
  const count = getUnreadNotificationsCount();
  const el = $("notificationsBellCount");
  if (!el) return;

  if (count > 0) {
    el.textContent = count > 99 ? "99+" : String(count);
    el.classList.remove("hidden");
  } else {
    el.textContent = "0";
    el.classList.add("hidden");
  }
}

function renderNotificationsDropdown() {
  const target = $("notificationsDropdownList");
  if (!target) return;

  const items = getRecentNotifications(5);

  if (!items.length) {
    target.innerHTML = `
      <div class="notifications-dropdown__empty">
        No notifications yet.
      </div>
    `;
    updateNotificationsBell();
    return;
  }

  target.innerHTML = items
    .map((item) => {
      const unreadClass = item.isRead ? "" : "notifications-dropdown__item--unread";

      return `
        <button
          class="notifications-dropdown__item ${unreadClass}"
          type="button"
          data-notification-id="${escapeHtml(item.id)}"
        >
          <div class="notifications-dropdown__item-top">
            <span class="notifications-dropdown__item-title">${escapeHtml(item.title || "Notification")}</span>
            ${!item.isRead ? `<span class="notifications-dropdown__item-dot" aria-hidden="true"></span>` : ""}
          </div>

          <p class="notifications-dropdown__item-text">${escapeHtml(item.message || "No details available.")}</p>

          <div class="notifications-dropdown__item-meta">
            <span class="${notificationTypeBadgeClass(item.type)}">${escapeHtml(item.type || "Update")}</span>
            <span>${escapeHtml(safeDateTime(item.createdDate))}</span>
          </div>
        </button>
      `;
    })
    .join("");

  updateNotificationsBell();
}

function openNotificationsDropdown() {
  const dropdown = $("notificationsDropdown");
  const trigger = $("notificationsBell");
  if (!dropdown || !trigger) return;

  renderNotificationsDropdown();
  dropdown.classList.remove("hidden");
  dropdown.setAttribute("aria-hidden", "false");
  trigger.setAttribute("aria-expanded", "true");
  isNotificationsDropdownOpen = true;
}

function closeNotificationsDropdown() {
  const dropdown = $("notificationsDropdown");
  const trigger = $("notificationsBell");
  if (!dropdown || !trigger) return;

  dropdown.classList.add("hidden");
  dropdown.setAttribute("aria-hidden", "true");
  trigger.setAttribute("aria-expanded", "false");
  isNotificationsDropdownOpen = false;
}

function toggleNotificationsDropdown() {
  if (isNotificationsDropdownOpen) {
    closeNotificationsDropdown();
  } else {
    openNotificationsDropdown();
  }
}

function markNotificationAsRead(notificationId) {
  notificationsCache = notificationsCache.map((item) =>
    item.id === notificationId ? { ...item, isRead: true } : item
  );

  renderNotificationsDropdown();
}

function markAllNotificationsAsRead() {
  notificationsCache = notificationsCache.map((item) => ({
    ...item,
    isRead: true
  }));

  renderNotificationsDropdown();
  showToast("All notifications marked as read.");
}

async function handleNotificationClick(notificationId) {
  const notification = notificationsCache.find((item) => item.id === notificationId);
  if (!notification) return;

  markNotificationAsRead(notificationId);
  closeNotificationsDropdown();

  if (notification.actionType === "maintenance" && notification.relatedRecordId) {
    const item = maintenanceItemsCache.find((m) => {
      return String(m.id || m.maintenanceId) === String(notification.relatedRecordId);
    });

    if (item) {
      await openMaintenanceDetail(item);
      return;
    }

    await openViewAndLoad("maintenance");
    return;
  }

  if (notification.actionType === "announcements") {
    await openViewAndLoad("announcements");
    return;
  }

  if (notification.actionType === "documents") {
    await openViewAndLoad("documents");
    return;
  }
}

async function loadNotifications(skipStatusMessage = false) {
  if (!skipStatusMessage) setStatus("loading", "Loading notifications");

  notificationsCache = getMockNotifications();
  updateNotificationsBell();

  if (!skipStatusMessage) setStatus("ok", "Connected");
}

function initNotificationsDropdown() {
  $("notificationsBell")?.addEventListener("click", (event) => {
    event.stopPropagation();
    toggleNotificationsDropdown();
  });

  $("notificationsDropdown")?.addEventListener("click", (event) => {
    event.stopPropagation();
  });

  $("markAllNotificationsReadBtn")?.addEventListener("click", (event) => {
    event.stopPropagation();
    markAllNotificationsAsRead();
  });

  document.addEventListener("click", () => {
    if (isNotificationsDropdownOpen) {
      closeNotificationsDropdown();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && isNotificationsDropdownOpen) {
      closeNotificationsDropdown();
    }
  });
}

/* =========================================================
   14. MAINTENANCE LIST RENDERING / FILTERING
   ========================================================= */

function renderMaintenanceItems(items, targetId, options = {}) {
  const target = $(targetId);
  if (!target) return;

  const {
    emptyTitle = "No maintenance requests yet",
    emptyText = "Create a request whenever something in your property needs attention.",
    emptyActionText = "Create request",
    emptyActionType = "new-maintenance",
    showViewButton = true
  } = options;

  if (!items || items.length === 0) {
    renderEmptyState({
      targetId,
      title: emptyTitle,
      text: emptyText,
      actionText: emptyActionText,
      actionType: emptyActionType,
      icon: "🛠"
    });
    return;
  }

  target.innerHTML = items
    .map((item, index) => {
      const statusClass = normaliseStatusClass(item.status);
      const footerText =
        item.portalUpdate ||
        item.description ||
        "No additional update has been posted yet.";
      const uniqueId = escapeHtml(item.id || item.maintenanceId || `maintenance-${index}`);

      return `
        <article class="list-item list-item--clickable" tabindex="0" data-maintenance-id="${uniqueId}">
          <div class="list-item__top">
            <div>
              <h3 class="list-item__title">${escapeHtml(item.subject || "Maintenance request")}</h3>
              <p class="list-item__meta">Submitted ${escapeHtml(
                safeDateTime(item.createdDate)
              )}</p>
            </div>
            <div class="list-item__actions">
              <span class="badge ${statusClass}">${escapeHtml(item.status || "Unknown")}</span>
              ${
                showViewButton
                  ? `<button class="btn btn--ghost btn--sm" type="button" data-maintenance-open="${uniqueId}">View details</button>`
                  : ""
              }
            </div>
          </div>
          <p class="list-item__text">${escapeHtml(footerText)}</p>
        </article>
      `;
    })
    .join("");
}

function renderFilteredMaintenance() {
  const filtered =
    maintenanceFilter === "all"
      ? maintenanceItemsCache
      : maintenanceItemsCache.filter((item) => {
          return String(item.status || "").trim().toLowerCase() === maintenanceFilter;
        });

  renderMaintenanceItems(filtered, "maintenanceList", {
    emptyTitle: "No requests in this filter",
    emptyText: "There are no maintenance items matching the selected status.",
    emptyActionText: "Create request",
    emptyActionType: "new-maintenance"
  });
}

/* =========================================================
   15. ANNOUNCEMENTS RENDERING
   ========================================================= */

function renderAnnouncements(items, targetId, options = {}) {
  const target = $(targetId);
  if (!target) return;

  const {
    emptyTitle = "No announcements right now",
    emptyText = "Property updates and notices will appear here when they are available.",
    showFullMessage = true
  } = options;

  if (!items || items.length === 0) {
    renderEmptyState({
      targetId,
      title: emptyTitle,
      text: emptyText,
      icon: "📢"
    });
    return;
  }

  target.innerHTML = items
    .map((item) => {
      const itemClass = announcementItemClass(item.priority);
      const badgeClass = announcementBadgeClass(item.priority);
      const body = item.message || "No announcement message was provided.";
      const clipped =
        showFullMessage || body.length <= 180 ? body : `${body.slice(0, 177)}...`;

      return `
        <article class="list-item ${itemClass}">
          <div class="list-item__top">
            <div>
              <h3 class="list-item__title">${escapeHtml(item.title || "Announcement")}</h3>
              <p class="list-item__meta">${escapeHtml(
                item.category || item.scope || "Property update"
              )} • ${escapeHtml(safeDateTime(item.startDateTime || item.createdDate))}</p>
            </div>
            <div class="list-item__actions">
              <span class="${badgeClass}">${escapeHtml(item.priority || "Standard")}</span>
            </div>
          </div>
          <p class="list-item__text">${escapeHtml(clipped)}</p>
        </article>
      `;
    })
    .join("");
}

/* =========================================================
   16. DOCUMENTS GROUPING / RENDERING / DOWNLOAD
   ========================================================= */

function groupDocuments(items) {
  const groups = {
    "Lease Documents": [],
    "Property Documents": [],
    "Safety Certificates": [],
    "Instructions": [],
    Other: []
  };

  items.forEach((doc) => {
    const rawCategory = String(doc.category || doc.type || "").toLowerCase();

    if (rawCategory.includes("lease") || rawCategory.includes("inventory")) {
      groups["Lease Documents"].push(doc);
    } else if (
      rawCategory.includes("safety") ||
      rawCategory.includes("gas") ||
      rawCategory.includes("electrical")
    ) {
      groups["Safety Certificates"].push(doc);
    } else if (
      rawCategory.includes("instruction") ||
      rawCategory.includes("guide") ||
      rawCategory.includes("manual")
    ) {
      groups["Instructions"].push(doc);
    } else if (rawCategory.includes("property") || rawCategory.includes("unit")) {
      groups["Property Documents"].push(doc);
    } else {
      groups.Other.push(doc);
    }
  });

  return groups;
}

function renderDocuments(items) {
  const target = $("documentsList");
  if (!target) return;

  if (!items || items.length === 0) {
    renderEmptyState({
      targetId: "documentsList",
      title: "No documents available yet",
      text: "There are no documents available for your tenancy at the moment.",
      icon: "📄"
    });
    return;
  }

  const grouped = groupDocuments(items);
  const sections = Object.entries(grouped)
    .filter(([, docs]) => docs.length > 0)
    .map(([groupName, docs]) => {
      const docsHtml = docs
        .map((doc) => {
          const id = escapeHtml(doc.contentDocumentId || doc.id || "");
          return `
            <article class="list-item">
              <div class="list-item__top">
                <div>
                  <h3 class="list-item__title">${escapeHtml(doc.title || doc.name || "Document")}</h3>
                  <p class="list-item__meta">${escapeHtml(
                    safeText(doc.fileType || doc.type || "File")
                  )} • ${escapeHtml(formatDate(doc.createdDate || doc.lastModifiedDate))}</p>
                </div>
                <div class="list-item__actions">
                  <button class="btn btn--ghost btn--sm" data-doc-download="${id}" type="button">
                    Download
                  </button>
                </div>
              </div>
            </article>
          `;
        })
        .join("");

      return `
        <section class="document-group">
          <div class="section-header">
            <div>
              <p class="eyebrow eyebrow--tight">Category</p>
              <h3 class="section-title">${escapeHtml(groupName)}</h3>
            </div>
          </div>
          <div class="list-stack">${docsHtml}</div>
        </section>
      `;
    })
    .join("");

  target.innerHTML = sections;
}

async function downloadDocument(doc) {
  const contentDocumentId = doc.contentDocumentId || doc.id;
  if (!contentDocumentId) {
    throw new Error("Document ID was not available for download.");
  }

  setStatus("loading", "Preparing download");
  const url = `/api/docs/download?id=${encodeURIComponent(contentDocumentId)}`;
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${await getAccessToken()}`
    }
  });

  if (!response.ok) {
    throw new Error(`Download failed with status ${response.status}`);
  }

  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = objectUrl;
  a.download = doc.title || doc.name || "document";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(objectUrl);
  setStatus("ok", "Connected");
  showToast("Document download started.");
}

/* =========================================================
   17. GENERIC TIMELINE RENDERING
   ========================================================= */

function renderMaintenanceTimeline(items) {
  const target = $("maintenanceDetailTimeline");
  if (!target) return;

  if (!items || items.length === 0) {
    target.innerHTML = `
      <div class="timeline-empty">
        <p>No tracking history is available for this request yet.</p>
      </div>
    `;
    return;
  }

  target.innerHTML = items
    .map((item) => {
      const type = safeText(item.type || item.updateType, "Update");
      const message = safeText(item.message, "No update message was provided.");
      const createdByName = safeText(item.createdByName, "Portal");
      const createdByType = safeText(item.createdByType, "");
      const statusSnapshot = safeText(item.statusSnapshot, "");
      const eventDate = safeDateTime(item.eventDateTime || item.createdDate);

      const subParts = [createdByName];
      if (createdByType && createdByType !== "—") subParts.push(createdByType);
      if (statusSnapshot && statusSnapshot !== "—") subParts.push(`Status: ${statusSnapshot}`);

      return `
        <article class="timeline-item">
          <div class="timeline-item__top">
            <p class="timeline-item__title">${escapeHtml(type)}</p>
            <p class="timeline-item__meta">${escapeHtml(eventDate)}</p>
          </div>
          <p class="timeline-item__body">${escapeHtml(message)}</p>
          <p class="timeline-item__sub">${escapeHtml(subParts.join(" • "))}</p>
        </article>
      `;
    })
    .join("");
}

/* =========================================================
   18. MAINTENANCE MESSAGES / CHAT RENDERING
   ========================================================= */

function safeMessageAuthor(item) {
  const senderType = String(item?.senderType || "").trim().toLowerCase();
  const isTenant = senderType === "tenant" || item?.isFromPortal === true;
  return isTenant ? "You" : "Property Team";
}

function renderMaintenanceMessages(items, options = {}) {
  const target = $("maintenanceMessagesList");
  if (!target) return;

  const {
    forceScroll = false,
    preserveIfReadingOlder = true
  } = options;

  const shouldStickToBottom =
    forceScroll || !preserveIfReadingOlder || isNearBottom(target);

  if (!items || items.length === 0) {
    target.innerHTML = `
      <div class="chat-empty">
        No messages yet.<br>
        Start the conversation with the property team.
      </div>
    `;

    if (shouldStickToBottom) {
      target.scrollTop = target.scrollHeight;
    }
    return;
  }

  target.innerHTML = items
    .map((item) => {
      const senderType = String(item?.senderType || "").trim().toLowerCase();
      const isTenant =
        senderType === "tenant" ||
        item?.isFromPortal === true;

      const isPending = item?.isPending === true;

      return `
        <article class="chat-message ${isTenant ? "chat-message--tenant" : "chat-message--staff"} ${isPending ? "chat-message--pending" : ""}">
          <div class="chat-message__meta">
            <span class="chat-message__author">${escapeHtml(safeMessageAuthor(item))}</span>
            <span>${escapeHtml(isPending ? "Sending..." : safeDateTime(item?.createdDate))}</span>
          </div>
          <p class="chat-message__body">${escapeHtml(safeText(item?.message, ""))}</p>
        </article>
      `;
    })
    .join("");

  if (shouldStickToBottom) {
    target.scrollTop = target.scrollHeight;
  }
}
/* =========================================================
   18B. MESSAGING HELPERS (PHASE 2)
   ========================================================= */

function getMaintenanceMessagesListEl() {
  return $("maintenanceMessagesList");
}

function isNearBottom(el, threshold = 72) {
  if (!el) return true;
  return el.scrollHeight - el.scrollTop - el.clientHeight <= threshold;
}

function stopMaintenanceMessagesPolling() {
  if (maintenanceMessagesPollTimer) {
    clearInterval(maintenanceMessagesPollTimer);
    maintenanceMessagesPollTimer = null;
  }
}

function isMaintenanceDetailModalOpen() {
  const modal = $("maintenanceDetailModal");
  return !!modal && !modal.classList.contains("hidden");
}

async function refreshMaintenanceMessages(options = {}) {
  const id = activeMaintenanceItem?.id || activeMaintenanceItem?.maintenanceId;
  if (!id) return;

  try {
    const latest = await loadMaintenanceMessages(id);
    maintenanceMessagesCache[id] = latest || [];
    renderMaintenanceMessages(maintenanceMessagesCache[id], options);
  } catch (error) {
    console.error("Failed to refresh messages", error);
  }
}

function startMaintenanceMessagesPolling() {
  stopMaintenanceMessagesPolling();

  maintenanceMessagesPollTimer = setInterval(async () => {
    if (!isMaintenanceDetailModalOpen()) {
      stopMaintenanceMessagesPolling();
      return;
    }

    if (isSendingMaintenanceMessage) return;

    await refreshMaintenanceMessages({
      forceScroll: false,
      preserveIfReadingOlder: true
    });
  }, 12000);
}

/* =========================================================
   19. AUTH0 CLIENT / AUTH FLOW
   ========================================================= */

function requireAuth0Client() {
  if (!window.auth0) {
    throw new Error("Auth0 library is not available.");
  }
  if (!auth0Client) {
    auth0Client = new window.auth0.Auth0Client({
      domain: AUTH0_DOMAIN,
      clientId: AUTH0_CLIENT_ID,
      authorizationParams: {
        audience: AUTH0_AUDIENCE,
        redirect_uri: window.location.origin
      },
      cacheLocation: "memory",
      useRefreshTokens: false
    });
  }
  return auth0Client;
}

async function handleAuthRedirectIfPresent() {
  const client = requireAuth0Client();
  const query = window.location.search;
  if (query.includes("code=") && query.includes("state=")) {
    await client.handleRedirectCallback();
    window.history.replaceState({}, document.title, window.location.pathname);
  }
}

async function login() {
  const client = requireAuth0Client();
  await client.loginWithRedirect({
    authorizationParams: {
      audience: AUTH0_AUDIENCE,
      redirect_uri: window.location.origin
    }
  });
}

async function logout() {
  const client = requireAuth0Client();
  closeAllModals();
  await client.logout({
    logoutParams: {
      returnTo: window.location.origin
    }
  });
}

async function isAuthenticated() {
  const client = requireAuth0Client();
  return client.isAuthenticated();
}

async function getAccessToken() {
  const client = requireAuth0Client();
  return client.getTokenSilently({
    authorizationParams: { audience: AUTH0_AUDIENCE }
  });
}

/* =========================================================
   20. GENERIC API HELPER
   ========================================================= */

async function api(path, opts = {}) {
  const token = await getAccessToken();
  const headers = new Headers(opts.headers || {});
  headers.set("Authorization", `Bearer ${token}`);

  if (!(opts.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, {
    ...opts,
    headers
  });

  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const payload = await response.json();
      message = payload?.message || payload?.error || message;
    } catch {
      const text = await response.text();
      if (text) message = text;
    }
    throw new Error(message);
  }

  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response.blob();
}

/* =========================================================
   21. PORTAL DATA LOADERS
   ========================================================= */

async function loadMe() {
  setStatus("loading", "Loading tenancy");

  const data = await api("/api/me");
  const context = data?.sf || {};

  applyTenantProfileToShell(context);
  hydrateProfileForm();

  setStatus("ok", "Connected");
}

async function loadMaintenance(skipStatusMessage = false) {
  if (!skipStatusMessage) setStatus("loading", "Loading maintenance");
  const data = await api("/api/maintenance");
  maintenanceItemsCache = Array.isArray(data) ? data : data?.items || [];
  renderFilteredMaintenance();
  if (!skipStatusMessage) setStatus("ok", "Connected");
  updateDashboardMetrics();
}

async function loadDocuments(skipStatusMessage = false) {
  if (!skipStatusMessage) setStatus("loading", "Loading documents");
  const data = await api("/api/docs");
  documentsCache = Array.isArray(data) ? data : data?.items || [];
  renderDocuments(documentsCache);
  if (!skipStatusMessage) setStatus("ok", "Connected");
  updateDashboardMetrics();
}

async function loadAnnouncementsAndRender(skipStatusMessage = false) {
  if (!skipStatusMessage) setStatus("loading", "Loading announcements");
  const data = await api("/api/announcements");
  announcementsCache = Array.isArray(data) ? data : data?.items || [];
  renderAnnouncements(announcementsCache, "announcementsList");
  if (!skipStatusMessage) setStatus("ok", "Connected");
  updateDashboardMetrics();
}

/* =========================================================
   22. MAINTENANCE DETAIL / MESSAGE API CALLS
   ========================================================= */

async function loadMaintenanceDetail(id) {
  if (!id) {
    throw new Error("Maintenance ID is required.");
  }

  const token = await getAccessToken();

  const response = await fetch(
    `/api/maintenance-detail?id=${encodeURIComponent(id)}`,
    {
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  );

  const rawText = await response.text();
  console.log("maintenance detail status", response.status);
  console.log("maintenance detail raw", rawText);

  let data = null;
  try {
    data = rawText ? JSON.parse(rawText) : null;
  } catch (error) {
    throw new Error(`Maintenance detail returned non-JSON: ${rawText.slice(0, 200)}`);
  }

  console.log("maintenance detail parsed", data);

  if (!response.ok) {
    throw new Error(data?.message || `Maintenance detail request failed with status ${response.status}`);
  }

  if (data?.item) return data.item;
  if (data?.id) return data;

  throw new Error(
    `Unexpected maintenance detail response: ${JSON.stringify(data).slice(0, 300)}`
  );
}

async function loadMaintenanceMessages(maintenanceId) {
  if (!maintenanceId) {
    throw new Error("Maintenance ID is required.");
  }

  const token = await getAccessToken();

  const response = await fetch(
    `/api/messages?maintenanceId=${encodeURIComponent(maintenanceId)}`,
    {
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  );

  const rawText = await response.text();
  console.log("messages status", response.status);
  console.log("messages raw", rawText);

  let data = null;
  try {
    data = rawText ? JSON.parse(rawText) : null;
  } catch (error) {
    throw new Error(`Messages returned non-JSON: ${rawText.slice(0, 200)}`);
  }

  if (!response.ok) {
    throw new Error(data?.message || `Messages request failed with status ${response.status}`);
  }

  const items = Array.isArray(data?.messages) ? data.messages : [];
  maintenanceMessagesCache[maintenanceId] = items;
  return items;
}

async function sendMaintenanceMessage(maintenanceId, message) {
  if (!maintenanceId) {
    throw new Error("Maintenance ID is required.");
  }

  const payload = {
    maintenanceId,
    message
  };

  const data = await api("/api/messages", {
    method: "POST",
    body: JSON.stringify(payload)
  });

  return data;
}

/* =========================================================
   23. MAINTENANCE DETAIL MODAL FLOW
   ========================================================= */

async function openMaintenanceDetail(item) {
  const id = item?.id || item?.maintenanceId;

  const historyToggle = $("maintenanceHistoryToggle");
  const historyPanel = $("maintenanceHistoryPanel");
   stopMaintenanceMessagesPolling();

  if (historyToggle) {
    historyToggle.setAttribute("aria-expanded", "false");
  }
  if (historyPanel) {
    historyPanel.classList.add("hidden");
  }
  if ($("maintenanceHistoryCount")) {
    $("maintenanceHistoryCount").textContent = "0 updates";
  }
  if ($("maintenanceDetailMeta")) {
    $("maintenanceDetailMeta").textContent = item?.createdDate
      ? `Submitted ${safeDateTime(item.createdDate)}`
      : "—";
  }

  if (!id) {
    showToast("Unable to open this maintenance request.");
    return;
  }

  activeMaintenanceItem = item;

  if ($("maintenanceDetailTitle")) {
    $("maintenanceDetailTitle").textContent = safeText(
      item.referenceNumber
        ? `${item.referenceNumber} · ${item.subject || "Request details"}`
        : item.subject,
      "Request details"
    );
  }

  if ($("maintenanceDetailStatus")) {
    $("maintenanceDetailStatus").innerHTML = `
      <span class="badge ${normaliseStatusClass(item.status)}">${escapeHtml(
        safeText(item.status, "Unknown")
      )}</span>
    `;
  }

  if ($("maintenanceDetailDescription")) {
    $("maintenanceDetailDescription").textContent = safeText(
      item.description,
      "No description was provided."
    );
  }

  renderMaintenanceTimeline([]);
   renderMaintenanceMessages([], { forceScroll: true, preserveIfReadingOlder: false });

  if ($("maintenanceMessageInput")) {
    $("maintenanceMessageInput").value = "";
  }

  openModal("maintenanceDetailModal");
  setStatus("loading", "Loading request details");

  try {
    const [detail, messages] = await Promise.all([
      loadMaintenanceDetail(id),
      maintenanceMessagesCache[id]
        ? Promise.resolve(maintenanceMessagesCache[id])
        : loadMaintenanceMessages(id)
    ]);

    if (!detail || !detail.id) {
      throw new Error("Maintenance detail response was incomplete.");
    }

    activeMaintenanceItem = detail;

    if ($("maintenanceDetailTitle")) {
      $("maintenanceDetailTitle").textContent = safeText(
        detail.referenceNumber
          ? `${detail.referenceNumber} · ${detail.subject || "Request details"}`
          : detail.subject,
        "Request details"
      );
    }

    if ($("maintenanceDetailMeta")) {
      $("maintenanceDetailMeta").textContent = detail.createdDate
        ? `Submitted ${safeDateTime(detail.createdDate)}`
        : "—";
    }

    if ($("maintenanceDetailStatus")) {
      $("maintenanceDetailStatus").innerHTML = `
        <span class="badge ${normaliseStatusClass(detail.status)}">${escapeHtml(
          safeText(detail.status, "Unknown")
        )}</span>
      `;
    }

    if ($("maintenanceDetailDescription")) {
      $("maintenanceDetailDescription").textContent = safeText(
        detail.description,
        "No description was provided."
      );
    }

    if ($("maintenanceHistoryCount")) {
      const updateCount = Array.isArray(detail.timeline) ? detail.timeline.length : 0;
      $("maintenanceHistoryCount").textContent =
        `${updateCount} ${updateCount === 1 ? "update" : "updates"}`;
    }

    renderMaintenanceTimeline(detail.timeline || []);
    maintenanceMessagesCache[id] = messages || [];

renderMaintenanceMessages(maintenanceMessagesCache[id], {
  forceScroll: true,
  preserveIfReadingOlder: false
});

startMaintenanceMessagesPolling();
    setStatus("ok", "Connected");
  } catch (error) {
    console.error(error);
    stopMaintenanceMessagesPolling();
    renderMaintenanceTimeline([]);
    renderMaintenanceMessages([], {
      forceScroll: true,
      preserveIfReadingOlder: false
    });
    setStatus("error", "Service unavailable");
    showToast(error.message || "Unable to load maintenance details.");
  }
}

function initMaintenanceHistoryAccordion() {
  const toggle = $("maintenanceHistoryToggle");
  const panel = $("maintenanceHistoryPanel");

  if (!toggle || !panel) return;

  toggle.addEventListener("click", () => {
    const isExpanded = toggle.getAttribute("aria-expanded") === "true";
    toggle.setAttribute("aria-expanded", String(!isExpanded));
    panel.classList.toggle("hidden", isExpanded);
  });
}

/* =========================================================
   24. FILE HELPERS / FILE UI
   ========================================================= */

function readFileAsBase64Payload(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result || "");
      const base64 = result.includes(",") ? result.split(",")[1] : result;
      resolve({
        fileName: file.name,
        contentType: file.type,
        base64
      });
    };
    reader.onerror = () => reject(new Error(`Failed to read ${file.name}`));
    reader.readAsDataURL(file);
  });
}

function updateSelectedFilesUI() {
  const input = $("photos");
  const list = $("photoSelectionList");
  const meta = $("photoSelectionMeta");
  if (!input || !list || !meta) return;

  const files = Array.from(input.files || []);
  if (files.length === 0) {
    list.innerHTML = "";
    meta.textContent = "You can upload up to 5 images, maximum 2MB each.";
    return;
  }

  list.innerHTML = files
    .map((file) => {
      const sizeKb = Math.round(file.size / 1024);
      return `<span class="file-chip">${escapeHtml(file.name)} • ${sizeKb}KB</span>`;
    })
    .join("");

  meta.textContent = `${files.length} ${files.length === 1 ? "file selected" : "files selected"}`;
}

/* =========================================================
   25. MAINTENANCE FORM
   ========================================================= */

function initMaintenanceForm() {
  $("photos")?.addEventListener("change", () => {
    setMaintenanceMessage("", "");
    updateSelectedFilesUI();
  });

  $("subject")?.addEventListener("input", () => setMaintenanceMessage("", ""));
  $("description")?.addEventListener("input", () => setMaintenanceMessage("", ""));

  $("maintenanceForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    setMaintenanceMessage("", "");

    const subject = $("subject").value.trim();
    const description = $("description").value.trim();
    const files = Array.from($("photos").files || []);

    if (!subject) {
      setMaintenanceMessage("error", "Please enter a subject for your maintenance request.");
      return;
    }

    if (!description) {
      setMaintenanceMessage("error", "Please provide a short description of the issue.");
      return;
    }

    if (files.length > MAX_FILES) {
      setMaintenanceMessage("error", `You can upload up to ${MAX_FILES} photos.`);
      return;
    }

    const oversized = files.find((file) => file.size > MAX_FILE_SIZE_BYTES);
    if (oversized) {
      setMaintenanceMessage("error", `${oversized.name} is larger than 2MB.`);
      return;
    }

    const submitBtn = $("maintenanceSubmitBtn");
    submitBtn.disabled = true;
    submitBtn.textContent = "Submitting...";
    setStatus("loading", "Submitting request");

    try {
      const photos = await Promise.all(files.map(readFileAsBase64Payload));

      await api("/api/maintenance", {
        method: "POST",
        body: JSON.stringify({ subject, description, photos })
      });

      closeModalById("maintenanceModal");
      showToast("Maintenance request submitted successfully.");
      await loadMaintenance(true);
      setActiveView("maintenance");
      setStatus("ok", "Connected");
    } catch (error) {
      setStatus("error", "Service unavailable");
      setMaintenanceMessage(
        "error",
        error.message || "We could not submit your request right now. Please try again."
      );
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "Submit request";
    }
  });
}

/* =========================================================
   26. PROFILE FORM
   ========================================================= */

function initProfileForm() {
  $("profileEmail")?.addEventListener("input", () => setProfileMessage("", ""));
  $("profilePhone")?.addEventListener("input", () => setProfileMessage("", ""));

  $("profileForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    setProfileMessage("", "");

    const email = $("profileEmail").value.trim();
    const phone = $("profilePhone").value.trim();

    const saveBtn = $("profileSaveBtn");
    saveBtn.disabled = true;
    saveBtn.textContent = "Saving...";
    setStatus("loading", "Saving profile");

    try {
      await api("/api/profile", {
        method: "POST",
        body: JSON.stringify({ email, phone })
      });

      portalContext = {
        ...portalContext,
        tenant: {
          ...(portalContext?.tenant || {}),
          email,
          phone
        }
      };

      applyTenantProfileToShell(portalContext);

      const savedAt = new Intl.DateTimeFormat("en-GB", {
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit"
      }).format(new Date());

      $("profileSavedAt").textContent = `Saved ${savedAt}`;
      setProfileMessage("success", "Your contact details were updated successfully.");
      showToast("Profile updated successfully.");
      setStatus("ok", "Connected");
      updateDashboardMetrics();
    } catch (error) {
      setStatus("error", "Service unavailable");
      setProfileMessage(
        "error",
        error.message || "We could not save your changes right now. Please try again."
      );
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = "Save changes";
    }
  });
}

function initTenancyDetailEditButtons() {
  document.querySelectorAll("[data-edit-profile-field]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const field = btn.dataset.editProfileField;

      await openViewAndLoad("profile");

      setTimeout(() => {
        if (field === "email") {
          $("profileEmail")?.focus();
          $("profileEmail")?.select?.();
        } else if (field === "phone") {
          $("profilePhone")?.focus();
          $("profilePhone")?.select?.();
        }
      }, 150);
    });
  });
}

/* =========================================================
   27. MAINTENANCE MESSAGING
   ========================================================= */

function initMaintenanceMessaging() {
  const sendBtn = $("maintenanceMessageSendBtn");
  const input = $("maintenanceMessageInput");

  if (!sendBtn || !input) return;

  async function handleSendMessage() {
    if (isSendingMaintenanceMessage) return;

    const maintenanceId =
      activeMaintenanceItem?.id || activeMaintenanceItem?.maintenanceId;

    if (!maintenanceId) {
      showToast("No maintenance request is currently selected.");
      return;
    }

    const message = (input.value || "").trim();

    if (!message) {
      showToast("Please enter a message before sending.");
      return;
    }

    const existing = maintenanceMessagesCache[maintenanceId] || [];

    const pendingMessage = {
      id: `pending-${Date.now()}`,
      message,
      senderType: "Tenant",
      isFromPortal: true,
      createdDate: new Date().toISOString(),
      isPending: true
    };

    isSendingMaintenanceMessage = true;
    sendBtn.disabled = true;
    sendBtn.textContent = "Sending...";
    setStatus("loading", "Sending message");

    input.value = "";

    maintenanceMessagesCache[maintenanceId] = [...existing, pendingMessage];

    renderMaintenanceMessages(maintenanceMessagesCache[maintenanceId], {
      forceScroll: true,
      preserveIfReadingOlder: false
    });

    try {
      await sendMaintenanceMessage(maintenanceId, message);

      const latest = await loadMaintenanceMessages(maintenanceId);

      maintenanceMessagesCache[maintenanceId] = latest || [];

      renderMaintenanceMessages(maintenanceMessagesCache[maintenanceId], {
        forceScroll: true,
        preserveIfReadingOlder: false
      });

      setStatus("ok", "Connected");
      showToast("Message sent successfully.");
    } catch (error) {
      console.error(error);

      maintenanceMessagesCache[maintenanceId] = existing;

      renderMaintenanceMessages(existing, {
        forceScroll: true,
        preserveIfReadingOlder: false
      });

      input.value = message;

      setStatus("error", "Service unavailable");
      showToast(error.message || "Unable to send message.");
    } finally {
      isSendingMaintenanceMessage = false;
      sendBtn.disabled = false;
      sendBtn.textContent = "Send";
    }
  }

  sendBtn.addEventListener("click", handleSendMessage);

  input.addEventListener("keydown", async (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      await handleSendMessage();
    }
  });
}

/* =========================================================
   28. NAVIGATION / FILTER INITIALISERS
   ========================================================= */

function initNavigation() {
  document.querySelectorAll(".nav__item").forEach((btn) => {
    btn.addEventListener("click", () => {
      openViewAndLoad(btn.dataset.view);
    });
  });

  document.querySelectorAll("[data-open-view]").forEach((btn) => {
    btn.addEventListener("click", () => {
      openViewAndLoad(btn.dataset.openView);
    });
  });
}

function initMaintenanceFilters() {
  document.querySelectorAll("[data-maintenance-filter]").forEach((chip) => {
    chip.addEventListener("click", () => {
      maintenanceFilter = chip.dataset.maintenanceFilter || "all";

      document.querySelectorAll("[data-maintenance-filter]").forEach((c) => {
        c.classList.toggle("is-active", c === chip);
      });

      renderFilteredMaintenance();
    });
  });
}

/* =========================================================
   29. AUTH / GLOBAL BUTTONS / DELEGATED CLICK HANDLERS
   ========================================================= */

function initAuthButtons() {
  $("loginBtn")?.addEventListener("click", login);
  $("logoutBtn")?.addEventListener("click", openLogoutModal);
  $("confirmLogoutBtn")?.addEventListener("click", logout);

  $("maintenanceCreateBtn")?.addEventListener("click", openMaintenanceModal);

  document.addEventListener("click", async (event) => {
    const openViewBtn = event.target.closest("[data-open-view]");
    if (openViewBtn) {
      await openViewAndLoad(openViewBtn.dataset.openView);
      return;
    }
     const notificationBtn = event.target.closest("[data-notification-id]");
if (notificationBtn) {
  const id = notificationBtn.dataset.notificationId;
  await handleNotificationClick(id);
  return;
}

    const actionBtn = event.target.closest("[data-action], [data-empty-action]");
    const actionType =
      actionBtn?.dataset.action || actionBtn?.dataset.emptyAction || "";

    if (actionType === "new-maintenance") {
      openMaintenanceModal();
      return;
    }

    const docBtn = event.target.closest("[data-doc-download]");
    if (docBtn) {
      const id = docBtn.dataset.docDownload;
      const doc = documentsCache.find((item) => {
        return String(item.contentDocumentId || item.id) === String(id);
      });

      if (doc) {
        try {
          await downloadDocument(doc);
        } catch (error) {
          setStatus("error", "Service unavailable");
          showToast(error.message || "Unable to download document.");
        }
      }
      return;
    }

    const maintenanceOpenBtn = event.target.closest("[data-maintenance-open]");
    if (maintenanceOpenBtn) {
      const id = maintenanceOpenBtn.dataset.maintenanceOpen;
      const item = maintenanceItemsCache.find((m) => {
        return String(m.id || m.maintenanceId) === String(id);
      });
      if (item) await openMaintenanceDetail(item);
      return;
    }

    const maintenanceCard = event.target.closest("[data-maintenance-id]");
    if (maintenanceCard && !event.target.closest("button")) {
      const id = maintenanceCard.dataset.maintenanceId;
      const item = maintenanceItemsCache.find((m) => {
        return String(m.id || m.maintenanceId) === String(id);
      });
      if (item) await openMaintenanceDetail(item);
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      if (activeModalId) {
        closeAllModals();
        return;
      }

      if (isMobileViewport()) {
        closeSidebar();
      }

      return;
    }

    if (
      event.key.toLowerCase() === "n" &&
      !$("app").classList.contains("hidden") &&
      !["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName)
    ) {
      openMaintenanceModal();
    }
  });
}

/* =========================================================
   30. AUTH STATE RENDERING
   ========================================================= */

function renderLoggedInState() {
  $("authLoading").classList.add("hidden");
  $("guestScreen").classList.add("hidden");
  $("app").classList.remove("hidden");
  applySidebarState();
}

function renderLoggedOutState() {
  $("authLoading").classList.add("hidden");
  $("guestScreen").classList.remove("hidden");
  $("app").classList.add("hidden");
}

/* =========================================================
   31. APP BOOTSTRAP
   ========================================================= */

async function boot() {
  if (isBooted) return;
  isBooted = true;

  initNavigation();
  initMaintenanceFilters();
  initModalControls();
  initMaintenanceForm();
  initProfileForm();
  initAuthButtons();
  initTenancyDetailEditButtons();
  initSidebarControls();
  initMaintenanceMessaging();
  initMaintenanceHistoryAccordion();
   initNotificationsDropdown();

  try {
    requireAuth0Client();
    await handleAuthRedirectIfPresent();

    const authenticated = await isAuthenticated();
    if (!authenticated) {
      renderLoggedOutState();
      return;
    }

    renderLoggedInState();
    setStatus("loading", "Loading portal");

    renderSkeletonList("recentMaintenanceList", 3);
    renderSkeletonList("homeAnnouncements", 2);
    renderSkeletonList("maintenanceList", 4);
    renderSkeletonList("documentsList", 4);
    renderSkeletonList("announcementsList", 3);

    await Promise.all([
      loadMe(),
      loadMaintenance(true),
      loadDocuments(true),
      loadAnnouncementsAndRender(true)
       loadNotifications(true)
    ]);

    const savedView = getSavedView();
    setActiveView(savedView, { skipScroll: true });

    if (savedView === "maintenance") {
      renderFilteredMaintenance();
    } else if (savedView === "documents") {
      renderDocuments(documentsCache);
    } else if (savedView === "announcements") {
      renderAnnouncements(announcementsCache, "announcementsList");
    } else if (savedView === "profile") {
      hydrateProfileForm();
    } else {
      updateDashboardMetrics();
    }

    setStatus("ok", "Connected");
  } catch (error) {
    console.error(error);
    renderLoggedOutState();
    showToast("We could not load the portal session. Please sign in again.");
  }
}

/* =========================================================
   32. STARTUP
   ========================================================= */

window.addEventListener("DOMContentLoaded", boot);
