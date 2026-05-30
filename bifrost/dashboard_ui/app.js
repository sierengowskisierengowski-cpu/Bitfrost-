(function () {
  "use strict";

  const PAGE = 25;
  const SEV_COLOR = {
    CRITICAL: "#FF2D2D",
    HIGH: "#FF6B35",
    MEDIUM: "#FFD166",
    LOW: "#4ECDC4",
    INFO: "#6B7280",
    UNKNOWN: "#6B7280",
  };

  let state = null;
  let range = "24h";
  let incidentPage = 0;
  let refreshTimer = null;
  let expandedIncident = null;
  let selectedAttacker = null;

  function $(id) {
    return document.getElementById(id);
  }

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function sevBadge(sev) {
    const u = String(sev || "UNKNOWN").toUpperCase();
    const c = SEV_COLOR[u] || SEV_COLOR.UNKNOWN;
    return (
      '<span class="sev-badge" style="--sev-color:' +
      c +
      '">' +
      esc(u) +
      "</span>"
    );
  }

  function mitreText(inc) {
    const m = inc.mitre_attack || [];
    if (!m.length) return "—";
    return m
      .map(function (x) {
        return (x.technique_id || "?") + " " + (x.technique || "?");
      })
      .join(", ");
  }

  function disclaimerOk() {
    return sessionStorage.getItem("bifrost_disclaimer_accepted") === "1";
  }

  function initDisclaimer() {
    const modal = $("disclaimer-modal");
    const scroll = $("disclaimer-scroll");
    const accept = $("disclaimer-accept");
    const app = $("app");
    if (disclaimerOk()) {
      document.body.classList.remove("disclaimer-locked");
      modal.style.display = "none";
      app.hidden = false;
      return;
    }
    scroll.addEventListener("scroll", function () {
      const atBottom =
        scroll.scrollTop + scroll.clientHeight >= scroll.scrollHeight - 8;
      accept.disabled = !atBottom;
    });
    accept.addEventListener("click", function () {
      sessionStorage.setItem("bifrost_disclaimer_accepted", "1");
      fetch("/api/disclaimer/accept", { method: "POST" }).catch(function () {});
      document.body.classList.remove("disclaimer-locked");
      modal.style.display = "none";
      app.hidden = false;
      loadState();
    });
  }

  function setView(name) {
    closeDetail();
    document.querySelectorAll(".nav-item").forEach(function (btn) {
      btn.classList.toggle("active", btn.dataset.view === name);
    });
    document.querySelectorAll(".view").forEach(function (v) {
      v.classList.toggle("active", v.id === "view-" + name);
    });
    const content = document.querySelector(".content");
    if (content) content.scrollTop = 0;
    if (name === "settings") renderSettings();
    if (name === "incidents") renderIncidentsTable();
    if (name === "attackers") renderAttackers();
    if (name === "timeline") renderTimelineFull();
    if (name === "overview") renderAll();
  }

  function openDetail(title, html) {
    $("detail-content").innerHTML = "<h2>" + esc(title) + "</h2>" + html;
    $("detail-overlay").hidden = false;
  }

  function closeDetail() {
    $("detail-overlay").hidden = true;
  }

  function renderConnectivity() {
    const c = state.connectivity || {};
    const db = $("db-status");
    const mon = $("monitor-status");
    if (c.database_connected) {
      db.innerHTML = '<span class="dot ok"></span> Database: Connected ✓';
    } else {
      db.innerHTML = '<span class="dot warn"></span> Database: Disconnected';
    }
    if (c.live_monitor_active) {
      mon.innerHTML = '<span class="dot ok"></span> Live Monitor: Active ✓';
    } else {
      mon.innerHTML = '<span class="dot warn"></span> Live Monitor: Idle';
    }
    $("generated-at").textContent = state.generated_at || "";
  }

  function criticalCount() {
    const sev = state.severity_counts || {};
    return (sev.CRITICAL || 0) + (sev.HIGH || 0);
  }

  function renderStatCards() {
    const s = state.summary || {};
    const cards = [
      { icon: "⬡", label: "Total Events", value: s.db_events ?? 0, panel: "events", color: "#9D4EDD" },
      { icon: "⚡", label: "Incidents", value: s.dashboard_incidents ?? 0, panel: "incidents", color: "#E040FB" },
      { icon: "🛡", label: "Blocked", value: s.blocked_actions ?? 0, panel: "blocked", color: "#C4607A" },
      { icon: "👤", label: "Unique Attackers", value: s.unique_attackers ?? 0, panel: "attackers", color: "#06B6D4" },
      { icon: "⏱", label: "Last Hour", value: s.last_hour_incidents ?? 0, panel: "hour", color: "#22C55E" },
      { icon: "🔥", label: "Critical + High", value: criticalCount(), panel: "critical", color: "#FF2D2D" },
    ];
    $("stat-cards").innerHTML = cards
      .map(function (c) {
        return (
          '<div class="stat-card" data-panel="' +
          c.panel +
          '">' +
          '<div class="stat-icon">' + esc(c.icon) + '</div>' +
          '<div class="stat-value" style="color:' + c.color + '">' +
          esc(c.value) +
          '</div><div class="stat-label">' +
          esc(c.label) +
          "</div></div>"
        );
      })
      .join("");
    document.querySelectorAll(".stat-card").forEach(function (el) {
      el.addEventListener("click", function () {
        openStatPanel(el.dataset.panel);
      });
    });
  }

  function openStatPanel(panel) {
    if (panel === "events") {
      const rows = (state.db_events || [])
        .map(function (e) {
          return (
            "<tr><td>" +
            esc(e.timestamp) +
            "</td><td>" +
            esc(e.source) +
            "</td><td>" +
            esc(e.boundary) +
            "</td><td>" +
            esc(e.threat_class || "—") +
            "</td><td>" +
            esc(e.action_taken || "—") +
            "</td></tr>"
          );
        })
        .join("");
      openDetail(
        "Total Events",
        '<div class="table-scroll tall"><table><thead><tr><th>Time</th><th>Source</th><th>Boundary</th><th>Threat</th><th>Action</th></tr></thead><tbody>' +
          (rows || '<tr><td colspan="5" class="muted">No events</td></tr>') +
          "</tbody></table></div>"
      );
      return;
    }
    if (panel === "incidents") {
      setView("incidents");
      return;
    }
    if (panel === "blocked") {
      const rows = (state.blocked_actions || [])
        .map(function (i) {
          return incidentRow(i, false);
        })
        .join("");
      openDetail(
        "Blocked Actions",
        '<div class="table-scroll tall"><table><thead><tr><th>Time</th><th>Severity</th><th>Threat</th><th>IP</th><th>Action</th><th>Summary</th></tr></thead><tbody>' +
          rows +
          "</tbody></table></div>"
      );
      return;
    }
    if (panel === "attackers") {
      setView("attackers");
      return;
    }
    if (panel === "hour") {
      const bars = (state.minute_breakdown || [])
        .map(function (b, idx, arr) {
          const max = Math.max.apply(null, arr.map(function (x) { return x.count; }).concat([1]));
          const h = Math.max(12, Math.round((b.count / max) * 110));
          return (
            '<div class="tl-bar-wrap"><div class="tl-bar" style="height:' +
            h +
            'px" title="' +
            esc(b.minute) +
            ": " +
            b.count +
            '"></div><div class="tl-lbl">' +
            esc(b.count) +
            "</div></div>"
          );
        })
        .join("");
      openDetail(
        "Last Hour — Per Minute",
        '<div class="tl-chart">' +
          (bars || '<p class="muted">No activity in the last hour</p>') +
          "</div>"
      );
      return;
    }
    if (panel === "critical") {
      const sev = state.severity_counts || {};
      openDetail(
        "Critical + High Severity",
        '<div class="settings-grid">' +
          '<div class="settings-row"><span>CRITICAL</span><span class="mono">' + esc(sev.CRITICAL || 0) + '</span></div>' +
          '<div class="settings-row"><span>HIGH</span><span class="mono">' + esc(sev.HIGH || 0) + '</span></div>' +
          "</div>"
      );
    }
  }

  function incidentRow(inc, clickable) {
    const cls = clickable ? "clickable" : "";
    return (
      "<tr class='" +
      cls +
      "' data-ts='" +
      esc(inc.timestamp) +
      "'>" +
      "<td>" +
      esc(inc.timestamp) +
      "</td><td>" +
      sevBadge(inc.severity) +
      "</td><td>" +
      esc(inc.threat_class) +
      "</td><td>" +
      esc(inc.attacker_identity) +
      "</td><td>" +
      esc(mitreText(inc)) +
      "</td><td>" +
      esc(inc.action_taken) +
      "</td><td>" +
      esc(inc.summary) +
      "</td></tr>"
    );
  }

  function incidentDetailHtml(inc) {
    return (
      '<div class="incident-expand"><strong>Threat:</strong> ' +
      esc(inc.threat_class) +
      "<br><strong>Attacker:</strong> " +
      esc(inc.attacker_identity) +
      "<br><strong>MITRE:</strong> " +
      esc(mitreText(inc)) +
      "<br><strong>Action:</strong> " +
      esc(inc.action_taken) +
      "<br><strong>Policy allowed:</strong> " +
      esc(inc.policy_allowed) +
      "<br><strong>Summary:</strong> " +
      esc(inc.summary) +
      "</div>"
    );
  }

  function bindIncidentClicks(container) {
    container.querySelectorAll("tr.clickable").forEach(function (row) {
      row.addEventListener("click", function () {
        const ts = row.dataset.ts;
        const inc = (state.all_incidents || []).find(function (i) {
          return i.timestamp === ts;
        });
        if (!inc) return;
        const next = row.nextElementSibling;
        if (next && next.classList.contains("expanded-detail")) {
          next.remove();
          expandedIncident = null;
          return;
        }
        container.querySelectorAll(".expanded-detail").forEach(function (r) {
          r.remove();
        });
        const detail = document.createElement("tr");
        detail.className = "expanded-detail";
        detail.innerHTML =
          '<td colspan="7">' + incidentDetailHtml(inc) + "</td>";
        row.after(detail);
        expandedIncident = ts;
      });
    });
  }

  function renderOverviewIncidents() {
    const list = state.all_incidents || [];
    const show = list.slice(0, Math.min(100, list.length));
    $("incident-count-badge").textContent =
      show.length + " shown · " + range.toUpperCase();
    const body = show.map(function (i) {
      return incidentRow(i, true);
    }).join("");
    const el = $("overview-incidents-table");
    el.innerHTML =
      "<table><thead><tr><th>Timestamp</th><th>Severity</th><th>Threat</th><th>Attacker</th><th>MITRE</th><th>Action</th><th>Summary</th></tr></thead><tbody>" +
      (body || '<tr><td colspan="7" class="muted">No incidents</td></tr>') +
      "</tbody></table>";
    bindIncidentClicks(el);
  }

  function renderIncidentsTable() {
    const list = state.all_incidents || [];
    const totalPages = Math.max(1, Math.ceil(list.length / PAGE));
    if (incidentPage >= totalPages) incidentPage = totalPages - 1;
    if (incidentPage < 0) incidentPage = 0;
    const slice = list.slice(incidentPage * PAGE, incidentPage * PAGE + PAGE);
    const body = slice.map(function (i) {
      return incidentRow(i, true);
    }).join("");
    const el = $("incidents-full-table");
    el.innerHTML =
      "<table><thead><tr><th>Timestamp</th><th>Severity</th><th>Threat</th><th>Attacker</th><th>MITRE</th><th>Action</th><th>Summary</th></tr></thead><tbody>" +
      body +
      "</tbody></table>";
    bindIncidentClicks(el);
    $("incidents-pager").innerHTML =
      '<button type="button" id="inc-prev"' +
      (incidentPage <= 0 ? " disabled" : "") +
      ">Prev</button><span>Page " +
      (incidentPage + 1) +
      " / " +
      totalPages +
      " (" +
      list.length +
      ')</span><button type="button" id="inc-next"' +
      (incidentPage >= totalPages - 1 ? " disabled" : "") +
      ">Next</button>";
    $("inc-prev").onclick = function () {
      incidentPage--;
      renderIncidentsTable();
    };
    $("inc-next").onclick = function () {
      incidentPage++;
      renderIncidentsTable();
    };
  }

  function renderBreakdown() {
    const sev = state.severity_counts || {};
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];
    const sevRows = order
      .filter(function (k) {
        return sev[k];
      })
      .map(function (k) {
        return (
          "<tr><td>" + sevBadge(k) + "</td><td>" + esc(sev[k]) + "</td></tr>"
        );
      })
      .join("");
    const threats = (state.top_threat_classes || [])
      .map(function (r) {
        return (
          "<tr><td>" +
          esc(r.name) +
          "</td><td>" +
          esc(r.count) +
          "</td></tr>"
        );
      })
      .join("");
    const mitre = (state.top_mitre_techniques || [])
      .map(function (r) {
        return (
          "<tr><td><code>" +
          esc(r.name) +
          "</code></td><td>" +
          esc(r.count) +
          "</td></tr>"
        );
      })
      .join("");
    $("breakdown-cards").innerHTML =
      '<div class="card"><h2 class="card-title">Severity</h2><table><tbody>' +
      (sevRows || '<tr><td class="muted">None</td></tr>') +
      '</tbody></table></div><div class="card"><h2 class="card-title">Threat Classes</h2><table><tbody>' +
      threats +
      '</tbody></table></div><div class="card"><h2 class="card-title">MITRE</h2><table><tbody>' +
      mitre +
      "</tbody></table></div>";
  }

  function renderTimelineCard(targetId, data) {
    const el = $(targetId);
    const tl = data || state.timeline || [];
    if (!tl.length) {
      el.innerHTML =
        '<h2 class="card-title">Activity Timeline</h2><p class="muted">No activity</p>';
      return;
    }
    const max = Math.max.apply(
      null,
      tl.map(function (r) {
        return r.count;
      }).concat([1])
    );
    const bars = tl
      .map(function (r) {
        const h = Math.max(12, Math.round((r.count / max) * 120));
        return (
          '<div class="tl-bar-wrap"><div class="tl-bar" style="height:' +
          h +
          'px" title="' +
          esc(r.minute) +
          ": " +
          r.count +
          '"></div><div class="tl-lbl">' +
          esc(r.count) +
          "</div></div>"
        );
      })
      .join("");
    el.innerHTML =
      '<h2 class="card-title">Activity Timeline <span class="badge">' +
      esc(range.toUpperCase()) +
      '</span></h2><div class="tl-chart">' +
      bars +
      "</div>";
  }

  function renderTimelineFull() {
    renderTimelineCard("timeline-full-card", state.timeline);
  }

  function sortAttackers(list, mode) {
    const copy = list.slice();
    copy.sort(function (a, b) {
      if (mode === "first_seen")
        return String(a.first_seen).localeCompare(String(b.first_seen));
      if (mode === "last_seen")
        return String(b.last_seen).localeCompare(String(a.last_seen));
      if (mode === "threat") {
        const o = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
        return (
          (o[b.threat_level] || 0) - (o[a.threat_level] || 0) ||
          b.total_hits - a.total_hits
        );
      }
      return b.total_hits - a.total_hits;
    });
    return copy;
  }

  function renderAttackers() {
    const sort = $("attacker-sort").value;
    const list = sortAttackers(state.attackers || [], sort);
    const rows = list
      .map(function (a) {
        return (
          "<tr class='clickable' data-ip='" +
          esc(a.ip) +
          "'><td>" +
          esc(a.country_flag) +
          " " +
          esc(a.ip) +
          "</td><td>" +
          esc(a.country_label) +
          "</td><td>" +
          esc(a.first_seen) +
          "</td><td>" +
          esc(a.last_seen) +
          "</td><td>" +
          esc(a.total_hits) +
          "</td><td>" +
          sevBadge(a.threat_level) +
          "</td><td>" +
          esc((a.event_types || []).join(", ")) +
          "</td></tr>"
        );
      })
      .join("");
    const el = $("attackers-table");
    el.innerHTML =
      "<table><thead><tr><th>IP</th><th>Region</th><th>First Seen</th><th>Last Seen</th><th>Hits</th><th>Threat</th><th>Event Types</th></tr></thead><tbody>" +
      (rows || '<tr><td colspan="7" class="muted">No attackers</td></tr>') +
      "</tbody></table>";
    el.querySelectorAll("tr.clickable").forEach(function (row) {
      row.addEventListener("click", function () {
        const ip = row.dataset.ip;
        const profile = (state.attackers || []).find(function (a) {
          return a.ip === ip;
        });
        if (!profile) return;
        $("attacker-detail-card").hidden = false;
        $("attacker-detail-ip").textContent = ip;
        const ev = (profile.events || [])
          .map(function (e) {
            return (
              "<tr><td>" +
              esc(e.timestamp) +
              "</td><td>" +
              sevBadge(e.severity) +
              "</td><td>" +
              esc(e.threat_class) +
              "</td><td>" +
              esc(e.action_taken) +
              "</td><td>" +
              esc(e.summary) +
              "</td></tr>"
            );
          })
          .join("");
        $("attacker-detail-events").innerHTML =
          "<table><thead><tr><th>Time</th><th>Severity</th><th>Threat</th><th>Action</th><th>Summary</th></tr></thead><tbody>" +
          ev +
          "</tbody></table>";
      });
    });
  }

  function renderSettings() {
    const s = state.settings || {};
    const tok = s.tokens || {};
    function tokRow(name, ok) {
      return (
        '<div class="settings-row"><span>' +
        esc(name) +
        '</span><span class="' +
        (ok ? "token-ok" : "token-miss") +
        '">' +
        (ok ? "Set ✓" : "Not set") +
        "</span></div>"
      );
    }
    const uptime = s.uptime_seconds || 0;
    const h = Math.floor(uptime / 3600);
    const m = Math.floor((uptime % 3600) / 60);
    $("settings-panel").innerHTML =
      '<h2 class="card-title">Configuration (read-only)</h2><div class="settings-grid">' +
      '<div class="settings-row"><span>Hardware tier</span><span>' +
      esc(s.hardware_tier) +
      "</span></div>" +
      '<div class="settings-row"><span>Analyst model</span><span>' +
      esc(s.analyst_model) +
      "</span></div>" +
      '<div class="settings-row"><span>Extractor model</span><span>' +
      esc(s.extractor_model) +
      "</span></div>" +
      '<div class="settings-row"><span>Learning mode</span><span>' +
      esc(s.learning_mode) +
      "</span></div>" +
      '<div class="settings-row"><span>Dry run</span><span>' +
      esc(s.dry_run) +
      "</span></div>" +
      '<div class="settings-row"><span>Autonomous enabled</span><span>' +
      esc(s.autonomous_actions_enabled) +
      "</span></div>" +
      '<div class="settings-row"><span>Confidence threshold</span><span>' +
      esc(s.confidence_threshold) +
      "</span></div>" +
      '<div class="settings-row"><span>Database path</span><span><code>' +
      esc(s.db_path) +
      "</code></span></div>" +
      '<div class="settings-row"><span>Log path</span><span><code>' +
      esc(s.log_path) +
      "</code></span></div>" +
      '<div class="settings-row"><span>Uptime</span><span>' +
      h +
      "h " +
      m +
      "m</span></div>" +
      tokRow("Ingest token", tok.ingest) +
      tokRow("Executor token", tok.executor) +
      tokRow("Dashboard token", tok.dashboard) +
      "</div>";
  }

  function renderAll() {
    if (!state) return;
    renderConnectivity();
    renderStatCards();
    renderBreakdown();
    renderTimelineCard("timeline-card");
    renderOverviewIncidents();
    const active = document.querySelector(".view.active");
    if (active && active.id === "view-incidents") renderIncidentsTable();
    if (active && active.id === "view-attackers") renderAttackers();
    if (active && active.id === "view-timeline") renderTimelineFull();
    if (active && active.id === "view-settings") renderSettings();
  }

  function loadState() {
    if (!disclaimerOk()) return;
    fetch("/api/state?range=" + encodeURIComponent(range))
      .then(function (r) {
        if (r.status === 403) return null;
        return r.json();
      })
      .then(function (data) {
        if (!data) return;
        state = data;
        renderAll();
      })
      .catch(function () {});
  }

  function scheduleRefresh() {
    clearTimeout(refreshTimer);
    const toggle = $("auto-refresh");
    if (toggle && toggle.checked) {
      refreshTimer = setTimeout(function () {
        loadState();
        scheduleRefresh();
      }, 5000);
    }
  }

  function initNav() {
    document.querySelectorAll(".nav-item").forEach(function (btn) {
      btn.addEventListener("click", function () {
        setView(btn.dataset.view);
      });
    });
    $("settings-gear").addEventListener("click", function () {
      setView("settings");
    });
    document.querySelectorAll("#time-range button").forEach(function (btn) {
      btn.addEventListener("click", function () {
        range = btn.dataset.range;
        document
          .querySelectorAll("#time-range button")
          .forEach(function (b) {
            b.classList.toggle("active", b === btn);
          });
        incidentPage = 0;
        loadState();
      });
    });
    $("attacker-sort").addEventListener("change", renderAttackers);
    $("detail-close").addEventListener("click", closeDetail);
    $("detail-overlay").addEventListener("click", function (e) {
      if (e.target === $("detail-overlay")) closeDetail();
    });
    $("auto-refresh").addEventListener("change", scheduleRefresh);
  }

  function bootstrap() {
    const el = $("bifrost-bootstrap");
    if (el) {
      try {
        state = JSON.parse(el.textContent);
      } catch (e) {}
    }
    initDisclaimer();
    initNav();
    if (disclaimerOk()) {
      renderAll();
      loadState();
    }
    scheduleRefresh();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap);
  } else {
    bootstrap();
  }
})();
