/* CyberGuardian AI - history & dashboard page logic (Phase 6: search + filters) */

(function () {
  const tbody = document.getElementById("history-tbody");
  const emptyState = document.getElementById("history-empty");
  const noResultsState = document.getElementById("history-no-results");
  const table = document.getElementById("history-table");
  const searchInput = document.getElementById("history-search");
  const severityBar = document.getElementById("severity-filter-bar");
  const categoryBar = document.getElementById("category-filter-bar");

  let allScans = [];
  let activeSeverity = "ALL";
  let activeCategory = "ALL";

  async function loadDashboard() {
    try {
      const res = await fetch("/api/dashboard");
      const data = await res.json();
      if (!data.success) return;

      const stats = data.stats;
      document.getElementById("stat-total").textContent = stats.total_scans;
      document.getElementById("stat-high").textContent = stats.high_risk;
      document.getElementById("stat-medium").textContent = stats.medium_risk;
      // "Low Risk" card also folds in the SAFE band so nothing is
      // silently dropped now that Phase 3/4 introduced a distinct SAFE level.
      document.getElementById("stat-low").textContent = (stats.low_risk || 0) + (stats.safe || 0);

      renderChart(stats.threat_distribution);
    } catch (e) {
      console.error("Failed to load dashboard stats", e);
    }
  }

  function renderChart(distribution) {
    const ctx = document.getElementById("threat-chart");
    if (!ctx || typeof Chart === "undefined") return;

    const labels = Object.keys(distribution);
    const values = Object.values(distribution);

    if (labels.length === 0) {
      ctx.parentElement.querySelector(".eyebrow").insertAdjacentHTML(
        "afterend",
        '<p style="color: var(--text-muted); margin-top: 8px;">No scans yet.</p>'
      );
      return;
    }

    new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels.map(l => l.replace(/_/g, " ")),
        datasets: [{
          label: "Scans",
          data: values,
          backgroundColor: "#6C5CE7",
          borderRadius: 6,
        }],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#8C96A8" }, grid: { color: "#232B3A" } },
          y: { ticks: { color: "#8C96A8", precision: 0 }, grid: { color: "#232B3A" }, beginAtZero: true },
        },
      },
    });
  }

  async function loadHistory() {
    try {
      const res = await fetch("/api/history?limit=100");
      const data = await res.json();
      if (!data.success) return;

      allScans = data.scans || [];
      if (allScans.length === 0) {
        table.style.display = "none";
        emptyState.style.display = "block";
        return;
      }

      buildCategoryFilters(allScans);
      renderRows(allScans);
    } catch (e) {
      console.error("Failed to load history", e);
    }
  }

  function buildCategoryFilters(scans) {
    // Built from the categories that actually appear in the data,
    // rather than a fixed hard-coded list that might not match reality.
    const categories = Array.from(new Set(scans.map(s => s.threat_type).filter(Boolean))).sort();
    categories.forEach(cat => {
      const chip = document.createElement("span");
      chip.className = "filter-chip";
      chip.dataset.category = cat;
      chip.textContent = cat.replace(/_/g, " ");
      categoryBar.appendChild(chip);
    });
  }

  function applyFilters() {
    const query = (searchInput.value || "").trim().toLowerCase();
    const filtered = allScans.filter(scan => {
      if (activeSeverity !== "ALL" && scan.risk_level !== activeSeverity) return false;
      if (activeCategory !== "ALL" && scan.threat_type !== activeCategory) return false;
      if (query) {
        const haystack = ((scan.threat_type || "") + " " + (scan.summary || "")).toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      return true;
    });
    renderRows(filtered);
  }

  function renderRows(scans) {
    tbody.innerHTML = "";
    if (!scans.length) {
      table.style.display = allScans.length ? "table" : "none";
      noResultsState.style.display = allScans.length ? "block" : "none";
      return;
    }
    noResultsState.style.display = "none";
    table.style.display = "table";

    scans.forEach(scan => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>#${scan.id}</td>
        <td>${escapeHtml((scan.threat_type || "").replace(/_/g, " "))}</td>
        <td><span class="pill ${escapeHtml(scan.risk_level)}">${escapeHtml(scan.risk_level)}</span></td>
        <td class="mono">${scan.risk_score}/100</td>
        <td>${formatDate(scan.created_at)}</td>
      `;
      tr.addEventListener("click", () => {
        window.location.href = `/threat-investigation?id=${scan.id}`;
      });
      tbody.appendChild(tr);
    });
  }

  function formatDate(iso) {
    try {
      const d = new Date(iso);
      return d.toLocaleDateString(undefined, { day: "2-digit", month: "short", year: "numeric" });
    } catch (e) {
      return iso;
    }
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  severityBar.addEventListener("click", (e) => {
    const chip = e.target.closest(".filter-chip");
    if (!chip) return;
    severityBar.querySelectorAll(".filter-chip").forEach(c => c.classList.remove("active"));
    chip.classList.add("active");
    activeSeverity = chip.dataset.severity;
    applyFilters();
  });

  categoryBar.addEventListener("click", (e) => {
    const chip = e.target.closest(".filter-chip");
    if (!chip) return;
    categoryBar.querySelectorAll(".filter-chip").forEach(c => c.classList.remove("active"));
    chip.classList.add("active");
    activeCategory = chip.dataset.category;
    applyFilters();
  });

  searchInput.addEventListener("input", applyFilters);

  loadDashboard();
  loadHistory();
})();
