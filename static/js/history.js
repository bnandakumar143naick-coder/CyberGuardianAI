/* CyberGuardian AI - history & dashboard page logic */

(function () {
  const tbody = document.getElementById("history-tbody");
  const emptyState = document.getElementById("history-empty");
  const table = document.getElementById("history-table");

  async function loadDashboard() {
    try {
      const res = await fetch("/api/dashboard");
      const data = await res.json();
      if (!data.success) return;

      const stats = data.stats;
      document.getElementById("stat-total").textContent = stats.total_scans;
      document.getElementById("stat-high").textContent = stats.high_risk;
      document.getElementById("stat-medium").textContent = stats.medium_risk;
      document.getElementById("stat-low").textContent = stats.low_risk;

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
      const res = await fetch("/api/history?limit=50");
      const data = await res.json();
      if (!data.success) return;

      const scans = data.scans || [];
      if (scans.length === 0) {
        table.style.display = "none";
        emptyState.style.display = "block";
        return;
      }

      scans.forEach(scan => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>#${scan.id}</td>
          <td>${escapeHtml(scan.threat_type.replace(/_/g, " "))}</td>
          <td><span class="pill ${scan.risk_level}">${scan.risk_level}</span></td>
          <td class="mono">${scan.risk_score}/100</td>
          <td>${formatDate(scan.created_at)}</td>
        `;
        tr.addEventListener("click", () => showScanDetail(scan));
        tbody.appendChild(tr);
      });
    } catch (e) {
      console.error("Failed to load history", e);
    }
  }

  function showScanDetail(scan) {
    const result = {
      risk_score: scan.risk_score,
      risk_level: scan.risk_level,
      risk_emoji: { LOW: "🟢", MEDIUM: "🟡", HIGH: "🟠", CRITICAL: "🔴" }[scan.risk_level] || "🟢",
      threat_type: scan.threat_type,
      indicators: scan.indicators,
      explanation: scan.explanation,
      recommendations: scan.recommendations,
      status_message: null,
    };
    sessionStorage.setItem("cg_last_result", JSON.stringify(result));
    window.location.href = "/result";
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

  loadDashboard();
  loadHistory();
})();
