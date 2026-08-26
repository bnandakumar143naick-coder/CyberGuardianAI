/* CyberGuardian AI - shared front-end utilities */

const CG = {
  apiBase: "",

  showError(message) {
    const el = document.getElementById("error-banner");
    if (!el) {
      alert(message);
      return;
    }
    el.textContent = message;
    el.classList.add("active");
  },

  clearError() {
    const el = document.getElementById("error-banner");
    if (el) {
      el.classList.remove("active");
      el.textContent = "";
    }
  },

  setLoading(isLoading) {
    const el = document.getElementById("loading-state");
    if (el) el.classList.toggle("active", isLoading);
  },

  async postJSON(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return CG._handleResponse(res);
  },

  async postForm(url, formData) {
    const res = await fetch(url, { method: "POST", body: formData });
    return CG._handleResponse(res);
  },

  async _handleResponse(res) {
    let data;
    try {
      data = await res.json();
    } catch (e) {
      throw new Error("The server returned an unexpected response. Please try again.");
    }
    if (!res.ok || data.success === false) {
      throw new Error(data.message || "Something went wrong. Please try again.");
    }
    return data;
  },

  goToResult(result) {
    sessionStorage.setItem("cg_last_result", JSON.stringify(result));
    window.location.href = "/result";
  },
};

// Tab switching (used on scan.html)
document.addEventListener("DOMContentLoaded", () => {
  const tabs = document.querySelectorAll(".tab");
  if (!tabs.length) return;

  const params = new URLSearchParams(window.location.search);
  const mode = params.get("mode");
  if (mode === "url") activateTab("url");
  if (mode === "camera" || mode === "upload") activateTab("image");

  tabs.forEach(tab => {
    tab.addEventListener("click", () => activateTab(tab.dataset.tab));
  });

  function activateTab(name) {
    tabs.forEach(t => t.classList.toggle("active", t.dataset.tab === name));
    document.querySelectorAll(".tab-panel").forEach(p => {
      p.style.display = p.id === `panel-${name}` ? "block" : "none";
    });
    CG.clearError();
  }
});
