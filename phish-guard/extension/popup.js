// ============================================================
// popup.js — PERSON A's file
// This controls everything that happens in the extension popup.
// It reads user input, calls the scorer/analyzer, and
// updates the UI with results.
// ============================================================

// ── Wait for the page to fully load before doing anything ──
document.addEventListener("DOMContentLoaded", () => {

  // ── PART 1: Auto-scan the current tab's URL when popup opens ──
  // chrome.tabs gives us info about the current browser tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const currentURL = tabs[0].url;

    // Don't scan Chrome's own internal pages (like chrome://extensions)
    if (currentURL.startsWith("chrome://") || currentURL.startsWith("chrome-extension://")) {
      showURLResult({ score: 0, level: "N/A", color: "#888", reasons: [], url: currentURL });
      document.getElementById("current-url-text").textContent = "Internal Chrome page";
      return;
    }

    // Show the URL in the UI
    document.getElementById("current-url-text").textContent = currentURL;

    // Run our scoring checks on it (from scorer.js)
    const result = analyzeURL(currentURL);
    showURLResult(result);
  });

  // ── PART 2: Manual URL input — scan any URL the user types ──
  document.getElementById("scan-btn").addEventListener("click", () => {
    const inputURL = document.getElementById("url-input").value.trim();
    if (!inputURL) return;

    const result = analyzeURL(inputURL);
    showURLResult(result);
  });

  // Also allow pressing Enter to scan
  document.getElementById("url-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") document.getElementById("scan-btn").click();
  });

  // ── PART 3: Email analysis ──
  document.getElementById("analyze-email-btn").addEventListener("click", () => {
    const emailText = document.getElementById("email-input").value.trim();
    const resultsDiv = document.getElementById("email-results");

    if (!emailText) {
      resultsDiv.innerHTML = `<p class="error">Please paste an email first.</p>`;
      return;
    }

    // Run local analysis (no API, instant result)
    const analysis = analyzeEmail(emailText);
    showEmailResult(analysis);
  });

  // ── Tab switching (URL tab vs Email tab) ──
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      // Update active tab button
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      // Show the right panel
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      document.getElementById(btn.dataset.tab).classList.add("active");
    });
  });
});

// ── Display URL scan results in the UI ──
function showURLResult(result) {
  const container = document.getElementById("url-result");

  const reasonsHTML = result.reasons.length > 0
    ? `<ul class="reasons">${result.reasons.map(r => `<li>⚠️ ${r}</li>`).join("")}</ul>`
    : `<p class="safe-msg">✅ No suspicious patterns detected.</p>`;

  container.innerHTML = `
    <div class="score-badge" style="background:${result.color}">
      <span class="score-number">${result.score}</span>
      <span class="score-label">/100</span>
    </div>
    <div class="risk-level" style="color:${result.color}">${result.level}</div>
    ${reasonsHTML}
  `;
}

// ── Display email analysis results in the UI ──
function showEmailResult(analysis) {
  const container = document.getElementById("email-results");

  if (analysis.error) {
    container.innerHTML = `<p class="error">❌ ${analysis.error}</p>`;
    return;
  }

  const riskColor = analysis.riskLevel === "High" ? "#e74c3c"
                  : analysis.riskLevel === "Medium" ? "#f39c12"
                  : "#27ae60";

  const redFlagsHTML = analysis.redFlags?.length
    ? `<div class="flags-section">
        <h4>🚩 Red Flags</h4>
        <ul>${analysis.redFlags.map(f => `<li>${f}</li>`).join("")}</ul>
       </div>`
    : "";

  const safeHTML = analysis.safeIndicators?.length
    ? `<div class="safe-section">
        <h4>✅ Safe Indicators</h4>
        <ul>${analysis.safeIndicators.map(s => `<li>${s}</li>`).join("")}</ul>
       </div>`
    : "";

  container.innerHTML = `
    <div class="email-score-header" style="border-left: 4px solid ${riskColor}">
      <span class="email-risk" style="color:${riskColor}">${analysis.riskLevel} Risk</span>
      <span class="email-score-num" style="color:${riskColor}">${analysis.riskScore}/100</span>
    </div>
    <p class="summary">${analysis.summary}</p>
    ${redFlagsHTML}
    ${safeHTML}
    <div class="verdict">
      <h4>🔎 Verdict</h4>
      <p>${analysis.verdict}</p>
    </div>
  `;
}
