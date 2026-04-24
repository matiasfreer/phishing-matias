// ============================================================
// virustotal.js — VirusTotal API integration
// Submits a URL to VirusTotal and returns how many
// security engines flagged it as malicious.
// ============================================================

// !! Replace this with your VirusTotal API key !!
// Get one free at: https://www.virustotal.com → sign up → profile → API Key
const VT_API_KEY = "2bd5174c85c2bb33dd48fe113ae400f81fc4a7cb1a0a3542b1651dc178735f6e";

// ── Step 1: Submit a URL to VirusTotal for scanning ──
// VirusTotal gives back an analysis ID we use in step 2
async function submitURLToVirusTotal(url) {
  const response = await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: {
      "x-apikey": VT_API_KEY,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: "url=" + encodeURIComponent(url)
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.error?.message || `VirusTotal error: ${response.status}`);
  }

  const data = await response.json();
  // The analysis ID is nested inside the response
  return data.data.id;
}

// ── Step 2: Fetch the analysis results using the ID ──
async function fetchAnalysisResults(analysisId) {
  const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
    headers: { "x-apikey": VT_API_KEY }
  });

  if (!response.ok) {
    throw new Error(`Could not fetch results: ${response.status}`);
  }

  return await response.json();
}

// ── Main function: scan a URL and return a clean result object ──
// This is what popup.js calls.
async function scanWithVirusTotal(url) {
  if (VT_API_KEY === "YOUR_VIRUSTOTAL_API_KEY_HERE") {
    return { error: "Add your VirusTotal API key to virustotal.js" };
  }

  try {
    // Step 1 — submit the URL
    const analysisId = await submitURLToVirusTotal(url);

    // Step 2 — wait 3 seconds for VirusTotal to finish scanning,
    // then fetch the results. (Free tier scans take a few seconds)
    await new Promise(resolve => setTimeout(resolve, 3000));
    const analysis = await fetchAnalysisResults(analysisId);

    const stats = analysis.data?.attributes?.stats;

    // If the analysis isn't done yet, wait another 3s and retry once
    if (!stats || analysis.data?.attributes?.status === "queued") {
      await new Promise(resolve => setTimeout(resolve, 3000));
      const retry = await fetchAnalysisResults(analysisId);
      return parseVTResults(retry, url);
    }

    return parseVTResults(analysis, url);

  } catch (err) {
    return { error: err.message };
  }
}

// ── Turn the raw VirusTotal response into something simple to display ──
function parseVTResults(analysis, url) {
  const stats = analysis.data?.attributes?.stats;

  if (!stats) {
    return { error: "VirusTotal analysis is still running. Try again in a moment." };
  }

  const malicious  = stats.malicious  || 0;
  const suspicious = stats.suspicious || 0;
  const harmless   = stats.harmless   || 0;
  const undetected = stats.undetected || 0;
  const total      = malicious + suspicious + harmless + undetected;

  // Build a clean verdict
  let vtLevel, vtColor;
  if (malicious >= 3)                      { vtLevel = "Dangerous";   vtColor = "#e74c3c"; }
  else if (malicious >= 1 || suspicious >= 3) { vtLevel = "Suspicious";  vtColor = "#f39c12"; }
  else                                      { vtLevel = "Clean";       vtColor = "#27ae60"; }

  // Direct link to the full VirusTotal report
  const vtURL = `https://www.virustotal.com/gui/url/${btoa(url).replace(/=/g, "")}/detection`;

  return {
    malicious,
    suspicious,
    harmless,
    undetected,
    total,
    vtLevel,
    vtColor,
    vtURL
  };
}
