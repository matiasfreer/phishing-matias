// ============================================================
// scorer.js — PERSON B's file
// This file contains all the URL analysis logic.
// Each function checks one suspicious thing about a URL
// and returns a "risk points" number.
// ============================================================

// Popular domains to check for typosquatting (faking a real site)
const POPULAR_DOMAINS = [
  "google.com", "facebook.com", "apple.com", "microsoft.com",
  "amazon.com", "paypal.com", "netflix.com", "instagram.com",
  "twitter.com", "linkedin.com", "bankofamerica.com", "chase.com",
  "wellsfargo.com", "gmail.com", "yahoo.com", "dropbox.com"
];

// Suspicious words often found in phishing URLs
const PHISHING_KEYWORDS = [
  "login", "verify", "secure", "account", "update", "confirm",
  "banking", "signin", "password", "credential", "wallet",
  "suspend", "unusual", "alert", "validate"
];

// ── Check 1: Is the URL really long? (phishing URLs tend to be long) ──
function checkURLLength(url) {
  if (url.length > 100) return { points: 20, reason: "URL is suspiciously long" };
  if (url.length > 75)  return { points: 10, reason: "URL is quite long" };
  return { points: 0, reason: null };
}

// ── Check 2: Does it use an IP address instead of a domain name? ──
// Real sites use names like "google.com", not "192.168.1.1"
function checkIPAddress(url) {
  const ipPattern = /https?:\/\/(\d{1,3}\.){3}\d{1,3}/;
  if (ipPattern.test(url)) {
    return { points: 40, reason: "Uses an IP address instead of a domain name" };
  }
  return { points: 0, reason: null };
}

// ── Check 3: Does the URL contain suspicious keywords? ──
function checkSuspiciousKeywords(url) {
  const lowerURL = url.toLowerCase();
  const found = PHISHING_KEYWORDS.filter(word => lowerURL.includes(word));
  if (found.length >= 3) return { points: 30, reason: `Contains many suspicious keywords: ${found.join(", ")}` };
  if (found.length >= 1) return { points: 10 * found.length, reason: `Contains suspicious keywords: ${found.join(", ")}` };
  return { points: 0, reason: null };
}

// ── Check 4: Does it use HTTPS? (HTTP is unencrypted and risky) ──
function checkHTTPS(url) {
  if (url.startsWith("http://")) {
    return { points: 20, reason: "Does not use HTTPS (connection is not secure)" };
  }
  return { points: 0, reason: null };
}

// ── Check 5: Too many subdomains? (e.g. paypal.com.evil.com) ──
function checkSubdomains(url) {
  try {
    const hostname = new URL(url).hostname;
    const parts = hostname.split(".");
    // A normal domain has 2 parts (google.com) or 3 (www.google.com)
    if (parts.length > 4) return { points: 30, reason: `Excessive subdomains: ${hostname}` };
    if (parts.length > 3) return { points: 15, reason: `Multiple subdomains: ${hostname}` };
    return { points: 0, reason: null };
  } catch {
    return { points: 0, reason: null };
  }
}

// ── Check 6: Too many special characters? (@, -, //, etc.) ──
function checkSpecialChars(url) {
  const atSymbol   = (url.match(/@/g) || []).length;
  const doubleDash = (url.match(/\/\//g) || []).length - 1; // first // is normal
  const hyphenCount = (url.match(/-/g) || []).length;

  let points = 0;
  let reasons = [];

  if (atSymbol > 0)      { points += 30; reasons.push("contains @ symbol"); }
  if (doubleDash > 0)    { points += 20; reasons.push("contains double slashes"); }
  if (hyphenCount > 3)   { points += 10; reasons.push("many hyphens in domain"); }

  return {
    points,
    reason: reasons.length > 0 ? `Suspicious characters: ${reasons.join(", ")}` : null
  };
}

// ── Check 7: Is it trying to impersonate a real website? ──
// This is called "typosquatting" — e.g. "gooogle.com" instead of "google.com"
function checkTyposquatting(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();

    for (const domain of POPULAR_DOMAINS) {
      if (hostname === domain) return { points: 0, reason: null }; // it IS the real domain

      const domainName = domain.split(".")[0]; // e.g. "google" from "google.com"
      const hostParts  = hostname.replace(/^www\./, "");

      // Check if it contains the brand name but isn't the real domain
      if (hostParts.includes(domainName) && hostParts !== domain) {
        return {
          points: 40,
          reason: `May be impersonating "${domain}" (typosquatting)`
        };
      }
    }
    return { points: 0, reason: null };
  } catch {
    return { points: 0, reason: null };
  }
}

// ── MAIN FUNCTION: Run all checks and return a final score + reasons ──
function analyzeURL(url) {
  // Make sure the URL has a protocol so we can parse it
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }

  const checks = [
    checkURLLength(url),
    checkIPAddress(url),
    checkSuspiciousKeywords(url),
    checkHTTPS(url),
    checkSubdomains(url),
    checkSpecialChars(url),
    checkTyposquatting(url)
  ];

  // Add up all risk points
  const totalPoints = checks.reduce((sum, c) => sum + c.points, 0);

  // Collect only the reasons that triggered (non-null)
  const reasons = checks.filter(c => c.reason !== null).map(c => c.reason);

  // Cap score at 100
  const score = Math.min(totalPoints, 100);

  // Assign a risk level
  let level, color;
  if (score >= 60)      { level = "High Risk 🔴";    color = "#e74c3c"; }
  else if (score >= 30) { level = "Medium Risk 🟡";  color = "#f39c12"; }
  else                  { level = "Low Risk 🟢";      color = "#27ae60"; }

  return { score, level, color, reasons, url };
}
