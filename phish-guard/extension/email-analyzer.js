// ============================================================
// email-analyzer.js — PERSON B's file (No API version)
// Analyzes emails using local rule-based checks.
// No internet connection needed, no API key, works offline.
// ============================================================

// ── Urgency words that phishing emails love to use ──
const URGENCY_WORDS = [
  "urgent", "immediately", "act now", "right away", "as soon as possible",
  "within 24 hours", "within 48 hours", "account suspended", "account locked",
  "unusual activity", "suspicious activity", "verify now", "limited time",
  "expires soon", "final notice", "last chance", "action required"
];

// ── Words that signal a request for sensitive info ──
const SENSITIVE_REQUESTS = [
  "social security", "ssn", "credit card", "debit card", "card number",
  "bank account", "routing number", "password", "pin number",
  "date of birth", "mother's maiden", "security question",
  "verify your identity", "confirm your details", "update your information",
  "provide your", "enter your"
];

// ── Free email providers — red flag if a "company" uses these ──
const FREE_EMAIL_PROVIDERS = [
  "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
  "aol.com", "icloud.com", "protonmail.com", "mail.com"
];

// ── Generic greetings that indicate mass phishing ──
const GENERIC_GREETINGS = [
  "dear customer", "dear user", "dear account holder", "dear member",
  "dear client", "hello user", "dear valued customer", "greetings"
];

// ── Top brands that are commonly impersonated ──
const POPULAR_BRANDS = [
  "paypal", "apple", "amazon", "google", "microsoft", "netflix",
  "facebook", "instagram", "twitter", "bank of america", "chase",
  "wells fargo", "citibank", "irs", "fedex", "ups", "dhl"
];

// ──────────────────────────────────────────────────
// HELPER: Extract the domain from an email address
// e.g. "support@paypal.com" → "paypal.com"
// ──────────────────────────────────────────────────
function extractEmailDomain(email) {
  const match = email.match(/@([\w.-]+)/);
  return match ? match[1].toLowerCase() : null;
}

// ──────────────────────────────────────────────────
// HELPER: Extract all URLs from a block of text
// ──────────────────────────────────────────────────
function extractURLs(text) {
  const urlPattern = /https?:\/\/[^\s"'<>]+/gi;
  return text.match(urlPattern) || [];
}

// ──────────────────────────────────────────────────
// CHECK 1: Is the sender using a free email provider?
// A real company (PayPal, Apple) won't email from gmail.com
// ──────────────────────────────────────────────────
function checkSenderDomain(emailText) {
  const fromMatch = emailText.match(/from\s*:?\s*([^\n\r]+)/i);
  if (!fromMatch) return { points: 0, reason: null };

  const fromLine = fromMatch[1].toLowerCase();
  const domain = extractEmailDomain(fromLine);
  if (!domain) return { points: 0, reason: null };

  const claimedBrand = POPULAR_BRANDS.find(brand => fromLine.includes(brand));
  const usingFreeMail = FREE_EMAIL_PROVIDERS.find(provider => domain === provider);

  if (claimedBrand && usingFreeMail) {
    return {
      points: 50,
      reason: `Sender claims to be "${claimedBrand}" but uses a free email provider (${domain})`
    };
  }

  return { points: 0, reason: null };
}

// ──────────────────────────────────────────────────
// CHECK 2: Does the subject line look suspicious?
// ──────────────────────────────────────────────────
function checkSubjectLine(emailText) {
  const subjectMatch = emailText.match(/subject\s*:?\s*([^\n\r]+)/i);
  if (!subjectMatch) return { points: 0, reason: null };

  const subject = subjectMatch[1];
  const subjectLower = subject.toLowerCase();

  let points = 0;
  let reasons = [];

  if (subject === subject.toUpperCase() && subject.length > 5) {
    points += 20;
    reasons.push("Subject line is ALL CAPS");
  }

  const urgentWord = URGENCY_WORDS.find(w => subjectLower.includes(w));
  if (urgentWord) {
    points += 20;
    reasons.push(`Urgent subject line: "${urgentWord}"`);
  }

  const exclamations = (subject.match(/!/g) || []).length;
  if (exclamations >= 2) {
    points += 10;
    reasons.push(`Excessive exclamation marks in subject (${exclamations})`);
  }

  return {
    points,
    reason: reasons.length > 0 ? reasons.join("; ") : null
  };
}

// ──────────────────────────────────────────────────
// CHECK 3: Does the body use urgency language?
// ──────────────────────────────────────────────────
function checkUrgencyLanguage(emailText) {
  const lower = emailText.toLowerCase();
  const found = URGENCY_WORDS.filter(w => lower.includes(w));

  if (found.length >= 3) {
    return { points: 30, reason: `Heavy urgency language: "${found.slice(0, 3).join('", "')}"` };
  }
  if (found.length >= 1) {
    return { points: 15, reason: `Urgency language detected: "${found[0]}"` };
  }
  return { points: 0, reason: null };
}

// ──────────────────────────────────────────────────
// CHECK 4: Does the email ask for sensitive info?
// ──────────────────────────────────────────────────
function checkSensitiveRequests(emailText) {
  const lower = emailText.toLowerCase();
  const found = SENSITIVE_REQUESTS.filter(w => lower.includes(w));

  if (found.length >= 2) {
    return { points: 40, reason: `Requests sensitive information: "${found.slice(0, 2).join('", "')}"` };
  }
  if (found.length === 1) {
    return { points: 20, reason: `Requests sensitive information: "${found[0]}"` };
  }
  return { points: 0, reason: null };
}

// ──────────────────────────────────────────────────
// CHECK 5: Does the email use a generic greeting?
// Real companies usually know your name.
// ──────────────────────────────────────────────────
function checkGenericGreeting(emailText) {
  const lower = emailText.toLowerCase();
  const found = GENERIC_GREETINGS.find(g => lower.includes(g));

  if (found) {
    return { points: 15, reason: `Generic greeting: "${found}" (real companies use your name)` };
  }
  return { points: 0, reason: null };
}

// ──────────────────────────────────────────────────
// CHECK 6: Do links in the email match the sender?
// e.g. email claims to be PayPal but links go to evil.com
// ──────────────────────────────────────────────────
function checkMismatchedLinks(emailText) {
  const lower = emailText.toLowerCase();
  const urls = extractURLs(emailText);
  if (urls.length === 0) return { points: 0, reason: null };

  const claimedBrand = POPULAR_BRANDS.find(brand => lower.includes(brand));
  if (!claimedBrand) return { points: 0, reason: null };

  const suspiciousLinks = urls.filter(url => {
    try {
      const hostname = new URL(url).hostname.toLowerCase();
      return !hostname.includes(claimedBrand.replace(/\s/g, ""));
    } catch {
      return false;
    }
  });

  if (suspiciousLinks.length > 0) {
    return {
      points: 40,
      reason: `Claims to be "${claimedBrand}" but links point elsewhere: ${suspiciousLinks[0]}`
    };
  }
  return { points: 0, reason: null };
}

// ──────────────────────────────────────────────────
// CHECK 7: Are there suspicious URLs in the body?
// ──────────────────────────────────────────────────
function checkSuspiciousLinksInBody(emailText) {
  const urls = extractURLs(emailText);
  if (urls.length === 0) return { points: 0, reason: null };

  const suspiciousTLDs = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link"];
  const ipPattern = /https?:\/\/(\d{1,3}\.){3}\d{1,3}/;

  for (const url of urls) {
    if (ipPattern.test(url)) {
      return { points: 30, reason: `Link uses an IP address instead of a domain: ${url}` };
    }
    const badTLD = suspiciousTLDs.find(tld => url.includes(tld));
    if (badTLD) {
      return { points: 25, reason: `Link uses a suspicious domain extension (${badTLD}): ${url}` };
    }
  }

  return { points: 0, reason: null };
}

// ──────────────────────────────────────────────────
// MAIN FUNCTION: Run all checks and return results
// This is what popup.js calls.
// ──────────────────────────────────────────────────
function analyzeEmail(emailText) {
  if (!emailText || emailText.trim().length < 10) {
    return { error: "Please paste an email to analyze." };
  }

  const checks = [
    checkSenderDomain(emailText),
    checkSubjectLine(emailText),
    checkUrgencyLanguage(emailText),
    checkSensitiveRequests(emailText),
    checkGenericGreeting(emailText),
    checkMismatchedLinks(emailText),
    checkSuspiciousLinksInBody(emailText)
  ];

  const totalPoints = checks.reduce((sum, c) => sum + c.points, 0);
  const riskScore   = Math.min(totalPoints, 100);
  const redFlags    = checks.filter(c => c.reason !== null).map(c => c.reason);

  let riskLevel, color;
  if (riskScore >= 60)      { riskLevel = "High";   color = "#e74c3c"; }
  else if (riskScore >= 30) { riskLevel = "Medium"; color = "#f39c12"; }
  else                      { riskLevel = "Low";    color = "#27ae60"; }

  let verdict;
  if (riskScore >= 60) {
    verdict = "This email has multiple strong indicators of a phishing attempt. Do not click any links, do not provide any information, and delete it immediately.";
  } else if (riskScore >= 30) {
    verdict = "This email has some suspicious characteristics. Proceed with caution — verify the sender through official channels before clicking anything.";
  } else {
    verdict = "No major red flags detected. This email appears relatively safe, but always stay cautious with unexpected messages.";
  }

  const safeIndicators = [];
  if (redFlags.length === 0) safeIndicators.push("No suspicious patterns detected");
  if (!emailText.toLowerCase().includes("click here")) safeIndicators.push("No generic 'click here' links");
  if (extractURLs(emailText).length === 0) safeIndicators.push("No links in email body");

  return {
    riskScore,
    riskLevel,
    color,
    redFlags,
    safeIndicators,
    verdict,
    summary: `Risk score: ${riskScore}/100 — ${riskLevel} risk`
  };
}
