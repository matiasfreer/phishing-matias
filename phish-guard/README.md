# 🛡 PhishGuard — Hackathon Build Guide

A Chrome Extension that detects phishing URLs and suspicious emails using AI.

---

## 📁 File Map — Who Owns What

```
extension/
├── manifest.json       ← Config file (touch once, don't change)
├── popup.html          ← PERSON A: The visual UI
├── popup.js            ← PERSON A: UI logic & tab switching
├── scorer.js           ← PERSON B: URL analysis logic
└── email-analyzer.js   ← PERSON B: AI email analysis
```

---

## 🚀 STEP 1 — Get the project running (both of you, together)

### 1.1 Install VS Code
Download from: https://code.visualstudio.com

### 1.2 Clone / open the project
- Open VS Code
- File → Open Folder → select the `phish-guard` folder

### 1.3 Get your free Claude API key
1. Go to https://console.anthropic.com
2. Sign up (free)
3. Go to "API Keys" → Create a key
4. Copy it

### 1.4 Add the API key
- Open `email-analyzer.js`
- Find this line near the top:
  ```
  const ANTHROPIC_API_KEY = "YOUR_API_KEY_HERE";
  ```
- Replace `YOUR_API_KEY_HERE` with your actual key (keep the quotes)

### 1.5 Load the extension into Chrome
1. Open Chrome and go to: `chrome://extensions`
2. Turn on **Developer Mode** (top right toggle)
3. Click **"Load unpacked"**
4. Select the `extension` folder inside `phish-guard`
5. You should see PhishGuard appear with a shield icon 🛡

### 1.6 Test it!
- Click the PhishGuard icon in your Chrome toolbar
- It should auto-scan the current tab's URL
- Try the Email tab and paste any email text

---

## 👩‍💻 PERSON A — Your Tasks (UI & popup.js)

Your file is `popup.js`. It's already written but here's what to understand and improve:

### What it does:
1. When the popup opens → auto-scans the current URL
2. When you type a URL and hit Scan → scans that URL
3. When you click "Analyze with AI" → sends email to Claude API
4. Switches between the URL and Email tabs

### Things you can improve / customize:
- Change colors in `popup.html` (look for the `:root { }` CSS variables at the top)
- Change the extension name, icon, or layout in `popup.html`
- Add a "copy result" button
- Add a history of last 5 scanned URLs (store in `chrome.storage.local`)

### How to reload after changes:
Every time you change a file:
1. Go to `chrome://extensions`
2. Click the 🔄 reload button on PhishGuard
3. Close and reopen the popup

---

## 👨‍💻 PERSON B — Your Tasks (scorer.js & email-analyzer.js)

### scorer.js — URL checks
The file has 7 check functions. Each returns `{ points, reason }`.

**To add a new check:**
```javascript
// Example: flag URLs with too many query parameters
function checkQueryParams(url) {
  try {
    const params = new URL(url).searchParams;
    const count = [...params.keys()].length;
    if (count > 5) return { points: 15, reason: `Too many URL parameters (${count})` };
    return { points: 0, reason: null };
  } catch {
    return { points: 0, reason: null };
  }
}
```

Then add it to the `checks` array inside `analyzeURL()`:
```javascript
const checks = [
  checkURLLength(url),
  // ... existing checks ...
  checkQueryParams(url),  // ← add here
];
```

### email-analyzer.js — AI analysis
The prompt sent to Claude is inside the `analyzeEmail()` function.

**To improve the analysis**, edit the `prompt` variable to ask for more things:
```javascript
// Example additions to the prompt:
"- Check if the sender email domain matches the company name"
"- Look for urgency language like 'act now' or 'limited time'"
"- Flag requests for personal information"
```

---

## 🧪 Testing with Real Phishing Examples

Use these to test your scanner (these are known phishing patterns, safe to analyze):

**Suspicious URLs to try:**
```
http://paypa1.com/verify/account/login
http://192.168.1.1/bank/login
https://secure-login-google-account.verify-now.com/signin
https://amazon-account-suspended.support-alert.com
```

**Phishing email text to test (paste into Email tab):**
```
From: security@paypa1-support.com
Subject: URGENT: Your account has been suspended

Dear Customer,

We have detected unusual activity on your PayPal account. 
Your account access has been limited. To restore access, 
please click the link below and verify your information within 24 hours.

Click here: http://paypal-verify-account.tk/restore

You must provide your: full name, date of birth, credit card number, and SSN.

Failure to respond will result in permanent account closure.

PayPal Security Team
```

---

## 🐛 Common Problems & Fixes

| Problem | Fix |
|---|---|
| Extension doesn't appear | Make sure you selected the `extension` folder, not `phish-guard` |
| "Could not parse AI response" | Check your API key in `email-analyzer.js` |
| Changes not showing | Reload extension at `chrome://extensions` and reopen popup |
| "Network error" on email | Check that your API key is correct and has credits |
| Popup looks broken | Open Chrome DevTools: right-click popup → Inspect |

### How to open DevTools for the extension popup:
1. Right-click anywhere in the popup
2. Click "Inspect"
3. Check the **Console** tab for error messages (red text = errors)

---

## 🎯 Demo Tips for the Hackathon

1. **Open with a live demo** — have a phishing URL ready to scan on stage
2. **Show the email tab** — paste the sample phishing email above live
3. **Explain the scoring** — "we built 7 different checks that each add risk points"
4. **Mention the AI** — "the email analyzer uses Claude AI to reason about suspicious patterns"
5. **Talk about what you'd add next** — WHOIS API integration, ML model, etc.

---

## ✅ Progress Checklist

- [ ] API key added to `email-analyzer.js`
- [ ] Extension loaded in Chrome
- [ ] URL auto-scan works on current tab
- [ ] Manual URL scan works
- [ ] Email analysis returns results
- [ ] Tested with phishing examples above
- [ ] (Bonus) Added one extra URL check in scorer.js
- [ ] (Bonus) Customized the UI colors/design

Good luck! 🚀
