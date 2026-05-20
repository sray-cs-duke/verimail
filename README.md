# Verimail 📧

A Python tool for detecting phishing and fake emails using heuristic analysis. Verimail inspects email content, sender address, embedded links, and attachments to produce a suspicion score and classify the email as **Safe**, **Suspicious**, or **Fake**.

---

## Features

- **Content analysis** — scans subject and body for common phishing phrases and suspicious formatting
- **Sender analysis** — flags mismatched or untrusted email domains
- **Link analysis** — extracts and inspects URLs for suspicious domains
- **Attachment analysis** — detects potentially dangerous file types (`.exe`, `.zip`, etc.)
- **Two input modes** — analyse a `.eml` file directly, or paste email content manually

---

## How it works

Each analysis module returns a suspicion score. The scores are summed and the email is classified:

| Score | Classification |
|-------|---------------|
| 0 – 39 | ✅ Safe |
| 40 – 69 | ⚠️ Suspicious |
| 70+ | 🚨 Likely Fake |

---

## Getting started

### Prerequisites

- Python 3.7+
- Install dependencies:

```bash
pip install requests beautifulsoup4
```

### Run the tool

```bash
python Verimail.py
```

You'll be prompted to either:
1. Provide a path to a `.eml` email file
2. Enter email details manually (subject, sender, body)

### Example output

```
Welcome to the Fake Email Detection Tool
> Choose an option: 1
> Enter path to .eml file: sample.eml

Subject: Urgent: Your account has been compromised
From: support@micros0ft-login.com

Suspicious phrase detected: urgent
Suspicious phrase detected: your account has been compromised
Suspicious email domain: micros0ft-login.com
Suspicious domain detected: micros0ft-login.com

Total Suspicion Score: 90/100
This email is likely FAKE.
```

---

## Project structure

```
Verimail/
├── Verimail.py       # Main script
└── README.md
```

---

## Limitations & future improvements

- Trusted domain list is currently hardcoded — could be replaced with an external allowlist or API
- No machine learning component yet — scoring is rule-based
- Could be extended into a web app or browser extension

---

## Built with

- Python standard library (`email`, `re`, `os`, `urllib`)
- [Requests](https://docs.python-requests.org/)
- [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/)
