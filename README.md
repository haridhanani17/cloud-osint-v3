# CloudOSINT Toolkit v3.0
### Advanced Cloud Reconnaissance Platform — 12 Real Modules

A production-grade, real-world cloud OSINT web dashboard built with Flask.
Dark hacker terminal UI. All modules perform real network requests against real APIs.

---

## What's Real

| Module | API/Source | Key Required | Cost |
|--------|-----------|-------------|------|
| CRT.sh Certificate Transparency | crt.sh | ❌ None | Free |
| Wayback Machine CDX | web.archive.org | ❌ None | Free |
| HackerTarget Host Search | api.hackertarget.com | ❌ None | Free (500/day) |
| DNS Brute Force | System resolvers | ❌ None | Free |
| Cloud Storage (AWS/Azure/GCP) | HTTP probe | ❌ None | Free |
| Firebase RTDB Probe | firebaseio.com | ❌ None | Free |
| Azure AD Tenant Discovery | login.microsoftonline.com | ❌ None | Free |
| GitHub OSINT | api.github.com | ✅ Optional | Free tier |
| VirusTotal Passive DNS | virustotal.com | ✅ Recommended | Free tier |
| Shodan Recon | api.shodan.io | ✅ Required | Free/Paid |
| Censys Intelligence | search.censys.io | ✅ Required | Free tier |
| AWS IAM Validation | boto3 STS | ✅ For testing | Free |

---

## Quick Start

### Linux / Mac
```bash
git clone <repo> && cd cloud-osint-v3
chmod +x run.sh
./run.sh
# Open http://127.0.0.1:5000
```

### Windows
```bat
run.bat
REM Open http://127.0.0.1:5000
```

### Manual
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

---

## API Key Setup

### 1. GitHub Token (Highly Recommended — Free)
- Go to: https://github.com/settings/tokens
- Click **Generate new token (classic)**
- Select scope: `public_repo` only (read-only is fine)
- Without token: 10 requests/hour. With token: 5,000/hour
- Paste into "GitHub Token" field in the dashboard

### 2. Shodan API Key (Recommended — Free tier available)
- Register at: https://shodan.io
- Go to: https://shodan.io/dashboard
- Copy the **API Key** shown on the page
- Free account: basic search, ~100 results/month
- Membership (~$65/yr): unlimited queries
- Paste into "Shodan API Key" field

### 3. Censys API (Free tier — 250 queries/month)
- Register at: https://censys.io
- Go to: https://censys.io/account/api
- Copy both **API ID** and **API Secret**
- Paste both into the corresponding sidebar fields

### 4. VirusTotal API Key (Free — 500 lookups/day)
- Register at: https://www.virustotal.com
- Go to: https://www.virustotal.com/gui/my-apikey
- Copy your API key
- Paste into "VirusTotal API Key" field

### 5. AWS IAM Testing (Optional — for testing found credentials)
```
⚠ ONLY USE ON KEYS YOU FOUND VIA YOUR OWN OSINT ON AUTHORIZED TARGETS
```
- If GitHub OSINT finds an AWS access key + secret in a public repo
- Paste them into "AWS Access Key" and "AWS Secret Key"
- The tool calls `sts.get_caller_identity()` to verify if they're valid
- If valid: reveals Account ID, ARN, and attempts to list S3 buckets
- Requires: `pip install boto3` (included in requirements.txt)

---

## Running Without Any API Keys (Passive Mode)

The following modules work 100% without any API keys:

```
✓ CRT.sh              — Finds subdomains from SSL certificate logs
✓ Wayback Machine     — Mines archived URLs for subdomain discovery  
✓ HackerTarget        — Free host search API (500 queries/day)
✓ DNS Brute Force     — 80-word wordlist against live DNS resolvers
✓ Cloud Storage       — Probes 168 URL patterns across AWS/Azure/GCP
✓ Firebase RTDB       — Checks 5 Firebase endpoint patterns
✓ Azure AD Discovery  — Queries Microsoft OpenID config endpoint
```

This passive-only mode is already more capable than most free OSINT tools.

---

## Dashboard Features

- **Real-time terminal** — Server-Sent Events stream scan output live
- **12-phase tracker** — Visual grid showing each module's status
- **Risk scoring** — 0–100 weighted score based on severity of findings
- **Critical findings** — Auto-extracts top risks to sidebar panel
- **5 result tabs** — Subdomains / Live Hosts / Storage / GitHub / Shodan
- **Azure+GCP+AWS tab** — Combined cloud provider intelligence
- **Censys tab** — Certificate + host intelligence
- **Export** — JSON report, CSV export, standalone HTML report
- **In-app Setup Guide** — Step-by-step API key setup inside the app

---

## Architecture

```
cloud-osint-v3/
├── app.py              Flask backend + 12 scan modules
├── requirements.txt    Dependencies (flask, requests, dnspython, boto3)
├── run.sh              Linux/Mac launcher with venv setup
├── run.bat             Windows launcher
└── templates/
    └── index.html      Full hacker dashboard UI (SSE, real-time)
```

---

## Legal Disclaimer

```
THIS TOOL IS FOR AUTHORIZED SECURITY TESTING AND RESEARCH ONLY.

✓ Your own domains and infrastructure
✓ Authorized penetration testing engagements (with written permission)
✓ Bug bounty programs (within defined scope)

✗ Any domain you don't own or don't have written permission to test
✗ Government, military, or critical infrastructure
✗ Production systems without explicit authorization

Unauthorized use may violate:
- Computer Fraud and Abuse Act (CFAA) — United States
- Computer Misuse Act — United Kingdom  
- IT Act 2000 — India
- GDPR — European Union
- And other national cybercrime laws

The authors assume ZERO liability for misuse.
```
