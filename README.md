# WebVerity
> **Intelligent Phishing Detection & Website Trust Assessment.**

WebVerity is an accessible, multi-layered cybersecurity platform that detects phishing infrastructure and evaluates website trustworthiness through deterministic feature extraction, DNS configuration analysis, cryptographic TLS certificate validation, and explainable rule-based risk scoring.

---

## Problem
Phishing remains the primary initial access vector in modern cyberattacks, accounting for catastrophic financial loss, credential theft, and ransomware deployment. Modern threat actors leverage ephemeral cloud infrastructure, typosquatting domains, punycode homographs, and disposable TLS certificates to impersonate trusted institutions. Traditional blacklists suffer from critical latency gaps, leaving users unprotected during the initial hours of a zero-day phishing campaign.

## Solution
WebVerity tackles this challenge through active, multi-layer verification performed immediately upon URL submission:
1. **URL Structural & Lexical Analysis:** Evaluates hostname entropy, subdomain depth, suspicious keywords, punycode encoding, embedded credentials, and obfuscated character encodings.
2. **DNS & Infrastructure Inspection:** Resolves IPv4/IPv6 address records, CNAME chains, mail exchanger (MX) presence, and nameservers.
3. **Cryptographic TLS Analysis:** Conducts an active TLS handshake against a validated public IP with Server Name Indication (SNI), verifying system trust-store chains, certificate validity dates, subject alternative names (SANs), cipher suites, and key strengths.
4. **Hardened SSRF Defenses:** Enforces strict IP address validation preventing internal network pivoting, DNS rebinding attacks, and cloud metadata access.
5. **Explainable Risk Scoring:** Provides a transparent heuristic score (0–100) and confidence rating with itemized, human-readable evidence.

---

## Tech Stack
- **Language:** Python 3.11+
- **API Framework:** FastAPI, Uvicorn (ASGI)
- **Data Validation:** Pydantic v2, Pydantic-Settings
- **DNS Resolution:** dnspython
- **Cryptography & Security:** Python `cryptography`, `ssl`, `ipaddress`, `socket`
- **Database & ORM:** SQLAlchemy 2.x (SQLite for local development; PostgreSQL/Supabase compatible)
- **HTTP Client:** HTTPX
- **Quality & Testing:** Pytest, Pytest-Asyncio, Ruff

---

## Architecture

The Day 1 synchronous API orchestrates an asynchronous security pipeline:

```
URL Submission (POST /api/v1/scans)
       │
       ▼
Input Validation & Normalization ──► Rejects non-HTTP(S), invalid ports, embedded credentials
       │
       ▼
SSRF Guard ──► Rejects private/loopback/link-local/metadata IPs & hostnames
       │
       ▼
Parallel Module Execution (Async Worker Threads)
  ├─► URL Feature Extraction (Entropy, keywords, subdomains, punycode)
  ├─► DNS Infrastructure Analysis (A, AAAA, CNAME, NS, MX, TXT records)
  └─► TLS Certificate Handshake (Pinned destination IP, SNI, X.509 validation)
       │
       ▼
Evidence Aggregator ──► Consolidates findings and normalizes module statuses
       │
       ▼
Rule-Based Risk Scoring ──► 0-100 Threat Score (URL: 50%, DNS: 25%, TLS: 25%)
       │
       ▼
Database Persistence ──► SQLAlchemy 2.x / SQLite scan record
       │
       ▼
API Response (ScanResponse)
```

---

## Setup and Run

### 1. Prerequisites
- Python 3.11 or newer
- Git

### 2. Clone and Setup Environment
```bash
git clone <repository-url>
cd WebVerity

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt
```

### 3. Environment Configuration
Copy the template configuration:
```bash
cp backend/.env.example backend/.env
```

Default settings in `.env.example`:
```env
APP_NAME=WebVerity
APP_ENV=development
APP_VERSION=0.1.0
DEBUG=true
DATABASE_URL=sqlite:///./webverity.db
CORS_ORIGINS=["http://localhost:3000","http://localhost:8000","http://127.0.0.1:3000","http://127.0.0.1:8000"]
DNS_TIMEOUT=3.0
TLS_TIMEOUT=4.0
SCAN_PIPELINE_TIMEOUT=10.0
```

### 4. Running the Application
From the repository root:
```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Access Interactive Documentation
Open your browser to:
- **Swagger UI:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Health Check:** [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)

### 6. Running Tests & Linting
```bash
# Run pytest test suite (49 automated tests)
pytest -v

# Run ruff code linter
ruff check .

# Run ruff code formatter
ruff format --check .
```

---

## Disclosures
- **Third-Party Dependencies:** All external libraries (`fastapi`, `uvicorn`, `pydantic`, `cryptography`, `dnspython`, `sqlalchemy`, `httpx`, `pytest`, `ruff`) are free and open-source software under permissive licenses (MIT, Apache-2.0, BSD).
- **AI-Assisted Development:** Built with pair-programming assistance from Antigravity (Google DeepMind). All architecture decisions, security boundaries, and code implementations were systematically reviewed, hardened, and verified with automated test suites.

---

## Track
`[TRACK / PROBLEM STATEMENT IDENTIFIER TO BE ENTERED BY TEAM]`
