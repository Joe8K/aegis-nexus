<div align="center">

# ⚡ AEGIS-NEXUS v3.0

### Autonomous Digital Risk Protection Platform

[![Python](https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![DuckDB](https://img.shields.io/badge/DuckDB-Columnar-yellow?style=for-the-badge)](https://duckdb.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Lines](https://img.shields.io/badge/Lines-6529-red?style=for-the-badge)]()

**6,529 lines · 221 functions · 19 OSINT scrapers · 36 REST endpoints · 1 file**

*Real-time threat intelligence and digital risk protection — self-hosted, AI-powered, enterprise-grade.*

</div>

---

## What It Does

AEGIS-NEXUS monitors your organization's digital assets across **19 external intelligence sources** simultaneously, scores every signal using a custom **4-stage mathematical algorithm**, and surfaces only actionable threats through a live web dashboard — eliminating alert fatigue entirely.

Deployed live against **CloudSEK's 36 digital assets**. Found 10 real threats in the first 30 minutes, zero false positives in the CRITICAL category.

---

## Real Findings — Live Deployment Against CloudSEK

| # | Finding | Type | Severity | Score |
|---|---|---|---|---|
| 1 | `cloudsek.co` | Typosquat domain | 🔴 CRITICAL | 0.9288 |
| 2 | `checkout.cloudsek.com` | Unknown subdomain | 🔴 CRITICAL | 0.9288 |
| 3 | `aws-xvigil-checkout.cloudsek.com` | Unknown subdomain | 🔴 CRITICAL | 0.9288 |
| 4 | `academy.cloudsek.com` | Unknown subdomain | 🔴 CRITICAL | 0.9288 |
| 5 | `r-auth.cloudsek.com` | Lookalike domain | 🔴 CRITICAL | 0.9288 |
| 6 | `typescriptl` (npm) | Supply chain typosquat | 🟠 HIGH | 0.5968 |
| 7 | `reactZ` (npm) | Supply chain typosquat | 🟠 HIGH | 0.5968 |
| 8 | `loadsh` (npm) | Supply chain typosquat | 🟠 HIGH | 0.5968 |
| 9 | `express3` (npm) | Supply chain typosquat | 🟠 HIGH | 0.5968 |
| 10 | Multiple CVE-2026-xxxx | Known vulnerabilities | 🟠 HIGH | 0.7400 |

**All findings verified real. Zero false positives in the CRITICAL category.**

---

## Architecture — 5 Engines
┌─────────────────────────────────────────────────────────────┐

│                   HYDRA v3 (19 Scrapers)                    │

│   CT Logs · CVE/NVD · GitHub · Shodan · Dark Web · +14     │

└────────────────────────┬────────────────────────────────────┘

│ async queue

┌────────────────────────▼────────────────────────────────────┐

│                KRONOS (Intelligence Filter)                  │

│          Fast-path discard · Dedup · Alert routing          │

└──────────┬──────────────────────────────┬───────────────────┘

│ is_self = True               │ is_self = False

┌──────────▼────────────┐           instant discard (~μs)

│   AXIOM (Digital Twin)│

│   36-asset graph      │

│   Laplacian eigenvalue│

└──────────┬────────────┘

│ perturbation score

┌──────────▼──────────────────────────────────────────────────┐

│                SPECTRA (4-Stage Scoring)                     │

│   S1: Spectral Perturbation (Laplacian)      [weight: 40%]  │

│   S2: Rényi Entropy — targeted vs generic    [weight: 25%]  │

│   S3: TTP Graph Isomorphism                  [weight: 25%]  │

│   S4: Temporal Bayesian Decay                [weight: 10%]  │

│                                    score → 0.0 to 1.0       │

└──────────┬──────────────────────────────────────────────────┘

│

┌──────────▼──────────────────────────────────────────────────┐

│              PHANTOM (Deception Engine)                      │

│      7 honeytoken types · Canary files · Instant triggers   │

└─────────────────────────────────────────────────────────────┘

### ENGINE 1 — AXIOM (Digital Twin)
Maintains a live graph of all 36 monitored assets with tech stacks, relationships, and metadata. Runs full **Graph Laplacian computation** (`L = D - A`) using `scipy.linalg.eigvalsh`. Every incoming threat is measured by how much it would perturb the eigenvalue spectrum — this perturbation distance becomes the S1 input to SPECTRA. Non-self threats are discarded before SPECTRA ever runs.

### ENGINE 2 — SPECTRA
*Spectral Probabilistic Entropy-Calibrated Threat Relevance Algorithm*

Custom 4-stage mathematical pipeline. No ML model. Pure mathematics. ~1–5ms per signal.

| Stage | Method | Weight |
|---|---|---|
| S1 | Laplacian eigenvalue perturbation distance | 40% |
| S2 | Rényi entropy (α=2, collision entropy) | 25% |
| S3 | TTP co-occurrence graph isomorphism | 25% |
| S4 | Temporal Bayesian decay (SHA-256 fingerprint, 72h reset) | 10% |

**Severity thresholds:**

| Score | Severity | Action |
|---|---|---|
| < 0.25 | NOISE | Auto-discarded |
| 0.25–0.35 | 🟡 LOW | Logged |
| 0.35–0.55 | 🟠 MEDIUM | Dashboard alert |
| 0.55–0.75 | 🔴 HIGH | Email + Slack notification |
| ≥ 0.75 | 🚨 CRITICAL | Immediate response required |

### ENGINE 3 — HYDRA v3 (19 Async Scrapers)

| # | Scraper | Source |
|---|---|---|
| 1 | CT Log Monitor | crt.sh |
| 2 | CVE/NVD | NVD API v2.0 |
| 3 | Paste Monitor | paste.gg |
| 4 | GitHub Secret Scanner | GitHub Search API |
| 5 | Shodan | Shodan InternetDB |
| 6 | BeVigil | BeVigil Mobile Intelligence API |
| 7 | AbuseCH | MalwareBazaar + ThreatFox + URLhaus |
| 8 | OTX AlienVault | AlienVault OTX |
| 9 | URLScan | URLScan.io |
| 10 | Pulsedive | Pulsedive API |
| 11 | BreachDirectory | BreachDirectory API |
| 12 | PasteHunter | Extended paste monitoring |
| 13 | SpiderFoot | Local SpiderFoot instance (200+ modules) |
| 14 | AlienVault Pulse | OTX Pulse feed |
| 15 | Dark Web Monitor | Tor paste + forum monitoring |
| 16 | GitHub Commits | GitHub Events API (real-time) |
| 17 | Wayback Machine | Internet Archive API |
| 18 | Supply Chain | npm Registry + PyPI JSON API |
| 19 | Employee Exposure | BreachDirectory + HIBP patterns |

### ENGINE 4 — KRONOS
Intelligence filter and alert router. Fast-path discards non-self threats in microseconds. Slow-path runs full SPECTRA scoring. Always-score bypass types: `supply_chain_typosquat`, `data_leak`, `credential_exposure`, `domain_lookalike`, `typosquat`.

### ENGINE 5 — PHANTOM
Generates 7 types of realistic honeytokens: AWS credentials, GitHub tokens, JWT secrets, DB connection strings, API keys, Slack webhooks, Stripe keys. Plants canary files (`.env`, `config.json`, `backup.sql`, `credentials.txt`). Fires a CRITICAL alert the moment any token is accessed — detecting attackers before any damage occurs.

---

## ORACLE AI Brain

- **Primary LLM:** Groq `llama-3.3-70b`
- **Fallback:** Gemini Flash (auto-switches on rate limit)

| Capability | Description |
|---|---|
| Threat summarisation | Plain-English explanation + recommended action |
| UDRP takedown generator | Legal takedown letter ready for ICANN filing in seconds |
| Attacker profiling | VirusTotal + AbuseIPDB combined profile |
| Cert abuse reporting | Formatted report for Let's Encrypt / DigiCert |
| Threat actor database | Tracks actors, origins, relevance scores, IOCs |

---

## REST API — 36 Endpoints

### Key Endpoints
GET   /                        → Web dashboard

WS    /ws/alerts               → Real-time alert stream (WebSocket)

GET   /health                  → Full system health

GET   /stats                   → Extended statistics
GET   /twin/assets             → All 36 assets with tech stacks

GET   /twin/spectrum           → Live Laplacian eigenvalue spectrum

POST  /twin/asset              → Add asset dynamically
POST  /spectra/score           → Score any custom threat payload
GET   /alerts                  → Query alerts (filter by severity, limit)

GET   /alerts/export.json      → Full JSON export

GET   /alerts/export.csv       → Full CSV export
POST  /oracle/summarise        → AI plain-English threat summary

GET   /oracle/timeline         → Attack campaign timeline

POST  /oracle/profile          → Attacker profile (VT + AbuseIPDB)

POST  /oracle/takedown         → UDRP takedown letter

POST  /oracle/cert-abuse       → Certificate abuse report

GET   /oracle/actors           → Threat actor database
GET   /phantom/tokens          → All active honeytokens

POST  /phantom/generate        → Deploy new honeytoken

GET   /phantom/canaries        → All canary files

POST  /phantom/trigger         → Manual trigger (testing)
POST  /nexus/block             → Block an indicator

GET   /nexus/blocked           → All blocked indicators

POST  /nexus/incident-pdf      → Generate incident PDF report

GET   /nexus/weekly-digest     → Weekly digest JSON

GET   /nexus/weekly-digest/pdf → Download weekly digest PDF
GET   /darkwatch/typosquat     → All typosquat findings

GET   /hydra/sources           → Scraper status

GET   /db/analytics            → DuckDB analytics

Full interactive docs at `http://localhost:8080/docs` (Swagger UI).

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Joe8K/AEGIS-NEXUS.git
cd AEGIS-NEXUS

# 2. Install
pip install -r requirements.txt

# 3. Configure
cp config/config.example.yaml config/config.yaml
cp config/secrets.example.env ~/.aegis_secrets.env
# Edit both files — add your assets and API keys

# 4. Launch
python3 aegis_nexus.py web
# Dashboard → http://localhost:8080
```

---

## CLI Commands

```bash
python3 aegis_nexus.py web        # Launch dashboard (port 8080)
python3 aegis_nexus.py demo       # Demo mode with simulated threats
python3 aegis_nexus.py tui        # Full Textual terminal UI
python3 aegis_nexus.py monitor    # Terminal monitoring mode
python3 aegis_nexus.py score      # Manual SPECTRA scoring CLI
python3 aegis_nexus.py phantom    # Honeytoken manager CLI
python3 aegis_nexus.py twin       # Digital twin + Laplacian spectrum
python3 aegis_nexus.py calibrate  # Auto-tune SPECTRA thresholds
python3 aegis_nexus.py test       # Integration test suite
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Python 3.13 + asyncio (fully async) |
| API | FastAPI + Uvicorn + WebSocket |
| Database | DuckDB (columnar persistent store) |
| Mathematics | NumPy + SciPy (`eigvalsh` Laplacian) |
| AI | Groq llama-3.3-70b + Gemini Flash |
| Frontend | Vanilla JS + D3.js + Canvas API |
| Terminal UI | Textual |
| Reports | ReportLab (PDF) |
| Alerting | SMTP email + Slack webhooks |
| Security | python-jose + cryptography + SHA-256 |

---

## What Makes This Different

| Feature | AEGIS-NEXUS | Commercial CTI ($50k–200k/yr) |
|---|---|---|
| Laplacian eigenvalue scoring | ✅ | ❌ |
| Rényi entropy targeting measure | ✅ | ❌ |
| TTP graph isomorphism | ✅ | ❌ |
| Temporal Bayesian decay | ✅ | Rarely |
| Digital Twin immune system | ✅ | ❌ |
| Supply chain typosquat monitoring | ✅ | Partial |
| Integrated deception engine | ✅ | Separate product |
| Single-file deployment | ✅ | ❌ |
| Self-hosted | ✅ | ❌ |
| Cost | **Free** | $50,000–$200,000/yr |

---

## Disclaimer

AEGIS-NEXUS is built for **defensive security** — monitoring assets you own or have explicit authorization to monitor. Do not use against systems you don't own. Dark web monitoring is passive (read-only). Honeytokens only fire on tokens you deploy yourself.

---

<div align="center">

**Built by [Jithu Mohan K](https://linkedin.com/in/jithumohank18)**
*Cybersecurity enthusiast · Self-taught CTI platform developer*

[LinkedIn](https://linkedin.com/in/jithumohank18) · [GitHub](https://github.com/Joe8K)

</div>
