# SECORA — Secure ESG & Cyber Operations Risk Analyzer

AI-powered platform combining ESG monitoring, cybersecurity risk detection, and blockchain audit trails for green finance security.

## Tech Stack
- **Backend:** Python 3.12 + FastAPI + SQLite
- **ML Engine:** scikit-learn Isolation Forest (200 trees)
- **Blockchain:** SHA-256 hash chain with proof-of-work
- **Frontend:** React 18 + Chart.js (standalone HTML or connect to API)

## Quick Start

```bash
# 1. Install dependencies
cd backend
pip install -r requirements.txt

# 2. Generate demo dataset
python seed_data.py

# 3. Start the API server
uvicorn main:app --reload --port 8000

# 4. Run the one-click demo (in another terminal)
curl -X POST http://localhost:8000/api/demo | python -m json.tool

# 5. Open the dashboard
# Open secora-dashboard.html in a browser, click "Run Demo Analysis"
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/demo` | One-click demo: generates data + runs ML + returns results |
| POST | `/api/upload` | Upload a CSV dataset |
| POST | `/api/analyze/{dataset_id}` | Run Isolation Forest on a dataset |
| GET | `/api/results/{analysis_id}` | Get detailed results |
| GET | `/api/dashboard` | Aggregated stats for the frontend |
| GET | `/api/blockchain` | Full blockchain audit trail |
| GET | `/api/blockchain/verify` | Verify chain integrity |
| GET | `/api/datasets` | List uploaded datasets |
| GET | `/api/analyses` | List past analysis runs |

## CSV Format
Your ESG dataset should have some of these columns:
```
company_name, sector, country,
esg_score, environmental_score, social_score, governance_score,
carbon_emissions, energy_consumption, waste_generated, water_usage,
revenue, esg_spending, employee_count,
cyber_incidents, data_breaches, ransomware_attacks,
phishing_attempts, vulnerability_count, avg_patch_time_days,
compliance_score, security_budget
```
Minimum 3 numeric columns required. Missing values are filled with column medians.

## Project Structure
```
secora/
├── backend/
│   ├── main.py           # FastAPI app (all endpoints)
│   ├── ml_engine.py       # Isolation Forest pipeline
│   ├── blockchain.py      # SHA-256 audit chain
│   ├── database.py        # SQLite schema + helpers
│   ├── seed_data.py       # Synthetic data generator
│   └── requirements.txt
├── data/
│   └── demo_esg_dataset.csv
├── secora-dashboard.html  # React frontend
└── README.md
```

## Architecture (4 Layers)
1. **Database Layer** — SQLite: companies, cyber threats, risk scores, audit log
2. **ML Layer** — Isolation Forest anomaly detection + risk scoring (0–100)
3. **Backend Layer** — FastAPI REST APIs connecting all components
4. **Frontend Layer** — React dashboard with charts, tables, blockchain viewer
