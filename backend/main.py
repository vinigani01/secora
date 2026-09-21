"""
SECORA - Secure ESG & Cyber Operations Risk Analyzer
FastAPI Backend — REST API for data ingestion, ML analysis, and blockchain audit.

Run: uvicorn main:app --reload --port 8000
Docs: http://localhost:8000/docs
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import pandas as pd
import io
import json
from datetime import datetime

from database import init_db, get_connection
from ml_engine import SECORAEngine, ALL_FEATURES
from blockchain import AuditChain
from seed_data import generate_dataset

# ─── App Setup ───────────────────────────────────────────────
app = FastAPI(
    title="SECORA API",
    description="Secure ESG & Cyber Operations Risk Analyzer — AI-powered ESG fraud and cyber risk detection",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize on startup
@app.on_event("startup")
def startup():
    init_db()
    print("[SECORA] Backend ready")


# ─── Health Check ────────────────────────────────────────────
@app.get("/", tags=["System"])
def root():
    return {
        "name": "SECORA API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "endpoints": {
            "upload": "POST /api/upload",
            "analyze": "POST /api/analyze/{dataset_id}",
            "results": "GET /api/results/{analysis_id}",
            "dashboard": "GET /api/dashboard",
            "blockchain": "GET /api/blockchain",
            "demo": "POST /api/demo"
        }
    }


# ─── 1. UPLOAD ESG DATASET ──────────────────────────────────
@app.post("/api/upload", tags=["Data"])
async def upload_dataset(file: UploadFile = File(...)):
    """
    Upload a CSV file containing ESG + Cybersecurity data.
    Stores companies and cyber threat data in the database.
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(400, "Only CSV files are supported")

    contents = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(400, f"Failed to parse CSV: {str(e)}")

    if len(df) < 5:
        raise HTTPException(400, "Dataset must have at least 5 rows")

    conn = get_connection()

    # Create dataset record
    cursor = conn.execute(
        "INSERT INTO datasets (filename, row_count, column_count) VALUES (?, ?, ?)",
        (file.filename, len(df), len(df.columns))
    )
    dataset_id = cursor.lastrowid

    # Insert companies and cyber data
    company_ids = []
    for _, row in df.iterrows():
        c = conn.execute("""
            INSERT INTO companies
                (company_name, sector, country, esg_score, environmental_score,
                 social_score, governance_score, carbon_emissions, energy_consumption,
                 waste_generated, water_usage, revenue, esg_spending, employee_count, dataset_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            row.get("company_name", "Unknown"),
            row.get("sector", ""),
            row.get("country", ""),
            row.get("esg_score"),
            row.get("environmental_score"),
            row.get("social_score"),
            row.get("governance_score"),
            row.get("carbon_emissions"),
            row.get("energy_consumption"),
            row.get("waste_generated"),
            row.get("water_usage"),
            row.get("revenue"),
            row.get("esg_spending"),
            row.get("employee_count"),
            dataset_id
        ))
        company_id = c.lastrowid
        company_ids.append(company_id)

        # Insert cyber threat data if columns exist
        conn.execute("""
            INSERT INTO cyber_threats
                (company_id, cyber_incidents, data_breaches, ransomware_attacks,
                 phishing_attempts, vulnerability_count, avg_patch_time_days,
                 compliance_score, security_budget, has_ciso, last_audit_days_ago)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            company_id,
            row.get("cyber_incidents", 0),
            row.get("data_breaches", 0),
            row.get("ransomware_attacks", 0),
            row.get("phishing_attempts", 0),
            row.get("vulnerability_count", 0),
            row.get("avg_patch_time_days", 0),
            row.get("compliance_score", 0),
            row.get("security_budget", 0),
            row.get("has_ciso", 0),
            row.get("last_audit_days_ago", 0)
        ))

    conn.commit()

    # Blockchain audit
    chain = AuditChain()
    chain.add_block("DATASET_UPLOAD", {
        "dataset_id": dataset_id,
        "filename": file.filename,
        "rows": len(df),
        "columns": len(df.columns)
    })

    conn.close()

    return {
        "status": "success",
        "dataset_id": dataset_id,
        "companies_loaded": len(company_ids),
        "columns_found": list(df.columns),
        "recognized_features": [f for f in ALL_FEATURES if f in df.columns],
        "message": f"Upload complete. Run POST /api/analyze/{dataset_id} to detect anomalies."
    }


# ─── 2. RUN ANOMALY DETECTION ───────────────────────────────
@app.post("/api/analyze/{dataset_id}", tags=["Analysis"])
def run_analysis(dataset_id: int, contamination: float = Query(0.15, ge=0.01, le=0.5)):
    """
    Run Isolation Forest anomaly detection on a dataset.
    contamination = expected % of anomalies (default 15%).
    """
    conn = get_connection()

    # Fetch companies for this dataset
    companies = conn.execute(
        "SELECT * FROM companies WHERE dataset_id = ?", (dataset_id,)
    ).fetchall()

    if not companies:
        conn.close()
        raise HTTPException(404, f"No data found for dataset_id={dataset_id}")

    # Also fetch cyber data
    company_ids = [c["id"] for c in companies]
    cyber_data = {}
    for cid in company_ids:
        row = conn.execute(
            "SELECT * FROM cyber_threats WHERE company_id = ?", (cid,)
        ).fetchone()
        if row:
            cyber_data[cid] = dict(row)

    # Build DataFrame for ML
    records = []
    for c in companies:
        rec = dict(c)
        cid = c["id"]
        if cid in cyber_data:
            rec.update(cyber_data[cid])
        records.append(rec)

    df = pd.DataFrame(records)

    # Run ML pipeline
    engine = SECORAEngine(contamination=contamination)
    try:
        analysis = engine.detect_anomalies(df)
    except ValueError as e:
        conn.close()
        raise HTTPException(400, str(e))

    # Store analysis run
    summary = analysis["summary"]
    cursor = conn.execute("""
        INSERT INTO analysis_runs
            (dataset_id, total_companies, anomalies_found, avg_risk_score,
             model_contamination, features_used, run_duration_ms)
        VALUES (?,?,?,?,?,?,?)
    """, (
        dataset_id,
        summary["total_companies"],
        summary["anomalies_found"],
        summary["avg_risk_score"],
        contamination,
        json.dumps(summary["features_used"]),
        summary["run_duration_ms"]
    ))
    analysis_id = cursor.lastrowid

    # Store per-company results
    for i, result in enumerate(analysis["results"]):
        company_id = company_ids[i] if i < len(company_ids) else None
        conn.execute("""
            INSERT INTO anomaly_results
                (company_id, is_anomaly, anomaly_score, risk_score, risk_level, flags, analysis_id)
            VALUES (?,?,?,?,?,?,?)
        """, (
            company_id,
            result["is_anomaly"],
            result["anomaly_score"],
            result["risk_score"],
            result["risk_level"],
            json.dumps(result["flags"]),
            analysis_id
        ))

    conn.commit()

    # Blockchain audit
    chain = AuditChain()
    chain.add_block("ANALYSIS_RUN", {
        "analysis_id": analysis_id,
        "dataset_id": dataset_id,
        "anomalies_found": summary["anomalies_found"],
        "avg_risk_score": summary["avg_risk_score"]
    })

    conn.close()

    return {
        "status": "success",
        "analysis_id": analysis_id,
        "summary": summary,
        "anomalies": [r for r in analysis["results"] if r["is_anomaly"] == 1],
        "message": f"Detected {summary['anomalies_found']} anomalies out of {summary['total_companies']} companies."
    }


# ─── 3. GET RESULTS ─────────────────────────────────────────
@app.get("/api/results/{analysis_id}", tags=["Analysis"])
def get_results(analysis_id: int):
    """Get detailed results for a specific analysis run."""
    conn = get_connection()

    run = conn.execute(
        "SELECT * FROM analysis_runs WHERE id = ?", (analysis_id,)
    ).fetchone()
    if not run:
        conn.close()
        raise HTTPException(404, "Analysis run not found")

    results = conn.execute("""
        SELECT ar.*, c.company_name, c.sector, c.country, c.esg_score,
               c.carbon_emissions, c.revenue
        FROM anomaly_results ar
        JOIN companies c ON ar.company_id = c.id
        WHERE ar.analysis_id = ?
        ORDER BY ar.risk_score DESC
    """, (analysis_id,)).fetchall()

    conn.close()

    return {
        "run": dict(run),
        "results": [dict(r) for r in results],
        "anomalies_only": [dict(r) for r in results if r["is_anomaly"] == 1]
    }


# ─── 4. DASHBOARD AGGREGATES ────────────────────────────────
@app.get("/api/dashboard", tags=["Dashboard"])
def get_dashboard():
    """Get aggregated stats for the React dashboard."""
    conn = get_connection()

    # Latest analysis run
    latest_run = conn.execute(
        "SELECT * FROM analysis_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()

    if not latest_run:
        conn.close()
        return {"message": "No analysis runs yet. Upload data and run analysis first."}

    analysis_id = latest_run["id"]

    # All results for latest run
    results = conn.execute("""
        SELECT ar.*, c.company_name, c.sector, c.country, c.esg_score,
               c.environmental_score, c.social_score, c.governance_score,
               c.carbon_emissions, c.revenue, c.esg_spending,
               ct.cyber_incidents, ct.data_breaches, ct.vulnerability_count,
               ct.compliance_score
        FROM anomaly_results ar
        JOIN companies c ON ar.company_id = c.id
        LEFT JOIN cyber_threats ct ON c.id = ct.company_id
        WHERE ar.analysis_id = ?
        ORDER BY ar.risk_score DESC
    """, (analysis_id,)).fetchall()

    results_list = [dict(r) for r in results]

    # Sector-wise risk
    sector_risk = {}
    for r in results_list:
        sector = r.get("sector", "Unknown")
        if sector not in sector_risk:
            sector_risk[sector] = {"total": 0, "anomalies": 0, "avg_risk": 0, "scores": []}
        sector_risk[sector]["total"] += 1
        sector_risk[sector]["scores"].append(r["risk_score"])
        if r["is_anomaly"]:
            sector_risk[sector]["anomalies"] += 1

    for s in sector_risk:
        scores = sector_risk[s]["scores"]
        sector_risk[s]["avg_risk"] = round(sum(scores) / len(scores), 2)
        del sector_risk[s]["scores"]

    # Risk distribution
    risk_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results_list:
        risk_dist[r["risk_level"]] = risk_dist.get(r["risk_level"], 0) + 1

    # Top threats
    top_threats = sorted(results_list, key=lambda x: x["risk_score"], reverse=True)[:10]

    # Blockchain status
    chain = AuditChain()
    chain_status = chain.verify_chain()

    # Dataset count
    dataset_count = conn.execute("SELECT COUNT(*) FROM datasets").fetchone()[0]
    total_analyses = conn.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0]

    conn.close()

    return {
        "overview": {
            "total_datasets": dataset_count,
            "total_analyses": total_analyses,
            "latest_analysis_id": analysis_id,
            "total_companies": latest_run["total_companies"],
            "anomalies_found": latest_run["anomalies_found"],
            "avg_risk_score": latest_run["avg_risk_score"],
            "model_contamination": latest_run["model_contamination"]
        },
        "risk_distribution": risk_dist,
        "sector_risk": sector_risk,
        "top_threats": [{
            "company_name": t["company_name"],
            "sector": t["sector"],
            "risk_score": t["risk_score"],
            "risk_level": t["risk_level"],
            "esg_score": t["esg_score"],
            "cyber_incidents": t.get("cyber_incidents", 0),
            "data_breaches": t.get("data_breaches", 0),
            "flags": json.loads(t["flags"]) if t["flags"] else []
        } for t in top_threats],
        "all_companies": [{
            "company_name": r["company_name"],
            "sector": r["sector"],
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
            "is_anomaly": r["is_anomaly"],
            "esg_score": r["esg_score"],
            "environmental_score": r.get("environmental_score"),
            "social_score": r.get("social_score"),
            "governance_score": r.get("governance_score"),
            "carbon_emissions": r.get("carbon_emissions"),
            "cyber_incidents": r.get("cyber_incidents", 0),
            "compliance_score": r.get("compliance_score", 0)
        } for r in results_list],
        "blockchain": chain_status
    }


# ─── 5. BLOCKCHAIN AUDIT ────────────────────────────────────
@app.get("/api/blockchain", tags=["Blockchain"])
def get_blockchain():
    """View the full blockchain audit trail and verify integrity."""
    chain = AuditChain()
    return {
        "verification": chain.verify_chain(),
        "chain": chain.get_full_chain()
    }


@app.get("/api/blockchain/verify", tags=["Blockchain"])
def verify_blockchain():
    """Verify blockchain integrity — checks every hash link."""
    chain = AuditChain()
    return chain.verify_chain()


# ─── 6. DEMO MODE ───────────────────────────────────────────
@app.post("/api/demo", tags=["Demo"])
def run_demo():
    """
    One-click demo: generates synthetic ESG data, uploads it,
    runs anomaly detection, and returns full results.
    """
    # Generate synthetic data
    df = generate_dataset(n_normal=40, n_anomalous=10)

    conn = get_connection()

    # Create dataset
    cursor = conn.execute(
        "INSERT INTO datasets (filename, row_count, column_count) VALUES (?, ?, ?)",
        ("demo_synthetic_50companies.csv", len(df), len(df.columns))
    )
    dataset_id = cursor.lastrowid

    # Insert all records
    company_ids = []
    for _, row in df.iterrows():
        c = conn.execute("""
            INSERT INTO companies
                (company_name, sector, country, esg_score, environmental_score,
                 social_score, governance_score, carbon_emissions, energy_consumption,
                 waste_generated, water_usage, revenue, esg_spending, employee_count, dataset_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            row["company_name"], row["sector"], row["country"],
            row["esg_score"], row["environmental_score"],
            row["social_score"], row["governance_score"],
            row["carbon_emissions"], row["energy_consumption"],
            row["waste_generated"], row["water_usage"],
            row["revenue"], row["esg_spending"],
            row["employee_count"], dataset_id
        ))
        cid = c.lastrowid
        company_ids.append(cid)

        conn.execute("""
            INSERT INTO cyber_threats
                (company_id, cyber_incidents, data_breaches, ransomware_attacks,
                 phishing_attempts, vulnerability_count, avg_patch_time_days,
                 compliance_score, security_budget, has_ciso, last_audit_days_ago)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            cid, row["cyber_incidents"], row["data_breaches"],
            row["ransomware_attacks"], row["phishing_attempts"],
            row["vulnerability_count"], row["avg_patch_time_days"],
            row["compliance_score"], row["security_budget"],
            row["has_ciso"], row["last_audit_days_ago"]
        ))

    conn.commit()
    conn.close()

    # Run ML analysis
    engine = SECORAEngine(contamination=0.15)
    analysis = engine.detect_anomalies(df)

    # Store results
    conn = get_connection()
    summary = analysis["summary"]
    cursor = conn.execute("""
        INSERT INTO analysis_runs
            (dataset_id, total_companies, anomalies_found, avg_risk_score,
             model_contamination, features_used, run_duration_ms)
        VALUES (?,?,?,?,?,?,?)
    """, (
        dataset_id, summary["total_companies"], summary["anomalies_found"],
        summary["avg_risk_score"], 0.15,
        json.dumps(summary["features_used"]), summary["run_duration_ms"]
    ))
    analysis_id = cursor.lastrowid

    for i, result in enumerate(analysis["results"]):
        cid = company_ids[i] if i < len(company_ids) else None
        conn.execute("""
            INSERT INTO anomaly_results
                (company_id, is_anomaly, anomaly_score, risk_score, risk_level, flags, analysis_id)
            VALUES (?,?,?,?,?,?,?)
        """, (
            cid, result["is_anomaly"], result["anomaly_score"],
            result["risk_score"], result["risk_level"],
            json.dumps(result["flags"]), analysis_id
        ))

    conn.commit()

    # Blockchain audit
    chain = AuditChain()
    chain.add_block("DEMO_RUN", {
        "dataset_id": dataset_id,
        "analysis_id": analysis_id,
        "anomalies_found": summary["anomalies_found"]
    })

    conn.close()

    return {
        "status": "success",
        "message": "Demo complete — 50 companies analyzed, anomalies detected",
        "dataset_id": dataset_id,
        "analysis_id": analysis_id,
        "summary": summary,
        "flagged_companies": [r for r in analysis["results"] if r["is_anomaly"] == 1],
        "blockchain_verified": chain.verify_chain()
    }


# ─── 7. LIST DATASETS & RUNS ────────────────────────────────
@app.get("/api/datasets", tags=["Data"])
def list_datasets():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM datasets ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/analyses", tags=["Analysis"])
def list_analyses():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM analysis_runs ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]
