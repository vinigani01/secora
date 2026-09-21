"""
SECORA - Database Layer
SQLite database for storing ESG data, cyber threats, risk scores, and audit logs.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "secora.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # --- ESG Company Data ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_name TEXT NOT NULL,
            sector TEXT,
            country TEXT,
            esg_score REAL,
            environmental_score REAL,
            social_score REAL,
            governance_score REAL,
            carbon_emissions REAL,
            energy_consumption REAL,
            waste_generated REAL,
            water_usage REAL,
            revenue REAL,
            esg_spending REAL,
            employee_count INTEGER,
            created_at TEXT DEFAULT (datetime('now')),
            dataset_id INTEGER,
            FOREIGN KEY (dataset_id) REFERENCES datasets(id)
        )
    """)

    # --- Cyber Threat Data ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cyber_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER,
            cyber_incidents INTEGER DEFAULT 0,
            data_breaches INTEGER DEFAULT 0,
            ransomware_attacks INTEGER DEFAULT 0,
            phishing_attempts INTEGER DEFAULT 0,
            vulnerability_count INTEGER DEFAULT 0,
            avg_patch_time_days REAL DEFAULT 0,
            compliance_score REAL DEFAULT 0,
            security_budget REAL DEFAULT 0,
            has_ciso INTEGER DEFAULT 0,
            last_audit_days_ago INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (company_id) REFERENCES companies(id)
        )
    """)

    # --- ML Anomaly Detection Results ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS anomaly_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER,
            is_anomaly INTEGER,
            anomaly_score REAL,
            risk_score REAL,
            risk_level TEXT,
            flags TEXT,
            analysis_id INTEGER,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (company_id) REFERENCES companies(id),
            FOREIGN KEY (analysis_id) REFERENCES analysis_runs(id)
        )
    """)

    # --- Analysis Runs (each time ML pipeline executes) ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dataset_id INTEGER,
            total_companies INTEGER,
            anomalies_found INTEGER,
            avg_risk_score REAL,
            model_contamination REAL,
            features_used TEXT,
            run_duration_ms REAL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (dataset_id) REFERENCES datasets(id)
        )
    """)

    # --- Dataset Uploads ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS datasets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            row_count INTEGER,
            column_count INTEGER,
            uploaded_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # --- Blockchain Audit Trail ---
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blockchain_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_index INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            data_hash TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            block_hash TEXT NOT NULL,
            nonce INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()
    print(f"[DB] Initialized at {DB_PATH}")


if __name__ == "__main__":
    init_db()
