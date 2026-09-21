"""
SECORA - Synthetic ESG + Cybersecurity Dataset Generator
Creates realistic data with planted anomalies for demo purposes.
"""

import pandas as pd
import numpy as np
import os

np.random.seed(42)

SECTORS = [
    "Energy", "Technology", "Banking", "Manufacturing",
    "Healthcare", "Retail", "Automotive", "Telecom",
    "Real Estate", "Insurance"
]

COUNTRIES = ["USA", "UK", "Germany", "India", "Japan", "Brazil", "Singapore", "UAE", "Canada", "Australia"]

COMPANY_NAMES = [
    "GreenVolt Energy", "TechNova Inc", "PrimeBank Holdings", "SteelForge Industries",
    "MedCore Health", "RetailMax Corp", "AutoDrive Motors", "ConnectTel Networks",
    "UrbanSpace Realty", "SecureLife Insurance", "SolarPeak Power", "CloudSphere Tech",
    "TrustCapital Bank", "EcoFab Manufacturing", "BioVita Pharma", "ShopStream Retail",
    "ElectraMotors Ltd", "WaveLink Telecom", "GreenHaven Properties", "RiskShield Corp",
    "WindRunner Energy", "DataPulse Systems", "GlobalFin Bank", "PrecisionWorks Mfg",
    "NeuralHealth AI", "ValueMart Stores", "HyperDrive Auto", "NetBridge Comms",
    "SkylineBuilders", "Guardian Assurance", "FusionGrid Power", "ByteForce Tech",
    "EquityFirst Bank", "NanoMaterials Inc", "CureGen Biotech", "FreshChain Markets",
    "VoltAuto Corp", "SignalTower Tel", "MetroLand Devs", "SafeHarbor Insurance",
    "BrightEnergy Co", "QuantumLogic AI", "MeridianBank", "TitanForge Steel",
    "PulseHealth Systems", "OmniRetail Group", "ZeroEmission Auto", "SpectrumNet Tel",
    "PrimeEstate Holdings", "FortressRisk Ltd"
]


def generate_normal_company(name: str, idx: int) -> dict:
    """Generate a normal (non-anomalous) company record."""
    sector = SECTORS[idx % len(SECTORS)]
    country = COUNTRIES[idx % len(COUNTRIES)]

    env = np.random.uniform(40, 85)
    soc = np.random.uniform(45, 80)
    gov = np.random.uniform(50, 85)
    esg = round((env + soc + gov) / 3, 2)

    revenue = np.random.uniform(50, 5000)  # millions
    esg_spending = revenue * np.random.uniform(0.02, 0.08)

    return {
        "company_name": name,
        "sector": sector,
        "country": country,
        "esg_score": round(esg, 2),
        "environmental_score": round(env, 2),
        "social_score": round(soc, 2),
        "governance_score": round(gov, 2),
        "carbon_emissions": round(np.random.uniform(500, 15000), 2),  # tonnes CO2
        "energy_consumption": round(np.random.uniform(1000, 50000), 2),  # MWh
        "waste_generated": round(np.random.uniform(50, 5000), 2),  # tonnes
        "water_usage": round(np.random.uniform(100, 20000), 2),  # cubic meters
        "revenue": round(revenue, 2),
        "esg_spending": round(esg_spending, 2),
        "employee_count": int(np.random.uniform(100, 50000)),
        # Cyber data
        "cyber_incidents": int(np.random.poisson(3)),
        "data_breaches": int(np.random.poisson(0.5)),
        "ransomware_attacks": int(np.random.poisson(0.3)),
        "phishing_attempts": int(np.random.poisson(15)),
        "vulnerability_count": int(np.random.poisson(8)),
        "avg_patch_time_days": round(np.random.uniform(5, 30), 1),
        "compliance_score": round(np.random.uniform(70, 98), 2),
        "security_budget": round(revenue * np.random.uniform(0.03, 0.10), 2),
        "has_ciso": 1,
        "last_audit_days_ago": int(np.random.uniform(30, 180))
    }


def generate_anomalous_company(name: str, idx: int, anomaly_type: str) -> dict:
    """Generate an anomalous company with specific suspicious patterns."""
    base = generate_normal_company(name, idx)

    if anomaly_type == "greenwashing":
        # High ESG score but terrible actual metrics
        base["esg_score"] = round(np.random.uniform(88, 98), 2)
        base["environmental_score"] = round(np.random.uniform(85, 97), 2)
        base["carbon_emissions"] = round(np.random.uniform(40000, 80000), 2)  # 5x normal
        base["energy_consumption"] = round(np.random.uniform(100000, 200000), 2)
        base["waste_generated"] = round(np.random.uniform(15000, 30000), 2)
        base["esg_spending"] = round(base["revenue"] * 0.005, 2)  # Tiny spending

    elif anomaly_type == "cyber_breach":
        # Massive cyber exposure
        base["cyber_incidents"] = int(np.random.uniform(25, 60))
        base["data_breaches"] = int(np.random.uniform(8, 20))
        base["ransomware_attacks"] = int(np.random.uniform(5, 12))
        base["vulnerability_count"] = int(np.random.uniform(50, 150))
        base["avg_patch_time_days"] = round(np.random.uniform(90, 200), 1)
        base["compliance_score"] = round(np.random.uniform(15, 40), 2)
        base["has_ciso"] = 0
        base["security_budget"] = round(base["revenue"] * 0.005, 2)

    elif anomaly_type == "esg_fraud":
        # Scores don't match each other — fabricated numbers
        base["esg_score"] = round(np.random.uniform(90, 99), 2)
        base["environmental_score"] = round(np.random.uniform(10, 25), 2)  # Contradicts ESG
        base["social_score"] = round(np.random.uniform(92, 99), 2)
        base["governance_score"] = round(np.random.uniform(5, 20), 2)   # Contradicts ESG
        base["esg_spending"] = round(base["revenue"] * 0.001, 2)

    elif anomaly_type == "combined":
        # Everything is off — greenwashing + cyber vulnerability
        base["esg_score"] = round(np.random.uniform(85, 95), 2)
        base["carbon_emissions"] = round(np.random.uniform(50000, 100000), 2)
        base["cyber_incidents"] = int(np.random.uniform(30, 80))
        base["data_breaches"] = int(np.random.uniform(10, 25))
        base["compliance_score"] = round(np.random.uniform(10, 30), 2)
        base["vulnerability_count"] = int(np.random.uniform(80, 200))
        base["esg_spending"] = round(base["revenue"] * 0.002, 2)

    return base


def generate_dataset(n_normal: int = 40, n_anomalous: int = 10) -> pd.DataFrame:
    """Generate full synthetic dataset with labeled anomalies."""
    records = []

    # Normal companies
    for i in range(n_normal):
        name = COMPANY_NAMES[i] if i < len(COMPANY_NAMES) else f"Company_{i+1}"
        records.append(generate_normal_company(name, i))

    # Anomalous companies
    anomaly_types = ["greenwashing", "cyber_breach", "esg_fraud", "combined"]
    anomalous_names = [
        "PhantomGreen Corp", "DataLeak Systems", "FakeScore Holdings",
        "ShadowFinance Ltd", "GhostEmissions Inc", "ZeroGuard Tech",
        "MirageESG Corp", "BreachPoint Networks", "FraudMetrics Inc",
        "ToxicGreen Industries"
    ]

    for i in range(n_anomalous):
        atype = anomaly_types[i % len(anomaly_types)]
        name = anomalous_names[i] if i < len(anomalous_names) else f"SuspiciousCo_{i+1}"
        records.append(generate_anomalous_company(name, 40 + i, atype))

    df = pd.DataFrame(records)
    # Shuffle so anomalies aren't at the bottom
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


def save_dataset():
    """Generate and save the demo dataset as CSV."""
    df = generate_dataset()
    out_path = os.path.join(os.path.dirname(__file__), "..", "data", "demo_esg_dataset.csv")
    df.to_csv(out_path, index=False)
    print(f"[SEED] Generated {len(df)} companies → {out_path}")
    print(f"  Normal: 40 | Anomalous: 10 (greenwashing, cyber_breach, esg_fraud, combined)")
    return df


if __name__ == "__main__":
    save_dataset()
