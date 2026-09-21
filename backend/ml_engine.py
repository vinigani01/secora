"""
SECORA - Machine Learning Engine
Isolation Forest for anomaly detection on ESG + Cybersecurity data.
Generates risk scores and flags suspicious patterns.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import json
import time

# Features used by the ML model
ESG_FEATURES = [
    "esg_score", "environmental_score", "social_score", "governance_score",
    "carbon_emissions", "energy_consumption", "waste_generated", "water_usage",
    "revenue", "esg_spending"
]

CYBER_FEATURES = [
    "cyber_incidents", "data_breaches", "ransomware_attacks",
    "phishing_attempts", "vulnerability_count", "avg_patch_time_days",
    "compliance_score", "security_budget"
]

ALL_FEATURES = ESG_FEATURES + CYBER_FEATURES


class SECORAEngine:
    """
    Core ML pipeline:
    1. Load data from DataFrame
    2. Scale features
    3. Run Isolation Forest
    4. Compute risk scores (0-100)
    5. Flag anomalies with reasons
    """

    def __init__(self, contamination: float = 0.15, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = []

    def prepare_features(self, df: pd.DataFrame) -> tuple:
        """Extract and scale numerical features from the dataset."""
        # Find which features exist in the uploaded data
        available = [f for f in ALL_FEATURES if f in df.columns]
        if len(available) < 3:
            raise ValueError(
                f"Need at least 3 numeric features. Found: {available}. "
                f"Expected some of: {ALL_FEATURES}"
            )

        self.feature_names = available
        X = df[available].copy()

        # Fill missing values with column median
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors="coerce")
            X[col] = X[col].fillna(X[col].median())

        X_scaled = self.scaler.fit_transform(X)
        return X, X_scaled

    def detect_anomalies(self, df: pd.DataFrame) -> dict:
        """
        Run the full anomaly detection pipeline.
        Returns analysis results with per-company risk scores.
        """
        start_time = time.time()

        X_raw, X_scaled = self.prepare_features(df)

        # --- Isolation Forest ---
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=200,
            max_samples="auto",
            n_jobs=-1
        )
        self.model.fit(X_scaled)

        # Predictions: 1 = normal, -1 = anomaly
        predictions = self.model.predict(X_scaled)
        # Decision scores: lower = more anomalous
        raw_scores = self.model.decision_function(X_scaled)

        # --- Risk Score Calculation (0-100, higher = riskier) ---
        min_score = raw_scores.min()
        max_score = raw_scores.max()
        if max_score - min_score == 0:
            risk_scores = np.full(len(raw_scores), 50.0)
        else:
            # Invert: lower decision score → higher risk
            risk_scores = 100 * (1 - (raw_scores - min_score) / (max_score - min_score))

        risk_scores = np.clip(risk_scores, 0, 100).round(2)

        # --- Risk Levels ---
        risk_levels = []
        for rs in risk_scores:
            if rs >= 75:
                risk_levels.append("CRITICAL")
            elif rs >= 50:
                risk_levels.append("HIGH")
            elif rs >= 25:
                risk_levels.append("MEDIUM")
            else:
                risk_levels.append("LOW")

        # --- Flag Generation (explain WHY each anomaly was flagged) ---
        all_flags = []
        feature_means = X_raw.mean()
        feature_stds = X_raw.std()

        for idx in range(len(df)):
            flags = []
            if predictions[idx] == -1:
                for feat in self.feature_names:
                    val = X_raw.iloc[idx][feat]
                    mean = feature_means[feat]
                    std = feature_stds[feat]
                    if std > 0:
                        z = (val - mean) / std
                        if abs(z) > 1.8:
                            direction = "abnormally high" if z > 0 else "abnormally low"
                            flags.append(f"{feat}: {val:.1f} ({direction}, z={z:.2f})")
            all_flags.append(flags)

        duration_ms = round((time.time() - start_time) * 1000, 2)

        # --- Build Results ---
        results = []
        for i in range(len(df)):
            company_name = df.iloc[i].get("company_name", f"Company_{i+1}")
            results.append({
                "company_name": str(company_name),
                "is_anomaly": int(predictions[i] == -1),
                "anomaly_score": round(float(raw_scores[i]), 4),
                "risk_score": float(risk_scores[i]),
                "risk_level": risk_levels[i],
                "flags": all_flags[i]
            })

        # --- Summary Stats ---
        anomaly_count = int((predictions == -1).sum())
        summary = {
            "total_companies": len(df),
            "anomalies_found": anomaly_count,
            "anomaly_rate": round(anomaly_count / len(df) * 100, 2),
            "avg_risk_score": round(float(risk_scores.mean()), 2),
            "max_risk_score": round(float(risk_scores.max()), 2),
            "min_risk_score": round(float(risk_scores.min()), 2),
            "features_used": self.feature_names,
            "contamination": self.contamination,
            "run_duration_ms": duration_ms,
            "risk_distribution": {
                "CRITICAL": risk_levels.count("CRITICAL"),
                "HIGH": risk_levels.count("HIGH"),
                "MEDIUM": risk_levels.count("MEDIUM"),
                "LOW": risk_levels.count("LOW")
            }
        }

        return {
            "summary": summary,
            "results": results
        }

    def get_feature_importance(self, X_scaled: np.ndarray) -> dict:
        """Estimate feature importance from Isolation Forest."""
        if self.model is None:
            return {}

        importances = {}
        base_score = self.model.decision_function(X_scaled).mean()

        for i, feat in enumerate(self.feature_names):
            X_permuted = X_scaled.copy()
            np.random.shuffle(X_permuted[:, i])
            permuted_score = self.model.decision_function(X_permuted).mean()
            importances[feat] = round(abs(base_score - permuted_score), 6)

        # Normalize to percentages
        total = sum(importances.values())
        if total > 0:
            importances = {k: round(v / total * 100, 2) for k, v in importances.items()}

        return dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))
