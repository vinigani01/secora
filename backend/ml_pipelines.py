import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import hashlib
import json

class SecoraMLPipeline:
    def __init__(self):
        self.esg_model = IsolationForest(n_estimators=200, contamination=0.15, random_state=42)
        self.cyber_model = IsolationForest(n_estimators=200, contamination=0.15, random_state=42)
        self.esg_scaler = StandardScaler()
        self.cyber_scaler = StandardScaler()

    def _power_mean(self, s_e, s_c, alpha=0.5, p=3):
        return (alpha * (s_e ** p) + (1 - alpha) * (s_c ** p)) ** (1 / p)

    def _categorise_risk(self, risk_val):
        score = risk_val * 100
        if score < 25: return "LOW"
        elif score < 50: return "MEDIUM"
        elif score < 75: return "HIGH"
        return "CRITICAL"

    def process_and_score(self, companies_df, cyber_df):
        df = pd.merge(companies_df, cyber_df, on="company_id")
        
        # ESG Feature Engineering
        df['emissions_intensity'] = df['emissions'] / df['revenue'].replace(0, np.nan)
        df['expenditure_share'] = df['esg_expenditure'] / df['revenue'].replace(0, np.nan)
        sector_medians = df.groupby('sector')['composite'].transform('median')
        df['sector_relative'] = df['composite'] - sector_medians
        df['score_consistency'] = df['composite'] - df[['env_score', 'soc_score', 'gov_score']].mean(axis=1)
        
        df.fillna(0, inplace=True)
        
        esg_features = ['env_score', 'soc_score', 'gov_score', 'composite', 'yoy_change', 
                        'emissions_intensity', 'expenditure_share', 'sector_relative', 'score_consistency']
        cyber_features = ['incidents', 'breaches', 'flow_duration']
        
        X_esg = self.esg_scaler.fit_transform(df[esg_features])
        X_cyber = self.cyber_scaler.fit_transform(df[cyber_features])
        
        self.esg_model.fit(X_esg)
        self.cyber_model.fit(X_cyber)
        
        # Isolation Forest returns -1 for anomaly, 1 for normal. Convert to 0-1 anomaly score.
        s_e = 0.5 - (self.esg_model.decision_function(X_esg) / 2)
        s_c = 0.5 - (self.cyber_model.decision_function(X_cyber) / 2)
        
        results = []
        for i, row in df.iterrows():
            agg_risk = self._power_mean(s_e[i], s_c[i])
            results.append({
                "company_id": row['company_id'],
                "esg_score": float(s_e[i]),
                "cyber_score": float(s_c[i]),
                "aggregate_risk": float(agg_risk),
                "risk_category": self._categorise_risk(agg_risk),
                "features_json": {f: float(X_esg[i][idx]) for idx, f in enumerate(esg_features)} | 
                                 {f: float(X_cyber[i][idx]) for idx, f in enumerate(cyber_features)}
            })
            
        manifest_data = {"esg_params": self.esg_model.get_params(), "cyber_params": self.cyber_model.get_params()}
        manifest_hash = hashlib.sha256(json.dumps(manifest_data, sort_keys=True).encode()).hexdigest()
        
        return results, manifest_hash
