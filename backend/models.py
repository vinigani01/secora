from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, JSON
from datetime import datetime, timezone
from database import Base

class Dataset(Base):
    __tablename__ = "datasets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    uploaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Company(Base):
    __tablename__ = "companies"
    id = Column(Integer, primary_key=True, index=True)
    dataset_id = Column(Integer, ForeignKey("datasets.id"))
    name = Column(String)
    env_score = Column(Float)
    soc_score = Column(Float)
    gov_score = Column(Float)
    composite = Column(Float)
    yoy_change = Column(Float)
    revenue = Column(Float)
    emissions = Column(Float)
    esg_expenditure = Column(Float)
    sector = Column(String)

class CyberThreat(Base):
    __tablename__ = "cyber_threats"
    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"))
    incidents = Column(Integer)
    breaches = Column(Integer)
    flow_duration = Column(Float)

class AnalysisRun(Base):
    __tablename__ = "analysis_runs"
    id = Column(Integer, primary_key=True, index=True)
    dataset_id = Column(Integer, ForeignKey("datasets.id"))
    run_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    manifest_hash = Column(String)

class AnomalyResult(Base):
    __tablename__ = "anomaly_results"
    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("analysis_runs.id"))
    company_id = Column(Integer, ForeignKey("companies.id"))
    esg_score = Column(Float)
    cyber_score = Column(Float)
    aggregate_risk = Column(Float)
    risk_category = Column(String)
    features_json = Column(JSON)

class BlockchainAudit(Base):
    __tablename__ = "blockchain_audit"
    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(Integer, ForeignKey("analysis_runs.id"))
    request_id = Column(String)
    timestamp = Column(DateTime)
    payload = Column(JSON)
    prev_hash = Column(String)
    curr_hash = Column(String)
