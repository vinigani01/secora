from fastapi import FastAPI, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import uuid
import io

from database import engine, Base, get_db
from models import Dataset, Company, CyberThreat, AnalysisRun, AnomalyResult, BlockchainAudit
from ml_pipeline import SecoraMLPipeline
import blockchain

Base.metadata.create_all(bind=engine)
app = FastAPI(title="SECORA API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pipeline = SecoraMLPipeline()

@app.post("/api/upload")
async def upload_csv(companies_file: UploadFile = File(...), cyber_file: UploadFile = File(...), db: Session = Depends(get_db)):
    try:
        comp_df = pd.read_csv(io.StringIO(str(await companies_file.read(), 'utf-8')))
        cyb_df = pd.read_csv(io.StringIO(str(await cyber_file.read(), 'utf-8')))
        
        dataset = Dataset(name=companies_file.filename)
        db.add(dataset)
        db.commit()
        db.refresh(dataset)
        
        for i, row in comp_df.iterrows():
            comp = Company(dataset_id=dataset.id, **row.to_dict())
            db.add(comp)
            db.commit()
            db.refresh(comp)
            
            cyb_row = cyb_df.iloc[i].to_dict()
            if 'company_id' in cyb_row:
                del cyb_row['company_id']
            cyb = CyberThreat(company_id=comp.id, **cyb_row)
            db.add(cyb)
            
        db.commit()
        return {"dataset_id": dataset.id, "message": "Upload successful"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/analyze/{dataset_id}")
def analyze(dataset_id: int, db: Session = Depends(get_db)):
    companies = db.query(Company).filter(Company.dataset_id == dataset_id).all()
    if not companies: 
        raise HTTPException(status_code=404, detail="Dataset not found")
    
    comp_data = []
    comp_ids = []
    for c in companies:
        comp_ids.append(c.id)
        comp_data.append({
            "company_id": c.id,
            "name": c.name,
            "env_score": c.env_score,
            "soc_score": c.soc_score,
            "gov_score": c.gov_score,
            "composite": c.composite,
            "yoy_change": c.yoy_change,
            "revenue": c.revenue,
            "emissions": c.emissions,
            "esg_expenditure": c.esg_expenditure,
            "sector": c.sector
        })
    comp_df = pd.DataFrame(comp_data)
    
    cybers = db.query(CyberThreat).filter(CyberThreat.company_id.in_(comp_ids)).all()
    cyb_data = []
    for cyb in cybers:
        cyb_data.append({
            "company_id": cyb.company_id,
            "incidents": cyb.incidents,
            "breaches": cyb.breaches,
            "flow_duration": cyb.flow_duration
        })
    cyb_df = pd.DataFrame(cyb_data)
    
    results, manifest_hash = pipeline.process_and_score(comp_df, cyb_df)
    
    run = AnalysisRun(dataset_id=dataset_id, manifest_hash=manifest_hash)
    db.add(run)
    db.commit()
    db.refresh(run)
    
    req_id = str(uuid.uuid4())
    for res in results:
        ar = AnomalyResult(
            run_id=run.id,
            company_id=res["company_id"],
            esg_score=res["esg_score"],
            cyber_score=res["cyber_score"],
            aggregate_risk=res["aggregate_risk"],
            risk_category=res["risk_category"],
            features_json=res["features_json"]
        )
        db.add(ar)
        blockchain.append_to_ledger(db, run.id, req_id, res['aggregate_risk'], res['esg_score'], res['cyber_score'], manifest_hash)
    
    db.commit()
    return {"run_id": run.id, "message": "Analysis complete"}

@app.get("/api/dashboard/{run_id}")
def dashboard(run_id: int, db: Session = Depends(get_db)):
    results = db.query(AnomalyResult).filter(AnomalyResult.run_id == run_id).all()
    if not results: 
        return {"status": "stale", "message": "Model unavailable/No data"}
    
    categories = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    flags = []
    
    for r in results:
        categories[r.risk_category] += 1
        if r.risk_category in ["HIGH", "CRITICAL"]:
            comp = db.query(Company).filter(Company.id == r.company_id).first()
            if comp:
                flags.append({
                    "company": comp.name, 
                    "sector": comp.sector, 
                    "risk": round(r.aggregate_risk * 100, 2), 
                    "category": r.risk_category, 
                    "z_scores": r.features_json
                })
            
    return {"distribution": categories, "flags": flags, "status": "fresh"}

@app.get("/api/blockchain/verify")
def verify_chain(db: Session = Depends(get_db)):
    is_valid = blockchain.verify_ledger(db)
    return {"status": "VALID" if is_valid else "TAMPERED"}

@app.get("/api/blockchain")
def get_blockchain(db: Session = Depends(get_db)):
    return db.query(BlockchainAudit).order_by(BlockchainAudit.id.desc()).limit(50).all()
