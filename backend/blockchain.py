import hashlib
import json
from datetime import datetime, timezone
from models import BlockchainAudit
from sqlalchemy.orm import Session

def canonicalize(payload: dict) -> str:
    return json.dumps(payload, separators=(',', ':'), sort_keys=True)

def append_to_ledger(db: Session, run_id: int, req_id: str, r: float, s_e: float, s_c: float, mh: str):
    timestamp = datetime.now(timezone.utc)
    tuple_payload = {
        "t": timestamp.isoformat(),
        "R": round(r, 6),
        "sE": round(s_e, 6),
        "sC": round(s_c, 6),
        "rid": req_id,
        "mh": mh
    }
    canon_json = canonicalize(tuple_payload)
    
    last_block = db.query(BlockchainAudit).order_by(BlockchainAudit.id.desc()).first()
    prev_hash = last_block.curr_hash if last_block else "0" * 64
    
    curr_hash = hashlib.sha256((canon_json + prev_hash).encode('utf-8')).hexdigest()
    
    new_block = BlockchainAudit(
        run_id=run_id, request_id=req_id, timestamp=timestamp,
        payload=tuple_payload, prev_hash=prev_hash, curr_hash=curr_hash
    )
    db.add(new_block)
    db.commit()

def verify_ledger(db: Session) -> bool:
    blocks = db.query(BlockchainAudit).order_by(BlockchainAudit.id.asc()).all()
    expected_prev = "0" * 64
    
    for block in blocks:
        if block.prev_hash != expected_prev:
            return False
        
        canon_json = canonicalize(block.payload)
        recalc_hash = hashlib.sha256((canon_json + block.prev_hash).encode('utf-8')).hexdigest()
        
        if recalc_hash != block.curr_hash:
            return False
            
        expected_prev = block.curr_hash
    return True
