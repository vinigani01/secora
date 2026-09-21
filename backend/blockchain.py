"""
SECORA - Blockchain Audit Trail
Simple SHA-256 hash chain for tamper-proof logging of all ESG data changes
and analysis runs. Each block links to the previous via hash.
"""

import hashlib
import json
from datetime import datetime
from database import get_connection


class Block:
    def __init__(self, index: int, timestamp: str, action: str,
                 data_hash: str, previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.action = action
        self.data_hash = data_hash
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "action": self.action,
            "data_hash": self.data_hash,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine(self, difficulty: int = 2):
        """Simple proof-of-work: hash must start with `difficulty` zeros."""
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.compute_hash()

    def to_dict(self) -> dict:
        return {
            "block_index": self.index,
            "timestamp": self.timestamp,
            "action": self.action,
            "data_hash": self.data_hash,
            "previous_hash": self.previous_hash,
            "block_hash": self.hash,
            "nonce": self.nonce
        }


class AuditChain:
    """Manages the blockchain audit trail stored in SQLite."""

    def __init__(self):
        self._ensure_genesis()

    def _ensure_genesis(self):
        conn = get_connection()
        count = conn.execute("SELECT COUNT(*) FROM blockchain_audit").fetchone()[0]
        if count == 0:
            genesis = Block(
                index=0,
                timestamp=datetime.utcnow().isoformat(),
                action="GENESIS",
                data_hash="0" * 64,
                previous_hash="0" * 64
            )
            genesis.mine()
            self._store_block(conn, genesis)
        conn.close()

    def _store_block(self, conn, block: Block):
        d = block.to_dict()
        conn.execute("""
            INSERT INTO blockchain_audit
                (block_index, timestamp, action, data_hash, previous_hash, block_hash, nonce)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (d["block_index"], d["timestamp"], d["action"],
              d["data_hash"], d["previous_hash"], d["block_hash"], d["nonce"]))
        conn.commit()

    def get_last_block(self) -> dict:
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM blockchain_audit ORDER BY block_index DESC LIMIT 1"
        ).fetchone()
        conn.close()
        return dict(row)

    def add_block(self, action: str, data: dict) -> dict:
        """Add a new block to the chain."""
        data_hash = hashlib.sha256(
            json.dumps(data, sort_keys=True, default=str).encode()
        ).hexdigest()

        last = self.get_last_block()
        new_block = Block(
            index=last["block_index"] + 1,
            timestamp=datetime.utcnow().isoformat(),
            action=action,
            data_hash=data_hash,
            previous_hash=last["block_hash"]
        )
        new_block.mine(difficulty=2)

        conn = get_connection()
        self._store_block(conn, new_block)
        conn.close()
        return new_block.to_dict()

    def verify_chain(self) -> dict:
        """Verify the entire chain integrity."""
        conn = get_connection()
        blocks = conn.execute(
            "SELECT * FROM blockchain_audit ORDER BY block_index ASC"
        ).fetchall()
        conn.close()

        if not blocks:
            return {"valid": False, "error": "Empty chain"}

        for i in range(1, len(blocks)):
            current = dict(blocks[i])
            previous = dict(blocks[i - 1])

            # Verify link
            if current["previous_hash"] != previous["block_hash"]:
                return {
                    "valid": False,
                    "error": f"Broken link at block {current['block_index']}",
                    "block_index": current["block_index"]
                }

            # Verify hash
            test_block = Block(
                index=current["block_index"],
                timestamp=current["timestamp"],
                action=current["action"],
                data_hash=current["data_hash"],
                previous_hash=current["previous_hash"]
            )
            test_block.nonce = current["nonce"]
            test_block.hash = test_block.compute_hash()

            if test_block.hash != current["block_hash"]:
                return {
                    "valid": False,
                    "error": f"Hash mismatch at block {current['block_index']}",
                    "block_index": current["block_index"]
                }

        return {
            "valid": True,
            "total_blocks": len(blocks),
            "latest_block": dict(blocks[-1])["block_index"]
        }

    def get_full_chain(self) -> list:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM blockchain_audit ORDER BY block_index ASC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
