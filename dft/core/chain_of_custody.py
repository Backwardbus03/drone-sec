"""
Tamper-Evident Chain-of-Custody (CoC) Manager.
Enforces an append-only audit trail linking each entry with HMAC-SHA256 signatures
and previous entry hashes, compliant with ISO/IEC 27037:2012.
"""

import os
import sqlite3
import hmac
import hashlib
from pathlib import Path
from typing import List, Optional, Tuple
from datetime import datetime, timezone
from dft.core.models import AuditLogEntry

# Read from DFT_HMAC_SECRET env var; hardcoded default is only for local dev.
# ALWAYS set a strong secret in production (Render dashboard > Environment).
DEFAULT_HMAC_SECRET = os.getenv(
    "DFT_HMAC_SECRET",
    "DFT_SECURE_FORENSIC_MASTER_KEY_2026_IITB"
).encode()


class ChainOfCustodyManager:
    def __init__(self, db_path: Path, secret_key: bytes = DEFAULT_HMAC_SECRET):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.secret_key = secret_key
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_trail (
                    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    evidence_item_id TEXT,
                    previous_hash TEXT NOT NULL,
                    signature TEXT NOT NULL
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _calculate_signature(self, entry_data: str) -> str:
        return hmac.new(self.secret_key, entry_data.encode("utf-8"), hashlib.sha256).hexdigest()

    def _calculate_entry_hash(self, entry_id: int, case_id: str, ts: str, actor: str, action: str, details: str, prev_hash: str) -> str:
        payload = f"{entry_id}|{case_id}|{ts}|{actor}|{action}|{details}|{prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def log_action(
        self,
        case_id: str,
        actor: str,
        action: str,
        details: str,
        evidence_item_id: Optional[str] = None
    ) -> AuditLogEntry:
        """
        Appends an immutable, cryptographically signed record to the Chain of Custody.
        """
        ts = datetime.now(timezone.utc).isoformat()
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            # Fetch the previous entry's signature for chaining
            cursor.execute("SELECT signature FROM audit_trail WHERE case_id = ? ORDER BY entry_id DESC LIMIT 1", (case_id,))
            last_row = cursor.fetchone()
            prev_hash = last_row["signature"] if last_row else "GENESIS_BLOCK_000000000000000000000000"

            # Calculate signature for this new entry
            raw_signature_payload = f"{case_id}|{ts}|{actor}|{action}|{details}|{evidence_item_id or ''}|{prev_hash}"
            signature = self._calculate_signature(raw_signature_payload)

            cursor.execute("""
                INSERT INTO audit_trail (case_id, timestamp_utc, actor, action, details, evidence_item_id, previous_hash, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (case_id, ts, actor, action, details, evidence_item_id, prev_hash, signature))
            conn.commit()
            entry_id = cursor.lastrowid

            return AuditLogEntry(
                entry_id=entry_id,
                case_id=case_id,
                timestamp_utc=ts,
                actor=actor,
                action=action,
                details=details,
                evidence_item_id=evidence_item_id,
                previous_hash=prev_hash,
                signature=signature
            )
        finally:
            conn.close()

    def get_entries(self, case_id: str) -> List[AuditLogEntry]:
        """Returns all audit entries for a case in chronological order."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_trail WHERE case_id = ? ORDER BY entry_id ASC", (case_id,))
            rows = cursor.fetchall()
            return [
                AuditLogEntry(
                    entry_id=r["entry_id"],
                    case_id=r["case_id"],
                    timestamp_utc=r["timestamp_utc"],
                    actor=r["actor"],
                    action=r["action"],
                    details=r["details"],
                    evidence_item_id=r["evidence_item_id"],
                    previous_hash=r["previous_hash"],
                    signature=r["signature"]
                )
                for r in rows
            ]
        finally:
            conn.close()

    def verify_chain(self, case_id: str) -> Tuple[bool, Optional[str]]:
        """
        Validates cryptographic integrity of the entire chain of custody for a case.
        Returns (True, None) if completely uncompromised, or (False, error_message) if tampered.
        """
        entries = self.get_entries(case_id)
        if not entries:
            return True, None

        expected_prev_hash = "GENESIS_BLOCK_000000000000000000000000"
        for entry in entries:
            if entry.previous_hash != expected_prev_hash:
                return False, f"Broken chain at entry #{entry.entry_id}: expected prev_hash {expected_prev_hash}, found {entry.previous_hash}"

            raw_payload = f"{entry.case_id}|{entry.timestamp_utc}|{entry.actor}|{entry.action}|{entry.details}|{entry.evidence_item_id or ''}|{entry.previous_hash}"
            recalculated_sig = self._calculate_signature(raw_payload)
            if recalculated_sig != entry.signature:
                return False, f"Tampered entry #{entry.entry_id}: signature mismatch. Integrity compromised."

            expected_prev_hash = entry.signature

        return True, None
