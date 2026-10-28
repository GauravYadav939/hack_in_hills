"""
Tamper-evident audit logging for Glasshouse Broker.

This module implements a cryptographic audit log with:
1. Hash chain - each entry includes hash of previous entry
2. Digital signatures - each entry is cryptographically signed
3. Sequential IDs - gaps indicate deleted entries
4. Tamper detection - verification catches any modification

Security Properties:
- Entries cannot be modified without detection
- Entries cannot be deleted without detection (gaps in sequence)
- Entries cannot be reordered without breaking the chain
- Requires protected signing key to forge valid entries

Limitations (be honest):
- An attacker with database AND signing key access can rewrite history
- Protection requires: secure key storage + external checkpoint retention
- This is tamper-EVIDENT, not tamper-PROOF
"""

import sqlite3
import hashlib
import json
import base64
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

import nacl.signing
import nacl.encoding
from nacl.exceptions import BadSignatureError

from app.models import Zone, Action, AuthorizationDecision


class AuditLogger:
    """
    Maintains a tamper-evident audit log in SQLite.

    Each entry includes:
    - Unique sequential ID
    - Request details (tenant, zone, action)
    - Authorization decision and reason
    - Outcome
    - Hash of previous entry (hash chain)
    - Hash of current entry
    - Cryptographic signature
    """

    def __init__(self, db_path: str, signing_key_b64: str):
        """
        Initialize the audit logger.

        Args:
            db_path: Path to SQLite database file
            signing_key_b64: Base64-encoded NaCl signing key

        The database is created automatically if it doesn't exist.
        """
        self.db_path = Path(db_path)

        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Load signing key
        try:
            key_bytes = base64.b64decode(signing_key_b64)
            self.signing_key = nacl.signing.SigningKey(key_bytes)
            self.verify_key = self.signing_key.verify_key
        except Exception as e:
            raise ValueError(f"Invalid audit signing key: {e}")

        # Initialize database
        self._init_database()

    def _init_database(self) -> None:
        """Create the audit log table if it doesn't exist."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    zone TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    current_hash TEXT NOT NULL,
                    signature TEXT NOT NULL
                )
            """)
            conn.commit()
            print(f"✓ Audit log database initialized: {self.db_path}")
        finally:
            conn.close()

    async def log_event(
        self,
        request_id: str,
        tenant_id: str,
        zone: Zone,
        action: Action,
        decision: AuthorizationDecision,
        reason: str,
        outcome: str
    ) -> int:
        """
        Log an audit event.

        Args:
            request_id: Unique request identifier
            tenant_id: Tenant making the request
            zone: Source zone
            action: Action requested
            decision: Authorization decision (allow/deny)
            reason: Reason for decision
            outcome: Request outcome (success/error/blocked)

        Returns:
            Entry ID of the logged event

        This method:
        1. Gets the previous entry's hash
        2. Creates the new entry data
        3. Computes hash of new entry
        4. Signs the entry
        5. Inserts into database
        """
        conn = sqlite3.connect(str(self.db_path))
        try:
            timestamp = datetime.utcnow().isoformat()

            # Get the hash of the previous entry
            previous_hash = self._get_last_hash(conn)

            # Create entry data (for hashing)
            entry_data = {
                "request_id": request_id,
                "timestamp": timestamp,
                "tenant_id": tenant_id,
                "zone": zone.value,
                "action": action.value,
                "decision": decision.value,
                "reason": reason,
                "outcome": outcome,
                "previous_hash": previous_hash
            }

            # Compute hash of this entry
            current_hash = self._compute_hash(entry_data)

            # Sign the entry
            signature = self._sign_entry(entry_data, current_hash)

            # Insert into database
            cursor = conn.execute("""
                INSERT INTO audit_log (
                    request_id, timestamp, tenant_id, zone, action,
                    decision, reason, outcome, previous_hash, current_hash, signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request_id, timestamp, tenant_id, zone.value, action.value,
                decision.value, reason, outcome, previous_hash, current_hash, signature
            ))

            conn.commit()
            entry_id = cursor.lastrowid

            return entry_id

        finally:
            conn.close()

    def _get_last_hash(self, conn: sqlite3.Connection) -> str:
        """Get the hash of the most recent entry, or genesis hash if log is empty."""
        cursor = conn.execute("SELECT current_hash FROM audit_log ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()

        if row:
            return row[0]
        else:
            # Genesis hash for first entry
            return hashlib.sha256(b"GLASSHOUSE_GENESIS").hexdigest()

    def _compute_hash(self, entry_data: Dict[str, Any]) -> str:
        """
        Compute deterministic hash of entry data.

        Uses SHA-256 and JSON serialization with sorted keys for determinism.
        """
        # Serialize with sorted keys for determinism
        entry_json = json.dumps(entry_data, sort_keys=True)
        entry_bytes = entry_json.encode('utf-8')

        hash_obj = hashlib.sha256(entry_bytes)
        return hash_obj.hexdigest()

    def _sign_entry(self, entry_data: Dict[str, Any], current_hash: str) -> str:
        """
        Sign an entry using NaCl.

        Signs the combination of entry data and its hash.
        """
        # Create message to sign: entry_data + current_hash
        sign_data = {**entry_data, "current_hash": current_hash}
        sign_json = json.dumps(sign_data, sort_keys=True)
        sign_bytes = sign_json.encode('utf-8')

        # Sign
        signed = self.signing_key.sign(sign_bytes)
        signature = signed.signature

        # Return base64-encoded signature
        return base64.b64encode(signature).decode('ascii')

    async def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve recent audit events.

        Args:
            limit: Maximum number of events to return

        Returns:
            List of event dictionaries, most recent first
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute("""
                SELECT * FROM audit_log
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))

            events = []
            for row in cursor.fetchall():
                events.append(dict(row))

            return events

        finally:
            conn.close()

    async def get_event_count(self) -> int:
        """Get total number of audit events."""
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.execute("SELECT COUNT(*) FROM audit_log")
            count = cursor.fetchone()[0]
            return count
        finally:
            conn.close()

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verify the integrity of the entire audit log.

        Checks:
        1. Hash chain is intact (each entry's hash matches next entry's previous_hash)
        2. Signatures are valid
        3. No gaps in sequence IDs

        Returns:
            Dictionary with verification results:
            {
                "valid": bool,
                "total_entries": int,
                "first_invalid_entry": int or None,
                "error_message": str or None
            }
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            # Get all entries in order
            cursor = conn.execute("SELECT * FROM audit_log ORDER BY id ASC")
            entries = cursor.fetchall()

            if not entries:
                return {
                    "valid": True,
                    "total_entries": 0,
                    "first_invalid_entry": None,
                    "error_message": None
                }

            # Track previous hash and ID
            expected_previous_hash = hashlib.sha256(b"GLASSHOUSE_GENESIS").hexdigest()
            expected_id = 1

            for entry in entries:
                entry_dict = dict(entry)
                entry_id = entry_dict['id']

                # Check for gaps in sequence
                if entry_id != expected_id:
                    return {
                        "valid": False,
                        "total_entries": len(entries),
                        "first_invalid_entry": entry_id,
                        "error_message": f"Sequence gap: expected ID {expected_id}, found {entry_id}"
                    }

                # Check hash chain
                if entry_dict['previous_hash'] != expected_previous_hash:
                    return {
                        "valid": False,
                        "total_entries": len(entries),
                        "first_invalid_entry": entry_id,
                        "error_message": f"Hash chain broken at entry {entry_id}"
                    }

                # Verify hash is correct
                entry_data = {
                    "request_id": entry_dict['request_id'],
                    "timestamp": entry_dict['timestamp'],
                    "tenant_id": entry_dict['tenant_id'],
                    "zone": entry_dict['zone'],
                    "action": entry_dict['action'],
                    "decision": entry_dict['decision'],
                    "reason": entry_dict['reason'],
                    "outcome": entry_dict['outcome'],
                    "previous_hash": entry_dict['previous_hash']
                }
                computed_hash = self._compute_hash(entry_data)

                if computed_hash != entry_dict['current_hash']:
                    return {
                        "valid": False,
                        "total_entries": len(entries),
                        "first_invalid_entry": entry_id,
                        "error_message": f"Hash mismatch at entry {entry_id}"
                    }

                # Verify signature
                signature_valid = self._verify_signature(entry_data, entry_dict['current_hash'], entry_dict['signature'])
                if not signature_valid:
                    return {
                        "valid": False,
                        "total_entries": len(entries),
                        "first_invalid_entry": entry_id,
                        "error_message": f"Invalid signature at entry {entry_id}"
                    }

                # Update for next iteration
                expected_previous_hash = entry_dict['current_hash']
                expected_id += 1

            # All checks passed
            return {
                "valid": True,
                "total_entries": len(entries),
                "first_invalid_entry": None,
                "error_message": None
            }

        finally:
            conn.close()

    def _verify_signature(self, entry_data: Dict[str, Any], current_hash: str, signature_b64: str) -> bool:
        """Verify the signature of an entry."""
        try:
            # Reconstruct the signed data
            sign_data = {**entry_data, "current_hash": current_hash}
            sign_json = json.dumps(sign_data, sort_keys=True)
            sign_bytes = sign_json.encode('utf-8')

            # Decode signature
            signature = base64.b64decode(signature_b64)

            # Verify
            self.verify_key.verify(sign_bytes, signature)
            return True

        except BadSignatureError:
            return False
        except Exception:
            return False
