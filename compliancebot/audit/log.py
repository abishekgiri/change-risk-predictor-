import json
import hashlib
import os
from typing import Optional, Dict

from compliancebot.audit.types import AuditEvent
from compliancebot.storage.atomic import atomic_write
from compliancebot.storage.paths import get_audit_log_path

class AuditLogger:
    """
    Manages the append-only, hash-chained audit log.
    """
    
    def __init__(self, repo_name: str):
        self.log_path = get_audit_log_path(repo_name)
        self._ensure_dir()
    
    def _ensure_dir(self):
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def _get_last_hash(self) -> Optional[str]:
        """Reads the last line of the log to get the previous hash."""
        if not os.path.exists(self.log_path):
            return None
        
        try:
            with open(self.log_path, 'rb') as f:
                # Efficiently read last line
                try:
                    f.seek(-2, os.SEEK_END)
                    while f.read(1) != b'\n':
                        f.seek(-2, os.SEEK_CUR)
                except OSError:
                    f.seek(0)
                
                last_line = f.readline().decode()
                
                if not last_line.strip():
                    return None
                
                data = json.loads(last_line)
                return data.get("event_hash")
        except Exception:
            return None

    def _compute_hash(self, event_dict: Dict) -> str:
        """
        Computes SHA256 of the canonical JSON representation of the event
        (excluding the event_hash field itself).
        """
        # Create copy to avoid mutating original
        data = event_dict.copy()
        data["event_hash"] = None # Nullify for computation
        
        # Canonical JSON: sort keys, no spaces
        payload = json.dumps(data, sort_keys=True, separators=(',', ':')).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def append_event(self, event: AuditEvent):
        """
        Appends a new event to the log efficiently.
        """
        # 1. Link to previous
        prev_hash = self._get_last_hash()
        event.previous_event_hash = prev_hash or "0000000000000000000000000000000000000000000000000000000000000000"
        
        # 2. Compute self hash
        event_dict = event.to_dict()
        current_hash = self._compute_hash(event_dict)
        event.event_hash = current_hash
        event_dict["event_hash"] = current_hash
        
        # 3. Append-only write
        # We use standard append mode 'a' here. 
        # Atomic write is tricky for appending to large files (requires copying).
        # Since this is a log, OS append is generally safe enough, 
        # or we could use the atomic utility if we accept the copy cost.
        # For high-volume logs, direct append is preferred.
        
        with open(self.log_path, 'a') as f:
            f.write(json.dumps(event_dict) + "\n")
        
        return current_hash

