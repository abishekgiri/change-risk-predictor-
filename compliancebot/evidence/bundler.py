import os
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any

from compliancebot.storage.paths import get_bundle_path
from compliancebot.audit.types import AuditEvent, TraceableFinding
from compliancebot.storage.atomic import ensure_directory, atomic_write
from compliancebot.evidence.snippets import extract_snippet

class EvidenceBundler:
    """
    Creates an immutable evidence bundle directory for a given run.
    """
    def __init__(self, repo: str, pr: int, audit_id: str):
        self.bundle_path = get_bundle_path(repo, pr, audit_id)
        self.manifest_path = os.path.join(self.bundle_path, "manifest.json")
        ensure_directory(self.bundle_path)
    
    def _write_json(self, filename: str, data: Any):
        path = os.path.join(self.bundle_path, filename)
        with atomic_write(path) as f:
            json.dump(data, f, indent=2, sort_keys=True)
    
    def _write_file(self, filename: str, content: str):
        path = os.path.join(self.bundle_path, filename)
        with atomic_write(path) as f:
            f.write(content)
    
    def _compute_file_hash(self, filename: str) -> str:
        path = os.path.join(self.bundle_path, filename)
        sha = hashlib.sha256()
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                sha.update(chunk)
        return sha.hexdigest()

    def create_bundle(self, 
                      inputs: Dict[str, Any],
                      findings: List[TraceableFinding],
                      diff_text: str,
                      policies: Dict[str, Any]) -> str:
        """
        Writes all artifacts and returns the SHA256 of the manifest.
        """
        
        # 1. Write Data Artifacts
        self._write_json("inputs/pr_metadata.json", inputs)
        self._write_json("findings.json", [f.__dict__ for f in findings])
        self._write_json("policies_used.json", policies)
        
        # 2. Write Diff Artifact
        ensure_directory(os.path.join(self.bundle_path, "artifacts"))
        self._write_file("artifacts/diff.patch", diff_text)
        
        # 3. Generate Snippets (if any findings)
        ensure_directory(os.path.join(self.bundle_path, "artifacts/snippets"))
        for i, finding in enumerate(findings):
            # Try to grab filename from message or context if possible
            # For MVP, we assume global diff or specific known file
            # This logic mimics finding context extraction
            snippet = extract_snippet(diff_text, "unknown.py") 
            fname = f"{finding.fingerprint[:8]}_{i}.txt"
            self._write_file(f"artifacts/snippets/{fname}", snippet)
            finding.evidence_files.append(f"artifacts/snippets/{fname}")
        
        # 4. Create Manifest
        # Scan all files we just wrote
        manifest = {}
        for root, _, files in os.walk(self.bundle_path):
            for file in files:
                if file == "manifest.json": continue
                rel_path = os.path.relpath(os.path.join(root, file), self.bundle_path)
                manifest[rel_path] = self._compute_file_hash(rel_path)
        
        self._write_json("manifest.json", manifest)
        
        # 5. Return Manifest Hash (Root of Trust)
        return self._compute_file_hash("manifest.json")

