import os
import json
import hashlib
from typing import Dict, List, Any

from releasegate.storage.paths import get_bundle_path
from releasegate.audit.types import TraceableFinding
from releasegate.storage.atomic import ensure_directory, atomic_write

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
        _ = diff_text  # Diff content is intentionally handled in-memory only.
        
        # 1. Write Data Artifacts
        self._write_json("inputs/pr_metadata.json", inputs)
        self._write_json("findings.json", [f.__dict__ for f in findings])
        self._write_json("policies_used.json", policies)

        # 2. Create Manifest
        # Scan all files we just wrote
        manifest = {}
        for root, _, files in os.walk(self.bundle_path):
            for file in files:
                if file == "manifest.json": continue
                rel_path = os.path.relpath(os.path.join(root, file), self.bundle_path)
                manifest[rel_path] = self._compute_file_hash(rel_path)
        
        self._write_json("manifest.json", manifest)
        
        # 3. Return Manifest Hash (Root of Trust)
        return self._compute_file_hash("manifest.json")
