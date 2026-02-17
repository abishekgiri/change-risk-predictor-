import os
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Any

from releasegate.storage.paths import get_bundle_path
from releasegate.audit.types import TraceableFinding
from releasegate.storage.atomic import ensure_directory, atomic_write
from releasegate.utils.paths import safe_join_under

class EvidenceBundler:
    """
    Creates an immutable evidence bundle directory for a given run.
    """
    def __init__(self, repo: str, pr: int, audit_id: str):
        self.bundle_path = get_bundle_path(repo, pr, audit_id)
        self._bundle_base = Path(self.bundle_path).resolve(strict=False)
        self.manifest_path = str(safe_join_under(self._bundle_base, "manifest.json"))
        ensure_directory(str(self._bundle_base))
    
    def _write_json(self, filename: str, data: Any):
        path = str(safe_join_under(self._bundle_base, filename))
        with atomic_write(path) as f:
            json.dump(data, f, indent=2, sort_keys=True)
    
    def _write_file(self, filename: str, content: str):
        path = str(safe_join_under(self._bundle_base, filename))
        with atomic_write(path) as f:
            f.write(content)
    
    def _compute_file_hash(self, filename: str) -> str:
        path = str(safe_join_under(self._bundle_base, filename))
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
        for root, _, files in os.walk(self._bundle_base):
            root_path = Path(root)
            for file in files:
                if file == "manifest.json": continue
                try:
                    rel_path = str(
                        root_path.joinpath(file)
                        .resolve(strict=False)
                        .relative_to(self._bundle_base)
                    )
                except Exception:
                    continue
                manifest[rel_path] = self._compute_file_hash(rel_path)
        
        self._write_json("manifest.json", manifest)
        
        # 3. Return Manifest Hash (Root of Trust)
        return self._compute_file_hash("manifest.json")
