"""
License Control (OSS-PR-001).

Prevents disallowed open-source licenses from being introduced.
"""
from typing import Dict, Any, List
from .types import ControlBase, ControlContext, ControlSignalSet, Finding
from releasegate.signals.licenses.detector import detect_licenses, classify_license

class LicensesControl(ControlBase):
    """
    License scanning control.
    
    Scans dependency files (package-lock.json, requirements.txt, go.mod)
    for forbidden or unknown licenses.
    """
    
    def execute(self, ctx: ControlContext) -> ControlSignalSet:
        """
        Execute license scanning.
        
        Args:
            ctx: Control execution context
        
        Returns:
            Control signals and findings
        """
        findings: List[Finding] = []
        all_packages: Dict[str, str] = {}
        
        skipped_diff_only = False
        # Scan all changed dependency files
        for file_path, diff_content in ctx.diff.items():
            if self._is_dependency_file(file_path):
                # If we only have a diff, we cannot reliably parse full manifest
                if self._looks_like_diff(diff_content):
                    # Try to fetch full file content from provider if available
                    full_content = None
                    if ctx.provider is not None:
                        get_file_content = getattr(ctx.provider, "get_file_content", None)
                        if callable(get_file_content):
                            ref = ctx.config.get("head_sha") or ctx.config.get("ref")
                            full_content = get_file_content(ctx.repo, file_path, ref)
                    if full_content:
                        packages = detect_licenses(file_path, full_content)
                        all_packages.update(packages)
                    else:
                        skipped_diff_only = True
                        continue
                else:
                    packages = detect_licenses(file_path, diff_content)
                    all_packages.update(packages)
        
        # Classify licenses
        forbidden_packages = []
        unknown_packages = []
        allowed_packages = []
        
        for pkg_name, license_name in all_packages.items():
            classification = classify_license(license_name)
            
            if classification == "FORBIDDEN":
                forbidden_packages.append((pkg_name, license_name))
                findings.append(Finding(
                    control_id="OSS-PR-001",
                    rule_id="OSS-PR-001.FORBIDDEN",
                    severity="HIGH",
                    message=f"Forbidden license detected: {pkg_name} ({license_name})",
                    file_path="",
                    evidence={
                        "package": pkg_name,
                        "license": license_name,
                        "classification": "FORBIDDEN"
                    }
                ))
            elif classification == "UNKNOWN":
                unknown_packages.append((pkg_name, license_name))
                findings.append(Finding(
                    control_id="OSS-PR-001",
                    rule_id="OSS-PR-001.UNKNOWN",
                    severity="MEDIUM",
                    message=f"Unknown license: {pkg_name} ({license_name})",
                    file_path="",
                    evidence={
                        "package": pkg_name,
                        "license": license_name,
                        "classification": "UNKNOWN"
                    }
                ))
            else:
                allowed_packages.append((pkg_name, license_name))
        
        # Generate signals
        signals: Dict[str, Any] = {
            "licenses.scanned": len(all_packages) > 0,
            "licenses.total_count": len(all_packages),
            "licenses.forbidden_count": len(forbidden_packages),
            "licenses.unknown_count": len(unknown_packages),
            "licenses.allowed_count": len(allowed_packages),
            "licenses.skipped_diff_only": skipped_diff_only
        }
        
        return ControlSignalSet(
            signals=signals,
            findings=findings
        )
    
    def _is_dependency_file(self, file_path: str) -> bool:
        """Check if file is a dependency manifest/lockfile."""
        dependency_files = [
            "package-lock.json",
            "package.json",
            "requirements.txt",
            "Pipfile.lock",
            "go.mod",
            "go.sum",
            "Gemfile.lock",
            "Cargo.lock"
        ]
        return any(file_path.endswith(f) for f in dependency_files)

    def _looks_like_diff(self, content: str) -> bool:
        """Heuristic: detect if content is a diff, not full file text."""
        if not isinstance(content, str):
            return True
        markers = ["diff --git", "\n@@", "\n+++", "\n---"]
        return any(m in content for m in markers) or content.startswith("@@")
