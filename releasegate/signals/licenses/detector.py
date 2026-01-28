"""
License detection from lockfiles and manifests.
"""
import json
from typing import Dict, List, Optional
from pathlib import Path

# Known forbidden licenses (copyleft, restrictive)
FORBIDDEN_LICENSES = [
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
]

# Known allowed licenses (permissive)
ALLOWED_LICENSES = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "0BSD",
]

def parse_package_lock(content: str) -> Dict[str, str]:
    """
    Parse package-lock.json (npm) for dependencies and licenses.
    
    Args:
        content: File content
    
    Returns:
        Dict mapping package names to licenses
    """
    try:
        data = json.loads(content)
        packages = {}
        
        # npm v2+ format
        if "packages" in data:
            for pkg_path, pkg_info in data.get("packages", {}).items():
                if pkg_path == "": # Root package
                    continue
                name = pkg_path.split("node_modules/")[-1]
                license_info = pkg_info.get("license", "UNKNOWN")
                packages[name] = license_info
        
        # npm v1 format (fallback)
        elif "dependencies" in data:
            for name, pkg_info in data.get("dependencies", {}).items():
                license_info = pkg_info.get("license", "UNKNOWN")
                packages[name] = license_info
        
        return packages
    except json.JSONDecodeError:
        return {}

def parse_requirements_txt(content: str) -> Dict[str, str]:
    """
    Parse requirements.txt (Python) for dependencies.
    
    Note: requirements.txt doesn't include license info,
    so we return UNKNOWN for all packages.
    
    Args:
        content: File content
    
    Returns:
        Dict mapping package names to "UNKNOWN"
    """
    packages = {}
    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        # Extract package name (before ==, >=, etc.)
        pkg_name = line.split("==")[0].split(">=")[0].split("<=")[0].strip()
        packages[pkg_name] = "UNKNOWN"
    
    return packages

def parse_go_mod(content: str) -> Dict[str, str]:
    """
    Parse go.mod for dependencies.
    
    Note: go.mod doesn't include license info.
    
    Args:
        content: File content
    
    Returns:
        Dict mapping package names to "UNKNOWN"
    """
    packages = {}
    in_require = False
    
    for line in content.split("\n"):
        line = line.strip()
        
        if line.startswith("require"):
            in_require = True
            continue
        
        if in_require:
            if line == ")":
                in_require = False
                continue
            
            # Extract module name
            parts = line.split()
            if len(parts) >= 2:
                pkg_name = parts[0]
                packages[pkg_name] = "UNKNOWN"
    
    return packages

def detect_licenses(file_path: str, content: str) -> Dict[str, str]:
    """
    Detect licenses from a dependency file.
    
    Args:
        file_path: Path to the file
        content: File content
    
    Returns:
        Dict mapping package names to licenses
    """
    filename = Path(file_path).name
    
    if filename == "package-lock.json":
        return parse_package_lock(content)
    elif filename == "requirements.txt":
        return parse_requirements_txt(content)
    elif filename == "go.mod":
        return parse_go_mod(content)
    
    return {}

def classify_license(license_name: str) -> str:
    """
    Classify a license as FORBIDDEN, ALLOWED, or UNKNOWN.
    
    Args:
        license_name: License identifier
    
    Returns:
        Classification: "FORBIDDEN", "ALLOWED", or "UNKNOWN"
    """
    if license_name in FORBIDDEN_LICENSES:
        return "FORBIDDEN"
    elif license_name in ALLOWED_LICENSES:
        return "ALLOWED"
    else:
        return "UNKNOWN"

