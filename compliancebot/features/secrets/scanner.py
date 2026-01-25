"""
Deterministic secret scanner.

Scans diffs for secrets using 2-factor detection:
1. Pattern match (regex)
2. Context check (keyword proximity) OR high entropy
"""
from typing import List, Optional
from .patterns import get_all_rules, check_context
from .entropy import is_high_entropy
from .types import SecretFinding

def scan_line(
    line: str,
    file_path: str,
    line_number: Optional[int] = None,
    diff_hunk: Optional[str] = None,
    diff_line_index: Optional[int] = None
) -> List[SecretFinding]:
    """
    Scan a single line for secrets.
    """
    findings = []
    
    for rule in get_all_rules():
        for match in rule.pattern.finditer(line):
            matched_value = match.group(0)
            match_start = match.start()
            match_end = match.end()
            
            # 2-factor detection
            if rule.requires_context:
                # Need context check OR high entropy
                has_context = check_context(line, match_start, match_end)
                has_high_entropy = is_high_entropy(matched_value)
                
                if not (has_context or has_high_entropy):
                    continue # Skip this match
            
            # Found a secret!
            finding = SecretFinding(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                file_path=file_path,
                line_number=line_number,
                line_content=line.strip(),
                matched_value=matched_value,
                severity=rule.severity,
                diff_hunk=diff_hunk,
                diff_line_index=diff_line_index
            )
            findings.append(finding)
    
    return findings

def scan_diff(diff_text: str, file_path: str) -> List[SecretFinding]:
    """
    Scan a git diff for secrets.
    """
    findings = []
    lines = diff_text.split('\n')
    
    current_hunk = None
    hunk_start_line = None
    
    for i, line in enumerate(lines):
        # Track diff hunks
        if line.startswith('@@'):
            current_hunk = line
            # Parse line number from hunk header
            try:
                parts = line.split('+')[1].split(',')[0].strip()
                hunk_start_line = int(parts)
            except (IndexError, ValueError):
                hunk_start_line = None
        
        # Only scan added lines
        if line.startswith('+') and not line.startswith('+++'):
            # Calculate actual line number
            line_number = None
            if hunk_start_line is not None:
                # Count '+' lines since hunk start
                # Need to be careful with indexing
                # For simplicity, recalculate based on current index vs current_hunk index
                hunk_idx = lines.index(current_hunk) if current_hunk in lines else 0
                added_lines = sum(
                    1 for l in lines[hunk_idx:i]
                    if l.startswith('+') and not l.startswith('+++')
                )
                line_number = hunk_start_line + added_lines
            
            # Scan the line (remove the '+' prefix)
            line_findings = scan_line(
                line=line[1:], # Remove '+'
                file_path=file_path,
                line_number=line_number,
                diff_hunk=current_hunk,
                diff_line_index=i
            )
            findings.extend(line_findings)
    
    return findings

def scan_pr_diff(pr_diff: dict) -> List[SecretFinding]:
    """
    Scan all files in a PR diff for secrets.
    """
    all_findings = []
    
    for file_path, diff_text in pr_diff.items():
        findings = scan_diff(diff_text, file_path)
        all_findings.extend(findings)
    
    return all_findings

