import csv
import json
import os
from typing import List
from releasegate.audit.types import TraceableFinding
from pathlib import Path

from releasegate.utils.paths import safe_join_under

class ReportGenerator:
    """
    Generates auditor-friendly reports in JSON, Markdown, and CSV formats.
    """
    
    def __init__(self, bundle_path: str):
        base = Path(bundle_path).resolve(strict=False)
        report_dir = safe_join_under(base, "reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir = str(report_dir)
    
    def generate_all(self, findings: List[TraceableFinding]):
        self.generate_json(findings)
        self.generate_markdown(findings)
        self.generate_csv(findings)
    
    def generate_json(self, findings: List[TraceableFinding]):
        path = safe_join_under(self.report_dir, "report.json")
        with path.open("w", encoding="utf-8") as f:
            data = [fd.__dict__ for fd in findings]
            json.dump(data, f, indent=2)
    
    def generate_csv(self, findings: List[TraceableFinding]):
        path = safe_join_under(self.report_dir, "report.csv")
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            # Header
            writer.writerow(["FindingID", "Severity", "PolicyID", "Rule", "Compliance", "Message"])
            for fd in findings:
                writer.writerow([
                    fd.finding_id,
                    fd.severity,
                    fd.policy_id,
                    fd.rule_id,
                    json.dumps(fd.compliance),
                    fd.message
                ])
    
    def generate_markdown(self, findings: List[TraceableFinding]):
        path = safe_join_under(self.report_dir, "report.md")
        with path.open("w", encoding="utf-8") as f:
            f.write("# Compliance Audit Report\n\n")
            f.write(f"**Findings:** {len(findings)}\n\n")
            
            if not findings:
                f.write("No compliance violations found.\n")
                return
            
            f.write("| Severity | Rules | Compliance | Traceability |\n")
            f.write("|----------|-------|------------|--------------|\n")
            
            for fd in findings:
                comp_str = ", ".join([f"**{k}**: {v}" for k,v in fd.compliance.items()])
                
                f.write(f"| **{fd.severity}** | `{fd.policy_id}` | {comp_str} | ")
                if fd.dsl_source:
                    f.write(f"Source: `{os.path.basename(fd.dsl_source)}`")
                f.write(" |\n")
            
            f.write("\n## Details\n")
            for fd in findings:
                f.write(f"### {fd.policy_id}\n")
                f.write(f"- **Message**: {fd.message}\n")
                f.write(f"- **Fingerprint**: `{fd.fingerprint}`\n")
                if fd.evidence_files:
                    f.write("- **Evidence Files**:\n")
                    for ef in fd.evidence_files:
                        f.write(f" - `{ef}`\n")
                f.write("\n")
