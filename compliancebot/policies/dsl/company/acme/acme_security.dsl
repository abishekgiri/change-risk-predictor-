
policy ACME_Sec_001 {
    version: "1.0.0"
    name: "Acme Corp Security Standard"
    description: "Company-specific overrides and stricter enforcement."

    control AcmeControls {
        signals: [
            approvals.count,
            licenses.id,
            deployment.risk_score
        ]
    }

    rules {
        # Overlay Rule: Stricter than SOC2 (Require 2 approvals)
        # SOC2 requires >= 1. If we have 1, SOC2 passes, but ACME fails (BLOCK).
        # Worst case wins -> BLOCK.
        require approvals.count >= 2

        # Specific Rule: Ban GPL explicitly
        when licenses.id == "GPL-3.0" {
            enforce BLOCK
            message "ACME Policy Violation: GPL-3.0 is strictly banned for commercial distribution."
        }
        
        # Risk Score Threshold
        when deployment.risk_score > 80 {
            enforce BLOCK
            message "ACME Policy Violation: Deployment risk score too high (>80). Reduce risk before merging."
        }
    }

    compliance {
        Internal: "Sec-Std-01"
    }
}
