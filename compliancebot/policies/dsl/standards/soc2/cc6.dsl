
policy SOC2_CC6 {
    version: "1.0.0"
    name: "SOC 2 CC6 - Logical and Physical Access Controls"
    description: "Ensures logical access is secured via secret scanning and approval workflows."

    control AccessControls {
        signals: [
            secrets.detected, 
            secrets.severity,
            approvals.security_review
        ]
    }

    rules {
        # CC6.1 - Prevent hardcoded credentials (Logical Access)
        when secrets.detected == true {
            enforce BLOCK
            message "SOC 2 CC6.1 Violation: Hardcoded credentials detected. This bypasses logical access controls."
        }

        # CC6.3 - Authorize access changes (Security Approvals)
        # Using 'require' syntax which maps to: when approvals.security_review < 1 -> BLOCK
        require approvals.security_review >= 1
    }

    compliance {
        SOC2: "CC6.1 - Logical Access Security Software"
    }
}
