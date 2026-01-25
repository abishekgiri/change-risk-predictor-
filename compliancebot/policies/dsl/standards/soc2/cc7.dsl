
policy SOC2_CC7 {
    version: "1.0.0"
    name: "SOC 2 CC7 - System Operations"
    description: "Monitors system operations for anomalies and boundary violations."

    control SystemMonitoring {
        signals: [
            privileged.is_sensitive,
            env.production_violation
        ]
    }

    rules {
        # CC7.2 - Monitor for anomalies (Privileged Code Changes)
        when privileged.is_sensitive == true {
            enforce WARN
            message "SOC 2 CC7.2: Sensitive system code modified. Verify this is a planned system operation."
        }

        # CC7.1 - Detection of unauthorized configuration changes (Env Boundary)
        when env.production_violation == true {
            enforce BLOCK
            message "SOC 2 CC7.1 Violation: Production configuration in non-prod environment detected."
        }
    }

    compliance {
        SOC2: "CC7.2 - Security Event Monitoring"
    }
}
