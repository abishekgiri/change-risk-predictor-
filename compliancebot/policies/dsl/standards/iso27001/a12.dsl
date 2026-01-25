
policy ISO27001_A12_OperationsSecurity {
    version: "1.0.0"
    name: "ISO 27001 A.12 - Operations Security"

    control OperationsSecurity {
        signals: [
            approvals.count,
            env.production_violation
        ]
    }

    rules {
        # A.12.1.2 - Change Management (Changes must be documented and approved)
        require approvals.count >= 1

        # A.12.1.4 - Separation of development, testing and operational environments
        when env.production_violation == true {
            enforce BLOCK
            message "ISO 27001 A.12.1.4: Separation of environments violated. Production config found in non-prod code."
        }
    }

    compliance {
        ISO27001: "A.12 - Operations Security"
    }
}
