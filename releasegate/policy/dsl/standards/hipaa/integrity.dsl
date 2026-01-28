
policy HIPAA_164_312_c_Integrity {
    version: "1.0.0"
    name: "HIPAA 164.312(c) - Integrity"
    description: "Implement policies and procedures to protect electronic protected health information from improper alteration or destruction."

    control IntegrityControls {
        signals: [
            env.production_violation,
            licenses.banned_detected
        ]
    }

    rules {
        # 164.312(c)(1) - Mechanism to authenticate electronic protected health information (Prevent prod leakage)
        when env.production_violation == true {
            enforce BLOCK
            message "HIPAA 164.312(c) Integrity Violation: Production configuration in non-prod environment creates integrity risk."
        }

        # 164.312(c)(2) - Establish mechanism to corroborate that ePHI has not been altered (Prevent unauthorized code)
        when licenses.banned_detected == true {
            enforce BLOCK
            message "HIPAA 164.312(c) Integrity: Use of unauthorized/banned software components detected."
        }
    }

    compliance {
        HIPAA: "164.312(c) - Integrity"
    }
}
