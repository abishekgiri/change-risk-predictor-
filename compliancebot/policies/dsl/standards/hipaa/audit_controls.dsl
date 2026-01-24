
policy HIPAA_164_312_b_AuditControls {
    version: "1.0.0"
    name: "HIPAA 164.312(b) - Audit Controls"
    description: "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information."

    control AuditMechanisms {
        signals: [
            privileged.is_sensitive
        ]
    }

    rules {
        # 164.312(b) - Audit Controls (Flag sensitive changes for audit review)
        when privileged.is_sensitive == true {
            enforce WARN
            message "HIPAA 164.312(b): Sensitive system modification detected. Ensure this change is logged in the audit trail."
        }
    }

    compliance {
        HIPAA: "164.312(b) - Audit Controls"
    }
}
