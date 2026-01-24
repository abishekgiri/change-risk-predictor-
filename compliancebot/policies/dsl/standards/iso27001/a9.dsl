
policy ISO27001_A9_AccessControl {
    version: "1.0.0"
    name: "ISO 27001 A.9 - Access Control"
    
    control AccessControl {
        signals: [
            secrets.detected,
            approvals.security_review
        ]
    }

    rules {
        # A.9.4.3 - Password Management System (Prevent hardcoded credentials)
        when secrets.detected == true {
            enforce BLOCK
            message "ISO 27001 A.9.4.3: Interactive password management required. Hardcoded secrets prohibited."
        }

        # A.9.2.3 - Management of Privileged Access Rights (Require approval for access changes)
        require approvals.security_review >= 1
    }

    compliance {
        ISO27001: "A.9 - Access Control"
    }
}
