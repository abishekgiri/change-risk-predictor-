
policy HIPAA_164_312_a_AccessControl {
    version: "1.0.0"
    name: "HIPAA 164.312(a) - Access Control"
    description: "Implement technical policies and procedures for electronic information systems that maintain electronic protected health information (ePHI) to allow access only to those persons or software programs that have been granted access rights."

    control AccessControl {
        signals: [
            secrets.detected,
            approvals.security_review
        ]
    }

    rules {
        # 164.312(a)(2)(i) - Unique User Identification (Prevent hardcoded/shared credentials)
        when secrets.detected == true {
            enforce BLOCK
            message "HIPAA 164.312(a)(2)(i) Violation: Hardcoded credentials detected. ePHI systems must enforce unique user identification."
        }

        # 164.312(a)(2)(ii) - Emergency Access Procedure (Require specific approvals for override/access)
        require approvals.security_review >= 1
    }

    compliance {
        HIPAA: "164.312(a) - Access Control"
    }
}
