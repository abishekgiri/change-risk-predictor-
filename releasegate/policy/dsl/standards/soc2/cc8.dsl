
policy SOC2_CC8 {
    version: "1.0.0"
    name: "SOC 2 CC8 - Change Management"
    description: "Ensures changes are authorized and tested prior to deployment."

    control ChangeManagement {
        signals: [
            approvals.count,
            licenses.banned_detected
        ]
    }

    rules {
        # CC8.1 - Authorize changes (Peer Review)
        # Require at least 1 generic approval (peer review)
        require approvals.count >= 1

        # CC8.1 - Prevent unauthorized software (Banned Licenses)
        when licenses.banned_detected == true {
            enforce BLOCK
            message "SOC 2 CC8.1 Violation: Unauthorized software license detected."
        }
    }

    compliance {
        SOC2: "CC8.1 - Authorization of Changes"
    }
}
