
policy ISO27001_A14_SecureDevelopment {
    version: "1.0.0"
    name: "ISO 27001 A.14 - System Acquisition, Development and Maintenance"

    control SecureDevelopment {
        signals: [
            privileged.is_sensitive,
            licenses.banned_detected
        ]
    }

    rules {
        # A.14.2.5 - Secure system engineering principles (Review sensitive changes)
        when privileged.is_sensitive == true {
            enforce WARN
            message "ISO 27001 A.14.2.5: Sensitive code modification requires security review."
        }
        
        # A.14.2.1 - Secure Development Policy (No banned components)
        when licenses.banned_detected == true {
            enforce BLOCK
            message "ISO 27001 A.14.2.1: Use of banned software components (licenses) is prohibited."
        }
    }

    compliance {
        ISO27001: "A.14 - System Acquisition, Development and Maintenance"
    }
}
