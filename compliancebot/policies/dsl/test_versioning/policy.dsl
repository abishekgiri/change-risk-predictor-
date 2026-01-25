
policy TEST_Policy {
    version: "2.0.0"
    name: "Test Policy V2"
    effective_date: "2026-01-01"
    supersedes: "1.0.0"
    
    rules {
        when test.signal == true { enforce BLOCK } # V2 is stricter
    }
}
