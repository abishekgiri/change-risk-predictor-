
policy SEC_PR_TEST {
 version: "1.0.0"
 name: "Test Policy"
 
 control TestControl {
 signals: [test.signal]
 }
 
 rules {
 when test.signal == true {
 enforce BLOCK
 message "Block message"
 }
 
 when test.signal == false {
 enforce WARN
 message "Warn message"
 }
 }
 
 compliance {
 TEST: "T1"
 }
}
