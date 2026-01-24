import sys
from compliancebot.policy_engine.dsl.lexer import DSLTokenizer
from compliancebot.policy_engine.dsl.parser import DSLParser
from compliancebot.policy_engine.dsl.validator import DSLValidator
from compliancebot.policy_engine.dsl.ast_types import CompareExpr

SAMPLE_DSL = """
policy SEC_PR_002 {
 version: "2.0.0"
 name: "Secret Scanner"
 
 control SecretScanning {
 signals: [secrets.detected, secrets.severity]
 }
 
 rules {
 # Standard WHEN rule
 when secrets.detected == true and secrets.severity == "HIGH" {
 enforce BLOCK
 message "High severity secret found"
 }
 
 # REQUIRE syntax (should invert logic)
 require approvals.security >= 1
 }
 
 compliance {
 SOC2: "CC6.1"
 }
}
"""

def test_dsl_foundation():
 print("1. Testing Tokenizer...")
 lexer = DSLTokenizer(SAMPLE_DSL)
 tokens = lexer.tokenize()
 print(f"Tokenized {len(tokens)} tokens")
 
 print("\n2. Testing Parser...")
 parser = DSLParser(tokens)
 ast = parser.parse()
 print(f"✅ Parsed Policy: {ast.policy_id} v{ast.version}")
 
 # Check Rules
 assert len(ast.rules) == 2, f"Expected 2 rules, got {len(ast.rules)}"
 
 # Check Logic Inversion for Require
 # require >= 1 ---> condition < 1
 req_rule = ast.rules[1]
 assert isinstance(req_rule.condition, CompareExpr)
 print(f"Rule 2 Condition: {req_rule.condition.left} {req_rule.condition.operator} {req_rule.condition.right}")
 
 if req_rule.condition.operator == '<' and req_rule.condition.right == 1:
 print("REQUIRE logic validated correctly (inverted to < 1)")
 else:
 print("❌ REQUIRE logic failed inversion")
 sys.exit(1)
 
 print("\n3. Testing Validator...")
 validator = DSLValidator()
 errors = validator.validate(ast)
 if not errors:
 print("Validation passed")
 else:
 print("❌ Validation errors:", errors)
 sys.exit(1)

if __name__ == "__main__":
 test_dsl_foundation()
