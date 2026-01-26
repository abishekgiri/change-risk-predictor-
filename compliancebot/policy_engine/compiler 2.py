import hashlib
import json
from typing import List, Dict, Any, Union
from .dsl.ast_types import PolicyNode, RuleNode, BinaryExpr, CompareExpr, Expr
from .types import CompiledPolicy

class PolicyCompiler:
    """
    Compiles DSL AST into Phase 2 YAML Policies.
    Strategy: 1-to-Many Expansion.
    Each DSL path (Rule) becomes a separate YAML Policy.
    """
    
    def compile(self, ast: PolicyNode, source_text: str) -> List[CompiledPolicy]:
        """
        Compile a PolicyNode into multiple CompiledPolicy objects.
        """
        normalized_id = ast.policy_id.replace("_", "-")
        source_hash = hashlib.sha256(source_text.encode('utf-8')).hexdigest()
        
        compiled_policies = []
        
        # Compile each rule into a separate policy
        for i, rule in enumerate(ast.rules):
            rule_suffix = f"R{i+1}"
            rule_id = f"{normalized_id}.{rule_suffix}"
            
            # 1. Convert Condition Expression to Control List
            controls = self._flatten_condition(rule.condition)
            
            # 2. Add "Require" logic -> Controls
            # Already handled by Parser (Require -> When x < y -> Block)
            # So controls list just reflects the 'condition' AST
            
            # 3. Determine Priority (BLOCK > WARN > COMPLIANT)
            # Higher number = Higher Priority
            base_priority = 100
            if rule.enforcement.result == "BLOCK":
                priority = base_priority + 20
            elif rule.enforcement.result == "WARN":
                priority = base_priority + 10
            else:
                priority = base_priority
            
            # 4. Construct YAML Content
            policy_yaml = {
                "policy_id": rule_id,
                "version": ast.version,
                "name": f"{ast.name} - Rule {rule_suffix}",
                "description": ast.description or "",
                
                # Phase 2 Schema: controls list + enforcement block
                "controls": controls,
                
                "enforcement": {
                    "result": rule.enforcement.result,
                    "message": rule.enforcement.message
                },
                
                "metadata": {
                    "parent_policy": normalized_id,
                    "rule_id": rule_suffix,
                    "version": ast.version,
                    "priority": priority - i, # Tie-break with order (earlier rules higher)
                    "compliance": ast.compliance,
                    "effective_date": ast.effective_date,
                    "supersedes": ast.supersedes
                }
            }
            
            filename = f"{rule_id}.yaml"
            compiled_policies.append(CompiledPolicy(
                filename=filename,
                content=policy_yaml,
                source_hash=source_hash,
                policy_id=rule_id
            ))
        
        return compiled_policies

    def _flatten_condition(self, expr: Expr) -> List[Dict[str, Any]]:
        """
        Flatten an Expression Tree into a list of Controls (Implicit AND).
        Note: Phase 2 engine only supports AND logic between controls in a list.
        If DSL has OR logic, we technically need multiple policies to represent it properly (DNF).
        For MVP Sprint 2, we will assume AND-only logic or throw error on OR.
        """
        if isinstance(expr, BinaryExpr):
            if expr.operator == "and":
                return self._flatten_condition(expr.left) + self._flatten_condition(expr.right)
            elif expr.operator == "or":
                # For Phase 4 MVP, we don't support splitting OR into multiple policies yet.
                # Complex OR logic should be written as separate rules in DSL.
                raise ValueError("OR logic is not supported in a single rule condition for MVP. Split into multiple rules.")
        
        elif isinstance(expr, CompareExpr):
            return [{
                "signal": expr.left,
                "operator": expr.operator,
                "value": expr.right
            }]
        
        return []
