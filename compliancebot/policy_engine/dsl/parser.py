from typing import List, Optional, Any, Dict
from .lexer import Token, DSLTokenizer
from .ast_types import (
    PolicyNode, ControlNode, RuleNode, EnforcementNode,
    Expr, BinaryExpr, CompareExpr
)

class DSLParser:
    """
    Recursive descent parser for Compliance DSL.
    Grammar:
    policy: POLICY IDENT LBRACE (control | rules | compliance | metadata)* RBRACE
    control: CONTROL IDENT LBRACE (SIGNALS | EVIDENCE) COLON LBRACKET list RBRACKET RBRACE
    rules: RULES LBRACE (rule)* RBRACE
    rule: WHEN expr LBRACE ENFORCE IDENT (MESSAGE STRING)? RBRACE
    | REQUIRE IDENT DOT IDENT operator literal
    """
    
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    def parse(self) -> PolicyNode:
        """Parse a full policy definition."""
        self._consume('POLICY')
        policy_id = self._consume('IDENT').value
        self._consume('LBRACE')
        
        name = ""
        version = ""
        description = None
        effective_date = None
        supersedes = None
        controls = []
        rules = []
        compliance = {}
        
        while not self._match('RBRACE') and not self._match('EOF'):
            if self._match('VERSION'):
                self._consume('VERSION')
                self._consume('COLON')
                version = self._consume('STRING').value
            
            elif self._match('NAME'):
                self._consume('NAME')
                self._consume('COLON')
                name = self._consume('STRING').value
            
            elif self._match('DESC'):
                self._consume('DESC')
                self._consume('COLON')
                description = self._consume('STRING').value

            elif self._match('EFFECTIVE'):
                self._consume('EFFECTIVE')
                self._consume('COLON')
                effective_date = self._consume('STRING').value # Keep as string for now

            elif self._match('SUPERSEDES'):
                self._consume('SUPERSEDES')
                self._consume('COLON')
                supersedes = self._consume('STRING').value
            
            elif self._match('CONTROL'):
                controls.append(self._parse_control())
            
            elif self._match('RULES'):
                rules.extend(self._parse_rules_block())
            
            elif self._match('COMPLIANCE'):
                compliance = self._parse_compliance()
            
            else:
                raise ValueError(f"Unexpected token in policy body: {self._current().type}")
        
        self._consume('RBRACE')
        
        if not version or not name:
            raise ValueError("Policy must have 'version' and 'name'")
        
        return PolicyNode(
            policy_id=policy_id,
            version=version,
            name=name,
            description=description,
            effective_date=effective_date,
            supersedes=supersedes,
            controls=controls,
            rules=rules,
            compliance=compliance
        )

    def _parse_control(self) -> ControlNode:
        self._consume('CONTROL')
        name = self._consume('IDENT').value
        self._consume('LBRACE')
        
        signals = []
        evidence = []
        
        while not self._match('RBRACE'):
            if self._match('SIGNALS'):
                self._consume('SIGNALS')
                self._consume('COLON')
                signals = self._parse_list()
            elif self._match('EVIDENCE'):
                self._consume('EVIDENCE')
                self._consume('COLON')
                evidence = self._parse_list()
            else:
                raise ValueError(f"Unexpected token in control: {self._current().type}")
        
        self._consume('RBRACE')
        return ControlNode(name, signals, evidence)

    def _parse_list(self) -> List[str]:
        """Parse [item1, item2, item.prop]"""
        self._consume('LBRACKET')
        items = []
        while not self._match('RBRACKET'):
            token = self._consume('IDENT')
            val = token.value
            # Handle dot notation for signals (e.g. secrets.detected)
            while self._match('DOT'):
                self._consume('DOT')
                val += "." + self._consume('IDENT').value
            items.append(val)
            if self._match('COMMA'):
                self._consume('COMMA')
        self._consume('RBRACKET')
        return items

    def _parse_rules_block(self) -> List[RuleNode]:
        self._consume('RULES')
        self._consume('LBRACE')
        rules = []
        while not self._match('RBRACE'):
            if self._match('WHEN'):
                rules.append(self._parse_when_rule())
            elif self._match('REQUIRE'):
                rules.append(self._parse_require_rule())
            else:
                raise ValueError(f"Expected WHEN or REQUIRE, got {self._current().type}")
        self._consume('RBRACE')
        return rules

    def _parse_when_rule(self) -> RuleNode:
        self._consume('WHEN')
        condition = self._parse_expression()
        self._consume('LBRACE')
        
        self._consume('ENFORCE')
        result = self._consume('IDENT').value # BLOCK/WARN
        
        message = None
        if self._match('MESSAGE'):
            self._consume('MESSAGE')
            message = self._consume('STRING').value
        
        self._consume('RBRACE')
        
        return RuleNode(
            condition=condition,
            enforcement=EnforcementNode(result, message)
        )

    def _parse_require_rule(self) -> RuleNode:
        # Syntactic sugar: "require approvals.security >= 1"
        # Becomes: when approvals.security < 1 { enforce BLOCK }
        self._consume('REQUIRE')
        left = self._parse_identifier()
        
        op_token = self._current()
        if op_token.type not in ('GTE', 'GT', 'LTE', 'LT', 'EQ', 'NEQ'):
            raise ValueError(f"Expected operator after require identifier, got {op_token.type}")
        self._advance()
        
        right = self._parse_literal()
        
        # Invert logic for "require"
        # require x >= 1 -> if x < 1 then BLOCK
        inverted_op_map = {
            '>=': '<', '>': '<=',
            '<=': '>', '<': '>=',
            '==': '!=', '!=': '=='
        }
        inverted_op = inverted_op_map.get(op_token.value, '==')
        
        condition = CompareExpr(left, inverted_op, right)
        enforcement = EnforcementNode("BLOCK", f"Requirement failed: {left} {op_token.value} {right}")
        
        return RuleNode(condition, enforcement)

    def _parse_expression(self) -> Expr:
        return self._parse_or()

    def _parse_or(self) -> Expr:
        left = self._parse_and()
        while self._match('OR'):
            op = self._consume('OR').value
            right = self._parse_and()
            left = BinaryExpr(left, op, right)
        return left

    def _parse_and(self) -> Expr:
        left = self._parse_comparison()
        while self._match('AND'):
            op = self._consume('AND').value
            right = self._parse_comparison()
            left = BinaryExpr(left, op, right)
        return left

    def _parse_comparison(self) -> Expr:
        # TODO: Handle parens
        left_id = self._parse_identifier()
        
        op_token = self._current()
        if op_token.type in ('EQ', 'NEQ', 'GT', 'LT', 'GTE', 'LTE', 'IN', 'NOT_IN'):
            self._advance()
            right = self._parse_literal()
            return CompareExpr(left_id, op_token.value, right)
        
        raise ValueError(f"Expected comparison operator, got {op_token.type}")

    def _parse_identifier(self) -> str:
        val = self._consume('IDENT').value
        while self._match('DOT'):
            self._consume('DOT')
            val += "." + self._consume('IDENT').value
        return val

    def _parse_literal(self) -> Any:
        if self._match('STRING'): return self._consume('STRING').value
        if self._match('NUMBER'): 
            val = self._consume('NUMBER').value
            return float(val) if '.' in val else int(val)
        if self._match('BOOL'): return self._consume('BOOL').value == 'true'
        raise ValueError(f"Expected literal, got {self._current().type}")

    def _parse_compliance(self) -> Dict[str, str]:
        self._consume('COMPLIANCE')
        self._consume('LBRACE')
        mapping = {}
        while not self._match('RBRACE'):
            key = self._consume('IDENT').value
            self._consume('COLON')
            val = self._consume('STRING').value
            mapping[key] = val
        self._consume('RBRACE')
        return mapping

    # Helper methods
    def _current(self) -> Token:
        if self.pos >= len(self.tokens):
            return self.tokens[-1]
        return self.tokens[self.pos]

    def _match(self, type_: str) -> bool:
        return self._current().type == type_

    def _consume(self, type_: str) -> Token:
        if self._match(type_):
            token = self._current()
            self.pos += 1
            return token
        raise ValueError(f"Expected token {type_}, got {self._current().type} at line {self._current().line}")
    
    def _advance(self):
        self.pos += 1

