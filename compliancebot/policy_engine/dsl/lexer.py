import re
from typing import List, NamedTuple, Optional

class Token(NamedTuple):
    type: str
    value: str
    line: int
    column: int

class DSLTokenizer:
    """
    Lexer for Compliance DSL.
    """
    
    # Token Types
    TOKEN_TYPES = [
        ('SKIP', r'[ \t\r]+'), # Skip whitespace
        ('COMMENT', r'#.*'), # Skip comments
        ('NEWLINE', r'\n'), # Track line numbers
        
        # Keywords
        ('POLICY', r'policy\b'),
        ('CONTROL', r'control\b'),
        ('RULES', r'rules\b'),
        ('WHEN', r'when\b'),
        ('ENFORCE', r'enforce\b'),
        ('MESSAGE', r'message\b'),
        ('REQUIRE', r'require\b'), # Minimal syntax support
        ('COMPLIANCE', r'compliance\b'),
        ('VERSION', r'version\b'),
        ('EFFECTIVE', r'effective_date\b'),
        ('SUPERSEDES', r'supersedes\b'),
        ('NAME', r'name\b'),
        ('DESC', r'description\b'),
        ('SIGNALS', r'signals\b'),
        ('EVIDENCE', r'evidence\b'),
        
        # Operators
        ('AND', r'and\b'),
        ('OR', r'or\b'),
        ('NOT_IN', r'not\s+in\b'),
        ('IN', r'in\b'),
        ('NOT', r'not\b'),
        ('EQ', r'=='),
        ('NEQ', r'!='),
        ('GTE', r'>='),
        ('LTE', r'<='),
        ('GT', r'>'),
        ('LT', r'<'),
        
        # Punctuation
        ('LBRACE', r'\{'),
        ('RBRACE', r'\}'),
        ('LBRACKET', r'\['),
        ('RBRACKET', r'\]'),
        ('COLON', r':'),
        ('COMMA', r','),
        ('DOT', r'\.'),
        
        # Literals
        ('BOOL', r'(true|false)\b'),
        ('STRING', r'"[^"]*"'), # Double quoted strings
        ('NUMBER', r'-?\d+(\.\d+)?'),
        ('IDENT', r'[a-zA-Z_][a-zA-Z0-9_]*'),
    ]
    
    def __init__(self, text: str):
        self.text = text
        self.tokens: List[Token] = []
        self.line = 1
        self.line_start = 0 # Index where current line started (for column calc)

    def tokenize(self) -> List[Token]:
        pos = 0
        while pos < len(self.text):
            match = None
            for token_type, pattern in self.TOKEN_TYPES:
                regex = re.compile(pattern)
                match = regex.match(self.text, pos)
                if match:
                    value = match.group(0)
                    
                    if token_type == 'NEWLINE':
                        self.line += 1
                        self.line_start = pos + 1
                    elif token_type in ('SKIP', 'COMMENT'):
                        pass
                    else:
                        column = match.start() - self.line_start + 1
                        
                        # Process literal values
                        if token_type == 'STRING':
                            value = value[1:-1] # Strip quotes
                        
                        self.tokens.append(Token(token_type, value, self.line, column))
                    
                    pos = match.end()
                    break
            
            if not match:
                # Error handling
                column = pos - self.line_start + 1
                char = self.text[pos]
                raise ValueError(f"Illegal character '{char}' at line {self.line}, column {column}")
        
        self.tokens.append(Token('EOF', '', self.line, 0))
        return self.tokens

