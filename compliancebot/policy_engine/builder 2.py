import os
import json
import hashlib
from typing import Dict, Any, List
from datetime import datetime, timezone

from .dsl.lexer import DSLTokenizer
from .dsl.parser import DSLParser
from .dsl.validator import DSLValidator
from .compiler import PolicyCompiler
from .types import CompiledPolicy

class PolicyBuilder:
    """
    Orchestrates the build process:
    DSL -> Tokens -> AST -> Validation -> Compilation -> YAML + Manifest
    """
    
    def __init__(self, source_dir: str, output_dir: str):
        self.source_dir = source_dir
        self.output_dir = output_dir
        self.compiler = PolicyCompiler()
        self.validator = DSLValidator()
        self.manifest: Dict[str, Any] = {
            "compiled_at": datetime.now(timezone.utc).isoformat(),
            "compiler_version": "1.0.0",
            "policies": {}
        }
    
    def build(self) -> bool:
        """
        Build all policies in source_dir.
        Returns True if successful, False if errors found.
        """
        print(f"Starting build from {self.source_dir} to {self.output_dir}")
        
        # 1. Clean output directory (optional, or just overwrite)
        os.makedirs(self.output_dir, exist_ok=True)
        
        errors = []
        
        # 2. Walk source directory
        for root, dirs, files in os.walk(self.source_dir):
            for file in files:
                if file.endswith(".dsl"):
                    path = os.path.join(root, file)
                    try:
                        self._process_file(path)
                    except Exception as e:
                        errors.append(f"Failed to process {path}: {str(e)}")
        
        # 3. Write Manifest
        manifest_path = os.path.join(self.output_dir, "manifest.json")
        with open(manifest_path, "w") as f:
            json.dump(self.manifest, f, indent=2)
        
        if errors:
            print("\nBuild Failed with Errors:")
            for e in errors:
                print(f" - {e}")
            return False
        
        print("\nBuild Complete")
        return True

    def _process_file(self, path: str):
        print(f"Processing {path}...")
        
        with open(path, "r") as f:
            source_text = f.read()
        
        # Pipeline
        lexer = DSLTokenizer(source_text)
        tokens = lexer.tokenize()
        
        parser = DSLParser(tokens)
        ast = parser.parse()
        
        validation_errors = self.validator.validate(ast)
        if validation_errors:
            raise ValueError(f"Validation failed: {validation_errors}")
        
        compiled_policies = self.compiler.compile(ast, source_text)
        
        # Write Outputs
        rule_ids = []
        for policy in compiled_policies:
            output_path = os.path.join(self.output_dir, policy.filename)
            with open(output_path, "w") as f:
                json.dump(policy.content, f, indent=2)
            rule_ids.append(policy.policy_id)
        
        # Update Manifest
        normalized_id = ast.policy_id.replace("_", "-")
        self.manifest["policies"][normalized_id] = {
            "source_hash": compiled_policies[0].source_hash,
            "version": ast.version,
            "rules": rule_ids
        }
