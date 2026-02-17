import os
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime, timezone

from .dsl.lexer import DSLTokenizer
from .dsl.parser import DSLParser
from .dsl.validator import DSLValidator
from .compiler import PolicyCompiler
from .types import CompiledPolicy

from releasegate.utils.paths import safe_join_under

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
        source_base = Path(self.source_dir).resolve(strict=False)
        output_base = Path(self.output_dir).resolve(strict=False)
        print(f"Starting build from {source_base} to {output_base}")
        
        # 1. Clean output directory (optional, or just overwrite)
        output_base.mkdir(parents=True, exist_ok=True)
        
        errors = []
        
        # 2. Walk source directory
        for root, dirs, files in os.walk(source_base):
            root_path = Path(root)
            for file in files:
                if file.endswith(".dsl"):
                    try:
                        rel_root = root_path.relative_to(source_base)
                        path = safe_join_under(source_base, rel_root, file)
                    except ValueError as e:
                        errors.append(f"Unsafe path skipped: {e}")
                        continue
                    try:
                        self._process_file(str(path))
                    except Exception as e:
                        errors.append(f"Failed to process {path}: {str(e)}")
        
        # 3. Write Manifest
        manifest_path = safe_join_under(output_base, "manifest.json")
        with manifest_path.open("w", encoding="utf-8") as f:
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
        
        with open(path, "r", encoding="utf-8") as f:
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
            output_base = Path(self.output_dir).resolve(strict=False)
            output_path = safe_join_under(output_base, str(policy.filename))
            with output_path.open("w", encoding="utf-8") as f:
                json.dump(policy.content, f, indent=2)
            rule_ids.append(policy.policy_id)
        
        # Update Manifest
        normalized_id = ast.policy_id.replace("_", "-")
        self.manifest["policies"][normalized_id] = {
            "source_hash": compiled_policies[0].source_hash,
            "version": ast.version,
            "rules": rule_ids
        }
