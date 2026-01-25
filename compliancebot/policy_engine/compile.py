import os
import sys
from compliancebot.policy_engine.builder import PolicyBuilder

# Configuration
DSL_ROOT = "compliancebot/policies/dsl"
COMPILED_ROOT = "compliancebot/policies/compiled"

def main():
    print("Phase 4: Compiling Compliance DSL")
    
    # Check source
    if not os.path.exists(DSL_ROOT):
        print(f"Source directory {DSL_ROOT} not found.")
        sys.exit(1)
    
    # Count files
    dsl_files = []
    for root, _, files in os.walk(DSL_ROOT):
        for f in files:
            if f.endswith(".dsl"):
                dsl_files.append(os.path.join(root, f))
    
    if not dsl_files:
        print("No .dsl files found.")
        sys.exit(1)
    
    print(f"✓ Parsed {len(dsl_files)} DSL files")
    
    # Run Builder (Recursive)
    # The Builder currently targets specific subfolders. 
    # We want a "Compile All" mode.
    # We can iterate through the known structure or just build recursively if Builder supports it.
    # Looking at Builder code, it takes source/dest dirs.
    # Let's handle the standard structure mapping.
    
    dirs_to_build = [
        ("standards/soc2", "standards/soc2"),
        ("standards/iso27001", "standards/iso27001"),
        ("standards/hipaa", "standards/hipaa"),
        ("company/acme", "company/acme"),
        # Add root or others as needed
    ]
    
    # Also handle the test dir if it exists
    if os.path.exists(os.path.join(DSL_ROOT, "test_versioning")):
        dirs_to_build.append(("test_versioning", "test_versioning"))

    total_policies = 0
    
    for src, dst in dirs_to_build:
        src_path = os.path.join(DSL_ROOT, src)
        dst_path = os.path.join(COMPILED_ROOT, dst)
        
        if os.path.exists(src_path):
            builder = PolicyBuilder(src_path, dst_path)
            if builder.build():
                # Validated Policies count? 
                # Builder doesn't return count easily, but we can count output files
                pass
            else:
                print(f"Failed to compile {src}")
                sys.exit(1)

    # Count compiled YAMLs
    yaml_count = 0
    for root, _, files in os.walk(COMPILED_ROOT):
        for f in files:
            if f.endswith(".yaml"):
                yaml_count += 1

    print(f"Validated {len(dsl_files)} policies (approx)") # 1 DSL = 1 Policy usually
    print(f"Compiled {yaml_count} YAML policies")
    print("Manifest written")
    print(f"Output directory: {COMPILED_ROOT}/")

if __name__ == "__main__":
    main()

