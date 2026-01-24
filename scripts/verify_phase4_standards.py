import sys
import os

# Import the individual verification functions
# We need to add the CWD to path to import from scripts if they were modules, 
# but they are scripts. We can just convert them to modules or run them.
# Importing is cleaner.

if "." not in sys.path: sys.path.append(".")

from scripts.verify_phase4_soc2 import verify_soc2_pack
from scripts.verify_phase4_iso27001 import verify_iso27001_pack
from scripts.verify_phase4_hipaa import verify_hipaa_pack

def main():
 print("Verifying Phase 4 Standard Packs\n")
 
 print("--- SOC 2 ---")
 verify_soc2_pack()
 print("SOC2 pack loaded\n")
 
 print("--- ISO 27001 ---")
 verify_iso27001_pack()
 print("ISO27001 pack loaded\n")
 
 print("--- HIPAA ---")
 verify_hipaa_pack()
 print("HIPAA pack loaded\n")
 
 print("All Standard Packs Verified")

if __name__ == "__main__":
 main()
