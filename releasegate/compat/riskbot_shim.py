import sys
from releasegate.cli import main as releasegate_main

def main():
    # Print one-line deprecation notice but still work.
    # Keep it short to avoid breaking JSON outputs in CI.
    if "--format" not in sys.argv and "--json" not in sys.argv:
        print("DEPRECATED: 'riskbot' is now 'releasegate'. Use: releasegate ...", file=sys.stderr)

    return releasegate_main()
