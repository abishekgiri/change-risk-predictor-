import subprocess
import shlex

def run_command(command: str) -> str:
    """Run a shell command and return stdout as string."""
    try:
        args = shlex.split(command)
        result = subprocess.run(args, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        # For now, just print error and return empty string or re-raise
        # Ideally we log this
        print(f"Error running command '{command}': {e.stderr}")
        return ""
