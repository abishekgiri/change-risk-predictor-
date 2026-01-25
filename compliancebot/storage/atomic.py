import os
import shutil
import tempfile
from contextlib import contextmanager

@contextmanager
def atomic_write(filepath: str, mode: str = "w"):
    """
    Safe atomic write. Writes to a temp file, then renames to target.
    Ensures no partial files exist at target path if process crashes.
    """
    folder = os.path.dirname(filepath)
    if folder:
        os.makedirs(folder, exist_ok=True)
    
    fd, temp_path = tempfile.mkstemp(dir=folder, text="b" not in mode)
    
    try:
        with os.fdopen(fd, mode) as f:
            yield f
        # Atomic rename
        os.replace(temp_path, filepath)
    except Exception:
        # Cleanup on fail
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise

def ensure_directory(path: str):
    os.makedirs(path, exist_ok=True)

