from typing import List, Dict, Optional
import re

def extract_snippet(diff_text: str, filename: str, line: int = 0, context: int = 3) -> str:
    """
    Extracts a minimal context snippet from a unified diff for a specific file/line.
    If line is 0, returns the first hunk for that file.
    """
    if not diff_text:
        return ""
    
    # Split diff into per-file chunks
    file_chunks = diff_text.split("diff --git")
    target_chunk = None
    
    for chunk in file_chunks:
        if f"b/{filename}" in chunk or f"a/{filename}" in chunk:
            target_chunk = chunk
            break
    
    if not target_chunk:
        return f"[Evidence] File {filename} not found in provided diff."
    
    lines = target_chunk.splitlines()
    snippet = []
    
    # Simple extraction: Return the whole hunk containing the line or first hunk
    # (Robust diff parsing is complex, this is Phase 5 MVP)
    recording = False
    for i, line_str in enumerate(lines):
        if line_str.startswith("@@"):
            recording = True
        
        if recording:
            snippet.append(line_str)
            # Limit snippet size for readability
            if len(snippet) > 20: 
                snippet.append("... (truncated)")
                break
    
    return "\n".join(snippet)

