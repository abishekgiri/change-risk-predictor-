"""
Deterministic entropy calculation for secret detection.

Uses Shannon entropy with fixed threshold (no ML).
"""
import math
from collections import Counter

def calculate_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.
    
    Deterministic: same string always returns same entropy.
    
    Args:
        s: Input string
    
    Returns:
        Entropy value (0.0 to ~6.0 for typical strings)
    """
    if not s:
        return 0.0
    
    # Count character frequencies
    counter = Counter(s)
    length = len(s)
    
    # Calculate Shannon entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy

def is_high_entropy(s: str, threshold: float = 4.5) -> bool:
    """
    Check if string has high entropy (likely random/secret).
    
    Threshold of 4.5 is empirically chosen:
    - "password123" = ~3.2
    - "AKIAIOSFODNN7EXAMPLE" = ~4.1
    - Random base64 = ~5.5+
    
    Args:
        s: Input string
        threshold: Entropy threshold (default 4.5)
    
    Returns:
        True if entropy exceeds threshold
    """
    return calculate_entropy(s) > threshold

