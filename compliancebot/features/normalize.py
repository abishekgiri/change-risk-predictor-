import math
from typing import List, Union

def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Ensure x is between lo and hi."""
    return max(lo, min(x, hi))

def safe_div(a: float, b: float, default: float = 0.0) -> float:
    """Safe division handling zero denominator."""
    if b == 0:
        return default
    return a / b

def log1p_int(n: int) -> float:
    """Log(n+1) safe for integers (guards n>=0)."""
    if n < 0: return 0.0
    return math.log1p(n)

def zscore(x: float, mean: float, std: float, default: float = 0.0) -> float:
    """Compute z-score safely. Returns default if std is near 0."""
    if abs(std) < 1e-9:
        return default
    return (x - mean) / std

def minmax(x: float, lo: float, hi: float) -> float:
    """Normalize x to 0-1 range based on lo/hi bounds. Clamps result."""
    if hi <= lo:
        return 0.0
    val = (x - lo) / (hi - lo)
    return clamp(val, 0.0, 1.0)

def winsorize(x: float, lo: float, hi: float) -> float:
    """Alias for clamp, but implies statistical intent."""
    return clamp(x, lo, hi)

def laplace_rate(incidents: int, total: int, alpha: int = 1, beta: int = 2) -> float:
    """
    Compute Laplace smoothed rate.
    rate = (incidents + alpha) / (total + beta)
    """
    return (incidents + alpha) / (total + beta)

