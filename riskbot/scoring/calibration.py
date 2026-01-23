from typing import Dict, List, Any
import json
import os
from riskbot.features import normalize

class Calibrator:
    """
    Calibrates raw scores (0-100) to probabilities (0.0-1.0).
    Uses empirical binning or defaults to linear scaling.
    """
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        # Load map from file if exists, else use defaults
        # mapping format: {"0-10": 0.05, "10-20": 0.15 ...}
        self.mapping = self._load_mapping()
        
    def _load_mapping(self) -> Dict[str, float]:
        # TODO: Load from calibration.json in future
        # For now return None to force default linear fallback
        return {}

    def calibrate(self, score: int) -> float:
        """
        Convert score 0-100 to probability 0.0-1.0
        """
        # 1. Bin Lookup (Phase 8.4)
        # bin_key = f"{score//10 * 10}-{(score//10 + 1) * 10}"
        # if bin_key in self.mapping:
        #     return self.mapping[bin_key]

        # 2. Linear Fallback (MVP)
        # Simple clamp 0-1
        return float(score) / 100.0
