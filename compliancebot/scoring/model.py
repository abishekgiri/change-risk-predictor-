import pickle
import os
from typing import Optional, Dict, Tuple
from compliancebot.features.types import FeatureVector

MODEL_PATH = "riskbot/scoring/model_v1.pkl"

class RiskModel:
    """
    Wrapper for ML Model (LogisticRegression / Tree).
    Handles loading and inference.
    """
    def __init__(self, model_path: str = MODEL_PATH):
        self.model = None
        self.model_type = "none"
        self.features_list = []
        
        if os.path.exists(model_path):
            try:
                with open(model_path, "rb") as f:
                    self.model = pickle.load(f)
                
                # Load metadata if exists
                meta_path = model_path + ".meta.json"
                if os.path.exists(meta_path):
                    import json
                    with open(meta_path, "r") as f:
                        meta = json.load(f)
                    self.features_list = meta.get("features", [])
                    self.model_type = meta.get("model_type", "unknown")
                else:
                    self.model_type = "legacy_pickle"
                
                print(f"Loaded ML Model: {self.model_type}")
            except Exception as e:
                print(f"Failed to load model: {e}")
                self.model = None

    def predict(self, features: FeatureVector) -> Optional[float]:
        """
        Returns raw score 0-100 if model available.
        Returns None if model missing or features incomplete.
        """
        if not self.model:
            return None
        
        try:
            # Construct feature vector for model
            # Must match training order
            if not self.features_list:
                # If no metadata, can't reliably predict
                return None
            
            X = []
            for name in self.features_list:
                val = features.get(name, 0.0)
                X.append(val)
            
            # Predict Prob (class 1)
            # sklearn: [ [prob_0, prob_1] ]
            probs = self.model.predict_proba([X])[0]
            prob_risky = probs[1]
            
            # Scale to 0-100
            return int(prob_risky * 100)
        
        except Exception as e:
            print(f"Prediction error: {e}")
            return None
            
    def get_version(self) -> str:
        return f"{self.model_type}-v1" if self.model else "none"

