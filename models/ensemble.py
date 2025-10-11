import os
import json
from typing import Dict, Any, Tuple
import numpy as np
import joblib
from .feature_pipeline import FEATURES
from .rules import RuleEngine


class EnsembleDetector:
    def __init__(self, artifacts_dir: str = 'models/artifacts', rules_path: str = 'models/rules.yaml'):
        self.artifacts_dir = artifacts_dir
        self.transformer = joblib.load(os.path.join(artifacts_dir, 'scaler.joblib'))
        self.iso = joblib.load(os.path.join(artifacts_dir, 'iso.joblib'))
        self.rf = joblib.load(os.path.join(artifacts_dir, 'rf.joblib'))
        self.xgb = joblib.load(os.path.join(artifacts_dir, 'xgb.joblib'))
        self.rule_engine = RuleEngine(rules_path)

    def _to_array(self, f: Dict[str, Any]) -> np.ndarray:
        x = np.array([[f.get(k, 0.0) for k in self.transformer['features']]], dtype=float)
        return self.transformer['scaler'].transform(x)

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        # Rule vote
        rule_vote, rule_conf, fired = self.rule_engine.evaluate(features)

        # Models
        x = self._to_array(features)
        # IsolationForest: decision_function higher is normal; anomaly if predict == -1
        iso_pred = self.iso.predict(x)[0]
        iso_vote = 1 if iso_pred == -1 else 0
        iso_score = float(self.iso.decision_function(x)[0])

        rf_prob = float(self.rf.predict_proba(x)[0, 1])
        xgb_prob = float(self.xgb.predict_proba(x)[0, 1])
        sup_prob = (rf_prob + xgb_prob) / 2.0
        sup_vote = 1 if sup_prob > 0.5 else 0

        votes = [rule_vote, iso_vote, sup_vote]
        majority = 1 if sum(votes) >= 2 else 0
        # Confidence definition from spec
        confidence = float(np.mean([sup_prob, 1.0 - max(-1.0, min(1.0, iso_score)), rule_conf]))

        return {
            'decision': 'attack' if majority == 1 else 'benign',
            'majority_vote': majority,
            'votes': {'rule': rule_vote, 'iso': iso_vote, 'supervised': sup_vote},
            'probs': {'rf': rf_prob, 'xgb': xgb_prob, 'supervised_avg': sup_prob},
            'iso_score': iso_score,
            'rule': {'confidence': rule_conf, 'fired': fired},
            'confidence': confidence,
        }
