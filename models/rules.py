import yaml
from dataclasses import dataclass
from typing import Dict, Any, List, Tuple


@dataclass
class Rule:
    id: str
    expr: str
    confidence: float


class RuleEngine:
    def __init__(self, rules_path: str):
        with open(rules_path, 'r') as f:
            cfg = yaml.safe_load(f) or {}
        self.critical: List[Rule] = [Rule(**r) for r in cfg.get('critical', [])]
        self.advisory: List[Rule] = [Rule(**r) for r in cfg.get('advisory', [])]

    @staticmethod
    def _safe_eval(expr: str, vars: Dict[str, Any]) -> bool:
        # Very restricted eval context (demo only)
        allowed_builtins = {}
        return bool(eval(expr, {"__builtins__": allowed_builtins}, vars))

    def evaluate(self, features: Dict[str, Any]) -> Tuple[int, float, List[str]]:
        fired: List[str] = []
        confs: List[float] = []
        vote = 0
        for r in self.critical:
            try:
                if self._safe_eval(r.expr, features):
                    fired.append(r.id)
                    confs.append(r.confidence)
                    vote = 1
            except Exception:
                continue
        for r in self.advisory:
            try:
                if self._safe_eval(r.expr, features):
                    fired.append(r.id)
                    confs.append(r.confidence * 0.5)
            except Exception:
                continue
        rule_conf = sum(confs) / len(confs) if confs else 0.0
        return vote, rule_conf, fired
