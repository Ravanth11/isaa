import os
from typing import Dict, Any, List, Tuple

PROMPT_TEMPLATE = (
    "Input: JSON features: {features}\n"
    "Model outputs: ensemble_decision='Attack', confidence={confidence:.2f}, shap_top={shap}\n"
    "Task: Write a concise (2–4 sentences) explanation why this traffic looks like a SlowDOS attack, "
    "mention which features are most influential, and list 3 ranked mitigation steps (with short rationale)."
)


def _rank_top_features(features: Dict[str, float]) -> List[Tuple[str, float]]:
    keys = ['connection_duration_sec', 'bytes_per_second', 'request_rate', 'time_to_first_byte_sec', 'headers_count']
    pairs = []
    for k in keys:
        v = float(features.get(k, 0.0))
        score = v if k in ('connection_duration_sec', 'request_rate', 'headers_count') else -v if k == 'bytes_per_second' else v
        pairs.append((k, round(score, 3)))
    pairs.sort(key=lambda x: abs(x[1]), reverse=True)
    return pairs[:3]


def _fallback_text(decision: str, confidence: float, shap_top: List[Tuple[str, float]], features: Dict[str, Any] | None = None) -> str:
    if decision == 'attack':
        return (
            "This request pattern likely reflects a Slow DoS attempt. The connection stays open unusually long, "
            "data flows very slowly, and request pacing looks abnormal. "
            f"Top signals: {shap_top[0][0]}({shap_top[0][1]}), {shap_top[1][0]}({shap_top[1][1]}), {shap_top[2][0]}({shap_top[2][1]}). "
            "Mitigations: (1) rate‑limit the source IP; (2) tighten idle/header timeouts; (3) challenge with CAPTCHA or divert to a honeypot."
        )
    # Benign reasoning using simple thresholds for clarity
    if features is None:
        return "Traffic looks normal given current thresholds and model votes."
    reasons = []
    if float(features.get('connection_duration_sec', 0.0)) <= 5.0:
        reasons.append("connection duration is short")
    if float(features.get('bytes_per_second', 9999.0)) >= 200:
        reasons.append("transfer rate is healthy")
    if float(features.get('headers_count', 0.0)) <= 55:
        reasons.append("header count is typical")
    if float(features.get('request_duration_sec', 0.0)) <= 3.0:
        reasons.append("request finished quickly")
    if float(features.get('time_to_first_byte_sec', 0.0)) <= 0.8:
        reasons.append("server responded promptly (TTFB)")
    if float(features.get('request_rate', 1.0)) >= 2:
        reasons.append("per‑IP request pacing is normal")
    if not reasons:
        reasons.append("no SlowDOS indicators crossed the rule thresholds")
    return "Traffic appears benign because " + ", ".join(reasons) + "."


def _try_llm(features: Dict[str, Any], confidence: float) -> str | None:
    api_key = os.environ.get('OPENAI_API_KEY')
    if not api_key:
        return None
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        prompt = PROMPT_TEMPLATE.format(features=features, confidence=confidence, shap=_rank_top_features(features))
        resp = client.chat.completions.create(
            model=os.environ.get('OPENAI_MODEL', 'gpt-4o-mini'),
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=220,
        )
        return resp.choices[0].message.content.strip()
    except Exception:
        return None


def generate_explanation(features: Dict[str, Any], decision_payload: Dict[str, Any]) -> str:
    decision = decision_payload.get('decision', 'benign')
    confidence = float(decision_payload.get('confidence', 0.0))
    shap_top = _rank_top_features(features)
    if decision == 'attack':
        txt = _try_llm(features, confidence)
        if txt:
            return txt
    return _fallback_text(decision, confidence, shap_top, features)
