import argparse
import json
from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from datetime import timedelta
import os

from .middleware import DetectionMiddleware
from .reputation import reputation
from .rate_limiter import rate_limiter
import os

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('FLASK_SECRET', 'devsecret')
app.permanent_session_lifetime = timedelta(hours=2)

# Simple in-memory catalog
PRODUCTS = {
    1: {"id": 1, "name": "Nimbus Tee", "price": 19.99, "img": "https://picsum.photos/seed/tee/400/280"},
    2: {"id": 2, "name": "Storm Jacket", "price": 89.0, "img": "https://picsum.photos/seed/jacket/400/280"},
    3: {"id": 3, "name": "Cloud Cap", "price": 14.5, "img": "https://picsum.photos/seed/cap/400/280"},
}


@app.before_request
def _before():
    if getattr(app, 'detector_mw', None):
        app.detector_mw.before()


@app.after_request
def _after(response):
    if getattr(app, 'detector_mw', None):
        return app.detector_mw.after(response)
    return response


@app.route('/')
def home():
    return render_template('index.html', products=list(PRODUCTS.values()), title='Nimbus Shop')


@app.route('/product/<int:pid>', methods=['GET'])
def product(pid: int):
    p = PRODUCTS.get(pid)
    if not p:
        return jsonify({"error": "not found"}), 404
    return render_template('product.html', product=p, title=p['name'])


@app.route('/cart', methods=['GET', 'POST'])
def cart():
    session.permanent = True
    cart = session.get('cart', {})
    if request.method == 'POST':
        pid = int(request.form.get('pid', '0'))
        if pid in PRODUCTS:
            cart[str(pid)] = cart.get(str(pid), 0) + 1
            session['cart'] = cart
        return redirect(url_for('cart'))
    # compute totals
    items = []
    total = 0.0
    for k, qty in cart.items():
        p = PRODUCTS.get(int(k))
        if p:
            line = {"product": p, "qty": qty, "line": round(p['price'] * qty, 2)}
            total += line['line']
            items.append(line)
    return render_template('cart.html', items=items, total=round(total, 2), title='Your Cart')


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        session['cart'] = {}
        return render_template('checkout.html', ok=True, title='Checkout')
    return render_template('checkout.html', ok=False, title='Checkout')


@app.route('/login', methods=['POST'])
def login():
    return jsonify({"status": "ok"})


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"})


# Dashboard and Events API
@app.route('/dashboard', methods=['GET'])
def dashboard():
    return render_template('dashboard.html', title='Defense Dashboard')


def _candidate_paths():
    # Primary: middleware-configured
    mw = getattr(app, 'detector_mw', None)
    if mw and getattr(mw, 'events_path', None):
        yield mw.events_path
    # Project root relative
    yield os.path.join(os.getcwd(), 'logs', 'events.jsonl')
    # Relative to repository root from this file location
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, os.pardir))
    yield os.path.join(repo_root, 'logs', 'events.jsonl')


def _tail_events(limit: int = 200):
    events = []
    for path in _candidate_paths():
        try:
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()[-limit:]
            for ln in lines:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    events.append(json.loads(ln))
                except Exception:
                    continue
            if events:
                break
        except FileNotFoundError:
            continue
    return events


@app.route('/api/events', methods=['GET'])
def api_events():
    try:
        limit = int(request.args.get('limit', '200'))
    except Exception:
        limit = 200
    raw = _tail_events(limit)
    # Trim payload for UI performance
    events = []
    for e in raw:
        try:
            events.append({
                'timestamp': e.get('timestamp'),
                'src_ip': e.get('src_ip'),
                'path': e.get('path'),
                'status_code': e.get('status_code'),
                'action': e.get('action'),
                'decision': {
                    'decision': e.get('decision', {}).get('decision'),
                    'confidence': e.get('decision', {}).get('confidence')
                }
            })
        except Exception:
            continue
    resp = jsonify({'events': events})
    # prevent any caching so dashboard always sees fresh data
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    return resp


@app.route('/api/events/debug', methods=['GET'])
def api_events_debug():
    paths = list(_candidate_paths())
    infos = []
    for p in paths:
        try:
            size = os.path.getsize(p)
            infos.append({'path': p, 'exists': True, 'size': size})
        except Exception:
            infos.append({'path': p, 'exists': False})
    return jsonify({'paths': infos})


# ------------- Optional LLM utilities (graceful fallback) -------------
class LLMWrapper:
    def __init__(self):
        # Prefer Gemini if GOOGLE_API_KEY is present; else try OpenAI; else fallback
        self.provider = None
        self.enabled = False
        self._client = None

        gemini_key = os.environ.get('GOOGLE_API_KEY')
        if gemini_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=gemini_key)
                model_name = os.environ.get('GEMINI_MODEL', 'gemini-1.5-flash')
                self._client = genai.GenerativeModel(model_name)
                self.provider = 'gemini'
                self.enabled = True
            except Exception:
                self._client = None
                self.enabled = False

        if not self.enabled:
            openai_key = os.environ.get('OPENAI_API_KEY')
            if openai_key:
                try:
                    from openai import OpenAI
                    self._client = OpenAI(api_key=openai_key)
                    self.provider = 'openai'
                    self.model = os.environ.get('OPENAI_MODEL', 'gpt-4o-mini')
                    self.enabled = True
                except Exception:
                    self._client = None
                    self.enabled = False

    def chat(self, prompt: str) -> str:
        if not self.enabled or not self._client:
            return "LLM disabled. Fallback summary: high header count and long durations indicate slow attack."
        try:
            if self.provider == 'gemini':
                resp = self._client.generate_content(prompt)
                # Try multiple ways to extract text
                txt = getattr(resp, 'text', None)
                if not txt and getattr(resp, 'candidates', None):
                    try:
                        parts = []
                        for c in resp.candidates:
                            if getattr(c, 'content', None) and getattr(c.content, 'parts', None):
                                for p in c.content.parts:
                                    if hasattr(p, 'text'):
                                        parts.append(p.text)
                        txt = "\n".join(parts)
                    except Exception:
                        txt = None
                if not txt and getattr(resp, 'prompt_feedback', None):
                    # Safety blocks or other feedback
                    fb = resp.prompt_feedback
                    reason = getattr(fb, 'block_reason', 'blocked')
                    return f"Gemini could not answer due to safety policy ({reason})."
                return (txt or 'No response.').strip()
            else:  # openai
                resp = self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are a concise security analyst."},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.2,
                    max_tokens=700,
                )
                return resp.choices[0].message.content.strip()
        except Exception as e:
            print(f"[LLM ERROR] provider={self.provider} error={e}")
            return "LLM unavailable right now."

    def ping(self) -> dict:
        if not self.enabled or not self._client:
            return {'ok': False, 'reason': 'disabled'}
        try:
            if self.provider == 'gemini':
                r = self._client.generate_content("Reply with OK")
                txt = getattr(r, 'text', None) or 'OK'
                return {'ok': True, 'text': txt}
            else:
                r = self._client.chat.completions.create(
                    model=self.model,
                    messages=[{"role":"user","content":"Reply with OK"}],
                    temperature=0.0,
                    max_tokens=5,
                )
                return {'ok': True, 'text': r.choices[0].message.content}
        except Exception as e:
            return {'ok': False, 'reason': str(e)}


llm = LLMWrapper()


def _recent_events(n: int = 200):
    return _tail_events(n)


@app.route('/api/explain', methods=['POST'])
def api_explain():
    payload = request.get_json(silent=True) or {}
    event = payload.get('event', {})
    # If no event was provided (user didn't click a row), pick the most recent blocked event
    if not event or not isinstance(event, dict) or not event.get('timestamp'):
        recent = _recent_events(200)
        # prefer blocked, else latest
        candidates = [e for e in recent if e.get('action') == 'blocked'] or (recent[-1:] if recent else [])
        event = candidates[-1] if candidates else {}
    prompt = (
        "Explain briefly why this event was classified as "
        f"{event.get('decision', {}).get('decision')} with confidence "
        f"{event.get('decision', {}).get('confidence')}. Provide 3 mitigations.\n\n"
        f"Event: {json.dumps(event)[:4000]}"
    )
    text = llm.chat(prompt)
    if not text:
        # Local fallback explanation using features
        f = event.get('features', {})
        bits = []
        if f:
            for k in ['headers_count','request_duration_sec','connection_duration_sec','request_rate','time_to_first_byte_sec']:
                if k in f:
                    bits.append(f"{k}={f.get(k)}")
        text = (
            "Local explanation: classified as attack due to abnormal request characteristics. "
            + ("; ".join(bits) if bits else "No feature snapshot available.")
        )
    return jsonify({'text': text, 'llm': llm.enabled})


@app.route('/api/llm/status', methods=['GET'])
def api_llm_status():
    info = {
        'enabled': llm.enabled,
        'provider': getattr(llm, 'provider', None),
    }
    return jsonify(info)


@app.route('/api/llm/ping', methods=['GET'])
def api_llm_ping():
    return jsonify(llm.ping())


# ------------------- Reputation API -------------------
@app.route('/api/reputation', methods=['GET'])
def api_reputation():
    k = int(request.args.get('limit', '20'))
    top = [{'ip': ip, 'score': score, 'banned': reputation.is_banned(ip)} for ip, score in reputation.top(k)]
    return jsonify({'top': top, 'params': {'decay_per_minute': reputation.decay_per_minute, 'ban_threshold': reputation.ban_threshold}})


@app.route('/api/ban', methods=['POST'])
def api_ban():
    data = request.get_json(silent=True) or {}
    ip = data.get('ip')
    if ip:
        reputation.ban(ip)
    return jsonify({'ok': True, 'banned': list(reputation.banned.keys())})


@app.route('/api/unban', methods=['POST'])
def api_unban():
    data = request.get_json(silent=True) or {}
    ip = data.get('ip')
    if ip:
        reputation.unban(ip)
    return jsonify({'ok': True, 'banned': list(reputation.banned.keys())})


@app.route('/api/bans', methods=['GET'])
def api_bans():
    return jsonify({'banned': list(reputation.banned.keys())})


# ------------------- Rate Limiter API -------------------
@app.route('/api/ratelimit', methods=['GET'])
def api_ratelimit():
    k = int(request.args.get('limit', '20'))
    snap = [
        {'ip': ip, 'capacity': cap, 'refill_per_sec': refill, 'tokens': tokens, 'limited': limited}
        for ip, (cap, refill, tokens, limited) in rate_limiter.snapshot(k)
    ]
    return jsonify({'top': snap, 'enabled': rate_limiter.enabled})


@app.route('/api/ratelimit/toggle', methods=['POST'])
def api_ratelimit_toggle():
    data = request.get_json(silent=True) or {}
    enabled = data.get('enabled')
    if enabled is not None:
        rate_limiter.enabled = bool(enabled)
    return jsonify({'enabled': rate_limiter.enabled})


@app.route('/api/query', methods=['POST'])
def api_query():
    body = request.get_json(silent=True) or {}
    question = body.get('question', '')
    events = _recent_events(300)
    sample = events[-30:]
    prompt = (
        "Answer concisely based on these recent events.\n"
        f"Question: {question}\n"
        f"Events sample: {json.dumps(sample)[:6000]}"
    )
    text = llm.chat(prompt)
    if not text:
        # Simple local answer: top blocked IPs last 1 minute
        from collections import Counter
        now_events = [e for e in events[-200:]]
        blocked = [e.get('src_ip') for e in now_events if e.get('action')=='blocked']
        cnt = Counter(blocked)
        top = ", ".join(f"{ip}({n})" for ip, n in cnt.most_common(5)) or "none"
        text = f"Top blocked IPs recently: {top}. Total blocked: {len(blocked)}"
    return jsonify({'text': text, 'llm': llm.enabled})


@app.route('/api/rules/propose', methods=['POST'])
def api_rules_propose():
    events = _recent_events(300)
    blocked = [e for e in events if e.get('action') == 'blocked']
    benign = [e for e in events if e.get('decision', {}).get('decision') == 'benign']
    prompt = (
        "Propose 2-4 YAML rules for slow/low-rate DoS using simple numeric thresholds.\n"
        "Return only YAML under critical:/advisory:.\n\n"
        f"Blocked: {json.dumps(blocked[-50:])[:6000]}\n\n"
        f"Benign: {json.dumps(benign[-50:])[:6000]}"
    )
    text = llm.chat(prompt)
    return jsonify({'yaml': text, 'llm': llm.enabled})


@app.route('/api/report', methods=['GET'])
def api_report():
    events = _recent_events(500)
    prompt = (
        "Create a brief incident report with Summary, Timeline, Detection, Mitigations, Next Steps.\n"
        f"Events (latest 100): {json.dumps(events[-100:])[:8000]}"
    )
    text = llm.chat(prompt)
    if not text:
        # Local deterministic report
        from collections import Counter
        total = len(events)
        blocked = [e for e in events if e.get('action')=='blocked']
        benign = [e for e in events if e.get('decision',{}).get('decision')=='benign']
        ips = Counter(e.get('src_ip') for e in blocked)
        top_ips = ", ".join(f"{ip}({n})" for ip, n in ips.most_common(5)) or "none"
        text = (
            "Summary: Slow/low-rate DoS detections observed.\n"
            f"Events scanned: {total}; blocked: {len(blocked)}; benign: {len(benign)}.\n"
            f"Top blocked IPs: {top_ips}.\n"
            "Detection: Ensemble models + rules with auto-mitigation (HTTP 429).\n"
            "Mitigations: keep header/idle timeouts strict, rate-limit bursty IPs, require challenge for repeat offenders.\n"
            "Next Steps: export events, review thresholds, add per-IP ban window if needed."
        )
    return jsonify({'text': text, 'llm': llm.enabled})

# Add adaptive rule tuning endpoint powered by LLM
import yaml
rules_memory = {
    'block_threshold': 0.8,
    'rate_limit': '100/min',
    'reputation_decay': 0.95,
    'auto_ban_score': 10.0
}

@app.route('/api/llm_tune_rules', methods=['POST'])
def api_llm_tune_rules():
    events = _recent_events(200)
    blocked = sum(1 for e in events if (e.get('action')=='blocked' or (e.get('decision',{}).get('decision')=='attack')))
    benign = sum(1 for e in events if (e.get('decision',{}).get('decision')=='benign'))
    current_yaml = yaml.dump({'rules': rules_memory}, default_flow_style=False)
    prompt = f"""
You are a security copilot. Given detection events and current tunable parameters, propose safer/better rules in valid YAML under 'rules:'.
Be less aggressive if too many benigns were blocked, more aggressive if too many attacks. Only include editable keys. Output YAML only!

Events: 
Blocked: {blocked}, Benign: {benign}
Current rules:
{current_yaml}
"""
    llm_result = llm.chat(prompt)
    # Try parse LLM YAML - strip ``` and ```yaml, etc.
    def clean_ymarkdown(txt:str) -> str:
        txt = txt.strip()
        if txt.startswith('```'):  # Remove up to first newline after ```yaml or ```
            first_nl = txt.find('\n')
            if first_nl > 0: txt = txt[first_nl+1:]
        if txt.endswith('```'): txt = txt[:txt.rfind('```')]
        return txt.strip()

    try:
        plain_yaml = clean_ymarkdown(llm_result)
        rules_out = yaml.safe_load(plain_yaml)
        if not (isinstance(rules_out, dict) and 'rules' in rules_out):
            raise ValueError('No rules: block in YAML')
        suggested_yaml = yaml.dump({'rules': rules_out['rules']}, default_flow_style=False)
        summary_prompt = f"Summarize in 2-4 sentences why you picked these rule values: {suggested_yaml} (blocked={blocked}, benign={benign})"
        explanation = llm.chat(summary_prompt)
    except Exception as e:
        suggested_yaml, explanation = llm_result, f'Could not parse/validate YAML (error: {e}) - please review.'
    return jsonify({'tuned_yaml': suggested_yaml, 'explanation': explanation, 'blocked': blocked, 'benign': benign, 'input_rules': rules_memory})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--auto_mitigation', type=lambda x: str(x).lower() == 'true', default=False)
    parser.add_argument('--host', type=str, default='127.0.0.1')
    parser.add_argument('--conf_threshold', type=float, default=0.5)
    args = parser.parse_args()
    # attach middleware
    app.detector_mw = DetectionMiddleware(
        app,
        auto_mitigation=args.auto_mitigation,
        conf_threshold=args.conf_threshold,
    )
    app.run(host=args.host, port=args.port)


if __name__ == '__main__':
    main()
