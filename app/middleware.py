import json
import os
import time
from collections import deque, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, Any
from flask import request, g
from models.ensemble import EnsembleDetector
from .reputation import reputation
from .rate_limiter import rate_limiter
from models.explain import generate_explanation


class RealtimeFeatureStore:
    def __init__(self, window_sec: int = 60):
        self.window = window_sec
        self.window5 = 300
        self.data: Dict[str, Deque[float]] = defaultdict(deque)  # timestamps per IP
        self.last_ts: Dict[str, float] = {}

    def update(self, ip: str, now: float) -> Dict[str, Any]:
        dq = self.data[ip]
        dq.append(now)
        # purge
        limit = now - self.window
        while dq and dq[0] < limit:
            dq.popleft()
        # compute features
        req_rate = len(dq)
        # avg time between recent requests (60s)
        if len(dq) >= 2:
            diffs = [dq[i] - dq[i-1] for i in range(1, len(dq))]
            avg_dt = sum(diffs)/len(diffs)
        else:
            avg_dt = self.window
        # 5min count using a separate pass
        count5 = sum(1 for t in dq if t >= now - self.window5)
        return {
            'request_rate': float(req_rate),
            'avg_time_between_requests': float(avg_dt),
            'last_1min_request_count': float(req_rate),
            'last_5min_request_count': float(count5),
        }


class DetectionMiddleware:
    def __init__(self, app, artifacts_dir='models/artifacts', rules_path='models/rules.yaml', events_path='logs/events.jsonl', auto_mitigation=False, conf_threshold=0.7):
        self.app = app
        self.store = RealtimeFeatureStore(window_sec=60)
        self.detector = EnsembleDetector(artifacts_dir=artifacts_dir, rules_path=rules_path)
        self.events_path = events_path
        os.makedirs(os.path.dirname(self.events_path), exist_ok=True)
        self.auto_mitigation = auto_mitigation
        self.conf_threshold = conf_threshold

    def _log_event(self, payload: Dict[str, Any]):
        with open(self.events_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(payload) + '\n')

    def before(self):
        g._start_time = time.time()

    def after(self, response):
        try:
            now = time.time()
            start = getattr(g, '_start_time', now)
            duration = max(0.0, now - start)
            ip = request.headers.get('X-Forwarded-For', request.remote_addr or '0.0.0.0').split(',')[0].strip()
            method = request.method
            path = request.path
            # Bypass detection for internal API/UI endpoints to avoid self-triggered blocking
            if path.startswith('/api/') or path.startswith('/static/') or path in ('/dashboard', '/favicon.ico'):
                return response

            # Reputation check: immediate block if banned
            if reputation.is_banned(ip):
                response.status_code = 429
                response.headers['X-Blocked'] = '1'
                response.set_data(json.dumps({
                    'status': 'blocked',
                    'reason': 'reputation-ban',
                    'confidence': 1.0
                }))
                response.mimetype = 'application/json'
                event = {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'src_ip': ip,
                    'method': method,
                    'path': path,
                    'status_code': response.status_code,
                    'features': {},
                    'decision': {'decision': 'attack', 'confidence': 0.99},
                    'explanation': 'Banned by reputation manager.',
                    'action': 'blocked',
                }
                self._log_event(event)
                return response

            # Pre-check token bucket rate limiter
            try:
                if rate_limiter.should_limit(ip, cost=1.0):
                    response.status_code = 429
                    response.headers['X-Blocked'] = '1'
                    response.set_data(json.dumps({
                        'status': 'blocked',
                        'reason': 'rate-limit',
                        'confidence': 0.9
                    }))
                    response.mimetype = 'application/json'
                    event = {
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'src_ip': ip,
                        'method': method,
                        'path': path,
                        'status_code': response.status_code,
                        'features': {},
                        'decision': {'decision': 'attack', 'confidence': 0.9},
                        'explanation': 'Blocked by token-bucket rate limiter.',
                        'action': 'blocked',
                    }
                    self._log_event(event)
                    return response
            except Exception:
                pass
            status = response.status_code
            headers_count = len(request.headers)
            body_bytes = int(request.content_length or 0)
            # Optional header-driven overrides for demo
            override_req = request.headers.get('X-Simulate-Request-Duration')
            override_conn = request.headers.get('X-Simulate-Connection-Duration')
            override_hdrs = request.headers.get('X-Simulate-Headers-Count')

            ttfb = duration * 0.3  # simple proxy; real TTFB requires streaming hooks
            bytes_tx = max(len(response.get_data(as_text=False) or b''), 0)
            conn_duration = duration  # per-request in this demo
            if override_req:
                try:
                    duration = float(override_req)
                except Exception:
                    pass
            if override_conn:
                try:
                    conn_duration = float(override_conn)
                except Exception:
                    pass
            if override_hdrs:
                try:
                    headers_count = int(override_hdrs)
                except Exception:
                    pass

            roll = self.store.update(ip, now)
            row_features = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'src_ip': ip,
                'client_port': 0,
                'method': method,
                'path': path,
                'status_code': status,
                'bytes_transferred': float(bytes_tx),
                'request_duration_sec': float(duration),
                'connection_duration_sec': float(conn_duration),
                'headers_count': float(headers_count),
                'body_bytes': float(body_bytes),
                'time_to_first_byte_sec': float(ttfb),
                'user_agent': request.headers.get('User-Agent', '-')
            }
            features = {
                'request_duration_sec': row_features['request_duration_sec'],
                'connection_duration_sec': row_features['connection_duration_sec'],
                'bytes_transferred': row_features['bytes_transferred'],
                'headers_count': row_features['headers_count'],
                'body_bytes': row_features['body_bytes'],
                'time_to_first_byte_sec': row_features['time_to_first_byte_sec'],
                **roll,
                'header_rate': (row_features['headers_count'] / row_features['connection_duration_sec']) if row_features['connection_duration_sec'] else 0.0,
            }
            decision = self.detector.predict(features)
            explanation = generate_explanation(features, decision)

            # Demo override to force an attack decision and blocking
            demo_attack = request.headers.get('X-Demo-Attack') == '1'
            if demo_attack:
                decision = {
                    **decision,
                    'decision': 'attack',
                    'confidence': max(decision.get('confidence', 0.0), 0.99),
                    'rule': {**decision.get('rule', {}), 'fired': ['demo_forced_attack'], 'confidence': 1.0},
                }

            should_block = False
            if (self.auto_mitigation and decision['decision'] == 'attack' and decision['confidence'] >= self.conf_threshold) or demo_attack:
                should_block = True
                try:
                    # mutate response to indicate block
                    response.status_code = 429
                    response.headers['X-Blocked'] = '1'
                    response.set_data(json.dumps({
                        'status': 'blocked',
                        'reason': 'auto-attack-detected',
                        'confidence': decision['confidence']
                    }))
                    response.mimetype = 'application/json'
                except Exception:
                    pass

            event = {
                'timestamp': row_features['timestamp'],
                'src_ip': ip,
                'method': method,
                'path': path,
                'status_code': response.status_code,
                'features': features,
                'decision': decision,
                'explanation': explanation,
                'action': 'blocked' if should_block else 'allowed',
            }
            self._log_event(event)

            # Update reputation scores
            try:
                if decision['decision'] == 'attack':
                    reputation.update(ip, +3.0)
                    rate_limiter.adjust(ip, more_strict=True)
                else:
                    reputation.update(ip, -1.0)
                    rate_limiter.adjust(ip, more_strict=False)
            except Exception:
                pass

            # auto mitigation (dry-run placeholder)
            if should_block:
                from .mitigation import MitigationExecutor
                MitigationExecutor(dry_run=True).block_ip(ip, reason='auto-attack-detected', confidence=decision['confidence'])
        except Exception:
            pass
        return response
