import argparse
import time
import threading
from typing import Dict, Any
import requests
import yaml

DEFAULT_HEADERS = {
    'User-Agent': 'SimClient/1.0'
}


def _headers_for_attack(atype: str) -> Dict[str, str]:
    if atype == 'slowloris':
        return {
            'X-Simulate-Request-Duration': '6.0',
            'X-Simulate-Connection-Duration': '18.0',
            'X-Simulate-Headers-Count': '90',
        }
    if atype == 'slowpost':
        return {
            'X-Simulate-Request-Duration': '8.0',
            'X-Simulate-Connection-Duration': '15.0',
        }
    if atype == 'slowread':
        return {
            'X-Simulate-Request-Duration': '7.0',
            'X-Simulate-Connection-Duration': '22.0',
        }
    if atype == 'http2slow':
        return {
            'X-Simulate-Request-Duration': '5.5',
            'X-Simulate-Connection-Duration': '18.0',
            'X-Simulate-Headers-Count': '18',
        }
    return {}


def _hit(session: requests.Session, base: str, step: Dict[str, Any]):
    target = step.get('endpoint', '/product/1')
    url = base + target
    method = step.get('method', 'GET').upper()
    headers = DEFAULT_HEADERS.copy()
    atype = step.get('type', 'benign')
    if atype != 'benign':
        headers.update(_headers_for_attack(atype))
    body = {}
    try:
        if method == 'POST':
            session.post(url, headers=headers, data=body, timeout=10)
        else:
            session.get(url, headers=headers, timeout=10)
    except Exception:
        pass


def run_step(base: str, step: Dict[str, Any]):
    rps = float(step.get('rps', 5))
    duration = float(step.get('duration_sec', 10))
    method = step.get('method', 'GET')
    endpoint = step.get('endpoint', '/product/1')
    atype = step.get('type', 'benign')
    session = requests.Session()

    interval = 1.0 / max(rps, 0.1)
    end = time.time() + duration
    while time.time() < end:
        t = threading.Thread(target=_hit, args=(session, base, step))
        t.daemon = True
        t.start()
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, required=True)
    parser.add_argument('--host', type=str, default='http://localhost:8081')
    args = parser.parse_args()

    with open(args.config, 'r') as f:
        cfg = yaml.safe_load(f)

    steps = cfg.get('steps', [])
    base = cfg.get('base_url', args.host)

    print(f"Running {len(steps)} steps against {base}")
    for i, step in enumerate(steps, 1):
        print(f"Step {i}/{len(steps)}: {step}")
        run_step(base, step)
    print("Done.")

if __name__ == '__main__':
    main()
