import os
import json
from typing import Dict, Any


class MitigationExecutor:
    def __init__(self, dry_run: bool = True, state_dir: str = 'logs'):
        self.dry_run = dry_run
        self.state_dir = state_dir
        os.makedirs(self.state_dir, exist_ok=True)
        self.blocklist_path = os.path.join(self.state_dir, 'blocklist.json')
        if not os.path.exists(self.blocklist_path):
            with open(self.blocklist_path, 'w') as f:
                json.dump({'blocked_ips': []}, f)

    def _save_block(self, ip: str, meta: Dict[str, Any]):
        with open(self.blocklist_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if ip not in data['blocked_ips']:
            data['blocked_ips'].append(ip)
        with open(self.blocklist_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def block_ip(self, ip: str, reason: str = '', confidence: float = 0.0):
        action = {'action': 'block_ip', 'ip': ip, 'reason': reason, 'confidence': confidence, 'dry_run': self.dry_run}
        # In real deployment, call firewall/Nginx API here.
        if not self.dry_run:
            self._save_block(ip, action)
        # Always log the intent for demo
        with open(os.path.join(self.state_dir, 'mitigations.jsonl'), 'a', encoding='utf-8') as f:
            f.write(json.dumps(action) + '\n')
        return action

    def rate_limit(self, ip: str, rps: int = 5):
        action = {'action': 'rate_limit', 'ip': ip, 'rps': rps, 'dry_run': self.dry_run}
        with open(os.path.join(self.state_dir, 'mitigations.jsonl'), 'a', encoding='utf-8') as f:
            f.write(json.dumps(action) + '\n')
        return action

    def captcha_challenge(self, ip: str):
        action = {'action': 'captcha', 'ip': ip, 'dry_run': self.dry_run}
        with open(os.path.join(self.state_dir, 'mitigations.jsonl'), 'a', encoding='utf-8') as f:
            f.write(json.dumps(action) + '\n')
        return action

    def honeypot_redirect(self, ip: str):
        action = {'action': 'honeypot', 'ip': ip, 'dry_run': self.dry_run}
        with open(os.path.join(self.state_dir, 'mitigations.jsonl'), 'a', encoding='utf-8') as f:
            f.write(json.dumps(action) + '\n')
        return action
