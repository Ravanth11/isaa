import json
import os
import time
from pathlib import Path
import streamlit as st

# Local imports via sys.path tweak
import sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.mitigation import MitigationExecutor

EVENTS_PATH = ROOT / 'logs' / 'events.jsonl'
MITIGATIONS_PATH = ROOT / 'logs' / 'mitigations.jsonl'
BLOCKLIST_PATH = ROOT / 'logs' / 'blocklist.json'

st.set_page_config(page_title="SlowDOS Live Dashboard", layout="wide")

st.title("SlowDOS Live Monitoring & Mitigation")

col1, col2 = st.columns([2,1])

with col2:
    st.subheader("Mitigation Controls")
    dry_run = st.toggle("Dry-run mode", value=True, help="If on, actions are logged but not persisted.")
    ip_to_block = st.text_input("IP to block")
    if st.button("Block IP") and ip_to_block:
        MitigationExecutor(dry_run=dry_run, state_dir=str(ROOT / 'logs')).block_ip(ip_to_block, reason='manual', confidence=1.0)
        st.success(f"Block request logged for {ip_to_block}")
    ip_to_rl = st.text_input("IP to rate-limit")
    rps = st.slider("RPS", 1, 50, 5)
    if st.button("Rate-limit IP") and ip_to_rl:
        MitigationExecutor(dry_run=dry_run, state_dir=str(ROOT / 'logs')).rate_limit(ip_to_rl, rps=rps)
        st.success(f"Rate-limit request logged for {ip_to_rl}")

with col1:
    st.subheader("Live Alerts")
    st.caption(str(EVENTS_PATH))
    refresh = st.button("Refresh")
    limit = st.slider("Show last N events", 10, 1000, 200)

    rows = []
    if EVENTS_PATH.exists():
        with open(EVENTS_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    rows = rows[-limit:]

    # Render table
    def row_to_display(r):
        dec = r.get('decision', {})
        return {
            'time': r.get('timestamp'),
            'ip': r.get('src_ip'),
            'path': r.get('path'),
            'status': r.get('status_code'),
            'decision': dec.get('decision'),
            'conf': round(dec.get('confidence', 0.0), 3),
            'rule': ','.join(dec.get('rule', {}).get('fired', [])) if dec.get('rule') else '',
            'sup_prob': round(dec.get('probs', {}).get('supervised_avg', 0.0), 3),
            'iso_score': round(dec.get('iso_score', 0.0), 3),
        }

    if rows:
        disp = [row_to_display(r) for r in rows]
        st.dataframe(disp, use_container_width=True)
    else:
        st.info("No events yet. Generate traffic by browsing the Flask shop or running the simulator against it.")

st.divider()

st.subheader("Blocklist Snapshot")
if BLOCKLIST_PATH.exists():
    with open(BLOCKLIST_PATH, 'r', encoding='utf-8') as f:
        st.json(json.load(f))
else:
    st.write("Blocklist not created yet.")

st.subheader("Recent Mitigation Actions")
if MITIGATIONS_PATH.exists():
    with open(MITIGATIONS_PATH, 'r', encoding='utf-8') as f:
        lines = f.readlines()[-200:]
        for ln in reversed(lines):
            try:
                st.code(ln.strip())
            except Exception:
                pass
else:
    st.write("No mitigations recorded yet.")
