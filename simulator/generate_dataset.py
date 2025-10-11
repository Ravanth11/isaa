import argparse
import os
import random
from datetime import datetime, timedelta
import numpy as np
import pandas as pd

ATTACK_LABELS = ['slowdos_slowloris', 'slowdos_slowpost', 'slowdos_slowread', 'slowdos_http2slow']
USER_AGENTS = [
    'Mozilla/5.0', 'Chrome/120.0', 'Safari/17.0', 'Edge/120.0'
]
PATHS = ['/login', '/product/1', '/product/2', '/product/3', '/cart', '/checkout']
METHODS = ['GET', 'POST']


def rand_ip(rng: random.Random) -> str:
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def gen_sample(ts: datetime, src_ip: str, rng: random.Random, attack: str | None) -> dict:
    benign = attack is None
    method = rng.choice(METHODS if benign else (['GET', 'POST'] if attack != 'slowdos_slowpost' else ['POST']))
    path = rng.choice(PATHS)

    # Base distributions
    if benign:
        status = 200
        conn_dur = max(0.05, rng.gauss(0.3, 0.1))
        req_dur = max(0.02, rng.gauss(0.12, 0.05))
        bytes_tx = int(max(100, rng.gauss(25000, 8000)))
        headers = int(max(5, rng.gauss(10, 3)))
        body_bytes = int(max(0, rng.gauss(1200, 600))) if method == 'POST' else 0
        ttfb = max(0.01, rng.gauss(0.05, 0.02))
    else:
        status = 200
        if attack == 'slowdos_slowloris':
            conn_dur = max(5.0, rng.gauss(20.0, 5.0))
            req_dur = max(2.0, rng.gauss(6.0, 1.0))
            bytes_tx = int(max(50, rng.gauss(2000, 500)))
            headers = int(max(30, rng.gauss(80, 10)))
            body_bytes = 0
            ttfb = max(0.5, rng.gauss(1.5, 0.5))
        elif attack == 'slowdos_slowpost':
            conn_dur = max(5.0, rng.gauss(15.0, 4.0))
            req_dur = max(3.0, rng.gauss(8.0, 2.0))
            bytes_tx = int(max(200, rng.gauss(4000, 1000)))
            headers = int(max(10, rng.gauss(15, 4)))
            body_bytes = int(max(50, rng.gauss(200, 60)))
            ttfb = max(0.5, rng.gauss(1.0, 0.3))
        elif attack == 'slowdos_slowread':
            conn_dur = max(8.0, rng.gauss(25.0, 6.0))
            req_dur = max(2.0, rng.gauss(7.0, 2.0))
            bytes_tx = int(max(50, rng.gauss(1500, 400)))
            headers = int(max(8, rng.gauss(12, 3)))
            body_bytes = 0
            ttfb = max(0.6, rng.gauss(1.4, 0.4))
        else:  # http2 slow
            conn_dur = max(6.0, rng.gauss(18.0, 5.0))
            req_dur = max(2.0, rng.gauss(5.5, 1.0))
            bytes_tx = int(max(80, rng.gauss(2500, 600)))
            headers = int(max(12, rng.gauss(18, 4)))
            body_bytes = int(max(0, rng.gauss(80, 30))) if method == 'POST' else 0
            ttfb = max(0.5, rng.gauss(1.2, 0.3))

    return {
        'timestamp': ts.isoformat(),
        'src_ip': src_ip,
        'client_port': rng.randint(1024, 65535),
        'method': method,
        'path': path,
        'status_code': status,
        'bytes_transferred': bytes_tx,
        'request_duration_sec': req_dur,
        'connection_duration_sec': conn_dur,
        'headers_count': headers,
        'body_bytes': body_bytes,
        'time_to_first_byte_sec': ttfb,
        'user_agent': rng.choice(USER_AGENTS),
        'label': 'benign' if benign else attack,
    }


def generate(n: int, benign_ratio: float, seed: int) -> pd.DataFrame:
    rng = random.Random(seed)
    np.random.seed(seed)

    start = datetime.utcnow()
    rows = []
    # Choose some source IPs to simulate sessions
    ips = [rand_ip(rng) for _ in range(max(50, n // 200))]

    for i in range(n):
        ts = start + timedelta(seconds=i * rng.uniform(0.01, 0.3))
        src_ip = rng.choice(ips)
        is_benign = rng.random() < benign_ratio
        attack = None if is_benign else rng.choice(ATTACK_LABELS)
        rows.append(gen_sample(ts, src_ip, rng, attack))

    df = pd.DataFrame(rows)
    return df


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--n', type=int, default=10000)
    parser.add_argument('--out', type=str, default='data/train.parquet')
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--benign_ratio', type=float, default=0.8)
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    df = generate(args.n, args.benign_ratio, args.seed)
    df.to_parquet(args.out, index=False)
    print(f"Wrote {len(df)} rows to {args.out}")

if __name__ == '__main__':
    main()
