import numpy as np
import pandas as pd
from typing import Tuple, Dict
from sklearn.preprocessing import StandardScaler
import joblib

FEATURES = [
    'request_duration_sec',
    'connection_duration_sec',
    'bytes_transferred',
    'headers_count',
    'body_bytes',
    'time_to_first_byte_sec',
    'request_rate',
    'bytes_per_second',
    'avg_time_between_requests',
    'header_rate',
    'last_1min_request_count',
    'last_5min_request_count',
]

LABEL_MAP = {
    'benign': 0,
    'slowdos_slowloris': 1,
    'slowdos_slowpost': 1,
    'slowdos_slowread': 1,
    'slowdos_http2slow': 1,
}


def compute_features(df: pd.DataFrame, window_sec: int = 60) -> pd.DataFrame:
    df = df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(['src_ip', 'timestamp'])

    # Per-row simple features
    df['bytes_per_second'] = (df['bytes_transferred'] / df['connection_duration_sec'].replace(0, np.nan)).fillna(0)
    df['header_rate'] = (df['headers_count'] / df['connection_duration_sec'].replace(0, np.nan)).fillna(0)

    # Grouped rolling features
    def group_apply(g):
        g = g.set_index('timestamp')
        g = g.sort_index()
        # request_rate approximated by rolling count per 60s window
        g['request_rate'] = g['method'].rolling(f'{window_sec}s').count()
        # last_1min_request_count same as request_rate; last_5min uses 300s
        g['last_1min_request_count'] = g['method'].rolling('60s').count()
        g['last_5min_request_count'] = g['method'].rolling('300s').count()
        # avg_time_between_requests: rolling mean of diffs
        diffs = g.index.to_series().diff().dt.total_seconds().fillna(0)
        g['avg_time_between_requests'] = diffs.rolling('60s').mean().fillna(0)
        return g.reset_index()

    df = df.groupby('src_ip', group_keys=False).apply(group_apply)

    # Fill NaNs
    df[FEATURES] = df[FEATURES].fillna(0)
    return df


def fit_transformer(train_df: pd.DataFrame, scaler_path: str) -> Tuple[np.ndarray, StandardScaler]:
    X = train_df[FEATURES].values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    joblib.dump({'scaler': scaler, 'features': FEATURES}, scaler_path)
    return Xs, scaler


def load_transformer(scaler_path: str) -> Dict:
    return joblib.load(scaler_path)


def transform(df: pd.DataFrame, transformer: Dict) -> np.ndarray:
    X = df[transformer['features']].values
    return transformer['scaler'].transform(X)
