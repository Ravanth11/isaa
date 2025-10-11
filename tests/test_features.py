import pandas as pd
from models.feature_pipeline import compute_features

def test_compute_features_basic():
    data = [
        {
            'timestamp': '2024-01-01T00:00:00', 'src_ip': '1.1.1.1', 'client_port': 1111,
            'method': 'GET', 'path': '/product/1', 'status_code': 200,
            'bytes_transferred': 1000, 'request_duration_sec': 0.1,
            'connection_duration_sec': 0.2, 'headers_count': 10,
            'body_bytes': 0, 'time_to_first_byte_sec': 0.02, 'user_agent': 'ua', 'label': 'benign'
        },
        {
            'timestamp': '2024-01-01T00:00:01', 'src_ip': '1.1.1.1', 'client_port': 1112,
            'method': 'GET', 'path': '/product/2', 'status_code': 200,
            'bytes_transferred': 2000, 'request_duration_sec': 0.2,
            'connection_duration_sec': 0.3, 'headers_count': 12,
            'body_bytes': 0, 'time_to_first_byte_sec': 0.03, 'user_agent': 'ua', 'label': 'benign'
        }
    ]
    df = pd.DataFrame(data)
    out = compute_features(df)
    assert 'bytes_per_second' in out.columns
    assert 'request_rate' in out.columns
    assert len(out) == 2
