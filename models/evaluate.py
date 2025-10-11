import argparse
import os
import json
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
from feature_pipeline import compute_features, load_transformer, transform, LABEL_MAP


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', type=str, default='data/train.parquet')
    parser.add_argument('--artifacts', type=str, default='models/artifacts')
    args = parser.parse_args()

    df = pd.read_parquet(args.dataset)
    df_feat = compute_features(df)
    y = df_feat['label'].map(LABEL_MAP).astype(int)

    transformer = load_transformer(os.path.join(args.artifacts, 'scaler.joblib'))
    Xs = transform(df_feat, transformer)

    rf = joblib.load(os.path.join(args.artifacts, 'rf.joblib'))
    xgb = joblib.load(os.path.join(args.artifacts, 'xgb.joblib'))

    rf_proba = rf.predict_proba(Xs)[:, 1]
    xgb_proba = xgb.predict_proba(Xs)[:, 1]
    sup_prob = (rf_proba + xgb_proba) / 2.0
    sup_pred = (sup_prob > 0.5).astype(int)

    report = classification_report(y, sup_pred, output_dict=True)
    cm = confusion_matrix(y, sup_pred)
    try:
        auc = roc_auc_score(y, sup_prob)
    except Exception:
        auc = float('nan')

    os.makedirs('results', exist_ok=True)
    with open('results/eval_report.json', 'w') as f:
        json.dump({'classification_report': report, 'roc_auc': auc, 'confusion_matrix': cm.tolist()}, f, indent=2)

    print(json.dumps({'roc_auc': auc, 'f1': report['weighted avg']['f1-score']}, indent=2))

if __name__ == '__main__':
    main()
