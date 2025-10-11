import argparse
import os
import json
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, roc_auc_score
import xgboost as xgb
import joblib
import yaml
from feature_pipeline import compute_features, fit_transformer, LABEL_MAP


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def load_config(path: str) -> dict:
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='models/config.yaml')
    parser.add_argument('--dataset', type=str, default='data/train.parquet')
    args = parser.parse_args()

    cfg = load_config(args.config)
    seed = int(cfg.get('seed', 42))
    artifacts_dir = cfg['artifacts_dir']
    ensure_dir(artifacts_dir)

    df = pd.read_parquet(args.dataset)
    df_feat = compute_features(df)

    # Binary label
    y = df_feat['label'].map(LABEL_MAP).astype(int)

    # Fit scaler on train split only
    X_train_df, X_test_df, y_train, y_test = train_test_split(df_feat, y, test_size=0.3, stratify=y, random_state=seed)
    X_train_scaled, scaler = fit_transformer(X_train_df, os.path.join(artifacts_dir, 'scaler.joblib'))

    # Prepare supervised features consistently
    from feature_pipeline import load_transformer, transform, FEATURES
    transformer = load_transformer(os.path.join(artifacts_dir, 'scaler.joblib'))
    X_test_scaled = transform(X_test_df, transformer)

    # IsolationForest — train on benign only
    if_benign_idx = y_train[y_train == 0].index
    X_if = X_train_scaled[np.isin(X_train_df.index, if_benign_idx)]
    iso = IsolationForest(n_estimators=cfg['models']['isolation_forest']['n_estimators'],
                          contamination=cfg['models']['isolation_forest']['contamination'],
                          random_state=seed)
    iso.fit(X_if)
    joblib.dump(iso, os.path.join(artifacts_dir, 'iso.joblib'))

    # RandomForest
    rf = RandomForestClassifier(
        n_estimators=cfg['models']['random_forest']['n_estimators'],
        max_depth=cfg['models']['random_forest']['max_depth'],
        class_weight=cfg['models']['random_forest']['class_weight'],
        random_state=seed
    )
    rf.fit(X_train_scaled, y_train)
    joblib.dump(rf, os.path.join(artifacts_dir, 'rf.joblib'))

    # XGBoost
    xgb_clf = xgb.XGBClassifier(
        n_estimators=cfg['models']['xgboost']['n_estimators'],
        max_depth=cfg['models']['xgboost']['max_depth'],
        learning_rate=cfg['models']['xgboost']['learning_rate'],
        subsample=cfg['models']['xgboost']['subsample'],
        colsample_bytree=cfg['models']['xgboost']['colsample_bytree'],
        random_state=seed,
        eval_metric='logloss',
        tree_method='hist'
    )
    xgb_clf.fit(X_train_scaled, y_train)
    joblib.dump(xgb_clf, os.path.join(artifacts_dir, 'xgb.joblib'))

    # Evaluate
    rf_proba = rf.predict_proba(X_test_scaled)[:, 1]
    xgb_proba = xgb_clf.predict_proba(X_test_scaled)[:, 1]
    sup_prob = (rf_proba + xgb_proba) / 2.0
    sup_pred = (sup_prob > 0.5).astype(int)

    report = classification_report(y_test, sup_pred, output_dict=True)
    try:
        auc = roc_auc_score(y_test, sup_prob)
    except Exception:
        auc = float('nan')

    meta = {
        'metrics': report,
        'roc_auc': auc,
        'features': transformer['features'],
    }
    with open(os.path.join(artifacts_dir, 'metrics.json'), 'w') as f:
        json.dump(meta, f, indent=2)

    print(json.dumps({'roc_auc': auc, 'f1': report['weighted avg']['f1-score']}, indent=2))

if __name__ == '__main__':
    main()
