# Architecture (M1-M3)

- Data generation in `simulator/generate_dataset.py` produces JSON-schema-aligned records written to Parquet.
- Feature pipeline in `models/feature_pipeline.py` computes per-IP rolling features on 60s windows and saves a scaler.
- Training in `models/train.py` fits IsolationForest (benign-only), RandomForest, and XGBoost, saving artifacts in `models/artifacts/`.
- Evaluation in `models/evaluate.py` outputs JSON with metrics in `results/`.

Next milestones add real-time middleware, ensemble, explainability, and mitigation.
