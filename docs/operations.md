# Operations (early)

- Seeds: set via `models/config.yaml`.
- Artifacts: stored in `models/artifacts/`.
- To regenerate dataset: `python simulator/generate_dataset.py --n 10000 --out data/train.parquet --seed 42`.
- To retrain: `python models/train.py --config models/config.yaml`.
