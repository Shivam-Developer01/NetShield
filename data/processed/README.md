# Processed Dataset Directory (`data/processed/`)

This directory stores intermediate and preprocessed dataset splits generated during Phase 2 (Leakage-Free Preprocessing) and Phase 3 (Feature Engineering):
- `train_nsl_kdd.parquet` / `.csv`
- `test_nsl_kdd.parquet` / `.csv`
- `train_cicids2017.parquet` / `.csv`
- `test_cicids2017.parquet` / `.csv`

> [!NOTE]
> Training and testing splits stored here are generated strictly using stratified split boundaries before applying feature transformations or scaling.
