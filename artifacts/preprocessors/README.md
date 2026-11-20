# Preprocessors Artifact Directory (`artifacts/preprocessors/`)

Stores fitted feature scalers, imputers, and scikit-learn `ColumnTransformer` pipelines (e.g., `preprocessor.joblib`).
These objects are fitted strictly on training data during Phase 2 and loaded during online inference to apply identical feature transformations.
