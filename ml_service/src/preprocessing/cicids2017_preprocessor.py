"""
NetShield Phase 2: CICIDS2017 Preprocessing Module
Strictly Leakage-Free Preprocessing Pipeline for CICIDS2017 benchmark.
Memory-optimized with float32 precision for 8GB RAM development machine.
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline

# 8 Zero-Variance / Constant Features identified in Phase 1
CONSTANT_FEATURES_CICIDS2017 = [
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate"
]


class CICIDS2017Preprocessor:
    def __init__(self):
        self.column_transformer = None
        self.label_encoder = LabelEncoder()
        self.feature_names = []
        self.constant_features = CONSTANT_FEATURES_CICIDS2017
        self.is_fitted = False

    def clean_inf_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Replaces +inf and -inf values with np.nan for safe median imputation.
        Casts all numeric columns to float32 to prevent 64-bit array memory allocation.
        """
        df_clean = df.copy()
        numeric_cols = df_clean.select_dtypes(include=[np.number]).columns
        # Downcast to float32 to halve memory usage (634 MB vs 1.2 GB)
        df_clean[numeric_cols] = df_clean[numeric_cols].astype(np.float32)
        df_clean[numeric_cols] = df_clean[numeric_cols].replace([np.inf, -np.inf], np.nan)
        return df_clean

    def fit_transform_train(self, X_train_df: pd.DataFrame, y_train_series: pd.Series):
        """
        Fits imputer and scaler strictly on training data and transforms training features.
        """
        X_train_df.columns = X_train_df.columns.str.strip()
        y_clean = y_train_series.astype(str).str.strip()

        # Fit label encoder strictly on train labels
        y_train_encoded = self.label_encoder.fit_transform(y_clean)

        # Drop constant features
        X_train_filtered = X_train_df.drop(columns=self.constant_features, errors='ignore')

        # Clean inf values -> NaNs & cast float32
        X_train_clean = self.clean_inf_values(X_train_filtered)

        self.feature_names = X_train_clean.columns.tolist()

        # Numerical pipeline (Imputer + Scaler) fitted strictly on X_train
        numeric_pipeline = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler())
        ])

        self.column_transformer = ColumnTransformer(
            transformers=[
                ('num', numeric_pipeline, self.feature_names)
            ],
            remainder='drop'
        )

        # Fit and transform training set
        X_train_transformed = self.column_transformer.fit_transform(X_train_clean)
        X_train_transformed = X_train_transformed.astype(np.float32)

        self.is_fitted = True

        return X_train_transformed, y_train_encoded, X_train_clean

    def transform_test(self, X_test_df: pd.DataFrame, y_test_series: pd.Series):
        """
        Transforms test data using pre-fitted transformers without fitting.
        """
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted on training data before transforming test data!")

        X_test_df.columns = X_test_df.columns.str.strip()
        y_clean = y_test_series.astype(str).str.strip()

        known_classes = set(self.label_encoder.classes_)
        y_test_encoded = np.array([
            self.label_encoder.transform([val])[0] if val in known_classes else -1 
            for val in y_clean
        ])

        X_test_filtered = X_test_df.drop(columns=self.constant_features, errors='ignore')
        X_test_clean = self.clean_inf_values(X_test_filtered)

        # Transform using pre-fitted ColumnTransformer
        X_test_transformed = self.column_transformer.transform(X_test_clean)
        X_test_transformed = X_test_transformed.astype(np.float32)

        return X_test_transformed, y_test_encoded, X_test_clean
