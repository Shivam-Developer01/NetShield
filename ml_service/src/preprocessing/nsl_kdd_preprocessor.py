"""
NetShield Phase 2: NSL-KDD Preprocessing Module
Strictly Leakage-Free Preprocessing Pipeline for NSL-KDD benchmark.
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline

NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty_level"
]

# Attack Class Mapping to 5 Major Categories
NSL_KDD_5CLASS_MAP = {
    'normal': 'Normal',
    # DoS
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS', 'smurf': 'DoS',
    'teardrop': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS', 'processtable': 'DoS', 'mailbomb': 'DoS',
    # Probe
    'satan': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
    # R2L
    'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L', 'multihop': 'R2L',
    'warezmaster': 'R2L', 'warezclient': 'R2L', 'spy': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L',
    'snmpguess': 'R2L', 'snmpgetattack': 'R2L', 'httptunnel': 'R2L', 'sendmail': 'R2L', 'named': 'R2L',
    # U2R
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'rootkit': 'U2R', 'perl': 'U2R',
    'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R'
}

# Explicitly excluded columns
EXCLUDED_COLUMNS = ['difficulty_level', 'num_outbound_cmds']

CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']


class NSLKDDPreprocessor:
    def __init__(self):
        self.column_transformer = None
        self.label_encoder_5class = LabelEncoder()
        self.label_encoder_raw = LabelEncoder()
        self.feature_names = []
        self.numerical_features = []
        self.categorical_features = CATEGORICAL_FEATURES
        self.is_fitted = False

    def fit_transform_train(self, df_train: pd.DataFrame):
        """
        Fits the preprocessor strictly on training data and transforms training features/labels.
        """
        # Ensure correct column names if un-headered
        if list(df_train.columns) != NSL_KDD_COLUMNS and df_train.shape[1] == 43:
            df_train.columns = NSL_KDD_COLUMNS

        # Separate targets
        y_train_raw = df_train['label'].astype(str).str.lower().str.strip()
        y_train_5class = y_train_raw.map(lambda x: NSL_KDD_5CLASS_MAP.get(x, 'Other'))

        # Fit label encoders strictly on training labels
        y_train_encoded_5class = self.label_encoder_5class.fit_transform(y_train_5class)
        self.label_encoder_raw.fit(y_train_raw)
        y_train_encoded_raw = self.label_encoder_raw.transform(y_train_raw)

        # Drop targets and excluded columns
        X_train_df = df_train.drop(columns=['label'] + EXCLUDED_COLUMNS, errors='ignore')

        # Determine numerical features dynamically
        self.numerical_features = [col for col in X_train_df.columns if col not in self.categorical_features]

        # Define Sklearn ColumnTransformer
        numeric_pipeline = Pipeline(steps=[
            ('scaler', StandardScaler())
        ])

        categorical_pipeline = Pipeline(steps=[
            ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
        ])

        self.column_transformer = ColumnTransformer(
            transformers=[
                ('num', numeric_pipeline, self.numerical_features),
                ('cat', categorical_pipeline, self.categorical_features)
            ],
            remainder='drop'
        )

        # Fit strictly on X_train
        X_train_transformed = self.column_transformer.fit_transform(X_train_df)

        # Extract feature names after fitting
        cat_ohe = self.column_transformer.named_transformers_['cat'].named_steps['onehot']
        cat_feature_names = cat_ohe.get_feature_names_out(self.categorical_features).tolist()
        self.feature_names = self.numerical_features + cat_feature_names

        self.is_fitted = True

        return X_train_transformed, y_train_encoded_5class, y_train_encoded_raw, X_train_df

    def transform_test(self, df_test: pd.DataFrame):
        """
        Transforms test data using pre-fitted transformers without fitting.
        """
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted on training data before transforming test data!")

        if list(df_test.columns) != NSL_KDD_COLUMNS and df_test.shape[1] == 43:
            df_test.columns = NSL_KDD_COLUMNS

        y_test_raw = df_test['label'].astype(str).str.lower().str.strip()
        y_test_5class = y_test_raw.map(lambda x: NSL_KDD_5CLASS_MAP.get(x, 'Other'))

        # Transform labels using fitted encoder
        # Safe transform for unknown labels
        known_5class = set(self.label_encoder_5class.classes_)
        y_test_5class_safe = y_test_5class.map(lambda x: x if x in known_5class else 'Other')
        if 'Other' not in known_5class:
            # Fallback if Other not in train classes
            y_test_encoded_5class = np.array([
                self.label_encoder_5class.transform([val])[0] if val in known_5class else -1 
                for val in y_test_5class
            ])
        else:
            y_test_encoded_5class = self.label_encoder_5class.transform(y_test_5class_safe)

        known_raw = set(self.label_encoder_raw.classes_)
        y_test_encoded_raw = np.array([
            self.label_encoder_raw.transform([val])[0] if val in known_raw else -1 
            for val in y_test_raw
        ])

        X_test_df = df_test.drop(columns=['label'] + EXCLUDED_COLUMNS, errors='ignore')

        # Transform using pre-fitted ColumnTransformer
        X_test_transformed = self.column_transformer.transform(X_test_df)

        return X_test_transformed, y_test_encoded_5class, y_test_encoded_raw, X_test_df
