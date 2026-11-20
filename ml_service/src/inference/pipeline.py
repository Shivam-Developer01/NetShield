"""
NetShield Phase 20 Production Inference Pipeline
Loads verified frozen model artifacts (NSL-KDD v1.3 Expert Ensemble and CICIDS2017 v1.2 Two-Stage)
and provides a clean HTTP-independent predict interface for real-time and batch intrusion prediction.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd

# Top-level class definitions for joblib unpickling
class IdentitySelector:
    """Identity feature selector to preserve pipeline contract for v1.3."""
    def transform(self, X):
        return X


class NetShieldNSLKDDExpertEnsembleV13:
    """
    Production-compatible container for NSL-KDD v1.3:
    Combines a base 5-class cost-sensitive model with dedicated R2L and U2R specialists
    and an uncertainty routing zone.
    """
    def __init__(self, m_base, m_r2l, m_u2r, classes, normal_idx, r2l_idx, u2r_idx,
                 tau_r2l=0.50, tau_u2r=0.60, tau_attack=0.45, tau_certainty=0.75):
        self.m_base = m_base
        self.m_r2l = m_r2l
        self.m_u2r = m_u2r
        self.classes = classes
        self.normal_idx = normal_idx
        self.r2l_idx = r2l_idx
        self.u2r_idx = u2r_idx
        self.tau_r2l = tau_r2l
        self.tau_u2r = tau_u2r
        self.tau_attack = tau_attack
        self.tau_certainty = tau_certainty

    def predict_proba(self, X):
        return self.m_base.predict_proba(X)

    def predict(self, X):
        probs_base = self.m_base.predict_proba(X)
        p_r2l = self.m_r2l.predict_proba(X)[:, 1]
        p_u2r = self.m_u2r.predict_proba(X)[:, 1]

        preds = np.zeros(len(X), dtype=int)
        for i in range(len(X)):
            p_norm = probs_base[i, self.normal_idx]
            p_atk = 1.0 - p_norm

            if p_u2r[i] >= self.tau_u2r:
                preds[i] = self.u2r_idx
            elif p_r2l[i] >= self.tau_r2l:
                preds[i] = self.r2l_idx
            elif p_atk >= self.tau_attack:
                atk_probs = [(c_idx, probs_base[i, c_idx]) for c_idx in range(len(self.classes)) if c_idx != self.normal_idx]
                preds[i] = max(atk_probs, key=lambda x: x[1])[0]
            elif p_norm < self.tau_certainty:
                atk_probs = [(c_idx, probs_base[i, c_idx]) for c_idx in range(len(self.classes)) if c_idx != self.normal_idx]
                preds[i] = max(atk_probs, key=lambda x: x[1])[0]
            else:
                preds[i] = self.normal_idx
        return preds


# Register classes into __main__ so joblib unpickler resolves them cleanly regardless of entrypoint
import __main__
setattr(__main__, "IdentitySelector", IdentitySelector)
setattr(__main__, "NetShieldNSLKDDExpertEnsembleV13", NetShieldNSLKDDExpertEnsembleV13)

# Ensure custom feature selector class for CICIDS2017 is resolvable
FEATURE_SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "features"))
if FEATURE_SRC_DIR not in sys.path:
    sys.path.append(FEATURE_SRC_DIR)

from feature_selector import NetShieldFeatureSelector
setattr(__main__, "NetShieldFeatureSelector", NetShieldFeatureSelector)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# Authoritative Verified Frozen Bundle Locations (Phase 20)
VERIFIED_BUNDLE_PATHS = {
    "nsl_kdd": os.path.join(PROJECT_ROOT, "artifacts", "v1.3", "nsl_kdd"),
    "cicids2017": os.path.join(PROJECT_ROOT, "artifacts", "v1.2", "cicids2017")
}

FALLBACK_PRODUCTION_DIR = os.path.join(PROJECT_ROOT, "artifacts", "production")


def add_nsl_kdd_derived_features(df):
    """
    Computes real-time derived network features required by NSL-KDD v1.3.
    """
    df = df.copy()
    dur = df['duration'].clip(lower=0.0) if 'duration' in df.columns else 0.0
    src_b = df['src_bytes'].clip(lower=0.0) if 'src_bytes' in df.columns else 0.0
    dst_b = df['dst_bytes'].clip(lower=0.0) if 'dst_bytes' in df.columns else 0.0

    df['total_bytes'] = src_b + dst_b
    df['bytes_per_sec'] = (df['total_bytes']) / (dur + 0.001)
    df['src_to_dst_byte_ratio'] = (src_b + 1.0) / (dst_b + 1.0)
    df['dst_to_src_byte_ratio'] = (dst_b + 1.0) / (src_b + 1.0)

    cnt = df['count'].clip(lower=0.0) if 'count' in df.columns else 0.0
    srv_cnt = df['srv_count'].clip(lower=0.0) if 'srv_count' in df.columns else 0.0
    df['count_per_sec'] = cnt / (dur + 0.001)
    df['srv_count_per_sec'] = srv_cnt / (dur + 0.001)

    s_err = df['serror_rate'].clip(lower=0.0, upper=1.0) if 'serror_rate' in df.columns else 0.0
    r_err = df['rerror_rate'].clip(lower=0.0, upper=1.0) if 'rerror_rate' in df.columns else 0.0
    df['error_rate_diff'] = np.abs(s_err - r_err)
    df['total_error_rate'] = np.clip(s_err + r_err, 0.0, 1.0)

    same_srv = df['same_srv_rate'].clip(lower=0.0, upper=1.0) if 'same_srv_rate' in df.columns else 1.0
    diff_srv = df['diff_srv_rate'].clip(lower=0.0, upper=1.0) if 'diff_srv_rate' in df.columns else 0.0
    df['srv_diversity_ratio'] = diff_srv / (same_srv + 0.01)

    dst_same = df['dst_host_same_srv_rate'].clip(lower=0.0, upper=1.0) if 'dst_host_same_srv_rate' in df.columns else 1.0
    dst_diff = df['dst_host_diff_srv_rate'].clip(lower=0.0, upper=1.0) if 'dst_host_diff_srv_rate' in df.columns else 0.0
    df['dst_host_srv_ratio'] = dst_diff / (dst_same + 0.01)

    interactive_services = {
        'telnet', 'ftp', 'ftp_data', 'ssh', 'login', 'exec', 'rje', 'shell',
        'klogin', 'kshell', 'pop_3', 'imap4', 'smtp', 'finger'
    }
    if 'service' in df.columns:
        df['is_interactive_service'] = df['service'].map(lambda s: 1.0 if str(s).strip() in interactive_services else 0.0)
    else:
        df['is_interactive_service'] = 0.0

    logged_in = df['logged_in'] if 'logged_in' in df.columns else 0
    failed_logins = df['num_failed_logins'] if 'num_failed_logins' in df.columns else 0
    df['failed_login_indicator'] = ((logged_in == 0) & (failed_logins > 0)).astype(float)

    comp = df['num_compromised'] if 'num_compromised' in df.columns else 0
    root_s = df['root_shell'] if 'root_shell' in df.columns else 0
    su_att = df['su_attempted'] if 'su_attempted' in df.columns else 0
    df['compromised_indicator'] = ((comp > 0) | (root_s == 1) | (su_att > 0)).astype(float)
    return df


class NetShieldInferencePipeline:
    """
    Production inference engine that loads verified frozen model bundles
    (NSL-KDD v1.3 and CICIDS2017 v1.2) and executes the complete 5-step ML prediction pipeline.
    """

    def __init__(self):
        self.bundles = {}
        self._load_production_bundle("nsl_kdd")
        self._load_production_bundle("cicids2017")

    def _load_production_bundle(self, dataset_key):
        # Priority: Load from verified versioned directories first
        bundle_path = VERIFIED_BUNDLE_PATHS.get(dataset_key)
        if not bundle_path or not os.path.exists(bundle_path):
            bundle_path = os.path.join(FALLBACK_PRODUCTION_DIR, dataset_key)
        
        if not os.path.exists(bundle_path):
            raise FileNotFoundError(f"Production bundle not found for {dataset_key} at {bundle_path}")

        model = joblib.load(os.path.join(bundle_path, "best_model.joblib"))
        preprocessor = joblib.load(os.path.join(bundle_path, "preprocessor.joblib"))
        selector = joblib.load(os.path.join(bundle_path, "feature_selector.joblib"))
        encoder = joblib.load(os.path.join(bundle_path, "label_encoder.joblib"))

        with open(os.path.join(bundle_path, "feature_schema.json"), "r") as f:
            schema = json.load(f)

        with open(os.path.join(bundle_path, "metadata.json"), "r") as f:
            metadata = json.load(f)

        self.bundles[dataset_key] = {
            "model": model,
            "preprocessor": preprocessor,
            "selector": selector,
            "encoder": encoder,
            "schema": schema,
            "metadata": metadata,
            "bundle_path": bundle_path
        }

    def predict(self, dataset_type, input_data):
        """
        Executes complete production inference chain.
        :param dataset_type: 'nsl_kdd' or 'cicids2017'
        :param input_data: pandas DataFrame or list of dicts containing raw feature records
        :return: dict containing predictions, probabilities, and execution metadata
        """
        key = dataset_type.lower().replace("-", "_")
        if key not in self.bundles:
            raise ValueError(f"Unsupported dataset_type: '{dataset_type}'. Supported: 'nsl_kdd', 'cicids2017'")

        bundle = self.bundles[key]

        if isinstance(input_data, dict):
            df_input = pd.DataFrame([input_data])
        elif isinstance(input_data, list):
            df_input = pd.DataFrame(input_data)
        elif isinstance(input_data, pd.DataFrame):
            df_input = input_data.copy()
        else:
            raise TypeError("input_data must be a dict, list of dicts, or pandas DataFrame")

        # Clean column names (strip whitespace) for robust schema matching
        df_input.columns = [str(col).strip() for col in df_input.columns]

        # For NSL-KDD v1.3: Generate derived network features prior to transformer
        if key == "nsl_kdd":
            df_input = add_nsl_kdd_derived_features(df_input)

        # Ensure any missing expected columns are populated with 0.0 for robust input handling
        prep = bundle["preprocessor"]
        if hasattr(prep, "feature_names_in_"):
            for col in prep.feature_names_in_:
                if col not in df_input.columns:
                    df_input[col] = 0.0

        # 1. Transform raw inputs through Sklearn preprocessor
        X_processed = prep.transform(df_input)

        # 2. Apply pre-fitted feature selector
        X_reduced = bundle["selector"].transform(X_processed)

        # 3. Model inference & Decision Policy
        model = bundle["model"]
        
        # 4. Confidence / Class Probabilities & Routing Policy
        if hasattr(model, "predict_proba"):
            probs_matrix = model.predict_proba(X_reduced)
            
            # Check for CICIDS2017 Two-Stage thresholding policy
            tau_attack = bundle["metadata"].get("attack_threshold", None)
            if tau_attack is not None and key == "cicids2017":
                benign_idx = list(bundle["encoder"].classes_).index("BENIGN") if "BENIGN" in bundle["encoder"].classes_ else 0
                attack_indices = [i for i in range(len(bundle["encoder"].classes_)) if i != benign_idx]
                y_pred_idx = []
                for row in probs_matrix:
                    p_benign = row[benign_idx]
                    p_attack = 1.0 - p_benign
                    if p_attack >= tau_attack:
                        best_attack = max(attack_indices, key=lambda idx: row[idx])
                        y_pred_idx.append(best_attack)
                    else:
                        y_pred_idx.append(benign_idx)
                y_pred_idx = np.array(y_pred_idx, dtype=int)
            else:
                # NSL-KDD v1.3 expert ensemble encapsulates its own internal gating in predict()
                y_pred_idx = model.predict(X_reduced)

            confidences = [float(np.max(row)) for row in probs_matrix]
            probs_dict = [
                {str(bundle["encoder"].classes_[idx]): float(prob) for idx, prob in enumerate(row)}
                for row in probs_matrix
            ]
        else:
            y_pred_idx = model.predict(X_reduced)
            confidences = [1.0] * len(y_pred_idx)
            probs_dict = [{str(bundle["encoder"].inverse_transform([idx])[0]): 1.0} for idx in y_pred_idx]

        # 5. Label decoding
        predicted_labels = bundle["encoder"].inverse_transform(y_pred_idx)

        results = []
        for idx in range(len(predicted_labels)):
            results.append({
                "record_index": idx,
                "prediction": str(predicted_labels[idx]),
                "prediction_index": int(y_pred_idx[idx]),
                "confidence": float(confidences[idx]),
                "class_probabilities": probs_dict[idx]
            })

        return {
            "dataset_type": key,
            "model_version": bundle["metadata"]["model_version"],
            "records_processed": len(results),
            "predictions": results
        }


# Singleton pipeline instance
_pipeline_instance = None


def get_inference_pipeline():
    global _pipeline_instance
    if _pipeline_instance is None:
        _pipeline_instance = NetShieldInferencePipeline()
    return _pipeline_instance
