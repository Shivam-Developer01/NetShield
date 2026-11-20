"""
NetShield Phase 3: Sklearn-Compatible Feature Selector
Selects specified feature indices/columns deterministically across train and test matrices.
"""

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin


class NetShieldFeatureSelector(BaseEstimator, TransformerMixin):
    def __init__(self, selected_indices=None, selected_feature_names=None):
        self.selected_indices = selected_indices
        self.selected_feature_names = selected_feature_names

    def fit(self, X, y=None):
        # Feature selection logic is pre-calculated on X_train
        return self

    def transform(self, X):
        if self.selected_indices is None:
            raise ValueError("selected_indices must be specified before transforming data!")
        
        if isinstance(X, np.ndarray):
            return X[:, self.selected_indices]
        elif hasattr(X, "iloc"):
            return X.iloc[:, self.selected_indices].to_numpy()
        else:
            return np.asarray(X)[:, self.selected_indices]
