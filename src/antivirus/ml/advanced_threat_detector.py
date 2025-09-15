"""
Advanced threat detection using machine learning.

This module provides enhanced ML-based threat detection with support for multiple algorithms,
ensembles, and advanced feature extraction.
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Type

import joblib
import lief
import numpy as np
import pandas as pd
from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier,
    VotingClassifier,
    StackingClassifier,
)
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    average_precision_score,
    f1_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import xgboost as xgb
import lightgbm as lgb
import mlflow

from ..core.config import MLConfig
from ..utils.logger import get_logger

logger = get_logger(__name__)


class ModelType(Enum):
    """Supported model types."""
    RANDOM_FOREST = "random_forest"
    XGBOOST = "xgboost"
    LIGHTGBM = "lightgbm"
    VOTING = "voting"
    STACKING = "stacking"


class BaseModel(ABC, BaseEstimator, ClassifierMixin):
    """Base class for all ML models."""
    
    @abstractmethod
    def fit(self, X, y):
        """Train the model."""
        pass
    
    @abstractmethod
    def predict(self, X):
        """Make predictions."""
        pass
    
    @abstractmethod
    def predict_proba(self, X):
        """Predict probabilities."""
        pass
    
    @abstractmethod
    def get_feature_importances(self, feature_names=None):
        """Get feature importances."""
        pass


class RandomForestModel(BaseModel):
    """Random Forest classifier with enhanced features."""
    
    def __init__(self, n_estimators=100, max_depth=None, random_state=42, **kwargs):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,
            **kwargs
        )
    
    def fit(self, X, y, **fit_params):
        self.model.fit(X, y, **fit_params)
        return self
    
    def predict(self, X):
        return self.model.predict(X)
    
    def predict_proba(self, X):
        return self.model.predict_proba(X)
    
    def get_feature_importances(self, feature_names=None):
        if hasattr(self.model, 'feature_importances_'):
            return dict(zip(feature_names or range(len(self.model.feature_importances_)), 
                          self.model.feature_importances_))
        return {}


class XGBoostModel(BaseModel):
    """XGBoost classifier with early stopping."""
    
    def __init__(self, n_estimators=100, max_depth=6, learning_rate=0.1, 
                 early_stopping_rounds=10, random_state=42, **kwargs):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.early_stopping_rounds = early_stopping_rounds
        self.random_state = random_state
        self.model = xgb.XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            random_state=random_state,
            n_jobs=-1,
            **kwargs
        )
        self.eval_set = None
    
    def fit(self, X, y, eval_set=None, **fit_params):
        self.eval_set = eval_set
        if eval_set:
            self.model.fit(
                X, y,
                eval_set=eval_set,
                early_stopping_rounds=self.early_stopping_rounds,
                verbose=False,
                **fit_params
            )
        else:
            self.model.fit(X, y, **fit_params)
        return self
    
    def predict(self, X):
        return self.model.predict(X)
    
    def predict_proba(self, X):
        return self.model.predict_proba(X)
    
    def get_feature_importances(self, feature_names=None):
        if hasattr(self.model, 'feature_importances_'):
            return dict(zip(feature_names or self.model.booster().feature_names,
                          self.model.feature_importances_))
        return {}


class LightGBMModel(BaseModel):
    """LightGBM classifier with early stopping."""
    
    def __init__(self, n_estimators=100, max_depth=-1, learning_rate=0.1, 
                 num_leaves=31, early_stopping_rounds=10, random_state=42, **kwargs):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.num_leaves = num_leaves
        self.early_stopping_rounds = early_stopping_rounds
        self.random_state = random_state
        self.model = lgb.LGBMClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            num_leaves=num_leaves,
            random_state=random_state,
            n_jobs=-1,
            **kwargs
        )
        self.eval_set = None
    
    def fit(self, X, y, eval_set=None, **fit_params):
        self.eval_set = eval_set
        if eval_set:
            self.model.fit(
                X, y,
                eval_set=eval_set,
                early_stopping_rounds=self.early_stopping_rounds,
                verbose=False,
                **fit_params
            )
        else:
            self.model.fit(X, y, **fit_params)
        return self
    
    def predict(self, X):
        return self.model.predict(X)
    
    def predict_proba(self, X):
        return self.model.predict_proba(X)
    
    def get_feature_importances(self, feature_names=None):
        if hasattr(self.model, 'feature_importances_'):
            return dict(zip(feature_names or range(len(self.model.feature_importances_)), 
                          self.model.feature_importances_))
        return {}


class AdvancedThreatDetector:
    """Advanced threat detector with support for multiple ML models and ensembling."""

    def __init__(
        self,
        model_type: Union[str, ModelType] = ModelType.RANDOM_FOREST,
        model_path: Optional[Union[str, Path]] = None,
        features: Optional[List[str]] = None,
        threshold: float = 0.7,
        **model_kwargs,
    ) -> None:
        """Initialize the advanced threat detector.

        Args:
            model_type: Type of model to use (random_forest, xgboost, lightgbm, voting, stacking).
            model_path: Path to a pre-trained model file.
            features: List of feature names used by the model.
            threshold: Confidence threshold for classification.
            **model_kwargs: Additional arguments for the model.
        """
        self.model = None
        self.model_type = ModelType(model_type) if isinstance(model_type, str) else model_type
        self.features = features or MLConfig.FEATURES
        self.threshold = threshold
        self.model_metadata = {}
        self.scaler = StandardScaler()
        self.model_kwargs = model_kwargs
        
        # Initialize MLflow if not already initialized
        mlflow.set_tracking_uri(MLConfig.MLFLOW_TRACKING_URI)
        
        if model_path:
            self.load_model(model_path)
        else:
            self._init_model()
    
    def _init_model(self):
        """Initialize the model based on model_type."""
        if self.model_type == ModelType.RANDOM_FOREST:
            self.model = RandomForestModel(**self.model_kwargs)
        elif self.model_type == ModelType.XGBOOST:
            self.model = XGBoostModel(**self.model_kwargs)
        elif self.model_type == ModelType.LIGHTGBM:
            self.model = LightGBMModel(**self.model_kwargs)
        elif self.model_type in (ModelType.VOTING, ModelType.STACKING):
            self._init_ensemble_model()
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
    
    def _init_ensemble_model(self):
        """Initialize an ensemble model (voting or stacking)."""
        estimators = [
            ('rf', RandomForestModel(n_estimators=100, random_state=42)),
            ('xgb', XGBoostModel(n_estimators=100, random_state=42)),
            ('lgbm', LightGBMModel(n_estimators=100, random_state=42))
        ]
        
        if self.model_type == ModelType.VOTING:
            self.model = VotingClassifier(estimators=estimators, voting='soft')
        else:  # Stacking
            self.model = StackingClassifier(
                estimators=estimators,
                final_estimator=RandomForestModel(n_estimators=50, random_state=42)
            )

    def load_model(self, model_path: Union[str, Path]) -> None:
        """Load a trained model from disk.

        Args:
            model_path: Path to the model file.
        """
        try:
            model_path = Path(model_path)
            if not model_path.exists():
                raise FileNotFoundError(f"Model file not found: {model_path}")

            # Load the model and metadata
            model_data = joblib.load(model_path)
            self.model = model_data["model"]
            self.features = model_data.get("features", self.features)
            self.threshold = model_data.get("threshold", self.threshold)
            self.model_metadata = model_data.get("metadata", {})
            self.model_type = ModelType(model_data.get("model_type", "random_forest"))
            self.scaler = model_data.get("scaler", StandardScaler())

            logger.info(
                f"Loaded {self.model_type.value} model from {model_path} with {len(self.features)} features"
            )

        except Exception as e:
            logger.error(f"Error loading model from {model_path}: {e}")
            raise

    def save_model(self, output_path: Union[str, Path]) -> None:
        """Save the model to disk.

        Args:
            output_path: Path to save the model file.
        """
        try:
            if not self.model:
                raise ValueError("No model to save. Train a model first.")

            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            model_data = {
                "model": self.model,
                "features": self.features,
                "threshold": self.threshold,
                "metadata": self.model_metadata,
                "model_type": self.model_type.value,
                "scaler": self.scaler,
            }

            joblib.dump(model_data, output_path)
            logger.info(f"Model saved to {output_path}")

        except Exception as e:
            logger.error(f"Error saving model to {output_path}: {e}")
            raise

    def extract_features(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Extract features from a file for prediction.

        Args:
            file_path: Path to the file to extract features from.

        Returns:
            Dictionary of extracted features.
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            features = {
                "file_size": file_path.stat().st_size,
                "is_pe": 0,
                "is_dll": 0,
                "is_exe": 0,
                "is_driver": 0,
                "has_certificate": 0,
                "has_debug": 0,
                "has_resources": 0,
                "has_relocations": 0,
                "has_tls": 0,
                "has_config": 0,
                "has_imports": 0,
                "has_exports": 0,
                "has_resources": 0,
                "has_exceptions": 0,
                "has_security": 0,
                "has_load_config": 0,
                "has_bound_imports": 0,
                "has_delay_imports": 0,
                "has_clr": 0,
            }

            # Try to parse as PE file
            try:
                binary = lief.parse(str(file_path))
                if binary:
                    features.update(self._extract_pe_features(binary))
                    features["is_pe"] = 1
                    
                    # Set file type flags
                    if binary.header.has_dos_signature:
                        features["has_dos_signature"] = 1
                    
                    if binary.has_resources:
                        features["has_resources"] = 1
                    
                    if binary.has_debug:
                        features["has_debug"] = 1
                    
                    if binary.has_relocations:
                        features["has_relocations"] = 1
                    
                    if binary.has_tls:
                        features["has_tls"] = 1
                    
                    if binary.has_configuration:
                        features["has_config"] = 1
                    
                    if binary.has_imports:
                        features["has_imports"] = 1
                    
                    if binary.has_exports:
                        features["has_exports"] = 1
                    
                    if binary.has_exceptions:
                        features["has_exceptions"] = 1
                    
                    if binary.has_security:
                        features["has_security"] = 1
                    
                    if binary.has_load_config:
                        features["has_load_config"] = 1
                    
                    if binary.has_bound_imports:
                        features["has_bound_imports"] = 1
                    
                    if binary.has_delay_imports:
                        features["has_delay_imports"] = 1
                    
                    if binary.has_clr:
                        features["has_clr"] = 1
                    
                    # Set file type
                    if binary.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.DLL):
                        features["is_dll"] = 1
                    elif binary.header.has_characteristic(lief.PE.HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE):
                        features["is_exe"] = 1
                    
                    # Check if it's a driver
                    if any(subsystem in [lief.PE.SUBSYSTEM.NATIVE, lief.PE.SUBSYSTEM.NATIVE_WINDOWS] 
                          for subsystem in binary.optional_header.subsystem):
                        features["is_driver"] = 1
                        
            except Exception as e:
                logger.debug(f"Error parsing PE file {file_path}: {e}")

            # Add entropy and other statistical features
            features.update(self._calculate_statistical_features(file_path))

            return {k: features.get(k, 0) for k in self.features}

        except Exception as e:
            logger.error(f"Error extracting features from {file_path}: {e}")
            raise

    def _extract_pe_features(self, binary: lief.Binary) -> Dict[str, Any]:
        """Extract features from a PE file.

        Args:
            binary: Parsed PE file using LIEF.

        Returns:
            Dictionary of PE-specific features.
        """
        features = {}

        # Basic header information
        header = binary.header
        features["num_sections"] = len(binary.sections)
        features["num_imports"] = len(binary.imports) if hasattr(binary, "imports") else 0
        features["num_exports"] = len(binary.exported_functions) if hasattr(binary, "exported_functions") else 0
        features["num_relocations"] = len(binary.relocations) if hasattr(binary, "relocations") else 0
        features["num_debug_entries"] = len(binary.debug) if hasattr(binary, "debug") else 0
        features["num_resources"] = len(binary.resources_manager.entries) if hasattr(binary, "resources_manager") else 0
        
        # Optional header features
        if hasattr(binary, "optional_header"):
            optional_header = binary.optional_header
            features["image_base"] = optional_header.imagebase
            features["size_of_code"] = optional_header.sizeof_code
            features["size_of_headers"] = optional_header.sizeof_headers
            features["size_of_image"] = optional_header.sizeof_image
            features["size_of_heap_commit"] = optional_header.sizeof_heap_commit
            features["size_of_stack_commit"] = optional_header.sizeof_stack_commit
            features["dll_characteristics"] = optional_header.dll_characteristics
            features["subsystem"] = optional_header.subsystem
        
        # Section characteristics
        section_entropies = []
        section_sizes = []
        section_virtual_sizes = []
        section_executable = []
        section_writable = []
        section_readable = []
        section_shared = []
        
        for section in binary.sections:
            section_entropies.append(section.entropy)
            section_sizes.append(section.size)
            section_virtual_sizes.append(section.virtual_size)
            section_executable.append(int(section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)))
            section_writable.append(int(section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE)))
            section_readable.append(int(section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_READ)))
            section_shared.append(int(section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_SHARED)))
        
        # Add section statistics
        if section_entropies:
            features.update({
                "section_entropy_min": min(section_entropies),
                "section_entropy_max": max(section_entropies),
                "section_entropy_avg": sum(section_entropies) / len(section_entropies),
                "section_size_total": sum(section_sizes),
                "section_size_avg": sum(section_sizes) / len(section_sizes),
                "section_virtual_size_total": sum(section_virtual_sizes),
                "section_virtual_size_avg": sum(section_virtual_sizes) / len(section_virtual_sizes),
                "num_executable_sections": sum(section_executable),
                "num_writable_sections": sum(section_writable),
                "num_readable_sections": sum(section_readable),
                "num_shared_sections": sum(section_shared),
            })
        
        # Import/Export features
        if hasattr(binary, "imports") and binary.imports:
            imports = [imp.name for imp in binary.imports if hasattr(imp, 'name') and imp.name]
            features["num_imports"] = len(imports)
            features["num_imported_dlls"] = len(set(imp.split(".")[0].lower() for imp in imports if "." in imp))
            
            # Count suspicious imports
            suspicious_imports = [
                'LoadLibrary', 'GetProcAddress', 'VirtualAlloc', 'VirtualProtect',
                'CreateRemoteThread', 'WriteProcessMemory', 'ReadProcessMemory',
                'OpenProcess', 'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next'
            ]
            features["num_suspicious_imports"] = sum(1 for imp in imports if any(susp in imp for susp in suspicious_imports))
        
        # Resource features
        if hasattr(binary, "resources_manager") and binary.resources_manager.has_configuration:
            features["has_config"] = 1
        
        return features

    def _calculate_statistical_features(self, file_path: Path, chunk_size: int = 4096) -> Dict[str, float]:
        """Calculate statistical features from file content.
        
        Args:
            file_path: Path to the file.
            chunk_size: Size of chunks to read from the file.
            
        Returns:
            Dictionary of statistical features.
        """
        features = {}
        
        try:
            # File size features
            file_size = file_path.stat().st_size
            features["file_size"] = file_size
            features["file_size_log"] = np.log1p(file_size) if file_size > 0 else 0
            
            # Read file in chunks to handle large files
            byte_counts = [0] * 256
            total_bytes = 0
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    for byte in chunk:
                        byte_counts[byte] += 1
                    total_bytes += len(chunk)
            
            if total_bytes > 0:
                # Byte value distribution
                byte_freq = np.array(byte_counts) / total_bytes
                
                # Entropy
                entropy = -np.sum([p * np.log2(p) for p in byte_freq if p > 0])
                features["entropy"] = entropy
                
                # Byte value statistics
                byte_values = np.array(byte_counts)
                features.update({
                    "byte_mean": np.mean(byte_values),
                    "byte_std": np.std(byte_values),
                    "byte_min": np.min(byte_values),
                    "byte_max": np.max(byte_values),
                    "byte_median": np.median(byte_values),
                    "byte_skew": float(pd.Series(byte_values).skew()),
                    "byte_kurtosis": float(pd.Series(byte_values).kurtosis()),
                })
                
                # Printable characters ratio
                printable = sum(byte_counts[32:127])  # ASCII 32-126 are printable
                features["printable_ratio"] = printable / total_bytes if total_bytes > 0 else 0
                
                # Null bytes ratio
                null_ratio = byte_counts[0] / total_bytes if total_bytes > 0 else 0
                features["null_byte_ratio"] = null_ratio
                
                # High entropy flag
                features["high_entropy"] = 1 if entropy > 7.0 else 0
                
        except Exception as e:
            logger.warning(f"Error calculating statistical features for {file_path}: {e}")
        
        return features

    def _calculate_entropy(self, file_path: Path, chunk_size: int = 4096) -> float:
        """Calculate the entropy of a file.

        Args:
            file_path: Path to the file.
            chunk_size: Size of chunks to read from the file.

        Returns:
            Entropy value.
        """
        try:
            import math
            from collections import Counter

            counts = Counter()
            total = 0

            with open(file_path, "rb") as f:
                while chunk := f.read(chunk_size):
                    counts.update(chunk)
                    total += len(chunk)

            if not total:
                return 0.0

            entropy = 0.0
            for count in counts.values():
                p_x = count / total
                entropy += -p_x * math.log2(p_x)

            return entropy

        except Exception as e:
            logger.warning(f"Error calculating entropy for {file_path}: {e}")
            return 0.0

    def predict_proba(
        self, features: Union[Dict[str, Any], pd.DataFrame]
    ) -> Tuple[float, float]:
        """Predict the probability of a file being malicious.

        Args:
            features: Dictionary or DataFrame of features.

        Returns:
            Tuple of (probability_benign, probability_malicious)
        """
        if not self.model:
            raise ValueError("No model loaded. Load or train a model first.")

        try:
            # Convert features to DataFrame if it's a dictionary
            if isinstance(features, dict):
                features_df = pd.DataFrame([features])
            else:
                features_df = features.copy()

            # Ensure all required features are present
            for feature in self.features:
                if feature not in features_df.columns:
                    features_df[feature] = 0

            # Reorder columns to match training
            features_df = features_df[self.features]
            
            # Scale features if scaler is available
            if hasattr(self, 'scaler') and self.scaler is not None:
                try:
                    features_df = pd.DataFrame(
                        self.scaler.transform(features_df),
                        columns=features_df.columns
                    )
                except Exception as e:
                    logger.warning(f"Error scaling features: {e}")

            # Predict probabilities
            proba = self.model.predict_proba(features_df)[0]
            return float(proba[0]), float(proba[1])

        except Exception as e:
            logger.error(f"Error making prediction: {e}")
            raise

    def predict(
        self, features: Union[Dict[str, Any], pd.DataFrame], threshold: Optional[float] = None
    ) -> Tuple[bool, float]:
        """Predict if a file is malicious.

        Args:
            features: Dictionary or DataFrame of features.
            threshold: Custom threshold for classification.

        Returns:
            Tuple of (is_malicious, confidence)
        """
        threshold = threshold or self.threshold
        prob_benign, prob_malicious = self.predict_proba(features)
        is_malicious = prob_malicious >= threshold
        confidence = prob_malicious if is_malicious else prob_benign
        return is_malicious, confidence

    def train(
        self,
        X: Union[pd.DataFrame, np.ndarray],
        y: Union[pd.Series, np.ndarray],
        test_size: float = 0.2,
        random_state: int = 42,
        use_mlflow: bool = True,
        experiment_name: str = "malware_detection",
        **kwargs,
    ) -> Dict[str, Any]:
        """Train a new model with cross-validation and logging.

        Args:
            X: Feature matrix.
            y: Target labels.
            test_size: Fraction of data to use for testing.
            random_state: Random seed for reproducibility.
            use_mlflow: Whether to log metrics to MLflow.
            experiment_name: Name of the MLflow experiment.
            **kwargs: Additional arguments for the model.

        Returns:
            Dictionary with training results and metrics.
        """
        try:
            # Set up MLflow
            if use_mlflow:
                mlflow.set_experiment(experiment_name)
                mlflow.start_run()
                mlflow.log_params({
                    "model_type": self.model_type.value,
                    "test_size": test_size,
                    "random_state": random_state,
                    **self.model_kwargs
                })
            
            # Split the data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )
            
            # Scale features
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Initialize and train the model
            if not self.model:
                self._init_model()
            
            # Train with early stopping if supported
            eval_set = None
            if hasattr(self.model, 'fit') and hasattr(self.model, 'set_params'):
                if hasattr(self.model, 'early_stopping_rounds') and self.model.early_stopping_rounds:
                    eval_set = [(X_test_scaled, y_test)]
                
                self.model.fit(X_train_scaled, y_train, eval_set=eval_set)
            
            # Make predictions
            y_pred = self.model.predict(X_test_scaled)
            y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            roc_auc = roc_auc_score(y_test, y_pred_proba)
            precision, recall, _ = precision_recall_curve(y_test, y_pred_proba)
            avg_precision = average_precision_score(y_test, y_pred_proba)
            f1 = f1_score(y_test, y_pred)
            
            # Cross-validation
            cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)
            cv_scores = cross_val_score(
                self.model, X_train_scaled, y_train, 
                cv=cv, scoring='roc_auc', n_jobs=-1
            )
            
            # Store metrics
            metrics = {
                "accuracy": accuracy,
                "roc_auc": roc_auc,
                "avg_precision": avg_precision,
                "f1_score": f1,
                "cv_mean_auc": np.mean(cv_scores),
                "cv_std_auc": np.std(cv_scores),
                "precision_recall_curve": {
                    "precision": precision.tolist(),
                    "recall": recall.tolist(),
                },
                "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
                "classification_report": classification_report(y_test, y_pred, output_dict=True),
            }
            
            # Log to MLflow
            if use_mlflow:
                mlflow.log_metrics({
                    "accuracy": accuracy,
                    "roc_auc": roc_auc,
                    "avg_precision": avg_precision,
                    "f1_score": f1,
                    "cv_mean_auc": np.mean(cv_scores),
                    "cv_std_auc": np.std(cv_scores),
                })
                
                # Log feature importances if available
                try:
                    importances = self.model.get_feature_importances(feature_names=self.features)
                    if importances:
                        # Log top 20 features
                        top_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:20]
                        for i, (feat, imp) in enumerate(top_features, 1):
                            mlflow.log_metric(f"feature_importance_{i}_{feat}", imp)
                except Exception as e:
                    logger.warning(f"Could not log feature importances: {e}")
                
                # Log model
                mlflow.sklearn.log_model(self.model, "model")
                
                # Log artifacts
                import tempfile
                import matplotlib.pyplot as plt
                
                # Plot ROC curve
                fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
                plt.figure(figsize=(10, 8))
                plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {roc_auc:.4f})')
                plt.plot([0, 1], [0, 1], 'k--')
                plt.xlabel('False Positive Rate')
                plt.ylabel('True Positive Rate')
                plt.title('ROC Curve')
                plt.legend(loc='lower right')
                
                # Save ROC curve
                with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
                    plt.savefig(f.name, bbox_inches='tight')
                    mlflow.log_artifact(f.name, "plots")
                plt.close()
                
                # End MLflow run
                mlflow.end_run()
            
            # Store model metadata
            self.model_metadata.update({
                "training_date": str(pd.Timestamp.now()),
                "num_samples": len(X),
                "num_features": X.shape[1],
                "test_size": test_size,
                "random_state": random_state,
                "model_type": self.model_type.value,
                "model_params": self.model_kwargs,
                "metrics": metrics,
                "feature_importances": self.model.get_feature_importances(feature_names=self.features) 
                                      if hasattr(self.model, 'get_feature_importances') else {},
            })

            return metrics

        except Exception as e:
            logger.error(f"Error training model: {e}")
            if use_mlflow and 'mlflow' in locals():
                mlflow.end_run(status="FAILED")
            raise

    def evaluate(self, X: Union[pd.DataFrame, np.ndarray], y: Union[pd.Series, np.ndarray]) -> Dict[str, Any]:
        """Evaluate the model on a test set.

        Args:
            X: Feature matrix.
            y: True labels.

        Returns:
            Dictionary with evaluation metrics.
        """
        if not self.model:
            raise ValueError("No model loaded. Load or train a model first.")

        try:
            # Scale features
            X_scaled = self.scaler.transform(X) if hasattr(self, 'scaler') and self.scaler is not None else X
            
            # Make predictions
            y_pred = self.model.predict(X_scaled)
            y_pred_proba = self.model.predict_proba(X_scaled)[:, 1]
            
            # Calculate metrics
            accuracy = accuracy_score(y, y_pred)
            roc_auc = roc_auc_score(y, y_pred_proba)
            precision, recall, _ = precision_recall_curve(y, y_pred_proba)
            avg_precision = average_precision_score(y, y_pred_proba)
            f1 = f1_score(y, y_pred)
            
            return {
                "accuracy": accuracy,
                "roc_auc": roc_auc,
                "avg_precision": avg_precision,
                "f1_score": f1,
                "precision_recall_curve": {
                    "precision": precision.tolist(),
                    "recall": recall.tolist(),
                },
                "confusion_matrix": confusion_matrix(y, y_pred).tolist(),
                "classification_report": classification_report(y, y_pred, output_dict=True),
            }

        except Exception as e:
            logger.error(f"Error evaluating model: {e}")
            raise
