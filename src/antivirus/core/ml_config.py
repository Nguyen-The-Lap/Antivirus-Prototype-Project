"""
Machine Learning configuration settings.

This module contains configuration parameters for the ML-based threat detection.
"""

from enum import Enum
from pathlib import Path
from typing import Dict, List, Any
from ..core.config import DATA_DIR, CACHE_DIR


class ModelType(Enum):
    """Supported model types for the advanced threat detector."""
    RANDOM_FOREST = "random_forest"
    XGBOOST = "xgboost"
    LIGHTGBM = "lightgbm"
    VOTING = "voting"
    STACKING = "stacking"


class MLConfig:
    """Configuration for machine learning components."""
    
    # Model parameters
    MODEL_TYPE = ModelType.RANDOM_FOREST  # Default model type
    RANDOM_STATE = 42                    # Random seed for reproducibility
    TEST_SIZE = 0.2                      # Fraction of data to use for testing/validation
    
    # Model hyperparameters
    RANDOM_FOREST_PARAMS = {
        'n_estimators': 100,
        'max_depth': 10,
        'min_samples_split': 2,
        'min_samples_leaf': 1,
        'class_weight': 'balanced',
        'n_jobs': -1,
        'random_state': RANDOM_STATE
    }
    
    XGBOOST_PARAMS = {
        'n_estimators': 100,
        'max_depth': 6,
        'learning_rate': 0.1,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'use_label_encoder': False,
        'eval_metric': 'logloss',
        'random_state': RANDOM_STATE
    }
    
    LIGHTGBM_PARAMS = {
        'n_estimators': 100,
        'max_depth': -1,  # <0 means no limit
        'learning_rate': 0.1,
        'num_leaves': 31,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'random_state': RANDOM_STATE
    }
    
    # Paths
    MODELS_DIR = DATA_DIR / 'models'
    CACHE_DIR = CACHE_DIR / 'ml'
    MLFLOW_DIR = DATA_DIR / 'mlruns'
    MLFLOW_TRACKING_URI = f"file://{MLFLOW_DIR.absolute()}"
    
    # Model files
    DEFAULT_MODEL_PATH = MODELS_DIR / 'threat_detector.joblib'
    SCALER_PATH = MODELS_DIR / 'feature_scaler.joblib'
    FEATURE_NAMES_PATH = MODELS_DIR / 'feature_names.json'
    
    # Feature configuration
    NUMERIC_FEATURES = [
        # File statistics
        'file_size',
        'file_size_log',
        'entropy',
        'byte_mean',
        'byte_std',
        'byte_median',
        'byte_skew',
        'byte_kurtosis',
        'printable_ratio',
        'null_byte_ratio',
        
        # PE header features
        'num_sections',
        'num_imports',
        'num_exports',
        'num_relocations',
        'num_debug_entries',
        'num_imported_dlls',
        'num_suspicious_imports',
        
        # Section statistics
        'section_entropy_min',
        'section_entropy_max',
        'section_entropy_avg',
        'section_size_total',
        'section_size_avg',
        'section_virtual_size_total',
        'section_virtual_size_avg',
        'num_executable_sections',
        'num_writable_sections',
        'num_readable_sections',
        'num_shared_sections',
        
        # Optional header features
        'image_base',
        'size_of_code',
        'size_of_headers',
        'size_of_image',
        'size_of_heap_commit',
        'size_of_stack_commit',
    ]
    
    BOOLEAN_FEATURES = [
        # File type flags
        'is_pe',
        'is_dll',
        'is_exe',
        'is_driver',
        'has_dos_signature',
        'high_entropy',
        
        # PE characteristics
        'has_resources',
        'has_debug',
        'has_relocations',
        'has_tls',
        'has_config',
        'has_imports',
        'has_exports',
        'has_exceptions',
        'has_security',
        'has_load_config',
        'has_bound_imports',
        'has_delay_imports',
        'has_clr',
    ]
    
    # Feature groups for analysis
    FEATURE_GROUPS = {
        'file_stats': ['file_size', 'entropy', 'printable_ratio', 'null_byte_ratio'],
        'pe_header': ['num_sections', 'num_imports', 'num_exports', 'num_relocations'],
        'sections': ['section_entropy_avg', 'section_size_avg', 'num_executable_sections', 'num_writable_sections'],
        'imports': ['num_imported_dlls', 'num_suspicious_imports'],
        'characteristics': ['is_pe', 'is_dll', 'is_exe', 'is_driver']
    }
    
    # Training parameters
    MIN_SAMPLES_PER_CLASS = 100  # Minimum samples required per class for training
    CLASS_WEIGHTS = {0: 1.0, 1: 2.0}  # Higher weight for malicious samples
    EARLY_STOPPING_ROUNDS = 10  # For models that support early stopping
    N_JOBS = -1  # Use all available CPU cores
    
    # Cross-validation
    CV_FOLDS = 5
    CV_SCORING = 'roc_auc'
    
    # Model evaluation
    METRICS = [
        'accuracy',
        'precision',
        'recall',
        'f1',
        'roc_auc',
        'average_precision',
        'log_loss'
    ]
    
    # Feature importance
    TOP_FEATURES = 20  # Number of top features to display
    
    # Threshold for classification
    DEFAULT_THRESHOLD = 0.7
    
    # MLflow experiment name
    MLFLOW_EXPERIMENT_NAME = 'malware_detection'
    
    @classmethod
    def ensure_directories_exist(cls) -> None:
        """Ensure all required directories exist."""
        cls.MODELS_DIR.mkdir(parents=True, exist_ok=True)
        cls.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cls.MLFLOW_DIR.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def get_model_params(cls, model_type: ModelType = None) -> Dict[str, Any]:
        """Get parameters for the specified model type.
        
        Args:
            model_type: Type of model to get parameters for.
            
        Returns:
            Dictionary of model parameters.
        """
        model_type = model_type or cls.MODEL_TYPE
        
        if model_type == ModelType.RANDOM_FOREST:
            return cls.RANDOM_FOREST_PARAMS
        elif model_type == ModelType.XGBOOST:
            return cls.XGBOOST_PARAMS
        elif model_type == ModelType.LIGHTGBM:
            return cls.LIGHTGBM_PARAMS
        else:
            return {}
    
    @classmethod
    def get_all_features(cls) -> List[str]:
        """Get all feature names."""
        return cls.NUMERIC_FEATURES + cls.BOOLEAN_FEATURES
