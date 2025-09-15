"""
Machine Learning configuration settings.

This module contains configuration parameters for the ML-based threat detection.
"""

from pathlib import Path
from ..core.config import DATA_DIR

class MLConfig:
    """Configuration for machine learning components."""
    
    # Model parameters
    N_ESTIMATORS = 100        # Number of trees in the random forest
    MAX_DEPTH = 10            # Maximum depth of each tree
    RANDOM_STATE = 42         # Random seed for reproducibility
    TEST_SIZE = 0.2           # Fraction of data to use for testing
    
    # Paths
    MODELS_DIR = DATA_DIR / 'models'
    DEFAULT_MODEL_PATH = MODELS_DIR / 'threat_detector.joblib'
    
    # Feature configuration
    NUMERIC_FEATURES = [
        'file_size',
        'entropy',
        'num_sections',
        'num_imports',
        'num_exports'
    ]
    
    BOOLEAN_FEATURES = [
        'is_executable',
        'has_signature',
        'has_debug_info',
        'has_resources',
        'has_tls',
        'has_relocations'
    ]
    
    # Training parameters
    MIN_SAMPLES_PER_CLASS = 100  # Minimum samples required per class for training
    CLASS_WEIGHTS = {0: 1.0, 1: 2.0}  # Higher weight for malicious samples
    
    # Model evaluation
    METRICS = [
        'accuracy',
        'precision',
        'recall',
        'f1',
        'roc_auc'
    ]
    
    # Feature importance
    TOP_FEATURES = 10  # Number of top features to display
    
    @classmethod
    def ensure_directories_exist(cls) -> None:
        """Ensure all required directories exist."""
        cls.MODELS_DIR.mkdir(parents=True, exist_ok=True)
