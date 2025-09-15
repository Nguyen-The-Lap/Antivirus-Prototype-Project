"""
Machine Learning-based threat detection module.

This module provides ML-powered detection of malicious files and behaviors.
"""

import os
import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import joblib
import pefile
import lief
import hashlib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pandas as pd

from ..core.config import MLConfig
from ..utils.logger import get_logger
from ..utils.file_utils import FileUtils

logger = get_logger(__name__)

class ThreatDetector:
    """Machine Learning-based threat detection engine."""
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize the ML threat detector.
        
        Args:
            model_path: Path to a pre-trained model. If None, a new model will be created.
        """
        self.model = None
        self.feature_columns = None
        self.model_path = Path(model_path) if model_path else MLConfig.DEFAULT_MODEL_PATH
        self.scaler = None
        
        if self.model_path.exists():
            self.load_model()
        else:
            self._init_model()
    
    def _init_model(self) -> None:
        """Initialize a new ML model with default parameters."""
        self.model = RandomForestClassifier(
            n_estimators=MLConfig.N_ESTIMATORS,
            max_depth=MLConfig.MAX_DEPTH,
            random_state=MLConfig.RANDOM_STATE,
            n_jobs=-1,
            verbose=1
        )
        logger.info("Initialized new ML model with default parameters")
    
    def extract_features(self, file_path: Union[str, Path]) -> Dict[str, float]:
        """Extract features from a file for ML analysis.
        
        Args:
            file_path: Path to the file to analyze.
            
        Returns:
            Dictionary of extracted features.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        features = {
            'file_size': os.path.getsize(file_path),
            'entropy': self._calculate_entropy(file_path),
            'is_executable': FileUtils.is_pe_file(file_path),
            'num_sections': 0,
            'num_imports': 0,
            'num_exports': 0,
            'has_signature': False,
            'has_debug_info': False,
            'has_resources': False,
            'has_tls': False,
            'has_relocations': False
        }
        
        # PE-specific features
        if features['is_executable']:
            try:
                pe = pefile.PE(file_path, fast_load=True)
                features.update(self._extract_pe_features(pe))
            except Exception as e:
                logger.warning(f"Error extracting PE features from {file_path}: {e}")
        
        return features
    
    def _extract_pe_features(self, pe: pefile.PE) -> Dict[str, float]:
        """Extract features from a PE file.
        
        Args:
            pe: PE file object.
            
        Returns:
            Dictionary of PE-specific features.
        """
        features = {}
        
        # Basic PE features
        features['num_sections'] = len(pe.sections)
        features['has_debug_info'] = hasattr(pe, 'DIRECTORY_ENTRY_DEBUG')
        features['has_tls'] = hasattr(pe, 'DIRECTORY_ENTRY_TLS')
        features['has_relocations'] = hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC')
        
        # Import/Export features
        features['num_imports'] = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
        features['num_exports'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
        
        # Check digital signature
        features['has_signature'] = False
        try:
            if pe.verify_checksum() and hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                features['has_signature'] = True
        except:
            pass
            
        return features
    
    @staticmethod
    def _calculate_entropy(file_path: Union[str, Path], chunk_size: int = 8192) -> float:
        """Calculate the entropy of a file.
        
        Args:
            file_path: Path to the file.
            chunk_size: Size of chunks to read at a time.
            
        Returns:
            Entropy value (bits per byte).
        """
        byte_counts = [0] * 256
        total_bytes = 0
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                for byte in chunk:
                    byte_counts[byte] += 1
                total_bytes += len(chunk)
        
        if total_bytes == 0:
            return 0.0
            
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / total_bytes
                entropy -= p * (p.bit_length() - 1.0)
                
        return entropy
    
    def train(self, X, y) -> Dict[str, float]:
        """Train the ML model on the provided data.
        
        Args:
            X: Feature matrix.
            y: Target labels.
            
        Returns:
            Dictionary containing training metrics.
        """
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=MLConfig.TEST_SIZE,
            random_state=MLConfig.RANDOM_STATE,
            stratify=y
        )
        
        logger.info(f"Training model on {len(X_train)} samples")
        self.model.fit(X_train, y_train)
        
        # Evaluate on test set
        y_pred = self.model.predict(X_test)
        report = classification_report(y_test, y_pred, output_dict=True)
        
        logger.info(f"Model accuracy: {report['accuracy']:.4f}")
        return report
    
    def predict(self, features: Dict[str, float]) -> Tuple[float, float]:
        """Predict if a file is malicious.
        
        Args:
            features: Dictionary of file features.
            
        Returns:
            Tuple of (prediction, confidence) where:
            - prediction: 0 (benign) or 1 (malicious)
            - confidence: Probability score [0, 1]
        """
        if not self.model:
            raise RuntimeError("Model not loaded or trained")
            
        # Convert features to array in the correct order
        X = np.array([[features[col] for col in self.feature_columns]])
        
        # Make prediction
        proba = self.model.predict_proba(X)[0]
        prediction = self.model.predict(X)[0]
        confidence = max(proba)
        
        return int(prediction), float(confidence)
    
    def save_model(self, path: Optional[str] = None) -> None:
        """Save the trained model to disk.
        
        Args:
            path: Path to save the model. Uses instance path if None.
        """
        save_path = Path(path) if path else self.model_path
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        model_data = {
            'model': self.model,
            'feature_columns': self.feature_columns,
            'config': {
                'n_estimators': MLConfig.N_ESTIMATORS,
                'max_depth': MLConfig.MAX_DEPTH,
                'random_state': MLConfig.RANDOM_STATE
            }
        }
        
        joblib.dump(model_data, save_path)
        logger.info(f"Saved model to {save_path}")
    
    def load_model(self, path: Optional[str] = None) -> None:
        """Load a trained model from disk.
        
        Args:
            path: Path to the model file. Uses instance path if None.
        """
        load_path = Path(path) if path else self.model_path
        
        if not load_path.exists():
            raise FileNotFoundError(f"Model file not found: {load_path}")
            
        try:
            model_data = joblib.load(load_path)
            self.model = model_data['model']
            self.feature_columns = model_data['feature_columns']
            logger.info(f"Loaded model from {load_path}")
        except Exception as e:
            logger.error(f"Error loading model from {load_path}: {e}")
            raise
    
    def generate_training_data(self, benign_dir: str, malicious_dir: str) -> pd.DataFrame:
        """Generate training data from directories of benign and malicious files.
        
        Args:
            benign_dir: Directory containing benign files.
            malicious_dir: Directory containing malicious files.
            
        Returns:
            DataFrame containing features and labels.
        """
        data = []
        
        # Process benign files
        for file_path in Path(benign_dir).rglob('*'):
            if file_path.is_file():
                try:
                    features = self.extract_features(file_path)
                    features['label'] = 0  # 0 for benign
                    data.append(features)
                except Exception as e:
                    logger.warning(f"Error processing {file_path}: {e}")
        
        # Process malicious files
        for file_path in Path(malicious_dir).rglob('*'):
            if file_path.is_file():
                try:
                    features = self.extract_features(file_path)
                    features['label'] = 1  # 1 for malicious
                    data.append(features)
                except Exception as e:
                    logger.warning(f"Error processing {file_path}: {e}")
        
        # Convert to DataFrame
        df = pd.DataFrame(data)
        
        # Save feature columns for later use
        self.feature_columns = [col for col in df.columns if col != 'label']
        
        return df
    
    def train_from_directories(self, benign_dir: str, malicious_dir: str, 
                             test_size: float = 0.2) -> Dict[str, float]:
        """Train the model using files from directories.
        
        Args:
            benign_dir: Directory containing benign files.
            malicious_dir: Directory containing malicious files.
            test_size: Fraction of data to use for testing.
            
        Returns:
            Dictionary containing training metrics.
        """
        # Generate training data
        df = self.generate_training_data(benign_dir, malicious_dir)
        
        # Split into features and labels
        X = df[self.feature_columns]
        y = df['label']
        
        # Train the model
        return self.train(X, y)
