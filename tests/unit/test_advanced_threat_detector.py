"""
Unit tests for the AdvancedThreatDetector class.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import numpy as np
import pandas as pd
from sklearn.datasets import make_classification

from src.antivirus.ml.advanced_threat_detector import (
    AdvancedThreatDetector,
    ModelType,
    RandomForestModel,
    XGBoostModel,
    LightGBMModel,
)


class TestBaseModel(unittest.TestCase):
    """Test the base model functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.X, self.y = make_classification(
            n_samples=100, n_features=20, n_classes=2, random_state=42
        )
        self.feature_names = [f"feature_{i}" for i in range(self.X.shape[1])]
    
    def test_random_forest_model(self):
        """Test RandomForestModel training and prediction."""
        model = RandomForestModel(n_estimators=10, random_state=42)
        model.fit(self.X, self.y)
        
        # Test prediction
        y_pred = model.predict(self.X[:5])
        self.assertEqual(y_pred.shape, (5,))
        
        # Test predict_proba
        y_proba = model.predict_proba(self.X[:5])
        self.assertEqual(y_proba.shape, (5, 2))
        
        # Test feature importances
        importances = model.get_feature_importances(self.feature_names)
        self.assertEqual(len(importances), len(self.feature_names))
    
    def test_xgboost_model(self):
        """Test XGBoostModel training and prediction."""
        model = XGBoostModel(n_estimators=10, random_state=42)
        model.fit(self.X, self.y)
        
        # Test prediction
        y_pred = model.predict(self.X[:5])
        self.assertEqual(y_pred.shape, (5,))
        
        # Test predict_proba
        y_proba = model.predict_proba(self.X[:5])
        self.assertEqual(y_proba.shape, (5, 2))
    
    def test_lightgbm_model(self):
        """Test LightGBMModel training and prediction."""
        model = LightGBMModel(n_estimators=10, random_state=42)
        model.fit(self.X, self.y)
        
        # Test prediction
        y_pred = model.predict(self.X[:5])
        self.assertEqual(y_pred.shape, (5,))
        
        # Test predict_proba
        y_proba = model.predict_proba(self.X[:5])
        self.assertEqual(y_proba.shape, (5, 2))


class TestAdvancedThreatDetector(unittest.TestCase):
    """Test the AdvancedThreatDetector class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = Path(self.temp_dir.name) / "test_file.bin"
        
        # Create a test file
        with open(self.test_file, 'wb') as f:
            f.write(os.urandom(1024))  # 1KB random data
        
        # Create test data
        self.X, self.y = make_classification(
            n_samples=100, n_features=20, n_classes=2, random_state=42
        )
        self.feature_names = [f"feature_{i}" for i in range(self.X.shape[1])]
        self.X_df = pd.DataFrame(self.X, columns=self.feature_names)
    
    def tearDown(self):
        """Clean up after tests."""
        self.temp_dir.cleanup()
    
    def test_init_default(self):
        """Test initialization with default parameters."""
        detector = AdvancedThreatDetector()
        self.assertIsNotNone(detector.model)
        self.assertEqual(detector.model_type, ModelType.RANDOM_FOREST)
    
    def test_init_xgboost(self):
        """Test initialization with XGBoost model."""
        detector = AdvancedThreatDetector(model_type=ModelType.XGBOOST)
        self.assertEqual(detector.model_type, ModelType.XGBOOST)
    
    def test_init_lightgbm(self):
        """Test initialization with LightGBM model."""
        detector = AdvancedThreatDetector(model_type=ModelType.LIGHTGBM)
        self.assertEqual(detector.model_type, ModelType.LIGHTGBM)
    
    def test_extract_features(self):
        """Test feature extraction from a file."""
        detector = AdvancedThreatDetector()
        features = detector.extract_features(self.test_file)
        
        # Check that expected features are present
        self.assertIn("file_size", features)
        self.assertIn("entropy", features)
        self.assertIn("is_pe", features)
    
    @patch('mlflow.start_run')
    @patch('mlflow.log_params')
    @patch('mlflow.log_metrics')
    @patch('mlflow.sklearn.log_model')
    @patch('mlflow.end_run')
    def test_train(self, mock_end_run, mock_log_model, mock_log_metrics, 
                  mock_log_params, mock_start_run):
        """Test model training."""
        detector = AdvancedThreatDetector(
            model_type=ModelType.RANDOM_FOREST,
            n_estimators=10,
            random_state=42
        )
        
        # Train the model
        metrics = detector.train(
            self.X_df,
            self.y,
            test_size=0.2,
            random_state=42,
            use_mlflow=False  # Disable MLflow for testing
        )
        
        # Check that metrics were returned
        self.assertIn("accuracy", metrics)
        self.assertIn("roc_auc", metrics)
        self.assertIn("f1_score", metrics)
        
        # Check that model was trained
        self.assertIsNotNone(detector.model)
    
    def test_predict(self):
        """Test prediction."""
        # Train a simple model
        detector = AdvancedThreatDetector(
            model_type=ModelType.RANDOM_FOREST,
            n_estimators=10,
            random_state=42
        )
        detector.train(
            self.X_df,
            self.y,
            test_size=0.2,
            random_state=42,
            use_mlflow=False
        )
        
        # Make predictions
        is_malicious, confidence = detector.predict(self.X_df.iloc[0].to_dict())
        
        # Check that predictions are valid
        self.assertIsInstance(is_malicious, bool)
        self.assertGreaterEqual(confidence, 0.0)
        self.assertLessEqual(confidence, 1.0)
    
    def test_save_load_model(self):
        """Test saving and loading a model."""
        # Create and train a model
        detector = AdvancedThreatDetector(
            model_type=ModelType.RANDOM_FOREST,
            n_estimators=10,
            random_state=42
        )
        detector.train(
            self.X_df,
            self.y,
            test_size=0.2,
            random_state=42,
            use_mlflow=False
        )
        
        # Save the model
        model_path = Path(self.temp_dir.name) / "test_model.joblib"
        detector.save_model(model_path)
        
        # Load the model
        loaded_detector = AdvancedThreatDetector(model_path=model_path)
        
        # Check that the loaded model works
        is_malicious, confidence = loaded_detector.predict(self.X_df.iloc[0].to_dict())
        self.assertIsInstance(is_malicious, bool)
        self.assertGreaterEqual(confidence, 0.0)
    
    def test_evaluate(self):
        """Test model evaluation."""
        # Train a simple model
        detector = AdvancedThreatDetector(
            model_type=ModelType.RANDOM_FOREST,
            n_estimators=10,
            random_state=42
        )
        detector.train(
            self.X_df,
            self.y,
            test_size=0.2,
            random_state=42,
            use_mlflow=False
        )
        
        # Evaluate the model
        metrics = detector.evaluate(self.X_df, self.y)
        
        # Check that metrics were returned
        self.assertIn("accuracy", metrics)
        self.assertIn("roc_auc", metrics)
        self.assertIn("f1_score", metrics)
        self.assertIn("confusion_matrix", metrics)
        self.assertIn("classification_report", metrics)


if __name__ == "__main__":
    unittest.main()
