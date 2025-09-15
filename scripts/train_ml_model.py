#!/usr/bin/env python3
"""
Script to train the ML model for threat detection.

This script trains a machine learning model to detect malicious files
using features extracted from both benign and malicious samples.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, roc_auc_score, classification_report,
    confusion_matrix
)
import matplotlib.pyplot as plt
import seaborn as sns

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.antivirus.ml.threat_detector import ThreatDetector
from src.antivirus.core.ml_config import MLConfig
from src.antivirus.utils.logger import setup_logging, get_logger

# Set up logging
setup_logging()
logger = get_logger(__name__)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Train ML model for threat detection')
    parser.add_argument('--input', '-i', type=str, default='data/processed/training_data.csv',
                        help='Input CSV file with training data')
    parser.add_argument('--output', '-o', type=str, 
                        default=str(MLConfig.DEFAULT_MODEL_PATH),
                        help='Output path for the trained model')
    parser.add_argument('--test-size', type=float, default=0.2,
                        help='Fraction of data to use for testing')
    parser.add_argument('--cv-folds', type=int, default=5,
                        help='Number of cross-validation folds')
    parser.add_argument('--random-state', type=int, default=MLConfig.RANDOM_STATE,
                        help='Random seed for reproducibility')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--plot', action='store_true',
                        help='Generate and save performance plots')
    return parser.parse_args()

def load_data(file_path: Union[str, Path]) -> Tuple[pd.DataFrame, List[str], List[str]]:
    """Load and preprocess the training data.
    
    Args:
        file_path: Path to the CSV file containing training data.
        
    Returns:
        Tuple of (X, y, feature_names) where:
        - X: Feature matrix
        - y: Target labels
        - feature_names: List of feature names
    """
    logger.info(f"Loading data from {file_path}")
    df = pd.read_csv(file_path)
    
    # Drop non-feature columns
    non_feature_cols = ['file_path', 'label', 'file_type', 'file_size']
    feature_cols = [col for col in df.columns if col not in non_feature_cols]
    
    # Separate features and target
    X = df[feature_cols].copy()
    y = df['label'].values
    
    # Convert boolean columns to int
    for col in X.select_dtypes(include=['bool']).columns:
        X[col] = X[col].astype(int)
    
    # Fill any remaining NaN values
    X = X.fillna(0)
    
    logger.info(f"Loaded {len(X)} samples with {len(feature_cols)} features")
    logger.info(f"Class distribution: {dict(df['label'].value_counts())}")
    
    return X, y, feature_cols

def train_model(X_train: np.ndarray, y_train: np.ndarray, 
               feature_names: List[str], random_state: int = 42) -> RandomForestClassifier:
    """Train a Random Forest classifier.
    
    Args:
        X_train: Training features.
        y_train: Training labels.
        feature_names: List of feature names.
        random_state: Random seed for reproducibility.
        
    Returns:
        Trained Random Forest classifier.
    """
    logger.info("\nTraining Random Forest classifier...")
    
    # Initialize the model
    model = RandomForestClassifier(
        n_estimators=MLConfig.N_ESTIMATORS,
        max_depth=MLConfig.MAX_DEPTH,
        random_state=random_state,
        n_jobs=-1,
        class_weight='balanced',
        verbose=1 if logger.level <= logging.INFO else 0
    )
    
    # Train the model
    model.fit(X_train, y_train)
    
    # Log feature importances
    feature_importances = pd.Series(
        model.feature_importances_, 
        index=feature_names
    ).sort_values(ascending=False)
    
    logger.info("\nTop 10 most important features:")
    for feat, imp in feature_importances.head(10).items():
        logger.info(f"  {feat}: {imp:.4f}")
    
    return model

def evaluate_model(model, X_test: np.ndarray, y_test: np.ndarray, 
                  feature_names: List[str], output_dir: Path, 
                  plot: bool = False) -> Dict:
    """Evaluate the trained model on test data.
    
    Args:
        model: Trained model.
        X_test: Test features.
        y_test: Test labels.
        feature_names: List of feature names.
        output_dir: Directory to save evaluation results.
        plot: Whether to generate and save plots.
        
    Returns:
        Dictionary containing evaluation metrics.
    """
    logger.info("\nEvaluating model on test set...")
    
    # Make predictions
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred),
        'recall': recall_score(y_test, y_pred),
        'f1': f1_score(y_test, y_pred),
        'roc_auc': roc_auc_score(y_test, y_pred_proba),
        'classification_report': classification_report(y_test, y_pred, output_dict=True)
    }
    
    # Log metrics
    logger.info("\nTest Set Performance:")
    logger.info(f"Accuracy: {metrics['accuracy']:.4f}")
    logger.info(f"Precision: {metrics['precision']:.4f}")
    logger.info(f"Recall: {metrics['recall']:.4f}")
    logger.info(f"F1 Score: {metrics['f1']:.4f}")
    logger.info(f"ROC AUC: {metrics['roc_auc']:.4f}")
    
    logger.info("\nClassification Report:")
    logger.info(classification_report(y_test, y_pred))
    
    # Generate and save plots if requested
    if plot:
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Confusion matrix
        plt.figure(figsize=(8, 6))
        cm = confusion_matrix(y_test, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Benign', 'Malicious'],
                    yticklabels=['Benign', 'Malicious'])
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix')
        plt.tight_layout()
        plt.savefig(output_dir / 'confusion_matrix.png')
        plt.close()
        
        # Feature importance
        plt.figure(figsize=(10, 8))
        feature_importances = pd.Series(
            model.feature_importances_, 
            index=feature_names
        ).sort_values(ascending=False).head(15)
        
        sns.barplot(x=feature_importances.values, y=feature_importances.index)
        plt.title('Top 15 Most Important Features')
        plt.tight_layout()
        plt.savefig(output_dir / 'feature_importance.png')
        plt.close()
    
    return metrics

def save_model(model, feature_names: List[str], output_path: Path, 
              metrics: Dict, config: Dict) -> None:
    """Save the trained model and metadata.
    
    Args:
        model: Trained model.
        feature_names: List of feature names.
        output_path: Path to save the model.
        metrics: Dictionary of evaluation metrics.
        config: Model configuration.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Prepare model data
    model_data = {
        'model': model,
        'feature_names': feature_names,
        'metrics': metrics,
        'config': config
    }
    
    # Save the model
    joblib.dump(model_data, output_path)
    logger.info(f"\nModel saved to {output_path}")
    
    # Save metrics to JSON
    metrics_path = output_path.parent / f"{output_path.stem}_metrics.json"
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"Metrics saved to {metrics_path}")

def main():
    """Main training function."""
    # Parse command line arguments
    args = parse_arguments()
    
    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=log_level)
    
    logger.info("Starting ML model training...")
    logger.info(f"Input data: {args.input}")
    logger.info(f"Output model: {args.output}")
    logger.info(f"Test size: {args.test_size}")
    logger.info(f"Random state: {args.random_state}")
    
    try:
        # Load and preprocess data
        X, y, feature_names = load_data(args.input)
        
        # Split into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=args.test_size,
            random_state=args.random_state,
            stratify=y
        )
        
        # Train the model
        model = train_model(X_train, y_train, feature_names, args.random_state)
        
        # Evaluate the model
        output_dir = Path(args.output).parent / 'evaluation'
        metrics = evaluate_model(
            model, X_test, y_test, feature_names, 
            output_dir, plot=args.plot
        )
        
        # Save the model and metadata
        config = {
            'n_estimators': MLConfig.N_ESTIMATORS,
            'max_depth': MLConfig.MAX_DEPTH,
            'random_state': args.random_state,
            'test_size': args.test_size,
            'cv_folds': args.cv_folds,
            'feature_names': feature_names
        }
        
        save_model(model, feature_names, Path(args.output), metrics, config)
        
        logger.info("\nTraining completed successfully!")
        return 0
        
    except Exception as e:
        logger.error(f"Error during training: {e}", exc_info=args.verbose)
        return 1

if __name__ == "__main__":
    sys.exit(main())
