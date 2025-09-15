"""
CLI commands for ML-based threat detection.

This module provides command-line interface commands for the ML-based threat detection
functionality of the antivirus system.
"""

import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any

import click
import pandas as pd
from tabulate import tabulate

from ...core.config import MLConfig
from ...ml.threat_detector import ThreatDetector
from ...scanners.ml_scanner import MLScanner
from ...utils.logger import get_logger

logger = get_logger(__name__)

@click.group()
def ml():
    """Machine learning-based threat detection commands."""
    pass

@ml.command()
@click.option('--input', '-i', 'input_path', required=True,
              help='File or directory to scan')
@click.option('--recursive', '-r', is_flag=True,
              help='Scan directories recursively')
@click.option('--output', '-o', 'output_file',
              help='Output file for scan results (JSON)')
@click.option('--model', '-m', 'model_path',
              default=str(MLConfig.DEFAULT_MODEL_PATH),
              help='Path to trained ML model')
@click.option('--threshold', '-t', type=float, default=0.7,
              help='Confidence threshold (0-1)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def scan(input_path: str, recursive: bool, output_file: Optional[str], 
        model_path: str, threshold: float, verbose: bool):
    """Scan files or directories using the ML model."""
    # Set log level
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Initialize the scanner
        scanner = MLScanner(model_path=model_path, threshold=threshold)
        
        # Perform the scan
        path = Path(input_path)
        if path.is_file():
            results = [scanner.scan_file(path)]
        else:
            results = scanner.scan_directory(path, recursive=recursive)
        
        # Filter out errors and detected files
        detected = [r for r in results if r.get('detected', False)]
        errors = [r for r in results if 'error' in r]
        
        # Print summary
        print(f"\nScan completed!")
        print(f"Files scanned: {len(results)}")
        print(f"Potential threats detected: {len(detected)}")
        print(f"Errors: {len(errors)}")
        
        # Print detected files in a table
        if detected:
            print("\nDetected files:")
            table = []
            for result in detected:
                table.append([
                    result['file'],
                    f"{result['confidence']:.2f}",
                    "Malicious" if result['malicious'] else "Suspicious"
                ])
            
            print(tabulate(
                table,
                headers=['File', 'Confidence', 'Verdict'],
                tablefmt='grid',
                maxcolwidths=[60, 15, 15]
            ))
        
        # Save results to file if specified
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"\nScan results saved to {output_path}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during scan: {e}", exc_info=verbose)
        return 1

@ml.command()
@click.option('--input', '-i', 'input_csv', required=True,
              help='Input CSV file with training data')
@click.option('--output', '-o', 'output_model',
              default=str(MLConfig.DEFAULT_MODEL_PATH),
              help='Output path for the trained model')
@click.option('--test-size', type=float, default=0.2,
              help='Fraction of data to use for testing')
@click.option('--plot', is_flag=True, help='Generate performance plots')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def train(input_csv: str, output_model: str, test_size: float, 
         plot: bool, verbose: bool):
    """Train a new ML model from prepared data."""
    # Set log level
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Import here to avoid circular imports
        from ....scripts.train_ml_model import (
            load_data, train_model, evaluate_model, save_model
        )
        
        # Load and preprocess data
        X, y, feature_names = load_data(input_csv)
        
        # Train the model
        model = train_model(X, y, feature_names)
        
        # Evaluate the model
        output_dir = Path(output_model).parent / 'evaluation'
        metrics = evaluate_model(
            model, X, y, feature_names, 
            output_dir, plot=plot
        )
        
        # Save the model
        config = {
            'n_estimators': MLConfig.N_ESTIMATORS,
            'max_depth': MLConfig.MAX_DEPTH,
            'random_state': MLConfig.RANDOM_STATE,
            'test_size': test_size,
            'feature_names': feature_names
        }
        
        save_model(model, feature_names, Path(output_model), metrics, config)
        
        print("\nTraining completed successfully!")
        print(f"Model saved to {output_model}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during training: {e}", exc_info=verbose)
        return 1

@ml.command()
@click.option('--model', '-m', 'model_path',
              default=str(MLConfig.DEFAULT_MODEL_PATH),
              help='Path to trained ML model')
def info(model_path: str):
    """Display information about the ML model."""
    try:
        # Load the model
        import joblib
        model_data = joblib.load(model_path)
        
        # Display model information
        model = model_data['model']
        feature_names = model_data.get('feature_names', [])
        metrics = model_data.get('metrics', {})
        config = model_data.get('config', {})
        
        print("\nML Model Information")
        print("===================")
        
        # Model type and parameters
        print("\nModel:")
        print(f"  Type: {model.__class__.__name__}")
        if hasattr(model, 'n_estimators'):
            print(f"  Number of estimators: {model.n_estimators}")
        if hasattr(model, 'max_depth'):
            print(f"  Max depth: {model.max_depth}")
        
        # Features
        print(f"\nFeatures ({len(feature_names)}):")
        if len(feature_names) <= 20:
            for i, feature in enumerate(feature_names, 1):
                print(f"  {i}. {feature}")
        else:
            print(f"  First 10 features: {', '.join(feature_names[:10])}")
            print(f"  ... and {len(feature_names) - 10} more")
        
        # Metrics
        if metrics:
            print("\nPerformance Metrics:")
            for metric, value in metrics.items():
                if isinstance(value, dict):
                    print(f"  {metric}:")
                    for k, v in value.items():
                        print(f"    {k}: {v:.4f}" if isinstance(v, (int, float)) else f"    {k}: {v}")
                else:
                    print(f"  {metric}: {value:.4f}" if isinstance(value, (int, float)) else f"  {metric}: {value}")
        
        # Configuration
        if config:
            print("\nConfiguration:")
            for key, value in config.items():
                if key != 'feature_names':  # Already displayed
                    print(f"  {key}: {value}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        return 1
