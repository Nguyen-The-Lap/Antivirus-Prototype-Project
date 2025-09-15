#!/usr/bin/env python3
"""
Script to prepare training data for the ML model.

This script processes files from the benign and malicious directories,
extracts features, and creates a dataset for training the ML model.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import pandas as pd
import numpy as np
from tqdm import tqdm

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.antivirus.ml.threat_detector import ThreatDetector
from src.antivirus.core.ml_config import MLConfig
from src.antivirus.utils.logger import setup_logging

# Set up logging
logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Prepare training data for ML model')
    parser.add_argument('--benign-dir', type=str, default='data/benign',
                        help='Directory containing benign files')
    parser.add_argument('--malicious-dir', type=str, default='data/malicious',
                        help='Directory containing malicious files')
    parser.add_argument('--output', '-o', type=str, default='data/processed/training_data.csv',
                        help='Output CSV file for processed data')
    parser.add_argument('--test-split', type=float, default=0.2,
                        help='Fraction of data to use for testing')
    parser.add_argument('--seed', type=int, default=42,
                        help='Random seed for reproducibility')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    return parser.parse_args()

def collect_file_paths(directory: Union[str, Path], label: int) -> List[Dict]:
    """Collect file paths and their corresponding labels.
    
    Args:
        directory: Directory containing files.
        label: Label for the files (0 for benign, 1 for malicious).
        
    Returns:
        List of dictionaries containing file paths and labels.
    """
    directory = Path(directory)
    if not directory.exists():
        logger.warning(f"Directory not found: {directory}")
        return []
    
    files = []
    for file_path in directory.rglob('*'):
        if file_path.is_file():
            files.append({
                'file_path': str(file_path),
                'label': label,
                'file_type': file_path.suffix.lower(),
                'file_size': file_path.stat().st_size
            })
    
    return files

def extract_features(file_paths: List[Dict]) -> List[Dict]:
    """Extract features from a list of files.
    
    Args:
        file_paths: List of dictionaries containing file paths and metadata.
        
    Returns:
        List of dictionaries containing extracted features.
    """
    detector = ThreatDetector()
    results = []
    
    for item in tqdm(file_paths, desc="Extracting features"):
        try:
            features = detector.extract_features(item['file_path'])
            features['label'] = item['label']
            features['file_path'] = item['file_path']
            features['file_type'] = item['file_type']
            features['file_size'] = item['file_size']
            results.append(features)
        except Exception as e:
            logger.warning(f"Error processing {item['file_path']}: {e}")
    
    return results

def save_dataset(df: pd.DataFrame, output_path: Union[str, Path], test_size: float = 0.2, 
                random_state: int = 42) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Save the dataset and split into training and testing sets.
    
    Args:
        df: DataFrame containing the dataset.
        output_path: Base path for saving the dataset.
        test_size: Fraction of data to use for testing.
        random_state: Random seed for reproducibility.
        
    Returns:
        Tuple of (train_df, test_df) DataFrames.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Save the full dataset
    df.to_csv(output_path, index=False)
    logger.info(f"Saved full dataset to {output_path} with {len(df)} samples")
    
    # Split into training and testing sets
    train_df = df.sample(frac=1-test_size, random_state=random_state)
    test_df = df.drop(train_df.index)
    
    # Save training and testing sets
    train_path = output_path.with_name(f"{output_path.stem}_train.csv")
    test_path = output_path.with_name(f"{output_path.stem}_test.csv")
    
    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)
    
    logger.info(f"Saved training set to {train_path} with {len(train_df)} samples")
    logger.info(f"Saved testing set to {test_path} with {len(test_df)} samples")
    
    return train_df, test_df

def main():
    """Main function to prepare training data."""
    args = parse_arguments()
    
    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=log_level)
    
    logger.info("Starting data preparation...")
    
    # Collect file paths
    logger.info("Collecting file paths...")
    benign_files = collect_file_paths(args.benign_dir, label=0)
    malicious_files = collect_file_paths(args.malicious_dir, label=1)
    
    logger.info(f"Found {len(benign_files)} benign files and {len(malicious_files)} malicious files")
    
    if not benign_files and not malicious_files:
        logger.error("No files found in the specified directories. Exiting.")
        sys.exit(1)
    
    # Extract features
    all_files = benign_files + malicious_files
    features = extract_features(all_files)
    
    if not features:
        logger.error("No features were extracted. Exiting.")
        sys.exit(1)
    
    # Convert to DataFrame
    df = pd.DataFrame(features)
    
    # Save dataset
    train_df, test_df = save_dataset(
        df, 
        args.output, 
        test_size=args.test_split, 
        random_state=args.seed
    )
    
    # Print dataset statistics
    logger.info("\nDataset Statistics:")
    logger.info(f"Total samples: {len(df)}")
    logger.info(f"  - Benign: {len(df[df['label'] == 0])}")
    logger.info(f"  - Malicious: {len(df[df['label'] == 1])}")
    logger.info(f"\nTraining set: {len(train_df)} samples")
    logger.info(f"Testing set: {len(test_df)} samples")
    
    # Print feature information
    logger.info("\nFeature Information:")
    for col in df.columns:
        if col not in ['file_path', 'label']:
            logger.info(f"- {col}: {df[col].dtype}")
    
    logger.info("\nData preparation complete!")

if __name__ == "__main__":
    main()
