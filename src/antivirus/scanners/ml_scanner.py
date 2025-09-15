"""
Machine Learning-based file scanner for the antivirus.

This module provides ML-based scanning capabilities to detect potentially
malicious files using machine learning models.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import numpy as np

from ..core.config import MLConfig
from ..ml.threat_detector import ThreatDetector
from ..utils.logger import get_logger
from ..utils.file_utils import FileUtils

logger = get_logger(__name__)

class MLScanner:
    """Machine Learning-based file scanner for detecting malicious files."""
    
    def __init__(self, model_path: Optional[str] = None, threshold: float = 0.7):
        """Initialize the ML scanner.
        
        Args:
            model_path: Path to the trained ML model. If None, uses default path.
            threshold: Confidence threshold for classification (0-1).
        """
        self.threshold = threshold
        self.model = ThreatDetector(model_path)
        self.features = {}
        
        logger.info(f"Initialized ML Scanner with threshold: {threshold}")
    
    def scan_file(self, file_path: Union[str, Path]) -> Dict:
        """Scan a file using ML model.
        
        Args:
            file_path: Path to the file to scan.
            
        Returns:
            Dictionary containing scan results.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        try:
            # Extract features from the file
            features = self.model.extract_features(file_path)
            self.features[file_path] = features
            
            # Make prediction
            is_malicious, confidence = self.model.predict(features)
            
            # Prepare result
            result = {
                'file': str(file_path),
                'malicious': bool(is_malicious),
                'confidence': float(confidence),
                'detected': bool(is_malicious and confidence >= self.threshold),
                'scan_type': 'ml',
                'features': features
            }
            
            logger.debug(f"ML scan result for {file_path}: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error scanning {file_path} with ML: {e}", exc_info=True)
            return {
                'file': str(file_path),
                'error': str(e),
                'scan_type': 'ml',
                'detected': False
            }
    
    def scan_directory(self, directory: Union[str, Path], recursive: bool = False) -> List[Dict]:
        """Scan all files in a directory.
        
        Args:
            directory: Directory to scan.
            recursive: Whether to scan subdirectories.
            
        Returns:
            List of scan results for each file.
        """
        directory = Path(directory)
        if not directory.is_dir():
            raise NotADirectoryError(f"Directory not found: {directory}")
        
        results = []
        
        # Get iterator based on recursive flag
        if recursive:
            file_iterator = directory.rglob('*')
        else:
            file_iterator = directory.glob('*')
        
        # Scan each file
        for file_path in file_iterator:
            if file_path.is_file():
                try:
                    result = self.scan_file(file_path)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")
                    results.append({
                        'file': str(file_path),
                        'error': str(e),
                        'scan_type': 'ml',
                        'detected': False
                    })
        
        return results
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from the trained model.
        
        Returns:
            Dictionary of feature names and their importance scores.
        """
        if not hasattr(self.model.model, 'feature_importances_'):
            return {}
            
        return dict(zip(
            self.model.feature_columns,
            self.model.model.feature_importances_
        ))
    
    def save_scan_report(self, results: List[Dict], output_file: Union[str, Path]) -> None:
        """Save scan results to a JSON file.
        
        Args:
            results: List of scan results.
            output_file: Path to save the report.
        """
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert Path objects to strings for JSON serialization
        serializable_results = []
        for result in results:
            serialized = result.copy()
            if 'features' in serialized and serialized['features'] is not None:
                serialized['features'] = {
                    str(k): v for k, v in serialized['features'].items()
                }
            serializable_results.append(serialized)
        
        with open(output_file, 'w') as f:
            json.dump(serializable_results, f, indent=2)
        
        logger.info(f"Scan report saved to {output_file}")

# Example usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Scan files using ML model')
    parser.add_argument('path', help='File or directory to scan')
    parser.add_argument('--recursive', '-r', action='store_true', help='Scan directories recursively')
    parser.add_argument('--output', '-o', help='Output file for scan results (JSON)')
    parser.add_argument('--model', '-m', help='Path to trained ML model')
    parser.add_argument('--threshold', '-t', type=float, default=0.7, 
                       help='Confidence threshold (0-1)')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = MLScanner(model_path=args.model, threshold=args.threshold)
    
    # Perform scan
    path = Path(args.path)
    if path.is_file():
        results = [scanner.scan_file(path)]
    else:
        results = scanner.scan_directory(path, recursive=args.recursive)
    
    # Print results
    detected = [r for r in results if r.get('detected', False)]
    print(f"\nScan complete!")
    print(f"Files scanned: {len(results)}")
    print(f"Potential threats detected: {len(detected)}")
    
    if detected:
        print("\nDetected files:")
        for result in detected:
            print(f"- {result['file']} (Confidence: {result['confidence']:.2f})")
    
    # Save results if output file is specified
    if args.output:
        scanner.save_scan_report(results, args.output)
