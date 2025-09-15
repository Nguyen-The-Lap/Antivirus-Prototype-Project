"""
Monitoring system for ML model performance and drift detection.

This module provides functionality to monitor the performance of the ML model
in production, detect data drift, and trigger retraining when necessary.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score
)

from ..core.config import MLConfig, DATA_DIR
from ..utils.logger import get_logger

logger = get_logger(__name__)

class ModelMonitor:
    """Monitor ML model performance and detect data drift."""
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize the model monitor.
        
        Args:
            model_path: Path to the trained ML model.
        """
        self.model_path = Path(model_path) if model_path else MLConfig.DEFAULT_MODEL_PATH
        self.monitoring_dir = DATA_DIR / 'monitoring'
        self.monitoring_dir.mkdir(parents=True, exist_ok=True)
        
        # Load model metadata
        self.model_metadata = self._load_model_metadata()
        self.reference_data = self._load_reference_data()
        
        # Initialize metrics history
        self.metrics_history = self._load_metrics_history()
    
    def _load_model_metadata(self) -> Dict:
        """Load metadata for the current model."""
        metadata_path = self.model_path.parent / f"{self.model_path.stem}_metadata.json"
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                return json.load(f)
        return {}
    
    def _load_reference_data(self) -> Optional[Dict]:
        """Load reference data for drift detection."""
        ref_data_path = self.monitoring_dir / 'reference_data.json'
        if ref_data_path.exists():
            with open(ref_data_path, 'r') as f:
                return json.load(f)
        return None
    
    def _load_metrics_history(self) -> pd.DataFrame:
        """Load historical metrics for monitoring."""
        metrics_path = self.monitoring_dir / 'metrics_history.csv'
        if metrics_path.exists():
            df = pd.read_csv(metrics_path, parse_dates=['timestamp'])
            # Ensure all required columns exist
            for col in ['timestamp', 'accuracy', 'precision', 'recall', 'f1', 'roc_auc']:
                if col not in df.columns:
                    df[col] = np.nan
            return df
        else:
            # Create empty DataFrame with required columns
            return pd.DataFrame(columns=[
                'timestamp', 'accuracy', 'precision', 'recall', 'f1', 'roc_auc',
                'data_drift_detected', 'concept_drift_detected', 'num_samples'
            ])
    
    def _save_metrics_history(self):
        """Save metrics history to disk."""
        if not self.metrics_history.empty:
            metrics_path = self.monitoring_dir / 'metrics_history.csv'
            self.metrics_history.to_csv(metrics_path, index=False)
    
    def _save_reference_data(self, reference_data: Dict):
        """Save reference data for drift detection."""
        ref_data_path = self.monitoring_dir / 'reference_data.json'
        with open(ref_data_path, 'w') as f:
            json.dump(reference_data, f, indent=2)
    
    def calculate_metrics(self, y_true: np.ndarray, y_pred: np.ndarray, 
                         y_pred_proba: Optional[np.ndarray] = None) -> Dict:
        """Calculate performance metrics.
        
        Args:
            y_true: True labels.
            y_pred: Predicted labels.
            y_pred_proba: Predicted probabilities (for ROC AUC).
            
        Returns:
            Dictionary of performance metrics.
        """
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1': f1_score(y_true, y_pred, zero_division=0),
        }
        
        if y_pred_proba is not None:
            metrics['roc_auc'] = roc_auc_score(y_true, y_pred_proba)
        
        return metrics
    
    def detect_data_drift(self, current_features: pd.DataFrame, 
                         reference_features: Optional[pd.DataFrame] = None, 
                         threshold: float = 0.05) -> Tuple[bool, Dict]:
        """Detect data drift using the Kolmogorov-Smirnov test.
        
        Args:
            current_features: Current batch of features.
            reference_features: Reference features for comparison. If None, uses stored reference data.
            threshold: P-value threshold for statistical significance.
            
        Returns:
            Tuple of (drift_detected, drift_metrics)
        """
        if reference_features is None:
            if self.reference_data is None:
                logger.warning("No reference data available for drift detection")
                return False, {}
            reference_features = pd.DataFrame(self.reference_data['features'])
        
        # Ensure both dataframes have the same columns
        common_cols = set(current_features.columns) & set(reference_features.columns)
        if not common_cols:
            logger.warning("No common columns between current and reference features")
            return False, {}
        
        drift_metrics = {}
        drift_detected = False
        
        for col in common_cols:
            # Skip non-numeric columns
            if not np.issubdtype(current_features[col].dtype, np.number):
                continue
                
            # Skip constant columns
            if current_features[col].nunique() <= 1 or reference_features[col].nunique() <= 1:
                continue
            
            # Perform Kolmogorov-Smirnov test
            ks_stat, p_value = stats.ks_2samp(
                reference_features[col].dropna(),
                current_features[col].dropna(),
                alternative='two-sided'
            )
            
            drift_metrics[col] = {
                'ks_statistic': ks_stat,
                'p_value': p_value,
                'drift_detected': p_value < threshold
            }
            
            if p_value < threshold:
                drift_detected = True
        
        return drift_detected, drift_metrics
    
    def detect_concept_drift(self, y_true: np.ndarray, y_pred: np.ndarray,
                           window_size: int = 100, threshold: float = 0.1) -> bool:
        """Detect concept drift using accuracy over time.
        
        Args:
            y_true: True labels.
            y_pred: Predicted labels.
            window_size: Size of the sliding window for accuracy calculation.
            threshold: Threshold for significant drop in accuracy.
            
        Returns:
            True if concept drift is detected, False otherwise.
        """
        if len(y_true) < 2 * window_size:
            logger.warning(f"Not enough samples for concept drift detection. Need at least {2 * window_size} samples.")
            return False
        
        # Calculate accuracy in sliding windows
        accuracies = []
        for i in range(len(y_true) - window_size + 1):
            window_true = y_true[i:i+window_size]
            window_pred = y_pred[i:i+window_size]
            acc = accuracy_score(window_true, window_pred)
            accuracies.append(acc)
        
        # Check for significant drop in accuracy
        if len(accuracies) >= 2:
            recent_accuracy = np.mean(accuracies[-window_size//2:])
            baseline_accuracy = np.mean(accuracies[:-window_size//2])
            
            if baseline_accuracy - recent_accuracy > threshold:
                logger.warning(f"Concept drift detected: accuracy dropped from {baseline_accuracy:.3f} to {recent_accuracy:.3f}")
                return True
        
        return False
    
    def update_metrics(self, metrics: Dict, num_samples: int,
                      data_drift_detected: bool = False,
                      concept_drift_detected: bool = False):
        """Update metrics history with new values."""
        new_row = {
            'timestamp': datetime.now(),
            'num_samples': num_samples,
            'data_drift_detected': data_drift_detected,
            'concept_drift_detected': concept_drift_detected
        }
        new_row.update(metrics)
        
        # Convert to DataFrame and append
        new_df = pd.DataFrame([new_row])
        self.metrics_history = pd.concat([self.metrics_history, new_df], ignore_index=True)
        
        # Keep only the most recent 1000 records
        if len(self.metrics_history) > 1000:
            self.metrics_history = self.metrics_history.iloc[-1000:]
        
        # Save to disk
        self._save_metrics_history()
    
    def generate_report(self, days: int = 30) -> Dict:
        """Generate a monitoring report for the specified time period.
        
        Args:
            days: Number of days to include in the report.
            
        Returns:
            Dictionary containing the monitoring report.
        """
        if self.metrics_history.empty:
            return {"status": "no_data", "message": "No metrics data available"}
        
        # Filter data for the specified time period
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_metrics = self.metrics_history[self.metrics_history['timestamp'] >= cutoff_date]
        
        if recent_metrics.empty:
            return {"status": "no_recent_data", "message": f"No data in the last {days} days"}
        
        # Calculate statistics
        report = {
            "time_period": f"Last {days} days",
            "start_date": recent_metrics['timestamp'].min().strftime('%Y-%m-%d'),
            "end_date": recent_metrics['timestamp'].max().strftime('%Y-%m-%d'),
            "total_samples": int(recent_metrics['num_samples'].sum()),
            "data_drift_detected": bool(recent_metrics['data_drift_detected'].any()),
            "concept_drift_detected": bool(recent_metrics['concept_drift_detected'].any()),
            "metrics_summary": {}
        }
        
        # Calculate statistics for each metric
        for metric in ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']:
            if metric in recent_metrics.columns:
                report['metrics_summary'][metric] = {
                    "mean": float(recent_metrics[metric].mean()),
                    "min": float(recent_metrics[metric].min()),
                    "max": float(recent_metrics[metric].max()),
                    "std": float(recent_metrics[metric].std()),
                    "trend": self._calculate_trend(recent_metrics[metric])
                }
        
        # Add alerts if needed
        report['alerts'] = self._generate_alerts(recent_metrics)
        
        return report
    
    def _calculate_trend(self, series: pd.Series, window: int = 5) -> float:
        """Calculate the trend of a metric over time.
        
        Args:
            series: Time series data.
            window: Window size for trend calculation.
            
        Returns:
            Slope of the trend line.
        """
        if len(series) < 2:
            return 0.0
        
        # Use simple linear regression for trend
        x = np.arange(len(series))
        y = series.values
        
        # Handle NaN values
        mask = ~np.isnan(y)
        if not np.any(mask):
            return 0.0
            
        x = x[mask]
        y = y[mask]
        
        if len(x) < 2:
            return 0.0
        
        # Calculate slope
        slope, _, _, _, _ = stats.linregress(x, y)
        return float(slope)
    
    def _generate_alerts(self, metrics: pd.DataFrame) -> List[Dict]:
        """Generate alerts based on metrics data."""
        alerts = []
        
        # Check for data drift
        if 'data_drift_detected' in metrics.columns and metrics['data_drift_detected'].any():
            alerts.append({
                "type": "data_drift",
                "severity": "high",
                "message": "Data drift detected in one or more features",
                "first_detected": metrics[metrics['data_drift_detected']]['timestamp'].min().strftime('%Y-%m-%d %H:%M:%S'),
                "last_detected": metrics[metrics['data_drift_detected']]['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
            })
        
        # Check for concept drift
        if 'concept_drift_detected' in metrics.columns and metrics['concept_drift_detected'].any():
            alerts.append({
                "type": "concept_drift",
                "severity": "critical",
                "message": "Concept drift detected - model performance has degraded",
                "first_detected": metrics[metrics['concept_drift_detected']]['timestamp'].min().strftime('%Y-%m-%d %H:%M:%S'),
                "last_detected": metrics[metrics['concept_drift_detected']]['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
            })
        
        # Check for performance degradation
        if 'accuracy' in metrics.columns and len(metrics) >= 10:
            # Compare recent performance to historical average
            recent_acc = metrics['accuracy'].iloc[-5:].mean()
            historical_acc = metrics['accuracy'].iloc[:-5].mean()
            
            if recent_acc < historical_acc - 0.1:  # 10% drop in accuracy
                alerts.append({
                    "type": "performance_degradation",
                    "severity": "medium",
                    "message": f"Model accuracy has dropped from {historical_acc:.3f} to {recent_acc:.3f}",
                    "detected_at": metrics['timestamp'].iloc[-1].strftime('%Y-%m-%d %H:%M:%S')
                })
        
        return alerts
