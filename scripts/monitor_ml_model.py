#!/usr/bin/env python3
"""
Script to monitor the performance of the ML model in production.

This script provides functionality to track model performance, detect drift,
and generate reports on the model's health.
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import yaml

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.antivirus.ml.monitoring import ModelMonitor
from src.antivirus.core.config import MLConfig
from src.antivirus.utils.logger import setup_logging, get_logger

# Set up logging
setup_logging()
logger = get_logger(__name__)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Monitor ML model performance')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Report subcommand
    report_parser = subparsers.add_parser('report', help='Generate a monitoring report')
    report_parser.add_argument('--days', type=int, default=30,
                             help='Number of days to include in the report')
    report_parser.add_argument('--output', '-o', 
                             help='Output file for the report (JSON)')
    report_parser.add_argument('--format', choices=['json', 'yaml', 'text'], 
                             default='text',
                             help='Output format (default: text)')
    
    # Check subcommand
    check_parser = subparsers.add_parser('check', 
                                        help='Check for model drift and issues')
    check_parser.add_argument('--features', help='CSV file with current features')
    check_parser.add_argument('--labels', help='CSV file with true labels')
    check_parser.add_argument('--predictions', help='CSV file with model predictions')
    check_parser.add_argument('--output', '-o', 
                            help='Output file for the check results')
    
    # Common arguments
    for p in [report_parser, check_parser]:
        p.add_argument('--model', '-m', 
                      default=str(MLConfig.DEFAULT_MODEL_PATH),
                      help='Path to the trained ML model')
        p.add_argument('--verbose', '-v', action='store_true',
                      help='Enable verbose output')
    
    return parser.parse_args()

def generate_report(monitor: ModelMonitor, days: int, 
                   output_file: Optional[str] = None,
                   fmt: str = 'text') -> bool:
    """Generate a monitoring report.
    
    Args:
        monitor: Initialized ModelMonitor instance.
        days: Number of days to include in the report.
        output_file: Optional file to save the report.
        fmt: Output format ('json', 'yaml', or 'text').
        
    Returns:
        True if successful, False otherwise.
    """
    try:
        # Generate the report
        report = monitor.generate_report(days=days)
        
        # Save or display the report
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if fmt == 'json':
                with open(output_path, 'w') as f:
                    json.dump(report, f, indent=2)
            elif fmt == 'yaml':
                with open(output_path, 'w') as f:
                    yaml.dump(report, f, default_flow_style=False)
            else:  # text
                with open(output_path, 'w') as f:
                    f.write(format_report_text(report))
            
            logger.info(f"Report saved to {output_path}")
        else:
            if fmt == 'json':
                print(json.dumps(report, indent=2))
            elif fmt == 'yaml':
                print(yaml.dump(report, default_flow_style=False))
            else:  # text
                print(format_report_text(report))
        
        return True
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return False

def format_report_text(report: Dict) -> str:
    """Format the monitoring report as text.
    
    Args:
        report: Dictionary containing the report data.
        
    Returns:
        Formatted text report.
    """
    lines = []
    
    # Header
    lines.append("=" * 80)
    lines.append(f"ML Model Monitoring Report")
    lines.append("=" * 80)
    lines.append(f"Time Period: {report.get('time_period', 'N/A')}")
    lines.append(f"From: {report.get('start_date', 'N/A')}  To: {report.get('end_date', 'N/A')}")
    lines.append(f"Total Samples Processed: {report.get('total_samples', 0):,}")
    
    # Alerts
    alerts = report.get('alerts', [])
    if alerts:
        lines.append("\n" + "!" * 80)
        lines.append("ALERTS")
        lines.append("!" * 80)
        for alert in alerts:
            lines.append(f"\n[{alert.get('severity', 'info').upper()}] {alert.get('type', 'alert')}")
            lines.append(f"Message: {alert.get('message', 'No message')}")
            if 'first_detected' in alert:
                lines.append(f"First Detected: {alert['first_detected']}")
            if 'last_detected' in alert:
                lines.append(f"Last Detected: {alert['last_detected']}")
    
    # Metrics Summary
    metrics = report.get('metrics_summary', {})
    if metrics:
        lines.append("\n" + "-" * 80)
        lines.append("PERFORMANCE METRICS")
        lines.append("-" * 80)
        
        # Determine the maximum metric name length for alignment
        max_name_len = max(len(name) for name in metrics.keys())
        
        for metric, stats in metrics.items():
            # Determine trend indicator
            trend = stats.get('trend', 0)
            if trend > 0.01:
                trend_arrow = "↑"  # Upward trend
            elif trend < -0.01:
                trend_arrow = "↓"  # Downward trend
            else:
                trend_arrow = "→"  # Stable
            
            # Format the line with aligned columns
            line = f"{metric:{max_name_len}}  {stats.get('mean', 0):.4f} {trend_arrow}"
            line += f"  (min: {stats.get('min', 0):.4f}, max: {stats.get('max', 0):.4f})"
            lines.append(line)
    
    # Data Quality
    if 'data_quality' in report:
        lines.append("\n" + "-" * 80)
        lines.append("DATA QUALITY")
        lines.append("-" * 80)
        
        for check, result in report['data_quality'].items():
            status = "✓" if result.get('passed', False) else "✗"
            lines.append(f"{status} {check}: {result.get('message', '')}")
    
    # Recommendations
    if 'recommendations' in report and report['recommendations']:
        lines.append("\n" + "-" * 80)
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 80)
        
        for i, rec in enumerate(report['recommendations'], 1):
            lines.append(f"{i}. {rec}")
    
    # Footer
    lines.append("\n" + "=" * 80)
    lines.append(f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 80)
    
    return "\n".join(lines)

def check_model_health(monitor: ModelMonitor, features_file: Optional[str] = None,
                     labels_file: Optional[str] = None,
                     predictions_file: Optional[str] = None,
                     output_file: Optional[str] = None) -> bool:
    """Check the model for drift and other issues.
    
    Args:
        monitor: Initialized ModelMonitor instance.
        features_file: CSV file with current features.
        labels_file: CSV file with true labels.
        predictions_file: CSV file with model predictions.
        output_file: Optional file to save the results.
        
    Returns:
        True if the check was successful, False otherwise.
    """
    try:
        results = {
            'timestamp': datetime.now().isoformat(),
            'checks': {},
            'status': 'healthy',
            'recommendations': []
        }
        
        # Check 1: Data drift detection
        if features_file:
            try:
                current_features = pd.read_csv(features_file)
                drift_detected, drift_metrics = monitor.detect_data_drift(current_features)
                
                results['checks']['data_drift'] = {
                    'detected': drift_detected,
                    'metrics': drift_metrics
                }
                
                if drift_detected:
                    results['status'] = 'warning'
                    results['recommendations'].append(
                        "Data drift detected. Consider retraining the model with "
                        "the latest data."
                    )
            except Exception as e:
                logger.error(f"Error checking for data drift: {e}")
                results['checks']['data_drift'] = {
                    'error': str(e)
                }
        
        # Check 2: Concept drift detection
        if all(f is not None for f in [labels_file, predictions_file]):
            try:
                y_true = pd.read_csv(labels_file).values.ravel()
                y_pred = pd.read_csv(predictions_file).values.ravel()
                
                concept_drift = monitor.detect_concept_drift(y_true, y_pred)
                results['checks']['concept_drift'] = {
                    'detected': concept_drift
                }
                
                if concept_drift:
                    results['status'] = 'critical'
                    results['recommendations'].append(
                        "Concept drift detected. Model performance has degraded. "
                        "Immediate retraining is recommended."
                    )
            except Exception as e:
                logger.error(f"Error checking for concept drift: {e}")
                results['checks']['concept_drift'] = {
                    'error': str(e)
                }
        
        # Save or display results
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Check results saved to {output_path}")
        else:
            print(json.dumps(results, indent=2))
        
        return True
        
    except Exception as e:
        logger.error(f"Error during model health check: {e}")
        return False

def main():
    """Main function to run the monitoring script."""
    args = parse_arguments()
    
    # Set log level
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level)
    
    try:
        # Initialize the model monitor
        monitor = ModelMonitor(model_path=args.model)
        
        # Execute the requested command
        if args.command == 'report':
            success = generate_report(
                monitor=monitor,
                days=args.days,
                output_file=args.output,
                fmt=args.format
            )
        elif args.command == 'check':
            success = check_model_health(
                monitor=monitor,
                features_file=args.features,
                labels_file=args.labels,
                predictions_file=args.predictions,
                output_file=args.output
            )
        else:
            logger.error("No command specified. Use 'report' or 'check'.")
            return 1
        
        return 0 if success else 1
        
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=args.verbose)
        return 1

if __name__ == "__main__":
    sys.exit(main())
