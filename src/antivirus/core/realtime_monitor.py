"""
Real-time file system monitoring for the antivirus engine.

This module provides real-time monitoring of file system events and integrates
with the ML-based threat detection system.
"""

import logging
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from ..ml.advanced_threat_detector import AdvancedThreatDetector
from ..utils.logger import get_logger

logger = get_logger(__name__)

class RealTimeMonitor:
    """Monitor file system events in real-time and scan new/modified files."""
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        monitored_dirs: Optional[List[str]] = None,
        callback: Optional[Callable[[str, Dict], None]] = None,
        scan_extensions: Optional[Set[str]] = None
    ):
        """Initialize the real-time monitor.
        
        Args:
            model_path: Path to the trained ML model.
            monitored_dirs: List of directories to monitor.
            callback: Callback function to handle scan results.
            scan_extensions: Set of file extensions to monitor.
        """
        self.observer = Observer()
        self.monitored_dirs = set(monitored_dirs or [])
        self.callback = callback
        self.scan_extensions = scan_extensions or {
            '.exe', '.dll', '.sys', '.bat', '.vbs', '.ps1', '.js', '.jse',
            '.vbe', '.wsf', '.wsh', '.msc', '.msi', '.msp', '.mst', '.doc',
            '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.jar', '.class'
        }
        
        # Initialize the ML model
        self.detector = AdvancedThreatDetector(model_path=model_path) if model_path else None
        
        # Track recently processed files to avoid duplicate scans
        self.recently_processed: Dict[str, float] = {}
        self.processed_timeout = 60  # seconds
        
        # Event handler for file system events
        self.event_handler = FileSystemEventHandler()
        self.event_handler.on_created = self._on_created
        self.event_handler.on_modified = self._on_modified
        
        logger.info("Real-time monitor initialized")
    
    def add_directory(self, path: str) -> None:
        """Add a directory to monitor."""
        path = str(Path(path).absolute())
        if path not in self.monitored_dirs:
            self.monitored_dirs.add(path)
            if self.observer.is_alive():
                self.observer.schedule(self.event_handler, path, recursive=True)
            logger.info(f"Added directory to monitor: {path}")
    
    def remove_directory(self, path: str) -> None:
        """Stop monitoring a directory."""
        path = str(Path(path).absolute())
        if path in self.monitored_dirs:
            self.monitored_dirs.remove(path)
            # Note: Watch objects can't be removed individually in watchdog,
            # so we'll just stop and restart the observer
            if self.observer.is_alive():
                self.stop()
                self.start()
            logger.info(f"Removed directory from monitoring: {path}")
    
    def start(self) -> None:
        """Start the file system monitoring."""
        if not self.monitored_dirs:
            logger.warning("No directories to monitor")
            return
            
        if not self.observer.is_alive():
            self.observer = Observer()
            for directory in self.monitored_dirs:
                self.observer.schedule(self.event_handler, directory, recursive=True)
            self.observer.start()
            logger.info("Started real-time monitoring")
    
    def stop(self) -> None:
        """Stop the file system monitoring."""
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
            logger.info("Stopped real-time monitoring")
    
    def _should_scan(self, file_path: str) -> bool:
        """Determine if a file should be scanned."""
        path = Path(file_path)
        
        # Skip directories and non-files
        if not path.is_file():
            return False
            
        # Check file extension
        if self.scan_extensions and path.suffix.lower() not in self.scan_extensions:
            return False
            
        # Skip recently processed files
        current_time = time.time()
        if file_path in self.recently_processed:
            if current_time - self.recently_processed[file_path] < self.processed_timeout:
                return False
                
        self.recently_processed[file_path] = current_time
        return True
    
    def _scan_file(self, file_path: str) -> Dict:
        """Scan a file using the ML model."""
        if not self.detector:
            return {"error": "No ML model loaded"}
            
        try:
            # Extract features and predict
            features = self.detector.extract_features(file_path)
            is_malicious, confidence = self.detector.predict(features)
            
            result = {
                "file_path": file_path,
                "is_malicious": bool(is_malicious),
                "confidence": float(confidence),
                "threat_name": "ML.Detected" if is_malicious else "",
                "details": {
                    "model_type": self.detector.model_type.value,
                    "features_used": list(features.keys()) if features else []
                }
            }
            
            logger.info(f"Scanned {file_path}: "
                      f"{'MALICIOUS' if is_malicious else 'CLEAN'} "
                      f"(confidence: {confidence:.2f})")
                      
            return result
            
        except Exception as e:
            error_msg = f"Error scanning {file_path}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return {"error": error_msg}
    
    def _process_event(self, event: FileSystemEvent) -> None:
        """Process a file system event."""
        if not hasattr(event, 'src_path') or not event.src_path:
            return
            
        file_path = event.src_path
        
        try:
            if not self._should_scan(file_path):
                return
                
            result = self._scan_file(file_path)
            
            if self.callback and 'error' not in result:
                self.callback(file_path, result)
                
        except Exception as e:
            logger.error(f"Error processing event for {file_path}: {str(e)}", exc_info=True)
    
    def _on_created(self, event: FileSystemEvent) -> None:
        """Handle file creation events."""
        self._process_event(event)
    
    def _on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification events."""
        self._process_event(event)
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


def start_realtime_monitoring(
    model_path: Optional[str] = None,
    directories: Optional[List[str]] = None,
    callback: Optional[Callable[[str, Dict], None]] = None,
    scan_extensions: Optional[Set[str]] = None
) -> RealTimeMonitor:
    """Start real-time monitoring of specified directories.
    
    Args:
        model_path: Path to the trained ML model.
        directories: List of directories to monitor.
        callback: Callback function to handle scan results.
        scan_extensions: Set of file extensions to monitor.
        
    Returns:
        An instance of RealTimeMonitor.
    """
    monitor = RealTimeMonitor(
        model_path=model_path,
        monitored_dirs=directories,
        callback=callback,
        scan_extensions=scan_extensions
    )
    
    for directory in (directories or []):
        monitor.add_directory(directory)
    
    monitor.start()
    return monitor
