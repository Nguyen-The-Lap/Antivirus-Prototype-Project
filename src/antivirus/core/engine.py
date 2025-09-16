"""
Advanced Antivirus Engine with real-time monitoring and ML-based detection.
"""

import os
import hashlib
import datetime
import platform
import json
import time
import threading
import queue
import signal
import sys
import ctypes
import psutil
import yara
import pefile
import magic
import requests
import logging
from typing import List, Dict, Tuple, Optional, Callable, Set, Any, Union
from dataclasses import dataclass, field, asdict
from pathlib import Path
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import internal modules
from ..ml.advanced_threat_detector import AdvancedThreatDetector
from .realtime_monitor import RealTimeMonitor
from ..utils.logger import get_logger

@dataclass
class ScanResult:
    """Represents the result of a file scan."""
    file_path: str
    is_infected: bool = False
    threat_name: str = ""
    threat_type: str = ""
    details: str = ""
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())

class AdvancedAntivirusEngine:
    """Advanced Antivirus Engine with real-time monitoring and ML-based detection."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the antivirus engine.
        
        Args:
            config: Optional configuration dictionary with the following keys:
                - model_path: Path to the trained ML model
                - quarantine_dir: Directory for quarantined files
                - scan_log: Path to the scan log file
                - monitored_dirs: List of directories to monitor in real-time
                - scan_extensions: Set of file extensions to scan
        """
        # Initialize configuration
        self.config = config or {}
        
        # Core components
        self.signatures = {}
        self.yara_rules = None
        self.whitelist = set()
        self.scan_queue = queue.Queue()
        self.running = True
        
        # File system paths
        self.quarantine_dir = Path(self.config.get('quarantine_dir', 'quarantine')).absolute()
        self.scan_log = Path(self.config.get('scan_log', 'scan_log.json')).absolute()
        
        # Real-time monitoring
        self.realtime_monitor = None
        self.monitored_dirs = set(self.config.get('monitored_dirs', []))
        
        # ML model
        self.ml_model = None
        self._init_ml_model()
        
        # Initialize directories and load data
        self._setup_directories()
        self._load_signatures()
        self._load_yara_rules()
        self._load_whitelist()
        
        # Initialize logger
        self.logger = get_logger(__name__)
        
        # Initialize colorama for console output
        init()
    
    def _init_ml_model(self) -> None:
        """Initialize the ML model if a model path is provided."""
        model_path = self.config.get('model_path')
        if model_path and Path(model_path).exists():
            try:
                self.ml_model = AdvancedThreatDetector(model_path=model_path)
                self.logger.info(f"Loaded ML model from {model_path}")
            except Exception as e:
                self.logger.error(f"Failed to load ML model: {e}")
        else:
            self.logger.warning("No ML model path provided or model not found")
    
    def _setup_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        try:
            # Create quarantine directory and subdirectories
            self.quarantine_dir.mkdir(exist_ok=True, parents=True)
            (self.quarantine_dir / 'suspicious').mkdir(exist_ok=True)
            (self.quarantine_dir / 'quarantined').mkdir(exist_ok=True)
            (self.quarantine_dir / 'backup').mkdir(exist_ok=True)
            
            # Create signature directories
            sig_dir = Path("signatures")
            sig_dir.mkdir(exist_ok=True, parents=True)
            (sig_dir / 'yara').mkdir(exist_ok=True)
            (sig_dir / 'hashes').mkdir(exist_ok=True)
            
            # Create logs directory
            logs_dir = Path("logs")
            logs_dir.mkdir(exist_ok=True, parents=True)
            
            self.logger.info("Initialized required directories")
            
        except Exception as e:
            self.logger.error(f"Failed to setup directories: {e}")
            raise
    
    def _load_signatures(self) -> None:
        """Load malware signatures from file."""
        sig_file = Path("signatures/hashes/malware_hashes.json")
        try:
            if sig_file.exists():
                with open(sig_file, 'r', encoding='utf-8') as f:
                    self.signatures = json.load(f)
                self.logger.info(f"Loaded {len(self.signatures)} malware signatures")
            else:
                self.logger.warning("No malware signatures file found")
                self.signatures = {}
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing signatures file: {e}")
            self.signatures = {}
        except Exception as e:
            self.logger.error(f"Error loading signatures: {e}")
            self.signatures = {}
    
    def _load_yara_rules(self) -> None:
        """Compile and load YARA rules."""
        yara_dir = Path("signatures/yara")
        try:
            if yara_dir.exists() and any(yara_dir.iterdir()):
                yara_rules = list(yara_dir.glob('*.yar'))
                if yara_rules:
                    self.yara_rules = yara.compile(filepaths={
                        f'rule_{i}': str(rule) for i, rule in enumerate(yara_rules)
                    })
                    self.logger.info(f"Loaded {len(yara_rules)} YARA rules")
                else:
                    self.logger.warning("No YARA rules found in the signatures directory")
            else:
                self.logger.warning("YARA rules directory not found or empty")
        except yara.Error as e:
            self.logger.error(f"Error compiling YARA rules: {e}")
            self.yara_rules = None
        except Exception as e:
            self.logger.error(f"Error loading YARA rules: {e}")
            self.yara_rules = None
    
    def _load_whitelist(self) -> None:
        """Load whitelisted files/directories."""
        whitelist_file = Path("whitelist.txt")
        try:
            if whitelist_file.exists():
                with open(whitelist_file, 'r', encoding='utf-8') as f:
                    self.whitelist = {line.strip() for line in f if line.strip()}
                self.logger.info(f"Loaded {len(self.whitelist)} whitelist entries")
            else:
                self.logger.warning("No whitelist file found")
                self.whitelist = set()
        except Exception as e:
            self.logger.error(f"Error loading whitelist: {e}")
            self.whitelist = set()
    
    def _calculate_file_hash(self, file_path: Union[str, Path]) -> str:
        """Calculate the SHA-256 hash of a file.
        
        Args:
            file_path: Path to the file to hash.
            
        Returns:
            Hex string of the SHA-256 hash.
        """
        file_path = Path(file_path)
        sha256_hash = hashlib.sha256()
        try:
            with file_path.open('rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except (IOError, PermissionError) as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def _scan_with_yara(self, file_path: Union[str, Path]) -> List[str]:
        """Scan a file using YARA rules.
        
        Args:
            file_path: Path to the file to scan.
            
        Returns:
            List of matched YARA rule names.
        """
        if not self.yara_rules:
            return []
            
        try:
            matches = self.yara_rules.match(str(file_path))
            return [match.rule for match in matches]
        except Exception as e:
            self.logger.error(f"YARA scan failed for {file_path}: {e}")
            return []
    
    def _log_scan_result(self, result: ScanResult) -> None:
        """Log the scan result to the scan log.
        
        Args:
            result: ScanResult object to log.
        """
        try:
            log_entry = {
                'timestamp': result.timestamp,
                'file_path': result.file_path,
                'is_infected': result.is_infected,
                'threat_name': result.threat_name,
                'threat_type': result.threat_type,
                'details': result.details
            }
            
            # Ensure the log file exists
            self.scan_log.parent.mkdir(parents=True, exist_ok=True)
            
            # Read existing logs
            logs = []
            if self.scan_log.exists():
                try:
                    with open(self.scan_log, 'r', encoding='utf-8') as f:
                        logs = json.load(f)
                    if not isinstance(logs, list):
                        logs = []
                except (json.JSONDecodeError, Exception):
                    logs = []
            
            # Add new log entry
            logs.append(log_entry)
            
            # Keep only the most recent 1000 entries
            if len(logs) > 1000:
                logs = logs[-1000:]
            
            # Write back to file
            with open(self.scan_log, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to log scan result: {e}")
    
    def scan_file(self, file_path: Union[str, Path]) -> ScanResult:
        """Scan a single file for threats using multiple detection methods.
        
        The scanning process includes:
        1. File existence and accessibility check
        2. Whitelist check
        3. Signature-based detection
        4. YARA rule matching
        5. ML-based detection (if ML model is available)
        
        Args:
            file_path: Path to the file to scan.
            
        Returns:
            ScanResult object with the scan results.
        """
        file_path = Path(file_path).absolute()
        result = ScanResult(file_path=str(file_path))
        
        try:
            # Check if file exists and is accessible
            if not file_path.exists():
                result.details = "File not found"
                self.logger.warning(f"File not found: {file_path}")
                return result
                
            # Skip whitelisted files
            if str(file_path) in self.whitelist:
                result.details = "File is whitelisted"
                self.logger.debug(f"Skipping whitelisted file: {file_path}")
                return result
                
            # 1. Check file hash against known malware signatures
            file_hash = self._calculate_file_hash(file_path)
            if file_hash in self.signatures:
                result.is_infected = True
                result.threat_name = self.signatures[file_hash].get('threat_name', 'Unknown')
                result.threat_type = 'SIGNATURE'
                result.details = f"Matched known malware signature: {result.threat_name}"
                self.logger.warning(f"Malware detected (signature): {file_path} - {result.threat_name}")
                return result
                
            # 2. Check against YARA rules if available
            if self.yara_rules:
                yara_matches = self._scan_with_yara(file_path)
                if yara_matches:
                    result.is_infected = True
                    result.threat_name = ", ".join(yara_matches)
                    result.threat_type = 'YARA'
                    result.details = f"Matched YARA rules: {', '.join(yara_matches)}"
                    self.logger.warning(f"YARA rule match: {file_path} - {result.threat_name}")
                    return result
            
            # 3. Use ML model for detection if available
            if self.ml_model:
                try:
                    features = self.ml_model.extract_features(str(file_path))
                    is_malicious, confidence = self.ml_model.predict(features)
                    
                    if is_malicious:
                        result.is_infected = True
                        result.threat_name = f"ML.Detected (confidence: {confidence:.2f})"
                        result.threat_type = 'ML'
                        result.details = f"ML model detected potential malware with {confidence*100:.1f}% confidence"
                        self.logger.warning(f"ML detection: {file_path} - {result.threat_name}")
                        return result
                        
                except Exception as e:
                    self.logger.error(f"ML detection failed for {file_path}: {e}", exc_info=True)
            
            # If we get here, the file appears to be clean
            result.details = "No threats detected"
            self.logger.debug(f"Clean file: {file_path}")
            return result
            
        except Exception as e:
            error_msg = f"Error scanning {file_path}: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            result.details = f"Error: {str(e)}"
            result.is_infected = False  # Default to not infected on error
            return result
    
    def quarantine_file(self, file_path: Union[str, Path], threat_name: str = "") -> bool:
        """Quarantine a potentially malicious file.
        
        Args:
            file_path: Path to the file to quarantine.
            threat_name: Name of the detected threat.
            
        Returns:
            True if the file was quarantined successfully, False otherwise.
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                self.logger.warning(f"File not found for quarantine: {file_path}")
                return False
                
            # Create a unique filename for the quarantined file
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_filename = f"{timestamp}_{file_path.name}"
            quarantine_path = self.quarantine_dir / 'quarantined' / safe_filename
            
            # Move the file to quarantine
            file_path.rename(quarantine_path)
            
            # Log the quarantine action
            self.logger.info(f"Quarantined {file_path} as {quarantine_path}")
            
            # Create a backup of the file
            backup_path = self.quarantine_dir / 'backup' / safe_filename
            quarantine_path.link_to(backup_path)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to quarantine {file_path}: {e}")
            return False
    
    def start_realtime_monitoring(self, directories: Optional[List[Union[str, Path]]] = None) -> None:
        """Start real-time monitoring of specified directories.
        
        Args:
            directories: List of directories to monitor. If None, uses directories from config.
        """
        if directories:
            self.monitored_dirs.update(str(Path(d).absolute()) for d in directories)
        
        if not self.monitored_dirs:
            self.logger.warning("No directories specified for real-time monitoring")
            return
        
        if self.realtime_monitor and self.realtime_monitor.is_alive():
            self.logger.info("Real-time monitoring is already running")
            return
        
        try:
            # Initialize the real-time monitor
            self.realtime_monitor = RealTimeMonitor(
                model_path=self.config.get('model_path'),
                monitored_dirs=list(self.monitored_dirs),
                callback=self._handle_scan_result,
                scan_extensions=self.config.get('scan_extensions')
            )
            
            # Start monitoring
            self.realtime_monitor.start()
            self.logger.info(f"Started real-time monitoring on {len(self.monitored_dirs)} directories")
            
        except Exception as e:
            self.logger.error(f"Failed to start real-time monitoring: {e}")
            raise
    
    def stop_realtime_monitoring(self) -> None:
        """Stop real-time monitoring."""
        if self.realtime_monitor:
            try:
                self.realtime_monitor.stop()
                self.logger.info("Stopped real-time monitoring")
            except Exception as e:
                self.logger.error(f"Error stopping real-time monitoring: {e}")
    
    def _handle_scan_result(self, file_path: str, result: Dict[str, Any]) -> None:
        """Handle scan results from real-time monitoring with enhanced features.
        
        This method processes scan results, performs threat intelligence lookups,
        handles rate limiting, and takes appropriate actions.
        
        Args:
            file_path: Path to the scanned file.
            result: Dictionary containing scan results with keys:
                - is_malicious: bool indicating if the file is malicious
                - threat_name: str name of the detected threat
                - details: dict with additional scan details
                - confidence: float confidence score (0-1)
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                self.logger.warning(f"File no longer exists: {file_path}")
                return
                
            # Skip files that were recently scanned to prevent duplicate processing
            current_time = time.time()
            if file_path in self._last_scan_times:
                time_since_last_scan = current_time - self._last_scan_times[file_path]
                if time_since_last_scan < 5:  # 5-second cooldown
                    self.logger.debug(f"Skipping recently scanned file: {file_path}")
                    return
            self._last_scan_times[file_path] = current_time
            
            # Check file size limit (100MB)
            file_size = file_path.stat().st_size
            if file_size > 100 * 1024 * 1024:  # 100MB
                self.logger.warning(f"Skipping large file ({(file_size/1024/1024):.2f}MB): {file_path}")
                return
                
            # Create a ScanResult object with enhanced details
            file_hash = self._calculate_file_hash(file_path)
            scan_result = ScanResult(
                file_path=str(file_path),
                is_infected=result.get('is_malicious', False),
                threat_name=result.get('threat_name', ''),
                threat_type=result.get('threat_type', 'UNKNOWN'),
                details={
                    'scan_details': result.get('details', {}),
                    'file_size': file_size,
                    'file_hash': file_hash,
                    'last_modified': file_path.stat().st_mtime,
                    'threat_intel': self._check_threat_intelligence(file_hash, str(file_path))
                }
            )
            
            # Log the result with more context
            self._log_scan_result(scan_result)
            
            # Take action based on threat level
            if scan_result.is_infected:
                threat_level = self._assess_threat_level(scan_result)
                self.logger.warning(
                    f"{threat_level} threat detected: {file_path} - "
                    f"{scan_result.threat_name} (Confidence: {result.get('confidence', 0.0):.1%})"
                )
                
                # Take appropriate action based on threat level
                if threat_level == "HIGH":
                    quarantine_success = self.quarantine_file(
                        file_path, 
                        scan_result.threat_name,
                        additional_metadata={
                            'detection_time': datetime.datetime.now().isoformat(),
                            'threat_level': threat_level,
                            'confidence': result.get('confidence', 0.0)
                        }
                    )
                    if quarantine_success:
                        self._notify_user(
                            "High Threat Contained",
                            f"Malicious file quarantined: {file_path.name}\n"
                            f"Threat: {scan_result.threat_name}\n"
                            f"Location: {file_path}"
                        )
                else:
                    self.logger.info(f"Monitoring potential threat: {file_path}")
                    
        except Exception as e:
            self.logger.error(f"Error handling scan result for {file_path}: {e}", exc_info=True)
            
    def _check_threat_intelligence(self, file_hash: str, file_path: str) -> Dict[str, Any]:
        """Check file hash against threat intelligence sources.
        
        Args:
            file_hash: SHA-256 hash of the file
            file_path: Path to the file for additional context
            
        Returns:
            Dict containing threat intelligence data
        """
        # TODO: Implement actual threat intelligence API calls
        # For now, return a mock response
        return {
            'known_malicious': file_hash in self.signatures,
            'last_seen': datetime.datetime.now().isoformat(),
            'reputation': 'malicious' if file_hash in self.signatures else 'unknown'
        }
        
    def _assess_threat_level(self, scan_result: ScanResult) -> str:
        """Determine the threat level based on scan results.
        
        Args:
            scan_result: ScanResult object with detection details
            
        Returns:
            str: Threat level (LOW, MEDIUM, HIGH)
        """
        # Simple heuristic - can be enhanced with more sophisticated logic
        if scan_result.threat_type == 'SIGNATURE':
            return 'HIGH'
        elif scan_result.threat_type == 'YARA':
            return 'MEDIUM' if 'suspicious' in scan_result.details.get('scan_details', {}) else 'HIGH'
        elif scan_result.threat_type == 'ML':
            confidence = scan_result.details.get('scan_details', {}).get('confidence', 0.0)
            return 'HIGH' if confidence > 0.8 else 'MEDIUM' if confidence > 0.5 else 'LOW'
        return 'LOW'
        
    def _notify_user(self, title: str, message: str, level: str = 'warning') -> None:
        """Send a notification to the user.
        
        Args:
            title: Notification title
            message: Notification message
            level: Notification level (info, warning, error)
        """
        try:
            # On Windows, use toast notifications
            if platform.system() == 'Windows':
                from win10toast import ToastNotifier
                toaster = ToastNotifier()
                toaster.show_toast(
                    title,
                    message,
                    icon_path=None,
                    duration=10,
                    threaded=True
                )
            # On Linux/macOS, use system notifications
            else:
                import subprocess
                if platform.system() == 'Darwin':  # macOS
                    subprocess.run(['osascript', '-e', f'display notification "{message}" with title "{title}"'])
                else:  # Linux
                    subprocess.run(['notify-send', title, message])
                    
            # Also log the notification
            log_func = getattr(self.logger, level.lower(), self.logger.info)
            log_func(f"[{title}] {message}")
            
        except Exception as e:
            self.logger.error(f"Failed to send notification: {e}")
            
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the antivirus engine.
        
        Args:
            config: Optional configuration dictionary with the following keys:
                - model_path: Path to the trained ML model
                - quarantine_dir: Directory for quarantined files
                - scan_log: Path to the scan log file
                - monitored_dirs: List of directories to monitor in real-time
                - scan_extensions: Set of file extensions to scan
        """
        # Initialize configuration
        self.config = config or {}
        
        # Core components
        self.signatures = {}
        self.yara_rules = None
        self.whitelist = set()
        self.scan_queue = queue.Queue()
        self.running = True
        self._last_scan_times = {}
        
        # File system paths
        self.quarantine_dir = Path(self.config.get('quarantine_dir', 'quarantine')).absolute()
        self.scan_log = Path(self.config.get('scan_log', 'scan_log.json')).absolute()
        
        # Real-time monitoring
        self.realtime_monitor = None
        self.monitored_dirs = set(self.config.get('monitored_dirs', []))
        
        # ML model
        self.ml_model = None
        self._init_ml_model()
        
        # Initialize directories and load data
        self._setup_directories()
        self._load_signatures()
        self._load_yara_rules()
        self._load_whitelist()
        
        # Initialize logger
        self.logger = get_logger(__name__)
        
        # Initialize colorama for console output
        init()
    
    def update_signatures(self) -> bool:
        """Update malware signatures from a remote source.
        
        Returns:
            True if the update was successful, False otherwise.
        """
        try:
            # Example: Download signatures from a remote URL
            sig_url = self.config.get('signature_url')
            if not sig_url:
                self.logger.warning("No signature URL configured")
                return False
                
            response = requests.get(sig_url, timeout=30)
            response.raise_for_status()
            
            # Save the signatures
            sig_file = Path("signatures/hashes/malware_hashes.json")
            sig_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(sig_file, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            # Reload signatures
            self._load_signatures()
            self.logger.info("Successfully updated malware signatures")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update signatures: {e}")
            return False
