"""
Behavioral analysis module for detecting suspicious process activities.
"""
import os
import time
import psutil
import threading
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import json
import logging

@dataclass
class ProcessActivity:
    """Tracks process behavior patterns."""
    pid: int
    name: str
    cmdline: str
    parent_pid: int
    children: Set[int] = field(default_factory=set)
    file_operations: List[Dict] = field(default_factory=list)
    registry_operations: List[Dict] = field(default_factory=list)
    network_connections: List[Dict] = field(default_factory=list)
    suspicious_apis: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    is_suspicious: bool = False
    detection_reasons: List[str] = field(default_factory=list)

class BehavioralAnalyzer:
    """Monitors and analyzes process behavior in real-time."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the behavioral analyzer."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.processes: Dict[int, ProcessActivity] = {}
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.known_safe_hashes = self._load_known_hashes()
        self.monitor_thread = None
        self.lock = threading.RLock()
        
    def _load_suspicious_patterns(self) -> Dict:
        """Load patterns of suspicious behavior."""
        patterns_path = Path(__file__).parent / 'data' / 'behavior_patterns.json'
        try:
            if patterns_path.exists():
                with open(patterns_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load behavior patterns: {e}")
        return {
            'suspicious_apis': [
                'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
                'NtCreateThreadEx', 'NtWriteVirtualMemory', 'NtProtectVirtualMemory'
            ],
            'suspicious_file_paths': [
                '\\Windows\\', '\\Program Files\\', '\\ProgramData\\',
                '\\AppData\\', '\\System32\\', '\\SysWOW64\\'
            ]
        }
        
    def _load_known_hashes(self) -> Set[str]:
        """Load hashes of known safe/trusted files."""
        hashes_path = Path(__file__).parent / 'data' / 'known_hashes.json'
        try:
            if hashes_path.exists():
                with open(hashes_path, 'r') as f:
                    return set(json.load(f).get('hashes', []))
        except Exception as e:
            self.logger.error(f"Failed to load known hashes: {e}")
        return set()
    
    def start(self) -> None:
        """Start the behavioral monitoring."""
        if self.running:
            return
            
        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_processes,
            daemon=True
        )
        self.monitor_thread.start()
        self.logger.info("Behavioral monitoring started")
        
    def stop(self) -> None:
        """Stop the behavioral monitoring."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.logger.info("Behavioral monitoring stopped")
        
    def _monitor_processes(self) -> None:
        """Main monitoring loop for process activities."""
        while self.running:
            try:
                self._update_process_list()
                self._analyze_process_behavior()
                time.sleep(1)  # Adjust based on performance needs
            except Exception as e:
                self.logger.error(f"Error in process monitoring: {e}")
                time.sleep(5)
                
    def _update_process_list(self) -> None:
        """Update the list of running processes."""
        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'ppid']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                
                if pid not in self.processes:
                    # New process detected
                    self._handle_new_process(proc)
                else:
                    # Update existing process
                    self.processes[pid].last_seen = time.time()
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        # Clean up terminated processes
        dead_pids = set(self.processes.keys()) - current_pids
        for pid in dead_pids:
            self.processes.pop(pid, None)
            
    def _handle_new_process(self, proc: psutil.Process) -> None:
        """Handle a newly detected process."""
        try:
            info = proc.info
            cmdline = ' '.join(info['cmdline']) if info['cmdline'] else info['name']
            
            process = ProcessActivity(
                pid=info['pid'],
                name=info['name'],
                cmdline=cmdline,
                parent_pid=info['ppid']
            )
            
            # Check if parent process is known
            if info['ppid'] in self.processes:
                self.processes[info['ppid']].children.add(info['pid'])
                
            # Initial risk assessment
            self._assess_process_risk(process)
            
            with self.lock:
                self.processes[info['pid']] = process
                
        except Exception as e:
            self.logger.error(f"Error handling new process {proc.pid}: {e}")
            
    def _assess_process_risk(self, process: ProcessActivity) -> None:
        """Assess the risk level of a process."""
        risk_factors = []
        
        # Check process path
        try:
            exe_path = psutil.Process(process.pid).exe()
            if not self._is_trusted_path(exe_path):
                risk_factors.append("Untrusted executable path")
                process.risk_score += 20
                
            # Check file hash
            if not self._is_known_safe(exe_path):
                risk_factors.append("Unknown file hash")
                process.risk_score += 10
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
        # Check command line for suspicious patterns
        if self._check_suspicious_cmdline(process.cmdline):
            risk_factors.append("Suspicious command line arguments")
            process.risk_score += 30
            
        # Check for code injection patterns
        if self._check_code_injection(process):
            risk_factors.append("Possible code injection detected")
            process.risk_score += 50
            
        # Update process status
        if risk_factors:
            process.is_suspicious = True
            process.detection_reasons.extend(risk_factors)
            self.logger.warning(
                f"Suspicious process detected (PID: {process.pid}, "
                f"Score: {process.risk_score}): {process.name}"
            )
            
    def _is_trusted_path(self, path: str) -> bool:
        """Check if a file path is in a trusted location."""
        if not path:
            return False
            
        trusted_paths = [
            'C:\\Windows\\',
            'C:\\Program Files\\',
            'C:\\Program Files (x86)\\',
            'C:\\ProgramData\\',
        ]
        
        path = path.lower()
        return any(p.lower() in path for p in trusted_paths)
        
    def _is_known_safe(self, file_path: str) -> bool:
        """Check if a file's hash is in the known safe list."""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                return file_hash in self.known_safe_hashes
        except Exception:
            return False
            
    def _check_suspicious_cmdline(self, cmdline: str) -> bool:
        """Check command line for suspicious patterns."""
        suspicious_terms = [
            '-e', 'iex', 'Invoke-Expression', 'Start-Process',
            'powershell -nop', 'cmd /c', 'certutil -f', 'bitsadmin',
            'regsvr32 /s /n /u /i:', 'mshta', 'wscript.shell',
            'shell.application', 'wshshell.run'
        ]
        
        cmdline = cmdline.lower()
        return any(term in cmdline for term in suspicious_terms)
        
    def _check_code_injection(self, process: ProcessActivity) -> bool:
        """Check for signs of code injection."""
        # This is a simplified check - in practice, you'd use more sophisticated detection
        suspicious_apis = self.suspicious_patterns.get('suspicious_apis', [])
        return any(api in str(process.cmdline).lower() for api in suspicious_apis)
    
    def _analyze_process_behavior(self) -> None:
        """Analyze running processes for suspicious behavior."""
        with self.lock:
            for pid, process in list(self.processes.items()):
                try:
                    self._check_process_behavior(process)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    self.processes.pop(pid, None)
                    
    def _check_process_behavior(self, process: ProcessActivity) -> None:
        """Check a single process for suspicious behavior."""
        # Check for suspicious memory regions
        self._check_memory_regions(process)
        
        # Check for suspicious network connections
        self._check_network_connections(process)
        
        # Check for suspicious file operations
        self._check_file_operations(process)
        
        # Update risk score based on behavior
        self._update_risk_score(process)
        
    def _check_memory_regions(self, process: ProcessActivity) -> None:
        """Check for suspicious memory regions (e.g., RWX pages)."""
        # This is platform-specific and requires additional permissions
        # For Windows, you'd use the Windows API via ctypes or a similar approach
        pass
        
    def _check_network_connections(self, process: ProcessActivity) -> None:
        """Check for suspicious network connections."""
        try:
            proc = psutil.Process(process.pid)
            for conn in proc.connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    # Check for connections to suspicious IPs/ports
                    if self._is_suspicious_connection(conn):
                        process.network_connections.append({
                            'remote_ip': conn.raddr[0] if conn.raddr else None,
                            'remote_port': conn.raddr[1] if conn.raddr else None,
                            'status': conn.status,
                            'timestamp': time.time()
                        })
                        process.risk_score += 20
                        process.is_suspicious = True
                        
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    def _is_suspicious_connection(self, conn) -> bool:
        """Determine if a network connection is suspicious."""
        # Check for connections to known bad IPs or unusual ports
        suspicious_ports = [
            4444,  # Common C2 port
            8080,  # Common C2 over HTTP
            53,    # DNS tunneling
            22,    # SSH
            3389,  # RDP
            5900,  # VNC
        ]
        
        if conn.raddr and conn.raddr[1] in suspicious_ports:
            return True
            
        # Add more sophisticated checks here (e.g., DNS lookups, IP reputation)
        return False
        
    def _check_file_operations(self, process: ProcessActivity) -> None:
        """Check for suspicious file operations."""
        # This would typically use a file system filter driver or similar
        # For now, we'll just log file opens
        try:
            proc = psutil.Process(process.pid)
            for file in proc.open_files():
                if self._is_suspicious_file_operation(file.path):
                    process.file_operations.append({
                        'path': file.path,
                        'mode': 'read',  # Simplified
                        'timestamp': time.time()
                    })
                    process.risk_score += 10
                    process.is_suspicious = True
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    def _is_suspicious_file_operation(self, file_path: str) -> bool:
        """Check if a file operation is suspicious."""
        suspicious_paths = self.suspicious_patterns.get('suspicious_file_paths', [])
        return any(p.lower() in file_path.lower() for p in suspicious_paths)
        
    def _update_risk_score(self, process: ProcessActivity) -> None:
        """Update the risk score based on recent behavior."""
        # Decay the risk score over time
        time_since_last_update = time.time() - process.last_seen
        decay_factor = max(0, 1 - (time_since_last_update / 3600))  # Decay over 1 hour
        process.risk_score *= decay_factor
        
        # Mark as suspicious if score exceeds threshold
        if process.risk_score > 50 and not process.is_suspicious:
            process.is_suspicious = True
            self.logger.warning(
                f"Process {process.name} (PID: {process.pid}) "
                f"marked as suspicious (Score: {process.risk_score:.1f})"
            )
            
    def get_suspicious_processes(self) -> List[Dict]:
        """Get a list of currently suspicious processes."""
        with self.lock:
            return [
                {
                    'pid': p.pid,
                    'name': p.name,
                    'cmdline': p.cmdline,
                    'risk_score': p.risk_score,
                    'reasons': p.detection_reasons,
                    'file_operations': p.file_operations[-10:],  # Last 10 file ops
                    'network_connections': p.network_connections[-10:],  # Last 10 connections
                    'duration': time.time() - p.start_time
                }
                for p in self.processes.values()
                if p.is_suspicious and p.risk_score > 30
            ]
            
    def terminate_process(self, pid: int) -> bool:
        """Terminate a suspicious process."""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            self.logger.warning(f"Terminated suspicious process (PID: {pid})")
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.error(f"Failed to terminate process {pid}: {e}")
            return False
