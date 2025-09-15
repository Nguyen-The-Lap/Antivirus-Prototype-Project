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
from typing import List, Dict, Tuple, Optional, Callable, Set
from dataclasses import dataclass, field
from pathlib import Path
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

@dataclass
class ScanResult:
    file_path: str
    is_infected: bool = False
    threat_name: str = ""
    threat_type: str = ""
    details: str = ""
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())

class AdvancedAntivirusEngine:
    def __init__(self):
        self.signatures = {}
        self.yara_rules = None
        self.quarantine_dir = Path("quarantine").absolute()
        self.scan_log = Path("scan_log.json").absolute()
        self.suspicious_patterns = [
            b'MZ',  # Windows executable
            b'This program cannot be run in DOS mode',
            b'CreateFile', 'ReadFile', 'WriteFile',  # Common API calls
            b'http://', b'https://',  # Network connections
            b'GetProcAddress', 'LoadLibrary',  # Dynamic loading
        ]
        self.suspicious_extensions = {
            '.exe', '.dll', '.sys', '.bat', '.vbs',
            '.ps1', '.js', '.jse', '.vbe', '.wsf',
            '.wsh', '.msc', '.msi', '.msp', '.mst'
        }
        self.whitelist = set()
        self.running = True
        self.scan_queue = queue.Queue()
        self.realtime_monitoring = False
        self.monitored_dirs = set()
        self.observer = None
        self._setup_directories()
        self._load_signatures()
        self._load_yara_rules()
        self._load_whitelist()
        init()  # Initialize colorama
        
    def _setup_directories(self):
        """Create necessary directories if they don't exist"""
        self.quarantine_dir.mkdir(exist_ok=True)
        
        # Create required subdirectories
        (self.quarantine_dir / 'suspicious').mkdir(exist_ok=True)
        (self.quarantine_dir / 'quarantined').mkdir(exist_ok=True)
        (self.quarantine_dir / 'backup').mkdir(exist_ok=True)
        
        # Create signature directories
        sig_dir = Path("signatures")
        sig_dir.mkdir(exist_ok=True)
        (sig_dir / 'yara').mkdir(exist_ok=True)
        (sig_dir / 'hashes').mkdir(exist_ok=True)
    
    def _load_signatures(self):
        """Load malware signatures from file"""
        sig_file = Path("signatures/hashes/malware_hashes.json")
        if sig_file.exists():
            try:
                with open(sig_file, 'r') as f:
                    self.signatures = json.load(f)
            except json.JSONDecodeError:
                self.signatures = {}
    
    def _load_yara_rules(self):
        """Compile and load YARA rules"""
        yara_dir = Path("signatures/yara")
        if yara_dir.exists() and any(yara_dir.iterdir()):
            try:
                yara_rules = []
                for rule_file in yara_dir.glob('*.yar'):
                    yara_rules.append(str(rule_file))
                if yara_rules:
                    self.yara_rules = yara.compile(filepaths={
                        f'rule_{i}': str(rule) for i, rule in enumerate(yara_rules)
                    })
            except yara.Error as e:
                print(f"Error loading YARA rules: {e}")
    
    def _load_whitelist(self):
        """Load whitelisted files/directories"""
        whitelist_file = Path("whitelist.txt")
        if whitelist_file.exists():
            with open(whitelist_file, 'r') as f:
                self.whitelist = {line.strip() for line in f if line.strip()}
    
    def calculate_file_hash(self, file_path: Union[str, Path], hash_type: str = 'sha256') -> str:
        """Calculate file hash using specified algorithm"""
        file_path = Path(file_path)
        if not file_path.is_file():
            return ""
            
        hash_func = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }.get(hash_type.lower(), hashlib.sha256)
        
        h = hash_func()
        try:
            with file_path.open('rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (IOError, PermissionError) as e:
            print(f"{Fore.RED}Error calculating hash for {file_path}: {e}{Style.RESET_ALL}")
            return ""

    def scan_file(self, file_path: Union[str, Path]) -> ScanResult:
        """Scan a single file for threats using multiple detection methods"""
        file_path = Path(file_path)
        result = ScanResult(file_path=str(file_path))
        
        if not file_path.exists():
            result.details = "File not found"
            return result
            
        # Skip whitelisted files
        if str(file_path) in self.whitelist:
            result.details = "File is whitelisted"
            return result
            
        try:
            # 1. Check file hash against known malware
            file_hash = self.calculate_file_hash(file_path)
            if file_hash in self.signatures:
                result.is_infected = True
                result.threat_name = self.signatures[file_hash].get('name', 'Unknown')
                result.threat_type = self.signatures[file_path].get('type', 'Virus')
                result.details = f"Known malicious file: {result.threat_name}"
                return result
            
            # 2. Check file extension against suspicious extensions
            if file_path.suffix.lower() in self.suspicious_extensions:
                result.details = f"Suspicious file extension: {file_path.suffix}"
                result.threat_type = "Suspicious"
            
            # 3. Check file content for suspicious patterns
            if self._check_suspicious_content(file_path):
                result.is_infected = True
                result.threat_type = "Heuristic"
                result.details = "File contains suspicious patterns"
                return result
            
            # 4. YARA rules scanning
            if self.yara_rules:
                try:
                    matches = self.yara_rules.match(str(file_path))
                    if matches:
                        result.is_infected = True
                        result.threat_name = ", ".join(m.rule for m in matches)
                        result.threat_type = "YARA"
                        result.details = f"YARA rule match: {result.threat_name}"
                        return result
                except Exception as e:
                    print(f"{Fore.YELLOW}YARA scan error for {file_path}: {e}{Style.RESET_ALL}")
            
            # 5. PE file analysis for executables
            if file_path.suffix.lower() in ['.exe', '.dll', '.sys']:
                pe_result = self._analyze_pe_file(file_path)
                if pe_result.is_infected:
                    return pe_result
            
            # If we get here, the file appears clean
            result.details = "File appears to be clean"
            return result
            
        except Exception as e:
            result.details = f"Scan error: {str(e)}"
            return result
    
    def _check_suspicious_content(self, file_path: Path) -> bool:
        """Check file content for suspicious patterns"""
        try:
            # Only check first 1MB of file for performance
            with file_path.open('rb') as f:
                content = f.read(1024 * 1024)
                
                # Check for suspicious strings
                for pattern in self.suspicious_patterns:
                    if isinstance(pattern, str):
                        pattern = pattern.encode('utf-8')
                    if pattern in content:
                        return True
                        
                # Check for high entropy (potential packed/encrypted content)
                if self._calculate_entropy(content) > 7.0:
                    return True
                    
        except Exception:
            pass
            
        return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate the Shannon entropy of a byte string"""
        if not data:
            return 0.0
            
        entropy = 0.0
        counter = {}
        
        for byte in data:
            counter[byte] = counter.get(byte, 0) + 1
            
        for count in counter.values():
            p = count / len(data)
            entropy -= p * (p and math.log(p, 2))
            
        return entropy
    
    def _analyze_pe_file(self, file_path: Path) -> ScanResult:
        """Analyze PE (Portable Executable) files for suspicious characteristics"""
        result = ScanResult(file_path=str(file_path))
        
        try:
            pe = pefile.PE(str(file_path), fast_load=True)
            
            # Check for common malware characteristics
            suspicious_sections = [
                '.text', '.rdata', '.data', '.rsrc', '.reloc',
                '.crt', '.tls', '.pdata', '.didat', '.edata',
                '.idata', '.msvcjme', '.ndata'
            ]
            
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                if section_name not in suspicious_sections:
                    result.is_infected = True
                    result.threat_type = "PE Analysis"
                    result.details = f"Suspicious section name: {section_name}"
                    return result
                
                # Check section characteristics
                if section.Characteristics & 0xE0000020:  # EXECUTE | READ | WRITE
                    result.is_infected = True
                    result.threat_type = "PE Analysis"
                    result.details = "Suspicious section permissions (RWX)"
                    return result
            
            # Check imports for suspicious APIs
            suspicious_imports = {
                'kernel32.dll': ['CreateRemoteThread', 'WriteProcessMemory', 'LoadLibraryA'],
                'advapi32.dll': ['RegSetValueExA', 'RegSetValueExW'],
                'ws2_32.dll': ['socket', 'connect', 'send', 'recv']
            }
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8').lower()
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8')
                            if dll_name in suspicious_imports and func_name in suspicious_imports[dll_name]:
                                result.is_infected = True
                                result.threat_type = "PE Analysis"
                                result.details = f"Suspicious import: {dll_name}!{func_name}"
                                return result
            
            # Check for packers/obfuscators
            packers = self._detect_packers(pe)
            if packers:
                result.is_infected = True
                result.threat_type = "Packer"
                result.details = f"Possible packer detected: {', '.join(packers)}"
                return result
                
        except Exception as e:
            # If we can't parse the PE, it might be packed or corrupted
            result.is_infected = True
            result.threat_type = "PE Analysis"
            result.details = f"Malformed PE file: {str(e)}"
            return result
            
        return result
    
    def _detect_packers(self, pe) -> List[str]:
        """Detect common packers and protectors"""
        packers = []
        
        # Check section names
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
            if 'upx' in section_name.lower():
                packers.append('UPX')
            elif 'aspack' in section_name.lower():
                packers.append('ASPack')
            elif 'fsg' in section_name.lower():
                packers.append('FSG')
                
        # Check entry point section name
        if hasattr(pe, 'get_section_by_rva'):
            try:
                ep_section = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                if ep_section:
                    section_name = ep_section.Name.decode('utf-8', 'ignore').strip('\x00')
                    if '.text' not in section_name and '.code' not in section_name:
                        packers.append('Entry point in non-standard section')
            except:
                pass
                
        return list(set(packers))  # Remove duplicates
    
    def scan_directory(self, directory_path: Union[str, Path], recursive: bool = True, 
                      max_workers: int = 4) -> Dict[str, Dict]:
        """Scan all files in a directory with parallel processing"""
        directory_path = Path(directory_path)
        results = {}
        
        if not directory_path.exists():
            return {"error": f"Directory not found: {directory_path}"}
            
        # Get all files to scan
        files_to_scan = []
        if recursive:
            files_to_scan = [f for f in directory_path.rglob('*') if f.is_file()]
        else:
            files_to_scan = [f for f in directory_path.iterdir() if f.is_file()]
        
        # Process files in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(self.scan_file, file_path): file_path 
                for file_path in files_to_scan
            }
            
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    results[str(file_path)] = {
                        'infected': result.is_infected,
                        'threat_name': result.threat_name,
                        'threat_type': result.threat_type,
                        'details': result.details,
                        'timestamp': result.timestamp
                    }
                    
                    # Log the result
                    self._log_scan_result(result)
                    
                except Exception as e:
                    results[str(file_path)] = {
                        'error': str(e),
                        'timestamp': datetime.datetime.now().isoformat()
                    }
        
        return results
    
    def quarantine_file(self, file_path: Union[str, Path], move: bool = True) -> bool:
        """Quarantine a suspicious file by moving or copying it to quarantine"""
        file_path = Path(file_path)
        if not file_path.exists():
            return False
            
        try:
            # Create quarantine directory if it doesn't exist
            quarantine_dir = self.quarantine_dir / 'quarantined'
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            
            # Create a unique filename with timestamp and original path
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = f"{timestamp}_{file_path.name}"
            quarantine_path = quarantine_dir / safe_name
            
            # Create a backup before moving
            backup_dir = self.quarantine_dir / 'backup'
            backup_dir.mkdir(exist_ok=True)
            backup_path = backup_dir / f"{timestamp}_{file_path.name}"
            
            try:
                # Try to create a backup first
                import shutil
                shutil.copy2(file_path, backup_path)
                
                # Then move or copy the file
                if move:
                    shutil.move(file_path, quarantine_path)
                else:
                    shutil.copy2(file_path, quarantine_path)
                    
                # Log the quarantine action
                with open(self.quarantine_dir / 'quarantine_log.txt', 'a') as log:
                    log.write(f"{datetime.datetime.now().isoformat()}|{file_path}|{quarantine_path}\n")
                
                return True
                
            except Exception as e:
                print(f"{Fore.RED}Error during quarantine operation: {e}{Style.RESET_ALL}")
                # Try to restore from backup if move failed
                if backup_path.exists() and not file_path.exists():
                    shutil.move(backup_path, file_path)
                return False
                
        except Exception as e:
            print(f"{Fore.RED}Error quarantining file {file_path}: {e}{Style.RESET_ALL}")
            return False
    
    def _log_scan_result(self, result: ScanResult):
        """Log scan results to a JSON file"""
        log_entry = {
            'timestamp': result.timestamp,
            'file_path': result.file_path,
            'infected': result.is_infected,
            'threat_name': result.threat_name,
            'threat_type': result.threat_type,
            'details': result.details
        }
        
        try:
            # Create log file if it doesn't exist
            if not self.scan_log.exists():
                with open(self.scan_log, 'w') as f:
                    json.dump([], f)
            
            # Read existing logs
            with open(self.scan_log, 'r+') as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []
                
                # Add new log entry
                logs.append(log_entry)
                
                # Keep only the last 1000 entries
                if len(logs) > 1000:
                    logs = logs[-1000:]
                
                # Write back to file
                f.seek(0)
                json.dump(logs, f, indent=2)
                f.truncate()
                
        except Exception as e:
            print(f"{Fore.RED}Error writing to log file: {e}{Style.RESET_ALL}")
    
    def start_realtime_monitoring(self, directories: List[Union[str, Path]]):
        """Start real-time file system monitoring"""
        if self.observer and self.observer.is_alive():
            print(f"{Fore.YELLOW}Real-time monitoring is already running{Style.RESET_ALL}")
            return
            
        class FileEventHandler(FileSystemEventHandler):
            def __init__(self, callback):
                self.callback = callback
                
            def on_created(self, event):
                if not event.is_directory:
                    self.callback(event.src_path)
                    
            def on_modified(self, event):
                if not event.is_directory:
                    self.callback(event.src_path)
        
        self.realtime_monitoring = True
        self.observer = Observer()
        
        for directory in directories:
            directory = Path(directory)
            if directory.exists() and directory.is_dir():
                self.monitored_dirs.add(str(directory))
                self.observer.schedule(
                    FileEventHandler(self._handle_realtime_event),
                    str(directory),
                    recursive=True
                )
        
        if self.monitored_dirs:
            self.observer.start()
            print(f"{Fore.GREEN}Started real-time monitoring on: {', '.join(self.monitored_dirs)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}No valid directories to monitor{Style.RESET_ALL}")
    
    def stop_realtime_monitoring(self):
        """Stop real-time file system monitoring"""
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
            self.realtime_monitoring = False
            print(f"{Fore.GREEN}Stopped real-time monitoring{Style.RESET_ALL}")
    
    def _handle_realtime_event(self, file_path: str):
        """Handle file system events in real-time"""
        try:
            # Skip temporary files and system files
            if any(x in file_path.lower() for x in ['~$', '.tmp', 'temp', 'tmp']):
                return
                
            # Skip whitelisted files
            if file_path in self.whitelist:
                return
                
            # Scan the file
            result = self.scan_file(file_path)
            
            # Take action if threat is detected
            if result.is_infected:
                print(f"{Fore.RED}ALERT: Malicious file detected: {file_path}{Style.RESET_ALL}")
                print(f"Threat: {result.threat_name} ({result.threat_type})")
                print(f"Details: {result.details}")
                
                # Auto-quarantine the file
                if self.quarantine_file(file_path):
                    print(f"{Fore.GREEN}File quarantined successfully{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Failed to quarantine file{Style.RESET_ALL}")
                    
        except Exception as e:
            print(f"{Fore.RED}Error handling real-time event: {e}{Style.RESET_ALL}")
    
    def update_signatures(self) -> bool:
        """Update virus signatures from a remote source"""
        try:
            # In a real implementation, this would download signatures from a security provider
            print(f"{Fore.CYAN}Updating virus signatures...{Style.RESET_ALL}")
            
            # Example: Download YARA rules from a repository
            yara_url = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
            response = requests.get(yara_url, timeout=30)
            
            if response.status_code == 200:
                # Extract and save YARA rules
                import zipfile
                import io
                
                with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                    zip_ref.extractall("signatures/yara")
                
                # Reload YARA rules
                self._load_yara_rules()
                
                print(f"{Fore.GREEN}Virus signatures updated successfully{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}Failed to download signatures: HTTP {response.status_code}{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}Error updating signatures: {e}{Style.RESET_ALL}")
            return False)


def print_banner():
    """Print the antivirus banner"""
    banner = f"""
    {Fore.CYAN}╔══════════════════════════════════════════════════╗
    ║{Fore.WHITE}               ADVANCED ANTIVIRUS SCANNER           {Fore.CYAN}║
    ║{Fore.WHITE}         Multi-Engine Threat Detection System        {Fore.CYAN}║
    ╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def print_menu():
    """Print the main menu"""
    menu = f"""
    {Fore.CYAN}╔══════════════════════════════════════════════════╗
    ║{Fore.WHITE}                   MAIN MENU                      {Fore.CYAN}║
    ╠══════════════════════════════════════════════════╣
    ║{Fore.WHITE} 1. Scan a file                                  {Fore.CYAN}║
    ║{Fore.WHITE} 2. Scan a directory                             {Fore.CYAN}║
    ║{Fore.WHITE} 3. Start real-time monitoring                   {Fore.CYAN}║
    ║{Fore.WHITE} 4. Stop real-time monitoring                    {Fore.CYAN}║
    ║{Fore.WHITE} 5. View scan log                                {Fore.CYAN}║
    ║{Fore.WHITE} 6. Update virus signatures                      {Fore.CYAN}║
    ║{Fore.WHITE} 7. Quarantine management                        {Fore.CYAN}║
    ║{Fore.WHITE} 8. Exit                                        {Fore.CYAN}║
    ╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(menu)

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_status(message: str, status: str = "info"):
    """Print a status message with color coding"""
    colors = {
        'info': Fore.CYAN,
        'success': Fore.GREEN,
        'warning': Fore.YELLOW,
        'error': Fore.RED
    }
    print(f"{colors.get(status, Fore.WHITE)}[•] {message}{Style.RESET_ALL}")

def main():
    """Main entry point for the antivirus program"""
    clear_screen()
    print_banner()
    
    # Initialize the antivirus engine
    try:
        av = AdvancedAntivirusEngine()
        print_status("Antivirus engine initialized successfully", "success")
    except Exception as e:
        print_status(f"Failed to initialize antivirus engine: {e}", "error")
        return
    
    # Main loop
    while True:
        try:
            print_menu()
            choice = input(f"{Fore.CYAN}Enter your choice (1-8): {Style.RESET_ALL}")
            
            if choice == '1':  # Scan file
                file_path = input("\nEnter the path to the file to scan: ").strip('"')
                if not file_path:
                    print_status("No file path provided", "warning")
                    continue
                    
                print_status(f"\nScanning file: {file_path}")
                start_time = time.time()
                result = av.scan_file(file_path)
                elapsed = time.time() - start_time
                
                if result.is_infected:
                    print(f"\n{Fore.RED}╔══════════════════════════════════════════════════╗")
                    print(f"║{' ' * 54}║")
                    print(f"║{Fore.WHITE}  MALWARE DETECTED!{' ' * 35}{Fore.RED}║")
                    print(f"║{' ' * 54}║")
                    print(f"║{Fore.WHITE}  File: {file_path[:43]:<47}{Fore.RED}║")
                    print(f"║{Fore.WHITE}  Threat: {result.threat_name:<45}{Fore.RED}║")
                    print(f"║{Fore.WHITE}  Type: {result.threat_type:<47}{Fore.RED}║")
                    print(f"║{Fore.WHITE}  Details: {result.details[:43]:<44}{Fore.RED}║")
                    print(f"║{' ' * 54}║")
                    print(f"║{Fore.WHITE}  Scan time: {elapsed:.2f} seconds{' ' * 29}{Fore.RED}║")
                    print(f"║{' ' * 54}║")
                    print(f"╚══════════════════════════════════════════════════╝{Style.RESET_ALL}")
                    
                    action = input(f"\n{Fore.YELLOW}Quarantine this file? (y/n): {Style.RESET_ALL}").lower()
                    if action == 'y':
                        if av.quarantine_file(file_path):
                            print_status("File quarantined successfully", "success")
                        else:
                            print_status("Failed to quarantine file", "error")
                else:
                    print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════╗")
                    print(f"║{' ' * 54}║")
                    print(f"║{Fore.WHITE}  FILE IS CLEAN{' ' * 39}{Fore.GREEN}║")
                    print(f"║{' ' * 54}║")
                    print(f"║{Fore.WHITE}  File: {file_path[:43]:<47}{Fore.GREEN}║")
                    print(f"║{Fore.WHITE}  Details: {result.details[:43]:<44}{Fore.GREEN}║")
                    print(f"║{Fore.WHITE}  Scan time: {elapsed:.2f} seconds{' ' * 29}{Fore.GREEN}║")
                    print(f"║{' ' * 54}║")
                    print(f"╚══════════════════════════════════════════════════╝{Style.RESET_ALL}")
                
            elif choice == '2':  # Scan directory
                dir_path = input("\nEnter the directory path to scan: ").strip('"')
                if not dir_path:
                    print_status("No directory path provided", "warning")
                    continue
                    
                recursive = input("Scan subdirectories? (y/n): ").lower() == 'y'
                max_workers = input("Enter number of parallel scans (default 4): ")
                max_workers = int(max_workers) if max_workers.isdigit() else 4
                
                print_status(f"\nScanning directory: {dir_path}")
                if recursive:
                    print_status("Recursive scan: ENABLED")
                else:
                    print_status("Recursive scan: DISABLED")
                print_status(f"Parallel workers: {max_workers}")
                
                start_time = time.time()
                results = av.scan_directory(dir_path, recursive=recursive, max_workers=max_workers)
                elapsed = time.time() - start_time
                
                # Count results
                total_files = len(results)
                infected_files = sum(1 for r in results.values() if r.get('infected', False))
                
                print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════╗")
                print(f"║{' ' * 54}║")
                print(f"║{Fore.WHITE}  SCAN COMPLETE{' ' * 39}{Fore.CYAN}║")
                print(f"║{' ' * 54}║")
                print(f"║{Fore.WHITE}  Directory: {dir_path[:42]:<41}{Fore.CYAN}║")
                print(f"║{Fore.WHITE}  Files scanned: {total_files:<37}{Fore.CYAN}║")
                print(f"║{Fore.RED}  Threats found: {infected_files:<37}{Fore.CYAN}║")
                print(f"║{Fore.WHITE}  Scan time: {elapsed:.2f} seconds{' ' * 29}{Fore.CYAN}║")
                print(f"║{' ' * 54}║")
                print(f"╚══════════════════════════════════════════════════╝{Style.RESET_ALL}")
                
                if infected_files > 0:
                    action = input(f"\n{Fore.YELLOW}View detailed results? (y/n): {Style.RESET_ALL}").lower()
                    if action == 'y':
                        for file, result in results.items():
                            if result.get('infected', False):
                                print(f"\n{Fore.RED}Threat found:{Style.RESET_ALL}")
                                print(f"File: {file}")
                                print(f"Threat: {result.get('threat_name', 'Unknown')}")
                                print(f"Type: {result.get('threat_type', 'Unknown')}")
                                print(f"Details: {result.get('details', 'No details')}")
                
            elif choice == '3':  # Start real-time monitoring
                paths = input("\nEnter directories to monitor (comma-separated): ").strip('"')
                if not paths:
                    print_status("No directories provided", "warning")
                    continue
                    
                directories = [p.strip() for p in paths.split(',') if p.strip()]
                av.start_realtime_monitoring(directories)
                
            elif choice == '4':  # Stop real-time monitoring
                av.stop_realtime_monitoring()
                
            elif choice == '5':  # View scan log
                try:
                    with open(av.scan_log, 'r') as f:
                        logs = json.load(f)
                        
                    if not logs:
                        print_status("Scan log is empty", "warning")
                        continue
                        
                    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════╗")
                    print(f"║{' ' * 54}║")
                    print(f"║{Fore.WHITE}  SCAN LOG ({len(logs)} entries){' ' * 34}{Fore.CYAN}║")
                    print(f"╚══════════════════════════════════════════════════╝{Style.RESET_ALL}")
                    
                    for log in logs[-10:]:  # Show last 10 entries
                        status = f"{Fore.RED}INFECTED" if log['infected'] else f"{Fore.GREEN}CLEAN"
                        print(f"\n{status}{Style.RESET_ALL} - {log['timestamp']}")
                        print(f"File: {log['file_path']}")
                        if log['infected']:
                            print(f"Threat: {log.get('threat_name', 'Unknown')} ({log.get('threat_type', 'Unknown')})")
                        print(f"Details: {log.get('details', 'No details')}")
                    
                except FileNotFoundError:
                    print_status("No scan log found", "warning")
                except json.JSONDecodeError:
                    print_status("Error reading scan log", "error")
                
            elif choice == '6':  # Update signatures
                print_status("Updating virus signatures...")
                if av.update_signatures():
                    print_status("Virus signatures updated successfully", "success")
                else:
                    print_status("Failed to update virus signatures", "error")
                    
            elif choice == '7':  # Quarantine management
                self._show_quarantine_menu(av)
                
            elif choice == '8':  # Exit
                if hasattr(av, 'realtime_monitoring') and av.realtime_monitoring:
                    av.stop_realtime_monitoring()
                print_status("Exiting...", "info")
                break
                
            else:
                print_status("Invalid choice. Please try again.", "warning")
                
            input("\nPress Enter to continue...")
            clear_screen()
            
        except KeyboardInterrupt:
            print("\n")
            if input("Do you want to exit? (y/n): ").lower() == 'y':
                if hasattr(av, 'realtime_monitoring') and av.realtime_monitoring:
                    av.stop_realtime_monitoring()
                break
            clear_screen()
            
        except Exception as e:
            print_status(f"An error occurred: {e}", "error")
            import traceback
            traceback.print_exc()
            input("\nPress Enter to continue...")
            clear_screen()

def _show_quarantine_menu(self, av):
    """Display the quarantine management menu"""
    while True:
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════╗")
        print(f"║{Fore.WHITE}               QUARANTINE MANAGEMENT             {Fore.CYAN}║")
        print(f"╠══════════════════════════════════════════════════╣")
        print(f"║{Fore.WHITE} 1. View quarantined files                      {Fore.CYAN}║")
        print(f"║{Fore.WHITE} 2. Restore file from quarantine                {Fore.CYAN}║")
        print(f"║{Fore.WHITE} 3. Delete quarantined file                     {Fore.CYAN}║")
        print(f"║{Fore.WHITE} 4. Back to main menu                           {Fore.CYAN}║")
        print(f"╚══════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        choice = input(f"{Fore.CYAN}Enter your choice (1-4): {Style.RESET_ALL}")
        
        if choice == '1':
            self._list_quarantined_files(av)
        elif choice == '2':
            self._restore_quarantined_file(av)
        elif choice == '3':
            self._delete_quarantined_file(av)
        elif choice == '4':
            break
        else:
            print_status("Invalid choice. Please try again.", "warning")

def _list_quarantined_files(self, av):
    """List all files in quarantine"""
    quarantine_dir = av.quarantine_dir / 'quarantined'
    if not quarantine_dir.exists() or not any(quarantine_dir.iterdir()):
        print_status("No files in quarantine", "info")
        return
        
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════╗")
    print(f"║{Fore.WHITE}              QUARANTINED FILES                {Fore.CYAN}║")
    print(f"╠══════════════════════════════════════════════════╣")
    
    for i, file_path in enumerate(quarantine_dir.iterdir(), 1):
        print(f"║{Fore.WHITE} {i}. {file_path.name:<50}{Fore.CYAN}║")
    
    print(f"╚══════════════════════════════════════════════════╝{Style.RESET_ALL}")

def _restore_quarantined_file(self, av):
    """Restore a file from quarantine"""
    quarantine_dir = av.quarantine_dir / 'quarantined'
    if not quarantine_dir.exists() or not any(quarantine_dir.iterdir()):
        print_status("No files in quarantine to restore", "info")
        return
        
    self._list_quarantined_files(av)
    
    try:
        file_num = int(input("\nEnter the number of the file to restore (0 to cancel): "))
        if file_num == 0:
            return
            
        files = list(quarantine_dir.iterdir())
        if 1 <= file_num <= len(files):
            file_to_restore = files[file_num - 1]
            original_path = input("Enter the path to restore to (leave empty for original location): ").strip('"')
            
            if not original_path:
                # Try to get original path from quarantine log
                log_file = av.quarantine_dir / 'quarantine_log.txt'
                if log_file.exists():
                    with open(log_file, 'r') as f:
                        for line in f:
                            parts = line.strip().split('|')
                            if len(parts) >= 3 and parts[2].endswith(file_to_restore.name):
                                original_path = parts[1]
                                break
                
                if not original_path:
                    print_status("Original path not found in log. Please specify the restore path.", "warning")
                    return
            
            try:
                import shutil
                shutil.copy2(file_to_restore, original_path)
                file_to_restore.unlink()  # Remove from quarantine
                print_status(f"File restored to: {original_path}", "success")
            except Exception as e:
                print_status(f"Failed to restore file: {e}", "error")
        else:
            print_status("Invalid file number", "error")
    except ValueError:
        print_status("Please enter a valid number", "error")

def _delete_quarantined_file(self, av):
    """Permanently delete a quarantined file"""
    quarantine_dir = av.quarantine_dir / 'quarantined'
    if not quarantine_dir.exists() or not any(quarantine_dir.iterdir()):
        print_status("No files in quarantine to delete", "info")
        return
        
    self._list_quarantined_files(av)
    
    try:
        file_num = int(input("\nEnter the number of the file to delete (0 to cancel): "))
        if file_num == 0:
            return
            
        files = list(quarantine_dir.iterdir())
        if 1 <= file_num <= len(files):
            file_to_delete = files[file_num - 1]
            confirm = input(f"Are you sure you want to permanently delete {file_to_delete.name}? (y/n): ").lower()
            if confirm == 'y':
                try:
                    file_to_delete.unlink()
                    print_status("File permanently deleted", "success")
                except Exception as e:
                    print_status(f"Failed to delete file: {e}", "error")
        else:
            print_status("Invalid file number", "error")
    except ValueError:
        print_status("Please enter a valid number", "error")
