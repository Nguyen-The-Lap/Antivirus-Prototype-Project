"""
Configuration settings for the Advanced Antivirus Scanner.

This module contains all the configuration settings for the antivirus system,
including scan parameters, paths, and behavior settings.
"""
import os
import sys
import platform
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Union

# ====================
# System Configuration
# ====================
SYSTEM = platform.system().lower()
IS_WINDOWS = SYSTEM == 'windows'
IS_LINUX = SYSTEM == 'linux'
IS_MAC = SYSTEM == 'darwin'

# ====================
# Base Directories
# ====================
BASE_DIR = Path(__file__).parent.parent.parent.absolute()
APP_DIR = Path(os.getenv('APPDATA' if IS_WINDOWS else '~/.antivirus')).expanduser()

# Data directories
QUARANTINE_DIR = APP_DIR / "quarantine"
SIGNATURES_DIR = APP_DIR / "signatures"
LOGS_DIR = APP_DIR / "logs"
CACHE_DIR = APP_DIR / "cache"
RULES_DIR = APP_DIR / "yara_rules"

# ====================
# Scan Configuration
# ====================
class ScanConfig:
    """Configuration for file scanning."""
    # Performance settings
    MAX_SCAN_THREADS = 4  # Number of parallel scan threads
    MAX_FILE_SIZE_MB = 100  # Maximum file size to scan in MB
    SCAN_TIMEOUT = 30  # Seconds before timing out a scan
    
    # Scan behavior
    SCAN_ARCHIVES = True  # Whether to scan inside archive files
    SCAN_ARCHIVE_MAX_DEPTH = 3  # Maximum archive nesting level to scan
    SCAN_ARCHIVE_MAX_SIZE_MB = 50  # Maximum size of archive to extract
    
    # File types to scan (None means scan all)
    SCAN_EXTENSIONS = None  # type: Optional[Set[str]]
    EXCLUDE_EXTENSIONS = {
        # Large files that are unlikely to be malicious
        '.iso', '.vmdk', '.vdi', '.vhd', '.qcow2', '.dmg',
        # Media files
        '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.m4v',
        '.wav', '.ogg', '.flac', '.aac', '.wma',
        # Large documents
        '.psd', '.ai', '.indd', '.cdr', '.sketch',
        # Virtual machine files
        '.vbox', '.vmx', '.vmem', '.vmsn', '.vmsd', '.nvram',
        # Database files
        '.mdb', '.accdb', '.sqlite', '.sqlitedb', '.db',
        # Other
        '.git', '.svn', '.hg',
    }
    
    # Memory scanning
    SCAN_PROCESS_MEMORY = True
    SCAN_PROCESS_INTERVAL = 300  # Seconds between process memory scans
    
    # Heuristic settings
    ENABLE_HEURISTICS = True
    HEURISTIC_SENSITIVITY = 0.7  # 0.0 to 1.0 (higher = more sensitive)
    
    # YARA rules
    ENABLE_YARA = True
    YARA_RULES_DIR = RULES_DIR
    
    # Machine learning
    ENABLE_ML = False
    ML_MODEL_PATH = APP_DIR / "models" / "malware_detection.model"

# ====================
# Real-time Monitoring
# ====================
class MonitorConfig:
    """Configuration for real-time monitoring."""
    ENABLED = True
    INTERVAL = 5  # Seconds between monitoring checks
    
    # Directories to monitor
    MONITORED_DIRS = [
        str(Path.home() / "Downloads"),
        str(Path.home() / "Desktop"),
        str(Path.home() / "Documents"),
    ]
    
    # File system events to monitor
    MONITOR_CREATE = True
    MONITOR_MODIFY = True
    MONITOR_DELETE = False
    MONITOR_MOVE = True
    
    # Exclude patterns (fnmatch)
    EXCLUDE_PATTERNS = [
        '*.tmp',
        '*.temp',
        '~*',
        '*.swp',
        '*.swx',
        '*.lock',
        '*.part',
        '.DS_Store',
        'Thumbs.db',
        'desktop.ini',
    ]
    
    # Maximum number of files to queue for scanning
    MAX_QUEUE_SIZE = 1000

# ====================
# Quarantine Settings
# ====================
class QuarantineConfig:
    """Configuration for quarantine functionality."""
    ENABLED = True
    MAX_SIZE_GB = 5  # Maximum quarantine size in GB
    MAX_ITEMS = 1000  # Maximum number of items to keep in quarantine
    
    # Encryption settings
    ENCRYPT_FILES = True
    ENCRYPTION_KEY = None  # Will be generated if None
    
    # Retention policy
    RETAIN_DAYS = 30  # Days to keep items in quarantine
    AUTO_DELETE = True  # Automatically delete old items

# ====================
# Update Settings
# ====================
class UpdateConfig:
    """Configuration for signature and software updates."""
    ENABLED = True
    CHECK_INTERVAL_HOURS = 4  # Hours between update checks
    
    # Signature sources (URLs or local paths)
    SIGNATURE_SOURCES = [
        "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/",
    ]
    
    # Proxy settings
    PROXY = None  # Example: {"http": "http://proxy:port", "https": "http://proxy:port"}
    TIMEOUT = 30  # Seconds to wait for network operations
    
    # Auto-update settings
    AUTO_UPDATE = True
    AUTO_UPDATE_HOUR = 3  # Hour of day to perform auto-updates (0-23)

# ====================
# Logging Configuration
# ====================
class LoggingConfig:
    """Configuration for logging."""
    LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    CONSOLE_LEVEL = "INFO"
    
    # File logging
    ENABLE_FILE_LOGGING = True
    LOG_FILE = LOGS_DIR / "antivirus.log"
    MAX_SIZE_MB = 10  # Maximum log file size in MB
    BACKUP_COUNT = 5  # Number of log files to keep
    
    # Remote logging (optional)
    ENABLE_REMOTE_LOGGING = False
    REMOTE_HOST = ""
    REMOTE_PORT = 514  # Default syslog port
    
    # Log format
    FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ====================
# Whitelist Settings
# ====================
WHITELIST_FILE = APP_DIR / "whitelist.txt"
WHITELISTED_PATHS = [
    str(Path.home() / "antivirus_whitelist"),
]

# Whitelisted file extensions (case-insensitive)
WHITELISTED_EXTENSIONS = {
    # Text and documents
    '.txt', '.md', '.markdown', '.rst', '.pdf',
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.svg',
    # Documents
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.odt', '.ods', '.odp', '.csv', '.rtf',
    # Archives (if not scanning archives)
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    # Audio/Video
    '.mp3', '.wav', '.ogg', '.flac', '.aac',
    '.mp4', '.avi', '.mkv', '.mov', '.wmv',
}

# ====================
# Advanced Settings
# ====================
class AdvancedConfig:
    """Advanced configuration options."""
    # Performance
    MAX_MEMORY_USAGE_PERCENT = 80  # Maximum memory usage before throttling
    CPU_THROTTLE_THRESHOLD = 80  # CPU usage % before throttling
    
    # Security
    SANDBOX_ENABLED = True
    SANDBOX_TIMEOUT = 60  # Seconds to run in sandbox
    
    # Cloud lookups
    CLOUD_LOOKUP_ENABLED = True
    CLOUD_LOOKUP_URL = "https://api.virustotal.com/v3/files/"
    CLOUD_API_KEY = ""  # Set your API key in local settings
    
    # Behavior monitoring
    BEHAVIOR_MONITORING = True
    SUSPICIOUS_API_CALLS = [
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
        'SetWindowsHookEx', 'SetWinEventHook', 'SetWindowsHook',
    ]

# ====================
# UI Configuration
# ====================
class UIConfig:
    """Configuration for the user interface."""
    THEME = {
        # Color scheme
        'primary': 'cyan',
        'success': 'green',
        'warning': 'yellow',
        'error': 'red',
        'info': 'blue',
        'text': 'white',
        'background': 'black',
        
        # UI elements
        'title': 'bright_white',
        'header': 'bright_blue',
        'highlight': 'bright_cyan',
        'prompt': 'bright_green',
    }
    
    # Display settings
    SHOW_PROGRESS = True
    PROGRESS_BAR_WIDTH = 40
    
    # Notification settings
    DESKTOP_NOTIFICATIONS = True
    NOTIFICATION_TIMEOUT = 5  # Seconds

def ensure_directories() -> None:
    """Ensure all required directories exist with proper permissions."""
    directories = [
        QUARANTINE_DIR,
        SIGNATURES_DIR,
        LOGS_DIR,
        CACHE_DIR,
        RULES_DIR,
        APP_DIR / "models",
    ]
    
    for directory in directories:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            if IS_LINUX or IS_MAC:
                # Set restrictive permissions on sensitive directories
                directory.chmod(0o700)
        except Exception as e:
            print(f"Error creating directory {directory}: {e}", file=sys.stderr)

# Initialize directories on import
ensure_directories()

# Load local settings if they exist
try:
    from .local_settings import *  # type: ignore # noqa
    from .local_settings import *  # type: ignore # noqa
    from .local_settings import *  # type: ignore # noqa
except ImportError:
    pass
