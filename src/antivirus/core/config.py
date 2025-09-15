"""
Configuration settings for the Advanced Antivirus Scanner.
"""
from pathlib import Path
from typing import Dict, List, Union

# Base directories
BASE_DIR = Path(__file__).parent.absolute()
QUARANTINE_DIR = BASE_DIR / "quarantine"
SIGNATURES_DIR = BASE_DIR / "signatures"
LOGS_DIR = BASE_DIR / "logs"

# Scan settings
MAX_SCAN_THREADS = 4  # Number of parallel scan threads
MAX_FILE_SIZE_MB = 100  # Maximum file size to scan in MB
SCAN_ARCHIVES = True  # Whether to scan inside archive files

# Real-time monitoring
MONITOR_INTERVAL = 5  # Seconds between monitoring checks
MONITORED_DIRS = [
    str(Path.home() / "Downloads"),
    str(Path.home() / "Desktop"),
]

# Quarantine settings
MAX_QUARANTINE_SIZE_GB = 5  # Maximum quarantine size in GB
MAX_QUARANTINE_ITEMS = 1000  # Maximum number of items to keep in quarantine

# Update settings
UPDATE_INTERVAL_HOURS = 24  # Hours between signature updates
SIGNATURE_SOURCES = [
    "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip",
]

# Logging settings
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FILE = LOGS_DIR / "antivirus.log"
MAX_LOG_SIZE_MB = 10  # Maximum log file size in MB
LOG_BACKUP_COUNT = 3  # Number of log files to keep

# Whitelist settings
WHITELIST_FILE = BASE_DIR / "whitelist.txt"
WHITELISTED_EXTENSIONS = {
    ".txt", ".md", ".pdf", ".jpg", ".jpeg", ".png", 
    ".gif", ".docx", ".xlsx", ".pptx", ".csv"
}

# Heuristics settings
ENTROPY_THRESHOLD = 7.0  # Files with higher entropy will be flagged
MAX_SUSPICIOUS_STRINGS = 5  # Maximum number of suspicious strings before flagging

# Network settings
PROXY = None  # Example: {"http": "http://proxy:port", "https": "http://proxy:port"}
TIMEOUT = 30  # Seconds to wait for network operations

# UI settings
THEME = {
    "primary": "cyan",
    "success": "green",
    "warning": "yellow",
    "error": "red",
    "info": "blue",
}

def ensure_directories() -> None:
    """Ensure all required directories exist."""
    for directory in [QUARANTINE_DIR, SIGNATURES_DIR, LOGS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)

# Initialize directories on import
ensure_directories()
