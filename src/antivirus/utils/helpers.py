"""
Utility functions for the Advanced Antivirus Scanner.
"""
import os
import hashlib
import logging
import logging.handlers
import platform
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Optional, Dict, List, Union, BinaryIO, Any
import magic
import requests
from colorama import Fore, Style

from config import LOG_FILE, MAX_LOG_SIZE_MB, LOG_BACKUP_COUNT, LOG_LEVEL, PROXY, TIMEOUT

class FileUtils:
    """File system utility functions."""
    
    @staticmethod
    def safe_delete(file_path: Union[str, Path]) -> bool:
        """Safely delete a file with error handling."""
        try:
            Path(file_path).unlink(missing_ok=True)
            return True
        except Exception as e:
            logging.error(f"Failed to delete {file_path}: {e}")
            return False
    
    @staticmethod
    def get_file_info(file_path: Union[str, Path]) -> Dict[str, Any]:
        """Get detailed information about a file."""
        path = Path(file_path)
        try:
            stat = path.stat()
            return {
                'path': str(path.absolute()),
                'size': stat.st_size,
                'created': stat.st_ctime,
                'modified': stat.st_mtime,
                'accessed': stat.st_atime,
                'permissions': oct(stat.st_mode)[-3:],
                'owner': path.owner() if hasattr(path, 'owner') else 'N/A',
                'group': path.group() if hasattr(path, 'group') else 'N/A',
                'type': 'file' if path.is_file() else 'directory' if path.is_dir() else 'other'
            }
        except Exception as e:
            logging.error(f"Error getting file info for {file_path}: {e}")
            return {}
    
    @staticmethod
    def calculate_hashes(file_path: Union[str, Path], chunk_size: int = 4096) -> Dict[str, str]:
        """Calculate multiple hash types for a file."""
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)
            
            return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
        except Exception as e:
            logging.error(f"Error calculating hashes for {file_path}: {e}")
            return {}
    
    @staticmethod
    def is_binary(file_path: Union[str, Path]) -> bool:
        """Check if a file is binary."""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\x00' in chunk or not chunk.isascii()
        except:
            return True
    
    @staticmethod
    def extract_archive(archive_path: Union[str, Path], output_dir: Union[str, Path]) -> bool:
        """Extract an archive file."""
        try:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            if str(archive_path).lower().endswith('.zip'):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(output_dir)
            else:
                # Add support for other archive types if needed
                return False
                
            return True
        except Exception as e:
            logging.error(f"Error extracting {archive_path}: {e}")
            return False


class NetworkUtils:
    """Network-related utility functions."""
    
    @staticmethod
    def download_file(url: str, destination: Union[str, Path], chunk_size: int = 8192) -> bool:
        """Download a file from a URL with progress tracking."""
        try:
            with requests.get(url, stream=True, proxies=PROXY, timeout=TIMEOUT) as r:
                r.raise_for_status()
                total_size = int(r.headers.get('content-length', 0))
                downloaded = 0
                
                with open(destination, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=chunk_size):
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            print(f"\rDownloading: {progress:.1f}%", end='')
                
                print()  # New line after progress
                return True
        except Exception as e:
            logging.error(f"Error downloading {url}: {e}")
            return False
    
    @staticmethod
    def check_internet_connection() -> bool:
        """Check if there's an active internet connection."""
        try:
            requests.get('https://www.google.com', timeout=5, proxies=PROXY)
            return True
        except:
            return False


def setup_logger(name: str = 'antivirus') -> logging.Logger:
    """Configure and return a logger instance."""
    # Create logs directory if it doesn't exist
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    logger = logging.getLogger(name)
    logger.setLevel(LOG_LEVEL)
    
    # Clear existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=MAX_LOG_SIZE_MB * 1024 * 1024,
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    
    # Formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_formatter = ColoredFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    file_handler.setFormatter(file_formatter)
    console_handler.setFormatter(console_formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger


class ColoredFormatter(logging.Formatter):
    """Custom formatter for colored console output."""
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }
    
    def format(self, record):
        log_message = super().format(record)
        if record.levelname in self.COLORS:
            return f"{self.COLORS[record.levelname]}{log_message}{Style.RESET_ALL}"
        return log_message


def get_system_info() -> Dict[str, str]:
    """Get information about the current system."""
    return {
        'system': platform.system(),
        'node': platform.node(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'architecture': platform.architecture()[0],
        'platform': platform.platform(),
        'cpu_count': os.cpu_count() or 1
    }


def human_readable_size(size_bytes: int) -> str:
    """Convert size in bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def is_admin() -> bool:
    """Check if the current process is running with admin/root privileges."""
    if os.name == 'nt':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0


# Initialize logger
logger = setup_logger()
