"""
Logging utility for the antivirus system.

This module provides a centralized logging system with file and console handlers,
as well as support for remote logging.
"""
import os
import sys
import logging
import logging.handlers
from pathlib import Path
from typing import Optional, Dict, Any

from ..core.config import LoggingConfig, LOGS_DIR

class AntivirusLogger:
    """Centralized logging for the antivirus system.
    
    This class provides a singleton logger instance with file and console handlers,
    as well as support for remote logging.
    """
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AntivirusLogger, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        self.logger = logging.getLogger('antivirus')
        self.logger.setLevel(getattr(logging, LoggingConfig.LEVEL.upper()))
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        """Configure logging handlers based on configuration."""
        formatter = logging.Formatter(
            fmt=LoggingConfig.FORMAT,
            datefmt=LoggingConfig.DATE_FORMAT
        )
        
        # Console handler
        console = logging.StreamHandler()
        console.setLevel(getattr(logging, LoggingConfig.CONSOLE_LEVEL.upper()))
        console.setFormatter(formatter)
        self.logger.addHandler(console)
        
        # File handler with rotation
        if LoggingConfig.ENABLE_FILE_LOGGING:
            try:
                # Ensure logs directory exists
                LOGS_DIR.mkdir(parents=True, exist_ok=True)
                
                # Rotating file handler
                file_handler = logging.handlers.RotatingFileHandler(
                    LoggingConfig.LOG_FILE,
                    maxBytes=LoggingConfig.MAX_SIZE_MB * 1024 * 1024,
                    backupCount=LoggingConfig.BACKUP_COUNT,
                    encoding='utf-8'
                )
                file_handler.setLevel(self.logger.level)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
            except Exception as e:
                self.logger.error(f"Failed to set up file logging: {e}")
        
        # Remote syslog handler (if enabled)
        if (LoggingConfig.ENABLE_REMOTE_LOGGING and 
            LoggingConfig.REMOTE_HOST):
            try:
                remote = logging.handlers.SysLogHandler(
                    address=(LoggingConfig.REMOTE_HOST, LoggingConfig.REMOTE_PORT)
                )
                remote.setFormatter(formatter)
                self.logger.addHandler(remote)
            except Exception as e:
                self.logger.error(f"Failed to set up remote logging: {e}")
    
    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        """Get a logger instance with the given name.
        
        Args:
            name: Optional name for the logger. If None, returns the root logger.
            
        Returns:
            Configured logger instance.
        """
        if name:
            return self.logger.getChild(name)
        return self.logger

# Create a default logger instance
default_logger = AntivirusLogger().get_logger()

# Convenience functions
def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a logger instance with the given name.
    
    This is a convenience function that creates a new AntivirusLogger instance
    if one doesn't exist, and returns a logger with the specified name.
    
    Args:
        name: Optional name for the logger. If None, returns the root logger.
        
    Returns:
        Configured logger instance.
    """
    return AntivirusLogger().get_logger(name)

def log_execution_time(logger: logging.Logger = None):
    """Decorator to log the execution time of a function.
    
    Args:
        logger: Logger instance to use. If None, uses the default logger.
    """
    if logger is None:
        logger = default_logger
    
    def decorator(func):
        import time
        from functools import wraps
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                end_time = time.time()
                logger.debug(
                    f"{func.__module__}.{func.__name__} executed in "
                    f"{end_time - start_time:.4f} seconds"
                )
        return wrapper
    return decorator

class LoggingContext:
    """Context manager for temporarily modifying logging configuration."""
    
    def __init__(self, logger=None, level=None, handler=None, close=True):
        self.logger = logger or logging.getLogger()
        self.level = level
        self.handler = handler
        self.close = close
        self.old_level = None
        
    def __enter__(self):
        if self.level is not None:
            self.old_level = self.logger.level
            self.logger.setLevel(self.level)
        if self.handler:
            self.logger.addHandler(self.handler)
    
    def __exit__(self, et, ev, tb):
        if self.level is not None:
            self.logger.setLevel(self.old_level)
        if self.handler and self.close:
            self.handler.close()
        # Don't suppress exceptions
        return False
