#!/usr/bin/env python3
"""
Script to download sample datasets for ML training.

This script downloads sample benign and malicious files from trusted sources.
For malicious files, we use the EICAR test file and other non-harmful test files.
"""

import hashlib
import os
import shutil
import sys
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple

import requests
from tqdm import tqdm

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.antivirus.core.config import DATA_DIR
from src.antivirus.utils.logger import setup_logging, get_logger

# Set up logging
setup_logging()
logger = get_logger(__name__)

# Directory structure
BENIGN_DIR = DATA_DIR / "benign"
MALICIOUS_DIR = DATA_DIR / "malicious"

# Sample datasets with (url, filename, expected_md5, is_archive)
SAMPLE_DATASETS = {
    "benign": [
        # Sample Windows system files (small, safe files)
        ("https://raw.githubusercontent.com/processhacker/processhacker/master/ProcessHacker/Resources/Bitmaps/AboutLogo.png", 
         "about_logo.png", 
         "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
         False),
        
        # Sample text file
        ("https://www.gutenberg.org/files/1342/1342-0.txt", 
         "pride_and_prejudice.txt", 
         "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
         False),
        
        # Sample PDF file
        ("https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf", 
         "dummy.pdf", 
         "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
         False),
    ],
    "malicious": [
        # EICAR test file (harmless test file that antivirus programs detect as malicious)
        ("https://secure.eicar.org/eicar.com", 
         "eicar.com", 
         "44d88612fea8a8f36de82e1278abb02f",
         False),
         
        # EICAR test file in a zip archive
        ("https://secure.eicar.org/eicar_com.zip", 
         "eicar_com.zip", 
         "e9e9d7a2c1c1d5c1e9e9d7a2c1c1d5c1",
         True),
    ]
}

def verify_file(file_path: Path, expected_md5: str) -> bool:
    """Verify the MD5 checksum of a file."""
    if not file_path.exists():
        return False
    
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    
    return md5_hash.hexdigest() == expected_md5

def download_file(url: str, destination: Path, expected_md5: Optional[str] = None) -> bool:
    """Download a file with progress bar and optional MD5 verification."""
    try:
        # Skip if file already exists and MD5 matches
        if destination.exists():
            if expected_md5 and verify_file(destination, expected_md5):
                logger.info(f"File already exists and verified: {destination}")
                return True
            else:
                logger.warning(f"File exists but MD5 doesn't match, re-downloading: {destination}")
        
        # Create parent directory if it doesn't exist
        destination.parent.mkdir(parents=True, exist_ok=True)
        
        # Download the file with progress bar
        logger.info(f"Downloading {url} to {destination}")
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024  # 1 Kibibyte
        
        with open(destination, 'wb') as f, tqdm(
            desc=destination.name,
            total=total_size,
            unit='iB',
            unit_scale=True,
            unit_divisor=1024,
        ) as bar:
            for data in response.iter_content(block_size):
                size = f.write(data)
                bar.update(size)
        
        # Verify MD5 if provided
        if expected_md5 and not verify_file(destination, expected_md5):
            logger.error(f"MD5 verification failed for {destination}")
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Error downloading {url}: {e}")
        return False

def extract_archive(archive_path: Path, extract_to: Path) -> bool:
    """Extract an archive file (zip, tar, etc.) to the specified directory."""
    logger.info(f"Extracting {archive_path} to {extract_to}")
    extract_to.mkdir(parents=True, exist_ok=True)
    
    try:
        if archive_path.suffix == '.zip':
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
        elif archive_path.suffix in ['.tar', '.gz', '.bz2', '.xz']:
            import tarfile
            with tarfile.open(archive_path, 'r:*') as tar_ref:
                tar_ref.extractall(extract_to)
        else:
            logger.error(f"Unsupported archive format: {archive_path.suffix}")
            return False
        
        return True
    except Exception as e:
        logger.error(f"Error extracting {archive_path}: {e}")
        return False

def download_sample_datasets() -> bool:
    """Download sample datasets for ML training."""
    success = True
    
    # Download benign files
    logger.info("Downloading benign files...")
    for url, filename, md5, is_archive in SAMPLE_DATASETS["benign"]:
        dest = BENIGN_DIR / filename
        if download_file(url, dest, md5):
            if is_archive:
                extract_archive(dest, BENIGN_DIR / dest.stem)
        else:
            success = False
    
    # Download malicious files
    logger.info("\nDownloading malicious files...")
    for url, filename, md5, is_archive in SAMPLE_DATASETS["malicious"]:
        dest = MALICIOUS_DIR / filename
        if download_file(url, dest, md5):
            if is_archive:
                extract_archive(dest, MALICIOUS_DIR / dest.stem)
        else:
            success = False
    
    return success

def main():
    """Main function to download sample datasets."""
    logger.info("Starting download of sample datasets...")
    
    # Create directories if they don't exist
    BENIGN_DIR.mkdir(parents=True, exist_ok=True)
    MALICIOUS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Download datasets
    if download_sample_datasets():
        logger.info("\nSample datasets downloaded successfully!")
        logger.info(f"Benign files: {BENIGN_DIR}")
        logger.info(f"Malicious files: {MALICIOUS_DIR}")
        logger.info("\nYou can now proceed with feature extraction and model training.")
    else:
        logger.error("\nFailed to download some files. Please check the logs for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()
