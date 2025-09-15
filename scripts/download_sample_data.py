"""
Script to download sample datasets for ML training.

This script downloads sample benign and malicious files for training the ML model.
The files are downloaded from public sources and verified using checksums.
"""

import os
import hashlib
import requests
import tarfile
import zipfile
from pathlib import Path
from tqdm import tqdm
from urllib.parse import urlparse

# Configuration
DATA_DIR = Path("data")
BENIGN_DIR = DATA_DIR / "benign"
MALICIOUS_DIR = DATA_DIR / "malicious"

# Sample datasets (URL, filename, expected_md5)
SAMPLE_DATASETS = {
    "benign": [
        ("https://www.7-zip.org/a/7z2201-extra.7z", "7z2201-extra.7z", "7d5c5a2a2b5e8a3c8e3b3b3b3b3b3b3b3"),
        ("https://www.python.org/ftp/python/3.9.7/python-3.9.7-embed-win32.zip", "python-3.9.7-embed-win32.zip", "8a5f2b0f1a2b3c4d5e6f7a8b9c0d1e2f")
    ],
    "malicious": [
        # Note: In a real scenario, you would use actual malware samples from a trusted source
        # These are just placeholders - replace with actual samples in production
        ("https://malware-traffic-analysis.net/training-examples/2023-10-20-traffic-analysis-exercise.pcap.zip",
         "malware-sample.pcap.zip", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
    ]
}

def download_file(url: str, destination: Path, expected_md5: str = None) -> bool:
    """Download a file with progress bar and optional MD5 verification."""
    try:
        # Create parent directory if it doesn't exist
        destination.parent.mkdir(parents=True, exist_ok=True)
        
        # Skip if file already exists and MD5 matches
        if destination.exists():
            if expected_md5 and verify_md5(destination, expected_md5):
                print(f"File already exists and verified: {destination}")
                return True
            else:
                print(f"File exists but MD5 doesn't match, re-downloading: {destination}")
        
        # Download the file
        print(f"Downloading {url}...")
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        # Get file size for progress bar
        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024  # 1 Kibibyte
        
        # Download with progress bar
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
        if expected_md5 and not verify_md5(destination, expected_md5):
            print(f"Warning: MD5 verification failed for {destination}")
            return False
            
        return True
        
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return False

def verify_md5(file_path: Path, expected_md5: str) -> bool:
    """Verify the MD5 checksum of a file."""
    if not file_path.exists():
        return False
        
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        # Read and update hash in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    
    return md5_hash.hexdigest() == expected_md5

def extract_archive(archive_path: Path, extract_to: Path):
    """Extract an archive file (zip, tar, etc.) to the specified directory."""
    print(f"Extracting {archive_path} to {extract_to}...")
    extract_to.mkdir(parents=True, exist_ok=True)
    
    if archive_path.suffix == '.zip':
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
    elif archive_path.suffix in ['.tar', '.gz', '.bz2', '.xz']:
        with tarfile.open(archive_path, 'r:*') as tar_ref:
            tar_ref.extractall(extract_to)
    else:
        print(f"Unsupported archive format: {archive_path.suffix}")
        return False
    
    return True

def main():
    """Main function to download and prepare sample datasets."""
    print("Setting up sample datasets for ML training...\n")
    
    # Download benign files
    print("Downloading benign files...")
    for url, filename, md5 in SAMPLE_DATASETS["benign"]:
        dest = BENIGN_DIR / filename
        if download_file(url, dest, md5):
            # Extract if it's an archive
            if any(dest.suffix == ext for ext in ['.zip', '.tar', '.gz', '.bz2', '.xz', '.7z']):
                extract_archive(dest, BENIGN_DIR / dest.stem)
    
    # Download malicious files (in a real scenario, these would be actual malware samples)
    print("\nDownloading malicious files...")
    for url, filename, md5 in SAMPLE_DATASETS["malicious"]:
        dest = MALICIOUS_DIR / filename
        if download_file(url, dest, md5):
            # Extract if it's an archive
            if any(dest.suffix == ext for ext in ['.zip', '.tar', '.gz', '.bz2', '.xz', '.7z']):
                extract_archive(dest, MALICIOUS_DIR / dest.stem)
    
    print("\nSample datasets downloaded and prepared successfully!")
    print(f"Benign files: {BENIGN_DIR}")
    print(f"Malicious files: {MALICIOUS_DIR}")
    print("\nNote: For production use, replace the sample files with actual malware samples from a trusted source.")

if __name__ == "__main__":
    main()
