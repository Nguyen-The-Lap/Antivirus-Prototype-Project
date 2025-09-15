"""
Script to set up the directory structure for ML data and models.
"""

import os
from pathlib import Path

def setup_directories():
    """Create the required directory structure for ML data and models."""
    base_dirs = [
        'data/benign',
        'data/malicious',
        'data/processed',
        'data/models',
        'data/raw',
        'data/features',
        'data/evaluation',
        'data/logs/ml_training'
    ]
    
    for dir_path in base_dirs:
        full_path = Path(dir_path)
        full_path.mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {full_path}")
    
    # Create a .gitkeep file in each directory to preserve the structure
    for dir_path in base_dirs:
        (Path(dir_path) / '.gitkeep').touch()
    
    print("\nDirectory structure created successfully!")

if __name__ == "__main__":
    setup_directories()
