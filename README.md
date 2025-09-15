# Simple Antivirus Scanner

A basic antivirus program written in Python that demonstrates core antivirus functionality including file scanning, signature-based detection, and file quarantine.

## Features

- File scanning using hash-based detection
- Directory scanning
- Quarantine functionality for infected files
- Scan logging
- Simple command-line interface

## Requirements

- Python 3.6 or higher
- Required packages listed in `requirements.txt`

## Installation

1. Clone this repository
2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the antivirus program:
```
python antivirus.py
```

### Options
1. **Scan a file**: Scan a specific file for malware
2. **Scan a directory**: Recursively scan all files in a directory
3. **View scan log**: View the history of scans
4. **Exit**: Close the program

## How It Works

The antivirus works by:
1. Calculating SHA-256 hashes of files
2. Comparing hashes against a database of known malware signatures
3. Quarantining suspicious files when detected
4. Logging all scan results

## Note

This is a basic implementation for educational purposes. A real antivirus would include:
- More sophisticated detection methods (heuristics, behavior analysis)
- Regular signature updates from a security provider
- Real-time protection
- System integration
- More comprehensive error handling

## License

This project is for educational purposes only.
