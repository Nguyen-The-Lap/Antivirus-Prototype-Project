"""
Signature-based detection using YARA rules and hash databases.
"""
import os
import json
import yara
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import hashlib
import logging

from config import SIGNATURES_DIR, WHITELIST_FILE
from utils import FileUtils, logger


class SignatureManager:
    """Manages malware signatures and YARA rules."""
    
    def __init__(self):
        self.yara_rules = None
        self.hash_db: Dict[str, Dict[str, str]] = {}
        self.whitelist: Set[str] = set()
        self.rule_count = 0
        self.hash_count = 0
        self._load_whitelist()
        self._load_signatures()
    
    def _load_whitelist(self) -> None:
        """Load whitelisted files and hashes."""
        if WHITELIST_FILE.exists():
            try:
                with open(WHITELIST_FILE, 'r') as f:
                    self.whitelist = {line.strip() for line in f if line.strip() and not line.startswith('#')}
                logger.info(f"Loaded {len(self.whitelist)} whitelist entries")
            except Exception as e:
                logger.error(f"Error loading whitelist: {e}")
    
    def _load_signatures(self) -> None:
        """Load all available signatures and rules."""
        self._load_hash_database()
        self._load_yara_rules()
    
    def _load_hash_database(self) -> None:
        """Load hash database from JSON files."""
        hash_dir = SIGNATURES_DIR / 'hashes'
        hash_dir.mkdir(parents=True, exist_ok=True)
        
        self.hash_db = {}
        self.hash_count = 0
        
        for hash_file in hash_dir.glob('*.json'):
            try:
                with open(hash_file, 'r') as f:
                    hashes = json.load(f)
                    if isinstance(hashes, dict):
                        self.hash_db.update(hashes)
                        self.hash_count += len(hashes)
            except Exception as e:
                logger.error(f"Error loading hash database {hash_file}: {e}")
        
        logger.info(f"Loaded {self.hash_count} hashes from {len(self.hash_db)} hash databases")
    
    def _load_yara_rules(self) -> None:
        """Compile and load YARA rules."""
        yara_dir = SIGNATURES_DIR / 'yara'
        yara_dir.mkdir(parents=True, exist_ok=True)
        
        rule_files = list(yara_dir.rglob('*.yar')) + list(yara_dir.rglob('*.yara'))
        self.rule_count = len(rule_files)
        
        if not rule_files:
            logger.warning("No YARA rule files found")
            return
        
        try:
            # Create a temporary rules file that includes all YARA rules
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yara') as tmp:
                for rule_file in rule_files:
                    with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                        tmp.write(f"// From: {rule_file}\n")
                        tmp.write(f.read() + "\n\n")
                tmp_path = tmp.name
            
            # Compile the combined rules
            self.yara_rules = yara.compile(filepath=tmp_path)
            logger.info(f"Compiled {self.rule_count} YARA rule files")
            
        except yara.Error as e:
            logger.error(f"Error compiling YARA rules: {e}")
            self.yara_rules = None
        except Exception as e:
            logger.error(f"Unexpected error loading YARA rules: {e}")
            self.yara_rules = None
        finally:
            # Clean up temporary file
            try:
                if 'tmp_path' in locals() and os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except:
                pass
    
    def match_hash(self, file_path: str) -> Optional[Dict[str, str]]:
        """Check if a file's hash matches any known malware hashes."""
        try:
            file_hash = FileUtils.calculate_hashes(file_path).get('sha256')
            if not file_hash:
                return None
                
            if file_hash in self.whitelist:
                return {'status': 'whitelisted', 'hash': file_hash}
                
            if file_hash in self.hash_db:
                return {
                    'status': 'malicious',
                    'hash': file_hash,
                    'threat_name': self.hash_db[file_hash].get('name', 'Unknown'),
                    'threat_type': self.hash_db[file_hash].get('type', 'Virus'),
                    'source': self.hash_db[file_hash].get('source', 'Unknown')
                }
        except Exception as e:
            logger.error(f"Error in hash matching for {file_path}: {e}")
        
        return None
    
    def match_yara(self, file_path: str) -> List[Dict[str, Any]]:
        """Check if a file matches any YARA rules."""
        if not self.yara_rules:
            return []
        
        try:
            matches = self.yara_rules.match(file_path)
            return [{
                'rule': str(match.rule),
                'namespace': match.namespace,
                'tags': match.tags,
                'meta': match.meta,
                'strings': [
                    {
                        'name': string[1],
                        'offset': string[0],
                        'data': string[2].decode('utf-8', errors='replace')
                    } for string in match.strings
                ]
            } for match in matches]
        except yara.Error as e:
            logger.warning(f"YARA scan error for {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error in YARA matching for {file_path}: {e}")
            return []
    
    def update_signatures(self) -> Dict[str, Any]:
        """Update all signature databases and rules."""
        from utils import NetworkUtils
        
        results = {
            'yara': {'updated': False, 'message': ''},
            'hashes': {'updated': False, 'message': ''}
        }
        
        # Update YARA rules
        yara_dir = SIGNATURES_DIR / 'yara'
        yara_dir.mkdir(parents=True, exist_ok=True)
        
        # Example: Download YARA rules from a repository
        yara_url = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
        zip_path = yara_dir / 'yara_rules.zip'
        
        try:
            if NetworkUtils.download_file(yara_url, zip_path):
                # Extract and clean up old rules
                for old_file in yara_dir.glob('*'):
                    if old_file.is_file() and old_file.suffix in ['.yar', '.yara']:
                        old_file.unlink()
                
                # Extract new rules
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(yara_dir / 'temp')
                
                # Move YARA files to the main directory
                for yara_file in (yara_dir / 'temp').rglob('*.yar'):
                    shutil.move(str(yara_file), str(yara_dir / yara_file.name))
                
                # Clean up
                shutil.rmtree(yara_dir / 'temp')
                zip_path.unlink()
                
                # Reload rules
                old_count = self.rule_count
                self._load_yara_rules()
                
                results['yara'].update({
                    'updated': True,
                    'message': f'Updated from {old_count} to {self.rule_count} rules',
                    'rule_count': self.rule_count
                })
        except Exception as e:
            results['yara']['message'] = f'Update failed: {str(e)}'
            logger.error(f"Error updating YARA rules: {e}")
        
        # Update hash database (example)
        try:
            # This is a placeholder - in a real implementation, you would download
            # hash databases from trusted sources
            old_count = self.hash_count
            self._load_hash_database()
            
            results['hashes'].update({
                'updated': old_count != self.hash_count,
                'message': f'Hash database updated: {self.hash_count} hashes',
                'hash_count': self.hash_count
            })
        except Exception as e:
            results['hashes']['message'] = f'Hash update failed: {str(e)}'
            logger.error(f"Error updating hash database: {e}")
        
        return results
    
    def add_to_whitelist(self, file_path: str) -> bool:
        """Add a file or hash to the whitelist."""
        try:
            # If it's a file, calculate its hash
            if os.path.exists(file_path):
                file_hash = FileUtils.calculate_hashes(file_path).get('sha256')
                if file_hash:
                    with open(WHITELIST_FILE, 'a') as f:
                        f.write(f"{file_hash}  # {os.path.basename(file_path)}\n")
                    self.whitelist.add(file_hash)
                    return True
            else:
                # Assume it's already a hash
                with open(WHITELIST_FILE, 'a') as f:
                    f.write(f"{file_path}\n")
                self.whitelist.add(file_path)
                return True
        except Exception as e:
            logger.error(f"Error adding to whitelist: {e}")
        
        return False
