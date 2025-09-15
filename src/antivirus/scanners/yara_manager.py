"""
YARA Rule Manager

This module handles loading, compiling, and matching YARA rules for malware detection.
"""
import os
import yara
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

class YaraRuleManager:
    """Manages YARA rules for malware detection."""
    
    def __init__(self, rules_dir: str = None):
        """Initialize the YARA rule manager.
        
        Args:
            rules_dir: Directory containing YARA rule files (.yar, .yara)
        """
        self.rules_dir = rules_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'data',
            'yara_rules'
        )
        self.rules: Dict[str, yara.Rules] = {}
        self.rule_files: List[str] = []
        
        # Create rules directory if it doesn't exist
        os.makedirs(self.rules_dir, exist_ok=True)
        
        # Load all YARA rules on initialization
        self.load_rules()
    
    def load_rules(self) -> bool:
        """Load all YARA rules from the rules directory.
        
        Returns:
            bool: True if rules were loaded successfully, False otherwise
        """
        try:
            # Clear existing rules
            self.rules = {}
            self.rule_files = []
            
            # Find all YARA rule files
            for ext in ('*.yar', '*.yara'):
                self.rule_files.extend(Path(self.rules_dir).rglob(ext))
            
            if not self.rule_files:
                logger.warning(f"No YARA rule files found in {self.rules_dir}")
                return False
            
            # Compile and load each rule file
            for rule_file in self.rule_files:
                try:
                    rule_name = rule_file.stem
                    self.rules[rule_name] = yara.compile(filepath=str(rule_file))
                    logger.debug(f"Loaded YARA rule: {rule_name}")
                except yara.SyntaxError as e:
                    logger.error(f"Error compiling YARA rule {rule_file}: {e}")
                except Exception as e:
                    logger.error(f"Error loading YARA rule {rule_file}: {e}")
            
            if not self.rules:
                logger.error("No valid YARA rules were loaded")
                return False
                
            logger.info(f"Successfully loaded {len(self.rules)} YARA rules")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            return False
    
    def scan_file(self, file_path: str) -> List[Dict]:
        """Scan a file using all loaded YARA rules.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of dictionaries containing match information
        """
        if not os.path.isfile(file_path):
            logger.error(f"File not found: {file_path}")
            return []
        
        matches = []
        
        try:
            for rule_name, rule in self.rules.items():
                try:
                    rule_matches = rule.match(file_path)
                    if rule_matches:
                        for match in rule_matches:
                            matches.append({
                                'rule': rule_name,
                                'namespace': match.namespace,
                                'tags': match.tags,
                                'meta': match.meta,
                                'strings': [
                                    {
                                        'name': s[1].decode() if isinstance(s[1], bytes) else s[1],
                                        'offset': s[0],
                                        'data': s[2].hex()
                                    }
                                    for s in match.strings
                                ]
                            })
                except yara.Error as e:
                    logger.error(f"Error matching YARA rule {rule_name} on {file_path}: {e}")
            
            return matches
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path} with YARA: {e}")
            return []
    
    def scan_buffer(self, buffer: bytes) -> List[Dict]:
        """Scan a buffer in memory using all loaded YARA rules.
        
        Args:
            buffer: Bytes buffer to scan
            
        Returns:
            List of dictionaries containing match information
        """
        if not buffer:
            return []
            
        matches = []
        
        try:
            for rule_name, rule in self.rules.items():
                try:
                    rule_matches = rule.match(data=buffer)
                    if rule_matches:
                        for match in rule_matches:
                            matches.append({
                                'rule': rule_name,
                                'namespace': match.namespace,
                                'tags': match.tags,
                                'meta': match.meta,
                                'strings': [
                                    {
                                        'name': s[1].decode() if isinstance(s[1], bytes) else s[1],
                                        'offset': s[0],
                                        'data': s[2].hex()
                                    }
                                    for s in match.strings
                                ]
                            })
                except yara.Error as e:
                    logger.error(f"Error matching YARA rule {rule_name} on buffer: {e}")
            
            return matches
            
        except Exception as e:
            logger.error(f"Error scanning buffer with YARA: {e}")
            return []
    
    def add_rule(self, rule_content: str, rule_name: str) -> bool:
        """Add a new YARA rule from a string.
        
        Args:
            rule_content: YARA rule as a string
            rule_name: Name to give the rule
            
        Returns:
            bool: True if rule was added successfully, False otherwise
        """
        try:
            # Try to compile the rule to check syntax
            rule = yara.compile(source=rule_content)
            
            # Save the rule to a file
            rule_path = os.path.join(self.rules_dir, f"{rule_name}.yara")
            with open(rule_path, 'w') as f:
                f.write(rule_content)
            
            # Add to our rules dictionary
            self.rules[rule_name] = rule
            
            # Reload rules to ensure consistency
            return self.load_rules()
            
        except yara.SyntaxError as e:
            logger.error(f"Invalid YARA rule syntax: {e}")
            return False
        except Exception as e:
            logger.error(f"Error adding YARA rule: {e}")
            return False
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a YARA rule by name.
        
        Args:
            rule_name: Name of the rule to remove
            
        Returns:
            bool: True if rule was removed successfully, False otherwise
        """
        try:
            # Find the rule file
            for rule_file in self.rule_files:
                if rule_file.stem == rule_name:
                    # Remove the file
                    os.remove(rule_file)
                    
                    # Remove from our rules dictionary
                    if rule_name in self.rules:
                        del self.rules[rule_name]
                    
                    logger.info(f"Removed YARA rule: {rule_name}")
                    return True
            
            logger.warning(f"YARA rule not found: {rule_name}")
            return False
            
        except Exception as e:
            logger.error(f"Error removing YARA rule {rule_name}: {e}")
            return False
    
    def get_rule_names(self) -> List[str]:
        """Get a list of all loaded rule names.
        
        Returns:
            List of rule names
        """
        return list(self.rules.keys())
