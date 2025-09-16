"""
Cloud-based threat intelligence integration module.

This module provides integration with various threat intelligence feeds and services
to enhance detection capabilities with real-time threat data.
"""

import json
import time
import hashlib
import requests
import logging
from typing import Dict, List, Optional, Set, Any, Union
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import concurrent.futures
import threading
import os
from filelock import FileLock

@dataclass
class ThreatIntelResult:
    """Represents the result of a threat intelligence lookup."""
    ioc: str
    ioc_type: str  # 'hash', 'ip', 'domain', 'url'
    malicious: bool
    confidence: float
    threat_types: List[str]
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    sources: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)


class ThreatIntelligence:
    """Manages integration with multiple threat intelligence sources."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the threat intelligence module.
        
        Args:
            config: Configuration dictionary with API keys and settings
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.cache: Dict[str, ThreatIntelResult] = {}
        self.cache_ttl = timedelta(hours=1)  # Default cache TTL
        self.enabled = self.config.get('enabled', True)
        self.sources = self._initialize_sources()
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.get('max_workers', 5),
            thread_name_prefix='threatintel_'
        )
        self._cache_lock = threading.RLock()
        self._source_locks = {source['name']: threading.RLock() for source in self.sources}
        self._load_cache()

    def _initialize_sources(self) -> List[Dict]:
        """Initialize threat intelligence sources from config."""
        sources = []

        # Add VirusTotal if configured
        if 'virustotal' in self.config:
            sources.append({
                'name': 'VirusTotal',
                'enabled': True,
                'api_key': self.config['virustotal'].get('api_key'),
                'lookup_fn': self._lookup_virustotal,
                'rate_limit': 4  # Requests per minute
            })

        # Add AbuseIPDB if configured
        if 'abuseipdb' in self.config:
            sources.append({
                'name': 'AbuseIPDB',
                'enabled': True,
                'api_key': self.config['abuseipdb'].get('api_key'),
                'lookup_fn': self._lookup_abuseipdb,
                'rate_limit': 1  # Requests per second
            })

        # Add custom threat feeds
        for feed in self.config.get('feeds', []):
            sources.append({
                'name': feed.get('name', 'Custom Feed'),
                'enabled': feed.get('enabled', True),
                'url': feed.get('url'),
                'type': feed.get('type', 'json'),  # json, csv, stix, etc.
                'lookup_fn': self._lookup_custom_feed,
                'rate_limit': feed.get('rate_limit', 1),
                'format': feed.get('format')
            })

        return sources

    def _load_cache(self) -> None:
        """Load cached threat intelligence data with thread safety."""
        cache_file = Path(self.config.get('cache_path', '~/.antivirus/threat_intel_cache.json')).expanduser()
        if not cache_file.exists():
            return

        try:
            # Use file lock to prevent corruption during read
            with FileLock(str(cache_file) + '.lock'):
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)

                # Process cache data outside the file lock
                temp_cache = {}
                for key, data in cache_data.items():
                    try:
                        if 'first_seen' in data and data['first_seen']:
                            data['first_seen'] = datetime.fromisoformat(data['first_seen'])
                        if 'last_seen' in data and data['last_seen']:
                            data['last_seen'] = datetime.fromisoformat(data['last_seen'])
                        temp_cache[key] = ThreatIntelResult(**data)
                    except Exception as e:
                        self.logger.warning(f"Error loading cache entry {key}: {e}")
                        continue

                # Update cache with lock
                with self._cache_lock:
                    self.cache.update(temp_cache)

                self.logger.info(f"Loaded {len(temp_cache)} cached threat intelligence items from {cache_file}")

        except Exception as e:
            self.logger.error(f"Failed to load threat intel cache: {e}")

    def _save_cache(self) -> None:
        """Save cached threat intelligence data with thread safety."""
        if not self.enabled or not self.cache:
            return

        cache_file = Path(self.config.get('cache_path', '~/.antivirus/threat_intel_cache.json')).expanduser()
        try:
            # Create parent directories if they don't exist
            cache_file.parent.mkdir(parents=True, exist_ok=True)

            # Create a temporary file first (atomic write)
            temp_file = cache_file.with_suffix('.tmp')

            # Get cache data with read lock
            with self._cache_lock:
                cache_data = {}
                for key, result in self.cache.items():
                    try:
                        data = result.__dict__.copy()
                        if hasattr(data['first_seen'], 'isoformat'):
                            data['first_seen'] = data['first_seen'].isoformat()
                        if hasattr(data['last_seen'], 'isoformat'):
                            data['last_seen'] = data['last_seen'].isoformat()
                        cache_data[key] = data
                    except Exception as e:
                        self.logger.warning(f"Error serializing cache entry {key}: {e}")
                        continue

            # Write to temporary file
            with open(temp_file, 'w') as f:
                json.dump(cache_data, f, indent=2)

            # Use file lock and atomic rename for thread/process safety
            with FileLock(str(cache_file) + '.lock'):
                # On Windows, we need to remove the destination first
                if cache_file.exists():
                    cache_file.unlink()
                temp_file.rename(cache_file)

        except Exception as e:
            self.logger.error(f"Failed to save threat intel cache: {e}")
            # Clean up temp file if it exists
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except:
                    pass

    def lookup(self, ioc: str, ioc_type: Optional[str] = None) -> Optional[ThreatIntelResult]:
        """Look up an indicator of compromise (IoC) in threat intelligence sources.

        Args:
            ioc: The indicator to look up (hash, IP, domain, URL)
            ioc_type: Type of the indicator ('hash', 'ip', 'domain', 'url')
                      If None, will be automatically detected.

        Returns:
            ThreatIntelResult if the indicator is found in any source, None otherwise
        """
        if not self.enabled:
            return None

        # Auto-detect IOC type if not specified
        if ioc_type is None:
            ioc_type = self._detect_ioc_type(ioc)
            if ioc_type is None:
                self.logger.warning(f"Could not determine type for IOC: {ioc}")
                return None

        # Normalize the IOC (e.g., lowercase for hashes, strip URLs)
        ioc = self._normalize_ioc(ioc, ioc_type)
        cache_key = f"{ioc_type}:{ioc}"

        # Check cache first with read lock
        with self._cache_lock:
            if cache_key in self.cache:
                cached_result = self.cache[cache_key]
                if datetime.now() - cached_result.last_seen < self.cache_ttl:
                    return cached_result if cached_result.malicious else None

        # Query all enabled sources in parallel with rate limiting
        futures = []
        for source in [s for s in self.sources if s.get('enabled', True)]:
            source_name = source.get('name', 'unknown')
            source_lock = self._source_locks.get(source_name, threading.RLock())

            future = self.executor.submit(
                self._query_source_with_lock,
                source=source,
                source_lock=source_lock,
                ioc=ioc,
                ioc_type=ioc_type
            )
            futures.append(future)

        # Process results with timeout
        results = []
        try:
            for future in concurrent.futures.as_completed(futures, timeout=30):  # 30s timeout
                try:
                    result = future.result()
                    if result and result.malicious:
                        results.append(result)
                except Exception as e:
                    self.logger.error(f"Error querying threat intel source: {e}")
        except concurrent.futures.TimeoutError:
            self.logger.warning("Timeout while waiting for threat intel results")

        # Combine results with cache lock
        with self._cache_lock:
            if results:
                combined = self._combine_results(results)
                self.cache[cache_key] = combined
                self._save_cache()
                return combined

            # Cache negative results with shorter TTL
            self.cache[cache_key] = ThreatIntelResult(
                ioc=ioc,
                ioc_type=ioc_type,
                malicious=False,
                confidence=0.0,
                threat_types=[],
                last_seen=datetime.now()
            )
            self._save_cache()
            return None

    def _query_source_with_lock(self, source: Dict, source_lock: threading.RLock, ioc: str, ioc_type: str) -> Optional[ThreatIntelResult]:
        """Query a single threat intelligence source with proper locking and rate limiting.

        Args:
            source: Source configuration
            source_lock: Lock for this specific source
            ioc: The indicator to look up
            ioc_type: Type of the indicator

        Returns:
            ThreatIntelResult if the indicator is found, None otherwise
        """
        source_name = source.get('name', 'unknown')

        try:
            # Apply rate limiting with source-specific lock
            with source_lock:
                current_time = time.time()
                last_call = source.get('_last_call', 0)
                min_interval = 60.0 / source.get('rate_limit', 1)

                if current_time - last_call < min_interval:
                    sleep_time = last_call + min_interval - current_time
                    if sleep_time > 0:
                        time.sleep(sleep_time)

                source['_last_call'] = time.time()

            # Call the appropriate lookup function
            lookup_fn = source.get('lookup_fn')
            if lookup_fn:
                result = lookup_fn(source, ioc, ioc_type)
                if result and result.malicious:
                    self.logger.debug(f"Malicious indicator found in {source_name}: {ioc}")
                return result

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error querying {source_name}: {e}")
        except Exception as e:
            self.logger.error(f"Error querying {source_name}: {e}", exc_info=True)

        return None

    def _lookup_virustotal(self, source: Dict, ioc: str, ioc_type: str) -> Optional[ThreatIntelResult]:
        """Look up an IOC in VirusTotal."""
        api_key = source.get('api_key')
        if not api_key:
            return None

        url = f"https://www.virustotal.com/api/v3/{ioc_type}s/{ioc}"
        headers = {"x-apikey": api_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            if 'data' in data and 'attributes' in data['data']:
                attrs = data['data']['attributes']
                malicious = attrs.get('last_analysis_stats', {}).get('malicious', 0) > 0
                confidence = attrs.get('last_analysis_stats', {}).get('malicious', 0) / 10.0  # Scale to 0-1

                threat_types = set()
                if 'last_analysis_results' in attrs:
                    for result in attrs['last_analysis_results'].values():
                        if result.get('category') == 'malicious':
                            threat_types.add(result.get('result', 'unknown'))

                return ThreatIntelResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    malicious=malicious,
                    confidence=min(1.0, confidence),
                    threat_types=list(threat_types),
                    first_seen=datetime.fromtimestamp(attrs.get('first_submission_date', 0)) if attrs.get('first_submission_date') else None,
                    last_seen=datetime.fromtimestamp(attrs.get('last_analysis_date', 0)) if attrs.get('last_analysis_date') else None,
                    sources=['VirusTotal'],
                    raw_data=data
                )

        except requests.RequestException as e:
            self.logger.error(f"VirusTotal API error: {e}")

        return None

    def _lookup_abuseipdb(self, source: Dict, ioc: str, ioc_type: str) -> Optional[ThreatIntelResult]:
        """Look up an IP in AbuseIPDB."""
        if ioc_type != 'ip':
            return None

        api_key = source.get('api_key')
        if not api_key:
            return None

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {'ipAddress': ioc, 'maxAgeInDays': '90'}

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

            if 'data' in data:
                ip_data = data['data']
                abuse_confidence = ip_data.get('abuseConfidenceScore', 0) / 100.0  # Scale to 0-1
                malicious = abuse_confidence >= 0.5  # Threshold can be adjusted

                return ThreatIntelResult(
                    ioc=ioc,
                    ioc_type='ip',
                    malicious=malicious,
                    confidence=abuse_confidence,
                    threat_types=[],  # AbuseIPDB doesn't provide specific threat types
                    last_seen=datetime.now(),  # AbuseIPDB doesn't provide last seen
                    sources=['AbuseIPDB'],
                    raw_data=data
                )

        except requests.RequestException as e:
            self.logger.error(f"AbuseIPDB API error: {e}")

        return None

    def _lookup_custom_feed(self, source: Dict, ioc: str, ioc_type: str) -> Optional[ThreatIntelResult]:
        """Look up an IOC in a custom threat feed."""
        # This is a placeholder for custom feed integration
        # Implement based on your specific feed format
        return None

    def _detect_ioc_type(self, ioc: str) -> Optional[str]:
        """Detect the type of an indicator of compromise."""
        # Check for hash
        if len(ioc) in [32, 40, 64]:  # MD5, SHA-1, SHA-256
            try:
                int(ioc, 16)  # Check if it's a valid hex string
                return 'hash'
            except ValueError:
                pass

        # Check for IP address (simple check)
        if '.' in ioc and all(part.isdigit() and 0 <= int(part) <= 255 for part in ioc.split('.')):
            return 'ip'

        # Check for domain
        if '.' in ioc and ' ' not in ioc and '://' not in ioc:
            return 'domain'

        # Check for URL
        if ioc.startswith(('http://', 'https://', 'ftp://')):
            return 'url'

        return None

    def _normalize_ioc(self, ioc: str, ioc_type: str) -> str:
        """Normalize an indicator of compromise."""
        if ioc_type == 'hash':
            return ioc.lower()
        elif ioc_type == 'ip':
            return ioc.strip()
        elif ioc_type == 'domain':
            return ioc.lower().strip().lstrip('.').rstrip('.')
        elif ioc_type == 'url':
            # Remove protocol and query parameters
            url = ioc.split('?')[0]
            if '://' in url:
                url = url.split('://', 1)[1]
            return url.lower().strip('/')
        return ioc

    def _combine_results(self, results: List[ThreatIntelResult]) -> ThreatIntelResult:
        """Combine results from multiple threat intelligence sources."""
        if not results:
            raise ValueError("No results to combine")

        # Use the first result as a base
        combined = results[0]

        # Combine data from other results
        for result in results[1:]:
            # Update confidence (weighted average)
            combined.confidence = (combined.confidence + result.confidence) / 2

            # Merge threat types
            combined.threat_types = list(set(combined.threat_types + result.threat_types))

            # Update first_seen and last_seen
            if result.first_seen and (combined.first_seen is None or result.first_seen < combined.first_seen):
                combined.first_seen = result.first_seen

            if result.last_seen and (combined.last_seen is None or result.last_seen > combined.last_seen):
                combined.last_seen = result.last_seen

            # Merge sources
            combined.sources = list(set(combined.sources + result.sources))

            # Merge raw data
            combined.raw_data.update(result.raw_data)

        return combined

    def bulk_lookup(self, iocs: List[Dict[str, str]], max_workers: Optional[int] = None) -> Dict[str, ThreatIntelResult]:
        """Look up multiple IOCs in parallel with configurable concurrency.

        Args:
            iocs: List of dicts with 'ioc' and 'type' keys
            max_workers: Maximum number of concurrent lookups (default: min(32, os.cpu_count() + 4))

        Returns:
            Dict mapping IOCs to their ThreatIntelResult (only includes malicious results)
        """
        if not self.enabled or not iocs:
            return {}

        results = {}
        start_time = time.time()
        processed = 0

        # Use a semaphore to limit concurrent API calls across all sources
        max_concurrent = max_workers or min(32, (os.cpu_count() or 4) + 4)
        semaphore = threading.Semaphore(max_concurrent)

        def process_ioc(ioc_data: Dict[str, str]) -> Optional[ThreatIntelResult]:
            nonlocal processed
            with semaphore:
                try:
                    result = self.lookup(ioc_data['ioc'], ioc_data.get('type'))
                    processed += 1
                    if processed % 10 == 0:  # Log progress every 10 lookups
                        elapsed = time.time() - start_time
                        rate = processed / elapsed if elapsed > 0 else 0
                        self.logger.info(
                            f"Processed {processed}/{len(iocs)} IOCs "
                            f"({rate:.1f} lookups/sec, {len(results)} malicious)"
                        )
                    return result
                except Exception as e:
                    self.logger.error(f"Error in bulk lookup: {e}", exc_info=True)
                    return None

        try:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_concurrent,
                thread_name_prefix='bulk_lookup_'
            ) as executor:
                # Submit all lookups
                future_to_ioc = {
                    executor.submit(process_ioc, ioc): ioc['ioc']
                    for ioc in iocs
                }

                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_ioc, timeout=300):  # 5min timeout
                    ioc = future_to_ioc[future]
                    try:
                        result = future.result()
                        if result and result.malicious:
                            results[ioc] = result
                    except concurrent.futures.TimeoutError:
                        self.logger.warning(f"Timeout processing IOC: {ioc}")
                    except Exception as e:
                        self.logger.error(f"Error processing IOC {ioc}: {e}")

        except Exception as e:
            self.logger.error(f"Fatal error in bulk lookup: {e}", exc_info=True)
        finally:
            elapsed = time.time() - start_time
            self.logger.info(
                f"Completed bulk lookup of {len(iocs)} IOCs in {elapsed:.1f} seconds. "
                f"Found {len(results)} malicious indicators."
            )

        return results

    def update_feeds(self) -> bool:
        """Update local threat intelligence feeds."""
        # Implement feed updates here
        return True

    def __del__(self):
        """Clean up resources."""
        self.executor.shutdown(wait=True)
        self._save_cache()
