"""
Database Module - Phase 4

Loads and queries JSON databases for enhanced honeypot detection.
Community-contributed data for open source collaboration.
"""

import json
import ipaddress
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class IPCheckResult:
    """Result of IP range check"""
    is_known: bool
    name: str = ""
    score: int = 0
    source: str = ""


@dataclass
class PatternCheckResult:
    """Result of service pattern check"""
    matches: List[Dict]
    total_score: int


@dataclass
class OSGuess:
    """OS fingerprint guess"""
    os_name: str
    confidence: float
    source: str


class ArgusDatabase:
    """
    Loads and queries community-contributed databases for:
    - Known honeypot IP ranges
    - Suspicious service patterns
    - OS fingerprints
    """
    
    def __init__(self, data_dir: Optional[Path] = None):
        if data_dir is None:
            # Default to argus/data relative to this file
            data_dir = Path(__file__).parent / "data"
        
        self.data_dir = Path(data_dir)
        self._honeypot_ips = None
        self._service_patterns = None
        self._os_fingerprints = None
    
    def _load_json(self, filename: str) -> Dict:
        """Load a JSON database file."""
        filepath = self.data_dir / filename
        if filepath.exists():
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
    
    @property
    def honeypot_ips(self) -> Dict:
        """Lazy load honeypot IPs database."""
        if self._honeypot_ips is None:
            self._honeypot_ips = self._load_json("honeypot_ips.json")
        return self._honeypot_ips
    
    @property
    def service_patterns(self) -> Dict:
        """Lazy load service patterns database."""
        if self._service_patterns is None:
            self._service_patterns = self._load_json("service_patterns.json")
        return self._service_patterns
    
    @property
    def os_fingerprints(self) -> Dict:
        """Lazy load OS fingerprints database."""
        if self._os_fingerprints is None:
            self._os_fingerprints = self._load_json("os_fingerprints.json")
        return self._os_fingerprints
    
    def check_ip(self, ip: str) -> IPCheckResult:
        """
        Check if an IP is in a known honeypot range.
        
        Args:
            ip: Target IP address
            
        Returns:
            IPCheckResult with match info
        """
        try:
            target_ip = ipaddress.ip_address(ip)
        except ValueError:
            return IPCheckResult(is_known=False)
        
        # Check single IPs first
        for entry in self.honeypot_ips.get("single_ips", []):
            if entry.get("ip") == ip:
                return IPCheckResult(
                    is_known=True,
                    name=entry.get("name", ""),
                    score=entry.get("score", 0),
                    source=entry.get("source", "")
                )
        
        # Check ranges
        for entry in self.honeypot_ips.get("ranges", []):
            try:
                network = ipaddress.ip_network(entry.get("cidr", ""), strict=False)
                if target_ip in network:
                    return IPCheckResult(
                        is_known=True,
                        name=entry.get("name", ""),
                        score=entry.get("score", 0),
                        source=entry.get("source", "")
                    )
            except ValueError:
                continue
        
        return IPCheckResult(is_known=False)
    
    def check_service_patterns(self, detected_services: List[str]) -> PatternCheckResult:
        """
        Check for suspicious service combinations.
        
        Args:
            detected_services: List of detected service names (e.g., ["SSH", "HTTP", "MySQL"])
            
        Returns:
            PatternCheckResult with matches and score
        """
        # Normalize service names
        services_upper = [s.upper() for s in detected_services]
        services_set = set(services_upper)
        
        matches = []
        total_score = 0
        
        for pattern in self.service_patterns.get("suspicious_combos", []):
            required = [r.upper() for r in pattern.get("requires", [])]
            min_match = pattern.get("min_match", len(required))
            
            # Count how many required services are present
            matched = sum(1 for r in required if r in services_set)
            
            if matched >= min_match:
                matches.append({
                    "name": pattern.get("name"),
                    "reason": pattern.get("reason"),
                    "score": pattern.get("score", 0)
                })
                total_score += pattern.get("score", 0)
        
        return PatternCheckResult(matches=matches, total_score=total_score)
    
    def guess_os_from_banner(self, banner: str, service: str = "") -> Optional[OSGuess]:
        """
        Guess OS from banner content.
        
        Args:
            banner: Banner text from service
            service: Service type (e.g., "SSH", "HTTP")
            
        Returns:
            OSGuess if match found, None otherwise
        """
        banner_lower = banner.lower()
        
        for fp in self.os_fingerprints.get("fingerprints", []):
            # Check general patterns
            for pattern in fp.get("patterns", []):
                if pattern.lower() in banner_lower:
                    return OSGuess(
                        os_name=fp["os"],
                        confidence=0.7,
                        source="banner_pattern"
                    )
            
            # Check service-specific patterns
            if service:
                service_patterns = fp.get("services", {}).get(service, [])
                for sp in service_patterns:
                    if re.search(sp, banner, re.IGNORECASE):
                        return OSGuess(
                            os_name=fp["os"],
                            confidence=0.85,
                            source="service_pattern"
                        )
        
        # Try service indicators
        for service_name, info in self.os_fingerprints.get("service_indicators", {}).items():
            if service_name.lower() in banner_lower:
                likely_os = info.get("likely_os", [])
                if likely_os:
                    return OSGuess(
                        os_name=likely_os[0],
                        confidence=info.get("confidence", 0.5),
                        source="service_indicator"
                    )
        
        return None
    
    def get_database_versions(self) -> Dict[str, str]:
        """Get versions of all loaded databases."""
        return {
            "honeypot_ips": self.honeypot_ips.get("version", "unknown"),
            "service_patterns": self.service_patterns.get("version", "unknown"),
            "os_fingerprints": self.os_fingerprints.get("version", "unknown"),
        }


# Singleton instance
_database: Optional[ArgusDatabase] = None


def get_database() -> ArgusDatabase:
    """Get the singleton database instance."""
    global _database
    if _database is None:
        _database = ArgusDatabase()
    return _database
