"""
Honeypot Detection Module - Phase 1 + Phase 4 Database Integration

Provides honeypot detection using:
1. Port Density Check - Suspicious if too many ports are open
2. Banner/OS Consistency - Cross-validates OS hints across services
3. Response Timing Analysis - Flags too-fast or zero-jitter responses
4. Database Checks - Known honeypot IPs and suspicious service patterns
"""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import statistics

from .database import get_database


@dataclass
class HoneypotResult:
    """Result of honeypot analysis"""
    score: int  # 0-100, higher = more likely honeypot
    confidence: str  # LOW, MEDIUM, HIGH
    breakdown: Dict[str, Dict]
    is_likely_honeypot: bool


class HoneypotDetector:
    """
    Analyzes scan results to detect potential honeypots.
    
    Phase 1 implements three basic checks:
    - Port density (weight: 40)
    - Banner/OS consistency (weight: 30)
    - Response timing patterns (weight: 30)
    
    Phase 4 adds database-backed checks:
    - Known honeypot IP ranges
    - Suspicious service pattern combinations
    """
    
    # Thresholds
    PORT_DENSITY_THRESHOLDS = {
        10: 5,    # 10+ ports = 5 points
        20: 15,   # 20+ ports = 15 points
        30: 25,   # 30+ ports = 25 points
        50: 35,   # 50+ ports = 35 points
        100: 40,  # 100+ ports = 40 points (max)
    }
    
    # Known OS indicators from banners
    OS_INDICATORS = {
        'linux': ['ubuntu', 'debian', 'centos', 'fedora', 'rhel', 'linux', 'openssh'],
        'windows': ['windows', 'microsoft', 'iis', 'win32', 'win64'],
        'freebsd': ['freebsd'],
        'macos': ['darwin', 'macos', 'osx'],
    }
    
    # Suspicious timing thresholds (in seconds)
    TIMING_TOO_FAST_MS = 5  # < 5ms is suspiciously fast
    TIMING_JITTER_THRESHOLD = 0.001  # Near-zero jitter is suspicious
    
    def __init__(self):
        self.weights = {
            'port_density': 40,
            'banner_consistency': 30,
            'timing': 30,
        }
        self.database = get_database()
    
    def analyze(
        self,
        open_ports: List[int],
        banners: Dict[int, str],
        os_guesses: Dict[int, str],
        timing_data: Dict[int, float],
        target_ip: Optional[str] = None,
        detected_services: Optional[List[str]] = None
    ) -> HoneypotResult:
        """
        Analyze scan results for honeypot indicators.
        
        Args:
            open_ports: List of open port numbers
            banners: Dict mapping port -> banner string
            os_guesses: Dict mapping port -> OS guess string
            timing_data: Dict mapping port -> response time in seconds
            target_ip: Target IP address (for database lookup)
            detected_services: List of detected service names (for pattern check)
            
        Returns:
            HoneypotResult with score and breakdown
        """
        # Calculate individual scores
        port_score, port_details = self._check_port_density(open_ports)
        banner_score, banner_details = self._check_banner_consistency(banners, os_guesses)
        timing_score, timing_details = self._check_timing_patterns(timing_data)
        
        # Phase 4: Database checks
        db_score = 0
        db_details = {}
        
        # Check known honeypot IPs
        if target_ip:
            ip_result = self.database.check_ip(target_ip)
            if ip_result.is_known and ip_result.score > 0:
                db_score += ip_result.score
                db_details['known_ip'] = {
                    'name': ip_result.name,
                    'score': ip_result.score,
                    'source': ip_result.source
                }
        
        # Check suspicious service patterns
        if detected_services:
            pattern_result = self.database.check_service_patterns(detected_services)
            if pattern_result.matches:
                db_score += pattern_result.total_score
                db_details['suspicious_patterns'] = pattern_result.matches
        
        # Combine scores (cap at 100)
        total_score = min(100, port_score + banner_score + timing_score + db_score)
        
        # Determine confidence level
        if total_score >= 60:
            confidence = "HIGH"
            is_likely = True
        elif total_score >= 40:
            confidence = "MEDIUM"
            is_likely = False
        else:
            confidence = "LOW"
            is_likely = False
        
        breakdown = {
            'port_density': {
                'score': port_score,
                'max': self.weights['port_density'],
                **port_details
            },
            'banner_consistency': {
                'score': banner_score,
                'max': self.weights['banner_consistency'],
                **banner_details
            },
            'timing': {
                'score': timing_score,
                'max': self.weights['timing'],
                **timing_details
            }
        }
        
        # Add database results if any
        if db_details:
            breakdown['database'] = {
                'score': db_score,
                **db_details
            }
        
        return HoneypotResult(
            score=total_score,
            confidence=confidence,
            breakdown=breakdown,
            is_likely_honeypot=is_likely
        )
    
    def _check_port_density(self, open_ports: List[int]) -> Tuple[int, Dict]:
        """
        Check if the number of open ports is suspiciously high.
        
        Real servers typically have 1-10 open ports.
        Honeypots often have 50+ ports open to attract scanners.
        """
        port_count = len(open_ports)
        score = 0
        
        for threshold, points in sorted(self.PORT_DENSITY_THRESHOLDS.items()):
            if port_count >= threshold:
                score = points
        
        details = {
            'open_port_count': port_count,
            'reason': self._get_port_density_reason(port_count, score)
        }
        
        return score, details
    
    def _get_port_density_reason(self, count: int, score: int) -> str:
        """Generate human-readable reason for port density score."""
        if score >= 35:
            return f"{count} open ports is extremely suspicious"
        elif score >= 25:
            return f"{count} open ports is highly unusual"
        elif score >= 15:
            return f"{count} open ports is above normal"
        elif score >= 5:
            return f"{count} open ports is slightly elevated"
        else:
            return f"{count} open ports is normal"
    
    def _check_banner_consistency(
        self,
        banners: Dict[int, str],
        os_guesses: Dict[int, str]
    ) -> Tuple[int, Dict]:
        """
        Cross-validate OS hints across different services.
        
        Example: SSH banner says "Ubuntu" but HTTP says "Windows Server"
        indicates a likely honeypot or misconfigured server.
        """
        detected_os_families = {}
        
        # Analyze each banner and OS guess
        for port in banners:
            banner = (banners.get(port) or "").lower()
            os_guess = (os_guesses.get(port) or "").lower()
            combined = f"{banner} {os_guess}"
            
            for os_family, indicators in self.OS_INDICATORS.items():
                for indicator in indicators:
                    if indicator in combined:
                        if os_family not in detected_os_families:
                            detected_os_families[os_family] = []
                        detected_os_families[os_family].append(port)
                        break
        
        # Check for conflicts
        unique_families = list(detected_os_families.keys())
        conflict_count = len(unique_families)
        
        score = 0
        conflicts = []
        
        if conflict_count > 1:
            # Multiple OS families detected = suspicious
            score = min(30, conflict_count * 15)  # 15 points per conflict
            
            # Build conflict description
            for family, ports in detected_os_families.items():
                conflicts.append(f"{family.upper()} on ports {ports[:3]}")
        
        details = {
            'os_families_detected': unique_families,
            'conflict_count': max(0, conflict_count - 1),
            'conflicts': conflicts,
            'reason': self._get_consistency_reason(conflict_count)
        }
        
        return score, details
    
    def _get_consistency_reason(self, conflict_count: int) -> str:
        """Generate human-readable reason for banner consistency score."""
        if conflict_count > 2:
            return "Multiple conflicting OS indicators detected"
        elif conflict_count == 2:
            return "OS mismatch between services"
        else:
            return "OS indicators are consistent"
    
    def _check_timing_patterns(self, timing_data: Dict[int, float]) -> Tuple[int, Dict]:
        """
        Analyze response timing patterns for anomalies.
        
        Suspicious patterns:
        - Too fast (< 5ms): Honeypots may respond instantly
        - Zero jitter: Real servers have natural timing variation
        """
        if not timing_data:
            return 0, {'reason': 'No timing data available'}
        
        times_ms = [t * 1000 for t in timing_data.values() if t > 0]
        
        if not times_ms:
            return 0, {'reason': 'No valid timing measurements'}
        
        score = 0
        issues = []
        
        # Check 1: Too fast responses
        fast_count = sum(1 for t in times_ms if t < self.TIMING_TOO_FAST_MS)
        fast_ratio = fast_count / len(times_ms)
        
        if fast_ratio > 0.5:
            # More than 50% of responses are suspiciously fast
            score += 15
            issues.append(f"{fast_count}/{len(times_ms)} responses under {self.TIMING_TOO_FAST_MS}ms")
        
        # Check 2: Low jitter (too consistent)
        if len(times_ms) >= 3:
            try:
                stdev = statistics.stdev(times_ms)
                mean = statistics.mean(times_ms)
                cv = stdev / mean if mean > 0 else 0  # Coefficient of variation
                
                if cv < 0.05:  # Less than 5% variation is suspicious
                    score += 15
                    issues.append(f"Near-zero timing jitter (CV={cv:.3f})")
            except statistics.StatisticsError:
                pass
        
        details = {
            'sample_count': len(times_ms),
            'min_ms': round(min(times_ms), 2) if times_ms else 0,
            'max_ms': round(max(times_ms), 2) if times_ms else 0,
            'avg_ms': round(statistics.mean(times_ms), 2) if times_ms else 0,
            'issues': issues,
            'reason': issues[0] if issues else 'Timing patterns appear normal'
        }
        
        return score, details
