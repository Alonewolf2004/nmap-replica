"""
Unit tests for Honeypot Detector module.
Run with: pytest tests/test_honeypot.py -v
"""
import pytest
from argus.honeypot_detector import HoneypotDetector, HoneypotResult


class TestPortDensity:
    """Test port density scoring algorithm"""
    
    def test_low_port_count_low_score(self):
        """Few open ports should result in low score"""
        detector = HoneypotDetector()
        result = detector.analyze(
            open_ports=[22, 80, 443],
            banners={22: "SSH-2.0-OpenSSH", 80: "HTTP", 443: "HTTPS"},
            os_guesses={22: "Linux", 80: "Linux", 443: "Linux"},
            timing_data={22: 0.05, 80: 0.06, 443: 0.07}
        )
        # 3 ports should give 0 points (under threshold of 10)
        assert result.breakdown['port_density']['score'] == 0
        assert result.breakdown['port_density']['open_port_count'] == 3
    
    def test_medium_port_count_medium_score(self):
        """Medium port count should result in elevated score"""
        detector = HoneypotDetector()
        ports = list(range(1, 26))  # 25 ports
        result = detector.analyze(
            open_ports=ports,
            banners={p: f"banner_{p}" for p in ports},
            os_guesses={p: "Linux" for p in ports},
            timing_data={p: 0.05 for p in ports}
        )
        # 25 ports should give 15 points (threshold 20)
        assert result.breakdown['port_density']['score'] == 15
    
    def test_high_port_count_high_score(self):
        """Many open ports should result in high score"""
        detector = HoneypotDetector()
        ports = list(range(1, 101))  # 100 ports
        result = detector.analyze(
            open_ports=ports,
            banners={p: f"banner_{p}" for p in ports},
            os_guesses={p: "Linux" for p in ports},
            timing_data={p: 0.05 for p in ports}
        )
        # 100 ports should give max 40 points
        assert result.breakdown['port_density']['score'] == 40


class TestBannerConsistency:
    """Test banner/OS consistency validation"""
    
    def test_consistent_os_low_score(self):
        """Consistent OS indicators should result in low score"""
        detector = HoneypotDetector()
        result = detector.analyze(
            open_ports=[22, 80],
            banners={22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu", 80: "Apache/2.4.41 (Ubuntu)"},
            os_guesses={22: "Ubuntu Linux", 80: "Ubuntu Linux"},
            timing_data={22: 0.05, 80: 0.06}
        )
        # All indicators point to Linux - should be 0
        assert result.breakdown['banner_consistency']['score'] == 0
        assert result.breakdown['banner_consistency']['conflict_count'] == 0
    
    def test_os_mismatch_high_score(self):
        """Mixed OS indicators should be flagged"""
        detector = HoneypotDetector()
        result = detector.analyze(
            open_ports=[22, 80],
            banners={22: "SSH-2.0-OpenSSH Ubuntu", 80: "Microsoft-IIS/10.0"},
            os_guesses={22: "Linux", 80: "Windows Server"},
            timing_data={22: 0.05, 80: 0.06}
        )
        # Linux (SSH) vs Windows (IIS) = conflict
        assert result.breakdown['banner_consistency']['score'] > 0
        assert result.breakdown['banner_consistency']['conflict_count'] >= 1


class TestTimingPatterns:
    """Test response timing analysis"""
    
    def test_normal_timing_low_score(self):
        """Normal response times should not be flagged"""
        detector = HoneypotDetector()
        result = detector.analyze(
            open_ports=[22, 80, 443],
            banners={22: "SSH", 80: "HTTP", 443: "HTTPS"},
            os_guesses={22: "Linux", 80: "Linux", 443: "Linux"},
            timing_data={22: 0.050, 80: 0.065, 443: 0.073}  # 50-73ms, normal
        )
        # Normal timing with variation
        assert result.breakdown['timing']['score'] < 15
    
    def test_too_fast_responses_flagged(self):
        """Sub-5ms responses should be flagged"""
        detector = HoneypotDetector()
        result = detector.analyze(
            open_ports=[22, 80, 443],
            banners={22: "SSH", 80: "HTTP", 443: "HTTPS"},
            os_guesses={22: "Linux", 80: "Linux", 443: "Linux"},
            timing_data={22: 0.001, 80: 0.002, 443: 0.001}  # 1-2ms, too fast
        )
        # Very fast responses should be flagged
        assert result.breakdown['timing']['score'] >= 15
        assert "under 5ms" in result.breakdown['timing']['issues'][0]
    
    def test_zero_jitter_flagged(self):
        """Near-zero jitter should be flagged"""
        detector = HoneypotDetector()
        result = detector.analyze(
            open_ports=list(range(1, 11)),  # 10 ports
            banners={p: "banner" for p in range(1, 11)},
            os_guesses={p: "Linux" for p in range(1, 11)},
            timing_data={p: 0.050 for p in range(1, 11)}  # Exactly same timing
        )
        # Zero variation in timing is suspicious
        timing_issues = result.breakdown['timing'].get('issues', [])
        assert any('jitter' in issue.lower() for issue in timing_issues)


class TestOverallScoring:
    """Test combined scoring and confidence levels"""
    
    def test_low_score_is_not_honeypot(self):
        """Low total score should not flag as honeypot"""
        detector = HoneypotDetector()
        result = detector.analyze(
            open_ports=[22, 80],
            banners={22: "SSH-2.0-OpenSSH Ubuntu", 80: "Apache Ubuntu"},
            os_guesses={22: "Ubuntu Linux", 80: "Ubuntu Linux"},
            timing_data={22: 0.050, 80: 0.065}
        )
        assert result.score < 40
        assert result.confidence == "LOW"
        assert result.is_likely_honeypot is False
    
    def test_high_score_is_honeypot(self):
        """High total score should flag as honeypot"""
        detector = HoneypotDetector()
        # Simulate honeypot: many ports, OS mismatch, fast responses
        ports = list(range(1, 101))  # 100 ports
        result = detector.analyze(
            open_ports=ports,
            banners={**{p: "SSH Linux" for p in ports[:50]}, **{p: "IIS Windows" for p in ports[50:]}},
            os_guesses={**{p: "Linux" for p in ports[:50]}, **{p: "Windows" for p in ports[50:]}},
            timing_data={p: 0.001 for p in ports}  # Very fast
        )
        assert result.score >= 60
        assert result.confidence == "HIGH"
        assert result.is_likely_honeypot is True
    
    def test_result_dataclass_fields(self):
        """Test HoneypotResult has all expected fields"""
        detector = HoneypotDetector()
        result = detector.analyze(
            open_ports=[80],
            banners={80: "HTTP"},
            os_guesses={80: "Unknown"},
            timing_data={80: 0.05}
        )
        assert isinstance(result, HoneypotResult)
        assert hasattr(result, 'score')
        assert hasattr(result, 'confidence')
        assert hasattr(result, 'breakdown')
        assert hasattr(result, 'is_likely_honeypot')
        assert 'port_density' in result.breakdown
        assert 'banner_consistency' in result.breakdown
        assert 'timing' in result.breakdown
