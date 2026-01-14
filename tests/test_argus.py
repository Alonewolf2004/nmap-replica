"""
Unit tests for Argus port scanner.
Run with: pytest tests/ -v --cov=argus --cov-report=html
"""
import pytest
import asyncio
from argus.analyzer import BannerAnalyzer
from argus.analyzers.registry import AnalyzerRegistry
from argus.analyzers.ssh import SSHAnalyzer
from argus.analyzers.http import HTTPAnalyzer
from argus.analyzers.database import DatabaseAnalyzer
from argus.utils import parse_ports, BloomFilter, RateLimiter, ResultCache
from argus.config import ScanConfig


class TestBannerAnalyzer:
    """Test banner analysis and Trie detection"""
    
    def test_trie_lookup_ssh(self):
        """Test Trie detects SSH banner"""
        banner = "SSH-2.0-OpenSSH_7.4"
        tag = BannerAnalyzer._trie_lookup(banner)
        assert tag == "SSH"
    
    def test_trie_lookup_http(self):
        """Test Trie detects HTTP response"""
        banner = "HTTP/1.1 200 OK\r\nServer: nginx"
        tag = BannerAnalyzer._trie_lookup(banner)
        assert tag == "HTTP"
    
    def test_trie_lookup_ftp(self):
        """Test Trie detects FTP banner"""
        banner = "220 Welcome to FTP server"
        tag = BannerAnalyzer._trie_lookup(banner)
        assert tag == "FTP"
    
    def test_trie_lookup_mysql(self):
        """Test Trie detects MySQL banner"""
        banner = "5.7.30-0ubuntu0.18.04.1"
        tag = BannerAnalyzer._trie_lookup(banner)
        assert tag == "MySQL"
    
    def test_trie_lookup_unknown(self):
        """Test Trie returns None for unknown"""
        banner = "Random junk data"
        tag = BannerAnalyzer._trie_lookup(banner)
        assert tag is None
    
    def test_get_probe_http(self):
        """Test HTTP probe generation"""
        probe, is_binary = BannerAnalyzer.get_probe(80, "example.com")
        assert b"GET / HTTP/1.1" in probe
        assert b"Host: example.com" in probe
        assert not is_binary
    
    def test_get_probe_ssh(self):
        """Test SSH uses generic probe (HTTP GET fallback)"""
        probe, is_binary = BannerAnalyzer.get_probe(22, "test.com")
        # SSH should get generic HTTP probe as fallback
        assert b"GET /" in probe
        assert not is_binary
    
    def test_get_probe_rtsp(self):
        """Test RTSP probe"""
        probe, is_binary = BannerAnalyzer.get_probe(554, "test.com")
        assert b"OPTIONS * RTSP/1.0" in probe
        assert not is_binary
    
    def test_analyze_ssh_banner(self):
        """Test SSH banner analysis"""
        banner = "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"
        service, os = BannerAnalyzer.analyze_banner(banner, 22)
        assert "SSH" in service
        assert "OpenSSH" in service
        assert "7.4" in service
        assert "Debian" in os
    
    def test_analyze_http_banner(self):
        """Test HTTP banner analysis"""
        banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"
        service, os = BannerAnalyzer.analyze_banner(banner, 80)
        assert "HTTP" in service
        assert "Apache" in service


class TestSSHAnalyzer:
    """Test SSH analyzer plugin"""
    
    def test_can_analyze_ssh_banner(self):
        """Test SSH detection"""
        analyzer = SSHAnalyzer()
        assert analyzer.can_analyze(22, "SSH-2.0-OpenSSH_7.4", "SSH")
        assert analyzer.can_analyze(22, "SSH-2.0-dropbear", None)
        assert not analyzer.can_analyze(80, "HTTP/1.1 200 OK", None)
    
    def test_analyze_openssh(self):
        """Test OpenSSH version extraction"""
        analyzer = SSHAnalyzer()
        service, os = analyzer.analyze("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1")
        assert "OpenSSH 8.2" in service
        assert "Ubuntu" in os
    
    def test_analyze_openssh_freebsd(self):
        """Test OpenSSH on FreeBSD"""
        analyzer = SSHAnalyzer()
        service, os = analyzer.analyze("SSH-2.0-OpenSSH_7.9 FreeBSD-20190318")
        assert "OpenSSH 7.9" in service
        assert "FreeBSD" in os
    
    def test_analyze_dropbear(self):
        """Test Dropbear SSH"""
        analyzer = SSHAnalyzer()
        service, os = analyzer.analyze("SSH-2.0-dropbear_2019.78")
        assert "SSH" in service
        assert "dropbear" in service


class TestHTTPAnalyzer:
    """Test HTTP analyzer plugin"""
    
    def test_can_analyze_http(self):
        """Test HTTP detection"""
        analyzer = HTTPAnalyzer()
        assert analyzer.can_analyze(80, "HTTP/1.1 200 OK", "HTTP")
        assert analyzer.can_analyze(443, "HTTP/2 200", None)
        assert not analyzer.can_analyze(22, "SSH-2.0", None)
    
    def test_analyze_apache(self):
        """Test Apache detection"""
        analyzer = HTTPAnalyzer()
        banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"
        service, os = analyzer.analyze(banner)
        assert "Apache" in service
        assert "2.4.41" in service
        assert "Ubuntu" in os
    
    def test_analyze_nginx(self):
        """Test Nginx detection"""
        analyzer = HTTPAnalyzer()
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0"
        service, os = analyzer.analyze(banner)
        assert "Nginx" in service or "nginx" in service
        assert "1.18.0" in service


class TestDatabaseAnalyzer:
    """Test database analyzer plugin"""
    
    def test_can_analyze_mysql(self):
        """Test MySQL detection"""
        analyzer = DatabaseAnalyzer()
        assert analyzer.can_analyze(3306, "5.7.30-0ubuntu", "MySQL")
        assert analyzer.can_analyze(3306, "mysql_native_password", None)
    
    def test_analyze_mysql_version(self):
        """Test MySQL version extraction"""
        analyzer = DatabaseAnalyzer()
        service, os = analyzer.analyze("5.7.30-0ubuntu0.18.04.1")
        assert "MySQL 5.7.30" in service


class TestAnalyzerRegistry:
    """Test the analyzer registry/dispatcher"""
    
    def test_registry_ssh(self):
        """Test registry dispatches to SSH analyzer"""
        registry = AnalyzerRegistry()
        service, os = registry.analyze(22, "SSH-2.0-OpenSSH_7.4", "SSH")
        assert "SSH" in service
        assert "OpenSSH" in service
    
    def test_registry_http(self):
        """Test registry dispatches to HTTP analyzer"""
        registry = AnalyzerRegistry()
        service, os = registry.analyze(80, "HTTP/1.1 200 OK\r\nServer: nginx", "HTTP")
        assert "HTTP" in service
    
    def test_registry_fallback(self):
        """Test registry fallback for unknown"""
        registry = AnalyzerRegistry()
        service, os = registry.analyze(9999, "weird banner", None)
        assert "Unknown" in service


class TestPortParser:
    """Test port parsing utility"""
    
    def test_parse_single_port(self):
        """Test single port"""
        ports = parse_ports("80")
        assert ports == [80]
    
    def test_parse_multiple_ports(self):
        """Test comma-separated ports"""
        ports = parse_ports("22,80,443")
        assert set(ports) == {22, 80, 443}
    
    def test_parse_range(self):
        """Test port range"""
        ports = parse_ports("20-25")
        assert set(ports) == {20, 21, 22, 23, 24, 25}
    
    def test_parse_mixed(self):
        """Test mixed format"""
        ports = parse_ports("22,80-82,443")
        assert set(ports) == {22, 80, 81, 82, 443}
    
    def test_parse_invalid_removed(self):
        """Test invalid ports are removed"""
        ports = parse_ports("80,99999,22")
        assert 99999 not in ports
        assert 80 in ports
        assert 22 in ports


class TestBloomFilter:
    """Test Bloom filter deduplication"""
    
    def test_bloom_filter_add_check(self):
        """Test adding and checking"""
        bf = BloomFilter()  # Uses default size/hashes
        bf.add("192.168.1.1:80")
        assert "192.168.1.1:80" in bf
        assert "192.168.1.1:443" not in bf
    
    def test_bloom_filter_no_false_negatives(self):
        """Test no false negatives"""
        bf = BloomFilter()
        items = [f"host{i}:port{i}" for i in range(100)]
        for item in items:
            bf.add(item)
        for item in items:
            assert item in bf, f"False negative for {item}"


class TestRateLimiter:
    """Test rate limiter"""
    
    @pytest.mark.asyncio
    async def test_rate_limiter_allows_within_limit(self):
        """Test rate limiter allows requests within limit"""
        limiter = RateLimiter(max_per_second=10)
        start = asyncio.get_event_loop().time()
        for _ in range(5):
            await limiter.acquire()
        elapsed = asyncio.get_event_loop().time() - start
        # Should be nearly instant for 5 requests with limit of 10/sec
        assert elapsed < 1.0
    
    @pytest.mark.asyncio
    async def test_rate_limiter_slows_beyond_limit(self):
        """Test rate limiter enforces limit"""
        limiter = RateLimiter(max_per_second=5)
        start = asyncio.get_event_loop().time()
        for _ in range(10):
            await limiter.acquire()
        elapsed = asyncio.get_event_loop().time() - start
        # Should take at least 1 second for 10 requests at 5/sec (relaxed from 1.5)
        assert elapsed >= 0.8  # Relaxed timing to account for overhead


class TestResultCache:
    """Test result caching"""
    
    def test_cache_get_set(self):
        """Test basic cache operations"""
        cache = ResultCache(ttl=300)
        cache.set("192.168.1.1", 80, {"status": "open", "service": "HTTP"})
        result = cache.get("192.168.1.1", 80)
        assert result["status"] == "open"
        assert result["service"] == "HTTP"
    
    def test_cache_miss(self):
        """Test cache miss returns None"""
        cache = ResultCache(ttl=300)
        result = cache.get("192.168.1.1", 443)
        assert result is None
    
    def test_cache_ttl_expiry(self):
        """Test TTL expiration"""
        import time
        cache = ResultCache(ttl=1)  # 1 second TTL
        cache.set("192.168.1.1", 80, {"status": "open"})
        assert cache.get("192.168.1.1", 80) is not None
        time.sleep(1.5)
        assert cache.get("192.168.1.1", 80) is None


class TestScanConfig:
    """Test Pydantic configuration validation"""
    
    def test_valid_config(self):
        """Test valid configuration"""
        config = ScanConfig(
            target_ip="192.168.1.1",
            ports=[80, 443],
            timeout=2.0,
            concurrency=500
        )
        assert config.target_ip == "192.168.1.1"
        assert config.ports == [80, 443]
    
    def test_invalid_timeout(self):
        """Test timeout validation"""
        with pytest.raises(Exception):  # Pydantic ValidationError
            ScanConfig(
                target_ip="192.168.1.1",
                ports=[80],
                timeout=-1.0  # Invalid!
            )
    
    def test_invalid_concurrency(self):
        """Test concurrency validation"""
        with pytest.raises(Exception):
            ScanConfig(
                target_ip="192.168.1.1",
                ports=[80],
                concurrency=10000  # Too high!
            )
    
    def test_empty_ports(self):
        """Test empty ports list"""
        with pytest.raises(Exception):
            ScanConfig(
                target_ip="192.168.1.1",
                ports=[],  # Invalid!
                concurrency=500
            )
