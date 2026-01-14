import re
from typing import Tuple, Optional
from .analyzers.registry import AnalyzerRegistry

class BannerAnalyzer:
    """
    Encapsulates logic for Protocol Probes, HTTP Parsing, and Banner Analysis.
    Delegates analysis to the Plugin Registry (Strategy Pattern).
    """
    
    # Trie Root for Protocol Prefixes (Optimization: O(k) lookup)
    _TRIE_ROOT = {}
    _REGISTRY = AnalyzerRegistry()

    @classmethod
    def _build_trie(cls):
        """
        Builds the prefix trie for fast O(k) protocol identification.
        """
        signatures = [
            ("SSH-", "SSH"),
            ("HTTP", "HTTP"),
            ("220 ", "FTP"),
            ("mysql", "MySQL"),
            ("MariaDB", "MySQL"),
            ("5.", "MySQL"), 
            ("+OK", "POP3"),
            ("RTSP", "RTSP"),
            ("PONG", "Redis"),
            ("RFB", "VNC")
        ]
        
        for pattern, tag in signatures:
            node = cls._TRIE_ROOT
            for char in pattern:
                node = node.setdefault(char, {})
            node['_tag'] = tag

    @classmethod
    def _trie_lookup(cls, text: str) -> Optional[str]:
        """
        Walks the Trie to find a matching protocol signature.
        """
        if not cls._TRIE_ROOT:
            cls._build_trie()
            
        node = cls._TRIE_ROOT
        for char in text[:20]:
            if char not in node:
                return None
            node = node[char]
            if '_tag' in node:
                return node['_tag']
        return None

    @staticmethod
    def get_probe(port: int, target_ip: str) -> Tuple[Optional[bytes], bool]:
        """
        Returns (Probe Data, IsBinary) based on port.
        """
        # HTTP Probes
        if port in [80, 8080, 8000, 443, 8443, 2052, 2053, 2082, 2083, 2095, 2096, 8880]:
            return f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Argus/1.0\r\n\r\n".encode(), False
        
        # RTSP
        if port == 554:
            return b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", False
            
        # PPTP
        if port == 1723:
            return (b"\x00\x9c\x00\x01\x1a\x2b\x3c\x4d" + b"\x00" * 148), True

        # FTP: Passive read first, then probe if needed
        if port == 21: 
            return b"HELP\r\n", False
        
        # SMTP
        if port in [25, 587]: 
            return b"EHLO scan\r\n", False
        
        # Redis
        if port == 6379: 
            return b"PING\r\n", False
        
        # Generic Fallback: HTTP GET works for most modern services
        return f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Argus/1.0\r\n\r\n".encode(), False

    @classmethod
    def analyze_banner(cls, banner: str, port: int) -> Tuple[str, str]:
        """
        Refactored: Uses Trie for Tagging -> Delegates to Registry Strategies.
        """
        # 1. Fast Path: Trie Lookup (Optimization)
        trie_tag = cls._trie_lookup(banner)
        
        # 2. Strategy Analysis (Architecture)
        return cls._REGISTRY.analyze(port, banner, trie_tag)
