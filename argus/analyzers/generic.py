"""
Generic Protocol Analyzer for FTP, RTSP, PPTP, and other common services.
"""
import re
from typing import Tuple
from .base import ServiceAnalyzer


class GenericProtocolAnalyzer(ServiceAnalyzer):
    """
    Handles multiple protocols: FTP, RTSP, PPTP, SMTP, POP3, IMAP, VNC, Redis.
    """
    
    # Port -> Protocol mapping
    PROTOCOL_MAP = {
        21: 'FTP',
        25: 'SMTP',
        110: 'POP3',
        143: 'IMAP',
        554: 'RTSP',
        587: 'SMTP',
        1723: 'PPTP',
        5900: 'VNC',
        5901: 'VNC',
        6379: 'Redis',
    }
    
    # Banner prefixes -> Protocol
    BANNER_SIGNATURES = {
        '220 ': 'FTP',
        '220-': 'FTP',
        '+OK': 'POP3',
        '* OK': 'IMAP',
        'RTSP/': 'RTSP',
        'PONG': 'Redis',
        '-ERR': 'Redis',
        '+PONG': 'Redis',
        'RFB ': 'VNC',
    }
    
    def can_analyze(self, port: int, banner: str, trie_tag: str = None) -> bool:
        # Check by port
        if port in self.PROTOCOL_MAP:
            return True
        
        # Check by trie tag
        if trie_tag in ['FTP', 'RTSP', 'POP3', 'Redis', 'VNC']:
            return True
        
        # Check by banner prefix
        for prefix in self.BANNER_SIGNATURES:
            if banner.startswith(prefix):
                return True
        
        return False
    
    def analyze(self, banner: str) -> Tuple[str, str]:
        """Analyze banner and return (service, os_guess)"""
        protocol = self._detect_protocol(banner)
        version = self._extract_version(banner, protocol)
        os_guess = self._guess_os(banner)
        
        if version:
            return f"[{protocol}] {version}", os_guess
        else:
            return f"[{protocol}]", os_guess
    
    def _detect_protocol(self, banner: str) -> str:
        """Detect protocol from banner content"""
        for prefix, protocol in self.BANNER_SIGNATURES.items():
            if banner.startswith(prefix):
                return protocol
        
        # RTSP response
        if 'RTSP/1.' in banner:
            return 'RTSP'
        
        return 'Unknown'
    
    def _extract_version(self, banner: str, protocol: str) -> str:
        """Extract version information from banner"""
        
        if protocol == 'FTP':
            # Match common FTP server names
            patterns = [
                r'(vsftpd)\s*([\d.]+)?',
                r'(ProFTPD)\s*([\d.]+)?',
                r'(Pure-FTPd)',
                r'(FileZilla Server)\s*([\d.]+)?',
                r'(Microsoft FTP)',
                r'220[- ]([^\r\n]+)',
            ]
            for pattern in patterns:
                m = re.search(pattern, banner, re.IGNORECASE)
                if m:
                    return m.group(0).replace('220 ', '').replace('220-', '').strip()[:40]
        
        elif protocol == 'RTSP':
            # Look for Server header in RTSP response
            m = re.search(r'Server:\s*([^\r\n]+)', banner, re.IGNORECASE)
            if m:
                return m.group(1).strip()[:40]
            # CSeq response indicates working RTSP
            if 'CSeq:' in banner:
                return 'Active'
        
        elif protocol == 'SMTP':
            m = re.search(r'220[- ]([^\r\n]+)', banner)
            if m:
                return m.group(1).strip()[:40]
        
        elif protocol == 'POP3':
            m = re.search(r'\+OK\s*([^\r\n]+)?', banner)
            if m and m.group(1):
                return m.group(1).strip()[:40]
        
        elif protocol == 'Redis':
            if 'PONG' in banner:
                return 'Active'
            m = re.search(r'redis_version:([\d.]+)', banner)
            if m:
                return f'Redis {m.group(1)}'
        
        elif protocol == 'VNC':
            m = re.search(r'RFB\s*([\d.]+)', banner)
            if m:
                return f'VNC {m.group(1)}'
        
        return ''
    
    def _guess_os(self, banner: str) -> str:
        """Attempt to guess OS from banner"""
        banner_lower = banner.lower()
        
        if 'ubuntu' in banner_lower:
            return 'Ubuntu Linux'
        elif 'debian' in banner_lower:
            return 'Debian Linux'
        elif 'centos' in banner_lower:
            return 'CentOS Linux'
        elif 'fedora' in banner_lower:
            return 'Fedora Linux'
        elif 'linux' in banner_lower:
            return 'Linux'
        elif 'windows' in banner_lower or 'microsoft' in banner_lower:
            return 'Windows Server'
        elif 'freebsd' in banner_lower:
            return 'FreeBSD'
        
        return 'Unknown'
