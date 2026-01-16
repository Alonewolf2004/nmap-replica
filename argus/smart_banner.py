"""
Smart Banner Grabbing Module - Phase 2

Multi-stage probing for deep service detection.
Enabled via -sV flag for thorough service fingerprinting.
"""

import asyncio
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class ProbeResult:
    """Result from a single probe stage"""
    stage: str
    response: str
    response_time_ms: float
    is_error: bool = False
    error_type: str = ""


@dataclass
class SmartBannerResult:
    """Aggregated result from smart banner grabbing"""
    banner: str
    service: str
    version: str
    os_guess: str
    confidence: str  # LOW, MEDIUM, HIGH
    probe_results: List[ProbeResult]
    error_fingerprint: str = ""


class SmartBannerGrabber:
    """
    Multi-stage banner grabber for deep service detection.
    
    Stages:
    1. Passive: Wait for server greeting
    2. Null probe: Send CRLF
    3. Protocol probe: Port-specific request
    4. Malformed probe: Invalid request to trigger error
    """
    
    # Port -> list of protocol probes
    PROTOCOL_PROBES = {
        21: [  # FTP
            b"USER anonymous\r\n",
            b"SYST\r\n",
            b"FEAT\r\n",
        ],
        22: [  # SSH - just wait, don't probe
        ],
        25: [  # SMTP
            b"EHLO scanner\r\n",
            b"HELP\r\n",
        ],
        80: [  # HTTP
            b"GET / HTTP/1.0\r\n\r\n",
            b"OPTIONS / HTTP/1.1\r\nHost: {hostname}\r\n\r\n",
        ],
        110: [  # POP3
            b"CAPA\r\n",
        ],
        143: [  # IMAP
            b"A001 CAPABILITY\r\n",
        ],
        443: [  # HTTPS - handled separately with SSL
            b"GET / HTTP/1.1\r\nHost: {hostname}\r\n\r\n",
        ],
        554: [  # RTSP
            b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
            b"DESCRIBE * RTSP/1.0\r\nCSeq: 2\r\n\r\n",
        ],
        1723: [  # PPTP - binary protocol
            b"\x00\x9c\x00\x01\x1a\x2b\x3c\x4d" + b"\x00" * 148,
        ],
        3306: [  # MySQL - wait for greeting
        ],
        6379: [  # Redis
            b"PING\r\n",
            b"INFO\r\n",
        ],
    }
    
    # Malformed probes to trigger error responses
    MALFORMED_PROBES = {
        'http': b"INVALID /\x00\x01\x02 HTTP/9.9\r\n\r\n",
        'ftp': b"XXXX invalid command\r\n",
        'smtp': b"XXXX\r\n",
        'generic': b"\x00\x01\x02\x03\r\n",
    }
    
    # Error patterns that reveal service info
    ERROR_PATTERNS = {
        # HTTP servers
        'nginx': ['nginx', 'openresty'],
        'apache': ['apache', 'httpd'],
        'iis': ['microsoft', 'iis'],
        'akamai': ['akamaihost', 'akamai'],
        'cloudflare': ['cloudflare'],
        # FTP servers
        'vsftpd': ['vsftpd'],
        'proftpd': ['proftpd'],
        'filezilla': ['filezilla'],
        # SMTP servers
        'postfix': ['postfix'],
        'exim': ['exim'],
        'sendmail': ['sendmail'],
    }
    
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
    
    async def grab(
        self, 
        reader: asyncio.StreamReader, 
        writer: asyncio.StreamWriter,
        port: int,
        hostname: str
    ) -> SmartBannerResult:
        """
        Perform multi-stage banner grabbing.
        
        Returns aggregated result with all probe responses.
        """
        import time
        probe_results = []
        all_responses = []
        
        # Stage 1: Passive read (wait for greeting)
        start = time.time()
        passive_response = await self._passive_read(reader, timeout=2.0)
        if passive_response:
            elapsed = (time.time() - start) * 1000
            probe_results.append(ProbeResult(
                stage='passive',
                response=passive_response,
                response_time_ms=elapsed
            ))
            all_responses.append(passive_response)
        
        # Stage 2: Null probe (CRLF)
        if not passive_response or len(passive_response) < 10:
            start = time.time()
            null_response = await self._send_probe(reader, writer, b"\r\n")
            if null_response:
                elapsed = (time.time() - start) * 1000
                probe_results.append(ProbeResult(
                    stage='null_probe',
                    response=null_response,
                    response_time_ms=elapsed
                ))
                all_responses.append(null_response)
        
        # Stage 3: Protocol-specific probes
        protocol_probes = self.PROTOCOL_PROBES.get(port, [])
        for probe in protocol_probes:
            # Format probe with hostname if needed
            if b'{hostname}' in probe:
                probe = probe.replace(b'{hostname}', hostname.encode())
            
            start = time.time()
            response = await self._send_probe(reader, writer, probe)
            if response:
                elapsed = (time.time() - start) * 1000
                probe_results.append(ProbeResult(
                    stage='protocol_probe',
                    response=response,
                    response_time_ms=elapsed
                ))
                all_responses.append(response)
                
                # If we got a good response, might not need more probes
                if len(response) > 50:
                    break
        
        # Stage 4: Malformed probe (to trigger error)
        malformed_type = self._get_malformed_type(port)
        malformed_probe = self.MALFORMED_PROBES.get(malformed_type, self.MALFORMED_PROBES['generic'])
        
        start = time.time()
        error_response = await self._send_probe(reader, writer, malformed_probe)
        if error_response:
            elapsed = (time.time() - start) * 1000
            is_error, error_type = self._classify_error(error_response)
            probe_results.append(ProbeResult(
                stage='malformed_probe',
                response=error_response,
                response_time_ms=elapsed,
                is_error=is_error,
                error_type=error_type
            ))
            all_responses.append(error_response)
        
        # Analyze all responses
        return self._analyze_results(probe_results, all_responses, port)
    
    async def _passive_read(self, reader: asyncio.StreamReader, timeout: float = 2.0) -> str:
        """Wait for server greeting without sending anything."""
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            if data:
                return data.decode('utf-8', errors='ignore').strip()
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        return ""
    
    async def _send_probe(
        self, 
        reader: asyncio.StreamReader, 
        writer: asyncio.StreamWriter,
        probe: bytes
    ) -> str:
        """Send probe and read response."""
        try:
            writer.write(probe)
            await writer.drain()
            
            data = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
            if data:
                return data.decode('utf-8', errors='ignore').strip()
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        return ""
    
    def _get_malformed_type(self, port: int) -> str:
        """Determine which malformed probe to use based on port."""
        if port in [80, 443, 8080, 8000, 8443]:
            return 'http'
        elif port == 21:
            return 'ftp'
        elif port in [25, 587]:
            return 'smtp'
        return 'generic'
    
    def _classify_error(self, response: str) -> Tuple[bool, str]:
        """Classify if response is an error and what type."""
        response_lower = response.lower()
        
        # HTTP errors
        if 'bad request' in response_lower:
            return True, 'HTTP_400'
        elif 'forbidden' in response_lower:
            return True, 'HTTP_403'
        elif 'not found' in response_lower:
            return True, 'HTTP_404'
        elif 'internal server error' in response_lower:
            return True, 'HTTP_500'
        elif 'method not allowed' in response_lower:
            return True, 'HTTP_405'
        
        # FTP errors
        elif response.startswith('5'):
            return True, 'FTP_5XX'
        
        # SMTP errors
        elif response.startswith('5') and 'smtp' in response_lower:
            return True, 'SMTP_5XX'
        
        return False, ''
    
    def _analyze_results(
        self, 
        probe_results: List[ProbeResult],
        all_responses: List[str],
        port: int
    ) -> SmartBannerResult:
        """Analyze all probe results to determine service info."""
        
        # Combine all responses for analysis
        combined = " ".join(all_responses).lower()
        
        # Detect service from error patterns
        detected_service = ""
        for service, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern in combined:
                    detected_service = service
                    break
            if detected_service:
                break
        
        # Extract version info
        version = self._extract_version(combined, detected_service)
        
        # Guess OS from responses
        os_guess = self._guess_os(combined)
        
        # Build banner from best response
        best_response = ""
        for pr in probe_results:
            if len(pr.response) > len(best_response):
                best_response = pr.response
        
        # Build error fingerprint
        error_fingerprint = ""
        for pr in probe_results:
            if pr.is_error:
                error_fingerprint = f"{pr.error_type}:{pr.response[:30]}"
                break
        
        # Determine confidence
        if detected_service and version:
            confidence = "HIGH"
        elif detected_service:
            confidence = "MEDIUM"
        elif best_response:
            confidence = "LOW"
        else:
            confidence = "NONE"
        
        # Build service string
        if detected_service:
            service_str = f"[{detected_service.upper()}]"
            if version:
                service_str += f" {version}"
        else:
            service_str = self._port_guess(port) if not best_response else "[Unknown]"
        
        return SmartBannerResult(
            banner=best_response[:100],
            service=service_str,
            version=version,
            os_guess=os_guess,
            confidence=confidence,
            probe_results=probe_results,
            error_fingerprint=error_fingerprint
        )
    
    def _extract_version(self, text: str, service: str) -> str:
        """Extract version information from response text."""
        import re
        
        # Common version patterns
        patterns = [
            r'(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)',  # Generic version
            r'server:\s*([^\r\n]+)',  # Server header
            r'version:\s*([^\r\n]+)',
        ]
        
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                return m.group(1).strip()[:30]
        
        return ""
    
    def _guess_os(self, text: str) -> str:
        """Guess OS from response text."""
        if 'ubuntu' in text:
            return 'Ubuntu Linux'
        elif 'debian' in text:
            return 'Debian Linux'
        elif 'centos' in text or 'rhel' in text:
            return 'RHEL/CentOS'
        elif 'windows' in text or 'win32' in text or 'win64' in text:
            return 'Windows'
        elif 'freebsd' in text:
            return 'FreeBSD'
        elif 'linux' in text:
            return 'Linux'
        return 'Unknown'
    
    def _port_guess(self, port: int) -> str:
        """Guess service from port number when no banner."""
        guesses = {
            21: '[FTP?]',
            22: '[SSH?]',
            23: '[Telnet?]',
            25: '[SMTP?]',
            53: '[DNS?]',
            80: '[HTTP?]',
            110: '[POP3?]',
            143: '[IMAP?]',
            443: '[HTTPS?]',
            554: '[RTSP?]',
            587: '[SMTP?]',
            993: '[IMAPS?]',
            995: '[POP3S?]',
            1723: '[PPTP?]',
            3306: '[MySQL?]',
            3389: '[RDP?]',
            5432: '[PostgreSQL?]',
            6379: '[Redis?]',
            8080: '[HTTP-Proxy?]',
        }
        return guesses.get(port, '[Unknown]')
