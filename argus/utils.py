import re
import time
import asyncio
from typing import List, Set, Tuple, Optional
from hashlib import sha256

class RateLimiter:
    """
    Token Bucket Rate Limiter to be a good network citizen.
    """
    def __init__(self, max_per_second=100):
        self.tokens = max_per_second
        self.max = max_per_second
        self.last_update = time.time()
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        async with self._lock:
            while self.tokens < 1:
                now = time.time()
                elapsed = now - self.last_update
                refill = elapsed * self.max
                if refill > 0:
                     self.tokens = min(self.max, self.tokens + refill)
                     self.last_update = now
                
                if self.tokens < 1:
                    await asyncio.sleep(0.1)
            
            self.tokens -= 1

class ResultCache:
    """
    Simple in-memory TTL cache for scan results.
    """
    def __init__(self, ttl=300):
        self.cache = {}
        self.ttl = ttl
    
    def get(self, ip, port):
        key = f"{ip}:{port}"
        if key in self.cache:
            timestamp, result = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return result
            else:
                del self.cache[key]
        return None
    
    def set(self, ip, port, result):
        self.cache[f"{ip}:{port}"] = (time.time(), result)

class BloomFilter:
    """
    Probabilistic data structure for O(1) membership testing.
    False Positive Rate ~1% with default size.
    """
    def __init__(self, size=10000, hash_count=3):
        self.size = size
        self.hash_count = hash_count
        self.bits = [False] * size

    def add(self, item):
        for i in range(self.hash_count):
            # Create unique hash for each seed 'i' using item string
            digest = sha256(f"{item}{i}".encode()).hexdigest()
            idx = int(digest, 16) % self.size
            self.bits[idx] = True

    def __contains__(self, item):
        for i in range(self.hash_count):
            digest = sha256(f"{item}{i}".encode()).hexdigest()
            idx = int(digest, 16) % self.size
            if not self.bits[idx]:
                return False
        return True

def parse_ports(port_input: str) -> List[int]:
    """
    Parses a string of ports (spaces, commas, ranges) into a list of integers.
    Example: "80 443 1000-1005" -> [80, 443, 1000, 1001, 1002, 1003, 1004, 1005]
    """
    ports = set()
    # Replace commas with spaces to handle both formats
    port_input = port_input.replace(',', ' ')
    tokens = port_input.split()
    
    for token in tokens:
        if '-' in token:
            try:
                start, end = map(int, token.split('-'))
                if start <= end:
                     # Clamp to valid range 1-65535
                    start = max(1, start)
                    end = min(65535, end)
                    if start <= end:
                        ports.update(range(start, end + 1))
            except ValueError:
                pass
        else:
            try:
                p = int(token)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(list(ports))
