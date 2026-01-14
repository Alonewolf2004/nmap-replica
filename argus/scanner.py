import asyncio
import time
import json
import heapq
from typing import List, Dict, Generator
from datetime import datetime
from rich.progress import Progress

from .analyzer import BannerAnalyzer
from .ui import ScannerUI
from .utils import BloomFilter, RateLimiter, ResultCache

class PortScanner:
    # Priority Map: Lower number = Higher Priority (Scanned First)
    COMMON_PORTS = {
        80: 1, 443: 1, 8080: 1, 8000: 1, # Web
        22: 2, 21: 2, 23: 2, 3389: 2,    # Admin
        25: 3, 53: 3, 110: 3, 143: 3,    # Infra
        3306: 3, 5432: 3, 6379: 3, 1433: 3 # DB
    }
    def __init__(self, target_ip: str, ports: List[int], timeout: float = 1.5, concurrency: int = 100, output_file: str = None):
        self.target_ip = target_ip
        self.ports = ports
        self.timeout = timeout
        self.concurrency = concurrency
        self.output_file = output_file
        self.results = {}
        self.open_ports_count = 0
        self.closed_ports_count = 0
        self.filtered_ports_count = 0
        self.ui = ScannerUI()
        self.scan_start_time = 0
        
        # New Optimizations
        self.cache = ResultCache(ttl=300)
        self.limiter = RateLimiter(max_per_second=concurrency * 2) # Allow burst
        self.measured_rtt = None

    async def _probe_rtt(self):
        """
        Adaptive Timeout: Measure RTT to target to adjust timeout dynamically.
        """
        start = time.time()
        try:
            conn = asyncio.open_connection(self.target_ip, 80)
            reader, writer = await asyncio.wait_for(conn, timeout=2.0)
            writer.close()
            try: await writer.wait_closed()
            except: pass
            self.measured_rtt = time.time() - start
        except Exception as e:
            # Fallback if port 80 is closed or filtered
            self.measured_rtt = None
            # print(f"RTT Probe Failed: {e}") 
            self.measured_rtt = None

    async def scan_port(self, port: int, progress_instance: Progress, progress_task_id: int):
        # 1. Check Cache
        cached = self.cache.get(self.target_ip, port)
        if cached:
            if cached.get('status') == 'open':
                self.open_ports_count += 1
                self.results[port] = cached
            elif cached.get('status') == 'closed':
               self.closed_ports_count += 1
            else:
               self.filtered_ports_count += 1
            progress_instance.advance(progress_task_id)
            return

        # 2. Rate Limit
        await self.limiter.acquire()

        # 3. Calculated Timeout (Relaxed for Reliability)
        # RTT * 5 + 1.0s buffer. 
        # Minimum 2.0s to account for OS overhead/queuing on public internet.
        base_timeout = max(2.0, (self.measured_rtt * 5) + 1.0) if self.measured_rtt else self.timeout
        
        # 4. Retry Logic
        retries = 2
        last_exception = None
        
        for attempt in range(retries):
            # Increase timeout on retry
            current_timeout = base_timeout * (1.5 ** attempt)
            
            try:
                conn = asyncio.open_connection(self.target_ip, port)
                try:
                    reader, writer = await asyncio.wait_for(conn, timeout=current_timeout)
                except asyncio.TimeoutError as e:
                    last_exception = e
                    continue # Retry
                except ConnectionRefusedError as e:
                    # Debug: Why is this happening?
                    if attempt == 0:
                        # Retry once for RST, just in case
                        last_exception = e
                        await asyncio.sleep(0.2) # Backoff slightly
                        continue
                    
                    self.closed_ports_count += 1
                    self.cache.set(self.target_ip, port, {'status': 'closed'})
                    progress_instance.advance(progress_task_id)
                    return
                except OSError as e:
                    # Network unreach/host down?
                    last_exception = e
                    continue # Possible transient issue
                except Exception as e:
                    last_exception = e
                    break 

                # If we get here, connection is OPEN
                self.open_ports_count += 1
                
                # --- BANNER GRABBING ---
                banner_text = ""
                try:
                    # 1. Passive Read (First Attempt)
                    # Many protocols (SSH, FTP, SMTP, MySQL) send a greeting immediately.
                    # We wait briefly (0.8s) for this greeting.
                    try:
                        raw_data = await asyncio.wait_for(reader.read(2048), timeout=0.8)
                        if raw_data:
                            banner_text = raw_data.decode('utf-8', errors='ignore').strip()
                    except asyncio.TimeoutError:
                        pass # No greeting, might need a probe.

                    # 2. Active Probe (If no banner yet)
                    if not banner_text:
                        probe_data, is_binary = BannerAnalyzer.get_probe(port, self.target_ip)
                        if probe_data:
                            writer.write(probe_data)
                            await writer.drain()
                            
                            # Read Response to Probe
                            try:
                                raw_data = await asyncio.wait_for(reader.read(2048), timeout=2.0)
                                if raw_data:
                                    # Append or set
                                    banner_text = raw_data.decode('utf-8', errors='ignore').strip()
                            except asyncio.TimeoutError:
                                pass
                except Exception:
                    pass
                finally:
                    writer.close()
                    try: await writer.wait_closed()
                    except: pass

                # 4. Analyze Service
                service, os_guess = BannerAnalyzer.analyze_banner(banner_text, port)
                
                res = {
                    "port": port,
                    "status": "open",
                    "service": service,
                    "banner": banner_text[:50],
                    "os_guess": os_guess
                }
                
                self.results[port] = res
                self.cache.set(self.target_ip, port, res)
                progress_instance.advance(progress_task_id)
                return # Successful scan

            except Exception:
                 pass
        
        # If exhausted retries
        if isinstance(last_exception, (asyncio.TimeoutError, OSError)):
             self.filtered_ports_count += 1
             self.cache.set(self.target_ip, port, {'status': 'filtered'})
        else:
             self.closed_ports_count += 1
             self.cache.set(self.target_ip, port, {'status': 'closed'})
             
        progress_instance.advance(progress_task_id)

    def _prioritize_ports(self) -> Generator[int, None, None]:
        """
        Yields ports in priority order using a Min-Heap.
        """
        heap = []
        for port in self.ports:
            # Default priority 999 for uncommon ports
            priority = self.COMMON_PORTS.get(port, 999)
            heapq.heappush(heap, (priority, port))
        
        while heap:
            _, port = heapq.heappop(heap)
            yield port

    async def run(self):
        """
        Orchestrates the asynchronous scan using a Memory-Efficient Producer-Consumer pattern.
        """
        self.ui.display_start(self.target_ip, len(self.ports))
        
        start_time = time.time()
        
        # Measure RTT for Adaptive Timeout
        await self._probe_rtt()
        if self.measured_rtt:
             rtt_ms = self.measured_rtt * 1000
             self.ui.console.print(f"[dim]Adaptive Timeout Enabled: RTT {rtt_ms:.2f}ms[/dim]")

        # O(N) Memory Optimization: use a bounded queue instead of creating all tasks at once
        queue = asyncio.Queue(maxsize=self.concurrency * 2)

        with self.ui.create_progress() as progress:
            task_id = progress.add_task(f"[cyan]Scanning {len(self.ports)} ports...", total=len(self.ports))
            
            # Deduplication Filter (Bloom Filter)
            scanned_filter = BloomFilter(size=len(self.ports) * 10 or 1000)

            async def producer():
                # Yield from priority generator (Heap Optimized)
                for port in self._prioritize_ports():
                    if port in scanned_filter:
                        continue
                    
                    scanned_filter.add(port)
                    await queue.put(port)
                
                # Send Sentinels to stop consumers
                for _ in range(self.concurrency):
                    await queue.put(None)

            async def consumer():
                while True:
                    port = await queue.get()
                    if port is None:
                        queue.task_done()
                        break
                    
                    # We don't need a semaphore here because the number of consumers IS the concurrency limit
                    await self.scan_port(port, progress, task_id)
                    queue.task_done()

            # Start Producer
            producer_task = asyncio.create_task(producer())
            
            # Start Consumers (Workers)
            consumers = [asyncio.create_task(consumer()) for _ in range(self.concurrency)]
            
            # Wait for completion
            await producer_task
            await asyncio.gather(*consumers)

        end_time = time.time()
        duration = end_time - start_time
        
        # OS Aggregation
        final_os = self._aggregate_os_detection()
        
        self.ui.display_results(
            self.target_ip, 
            duration, 
            list(self.results.values()), 
            final_os, 
            self.closed_ports_count, 
            self.filtered_ports_count
        )
        self.save_results(final_os)

    def _aggregate_os_detection(self) -> str:
        """
        Aggregates OS guesses from all ports to find a high-confidence OS.
        """
        final_os = "Unknown"
        # 1. Look for high confidence hints
        for res in self.results.values():
            os_hint = res.get("os_guess")
            if os_hint and os_hint != "Unknown":
                if "Linux" in os_hint or "Windows" in os_hint or "FreeBSD" in os_hint:
                    final_os = os_hint
                    break 
        
        # 2. Backfill details
        for res in self.results.values():
            if res["os_guess"] == "Unknown":
                 res["os_guess"] = final_os
        return final_os

    def save_results(self, final_os: str):
        if self.output_file:
            filename = self.output_file
        else:
            filename = f"scan_results_{self.target_ip.replace('.', '_')}.json"
            
        data = {
            "target": self.target_ip,
            "timestamp": datetime.now().isoformat(),
            "os_detected": final_os,
            "results": list(self.results.values())
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        self.ui.show_saved(filename)
