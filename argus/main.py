import argparse
import asyncio
import socket
import sys

from .ui import ScannerUI
from .scanner import PortScanner
from .utils import parse_ports
from .config import ScanConfig

def main():
    # 1. CLI Argument Parsing
    parser = argparse.ArgumentParser(description="Argus - The All-Seeing Port Scanner")
    parser.add_argument("-t", "--target", help="Target IP or Hostname")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g. 80,443,1-1000)")
    parser.add_argument("-c", "--concurrency", type=int, default=500, help="Concurrent tasks (Default: 500)")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    parser.add_argument("-sV", "--service-version", action="store_true", 
                        help="Deep service detection with multi-stage probing")
    
    args = parser.parse_args()
    
    ui = ScannerUI()
    if not args.target:
        ui.display_welcome()
    
    try:
        # 2. Input Resolution (CLI vs Interactive)
        
        # Target
        if args.target:
            target = args.target
        else:
            target = ui.get_target()
            
        try:
           target_ip = socket.gethostbyname(target)
           if args.target:
               ui.console.print(f"[green]Resolved {target} to {target_ip}[/green]")
        except socket.gaierror:
           ui.console.print(f"[bold red]Error:[/bold red] Could not resolve hostname {target}")
           return

        # Ports
        if args.ports:
            ports_str = args.ports
        else:
            ports_str = ui.get_ports()
        raw_ports = parse_ports(ports_str)
        
        # Concurrency
        if args.concurrency and args.concurrency != 500:
            # If user manually set flag, use it
            concurrency = args.concurrency
        elif args.target:
             # If running in CLI mode but no speed set, default to 500 without prompting
             concurrency = 500
        else:
             # Interactive mode
             concurrency = ui.get_speed()
        
        # 3. Validate with Pydantic
        config = ScanConfig(
            target_ip=target_ip,
            hostname=target,  # Original hostname for SNI
            ports=raw_ports,
            concurrency=concurrency,
            output_file=args.output,
            deep_scan=args.service_version  # -sV flag
        )
        
        # 4. Initialize & Run
        scanner = PortScanner(**config.dict())
        asyncio.run(scanner.run())
        
    except KeyboardInterrupt:
        ui.console.print("\n[yellow]Scan interrupted by user.[/yellow]")
    except Exception as e:
        ui.console.print(f"\n[bold red]Fatal Error:[/bold red] {e}")

if __name__ == "__main__":
    main()
