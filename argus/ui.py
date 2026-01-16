from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
import time
import re

console = Console()

class ScannerUI:
    def __init__(self):
        self.console = console

    def display_welcome(self):
        self.console.rule("[bold red]ARGUS - The All-Seeing Scanner[/bold red]")

    def get_target(self):
        return Prompt.ask("[bold blue]Enter Target IP/Hostname[/bold blue]")

    def get_ports(self):
        return Prompt.ask("[bold blue]Enter Ports (e.g. 80 443 1000-2000)[/bold blue]", default="1-1024")

    def get_speed(self):
        self.console.print("\n[bold cyan]Select Scan Speed:[/bold cyan]")
        self.console.print("1. [green]Stealthy[/green] (50 threads)")
        self.console.print("2. [blue]Moderate[/blue] (200 threads)")
        self.console.print("3. [yellow]Normal[/yellow]   (500 threads)")
        self.console.print("4. [magenta]Fast[/magenta]     (1000 threads)")
        self.console.print("5. [red]Insane[/red]   (2000 threads)")
        
        speed_map = {1: 50, 2: 200, 3: 500, 4: 1000, 5: 2000}
        choice = IntPrompt.ask("[bold blue]Enter Speed Level (1-5)[/bold blue]", default=3, choices=["1", "2", "3", "4", "5"])
        return speed_map[choice]

    def display_start(self, target_ip, port_count):
        self.console.print(Panel.fit(f"[bold green]Starting Scan on {target_ip}[/bold green]", border_style="blue"))
        # We return the progress context manager usage logic to the scanner, 
        # but we can provide the columns here or a factory.

    def create_progress(self):
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console
        )

    def display_results(self, target_ip, duration, results, final_os, closed_count, filtered_count, honeypot_result=None):
        """
        Displays the results in a Rich table.
        """
        self.console.print("\n")
        
        # Honeypot Detection Warning
        if honeypot_result:
            self._display_honeypot_warning(honeypot_result)
        
        # Table of Open Ports
        table = Table(title=f"Scan Results for {target_ip} (OS: {final_os})", show_header=True, header_style="bold magenta")
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("State", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Version/Banner", style="white")
        table.add_column("OS Guess", style="blue")

        for res in sorted(results, key=lambda x: x['port']):
            banner = res.get("banner") or ""
            banner_display = banner[:50]
            
            # Clean up binary garbage in display for MySQL
            if "MySQL" in (res.get("service") or "") and "Protocol:" not in banner_display:
                 m = re.search(r'((?:5|8|10)\.\d+\.\d+[\w\-]*)', banner)
                 if m: banner_display = m.group(1)
            
            if len(banner) > 50: banner_display += "..."
            
            table.add_row(
                str(res['port']), 
                res['status'].upper(), 
                res['service'] or "N/A", 
                banner_display or "N/A",
                res['os_guess'] or "N/A"
            )

        self.console.print(table)
        
        # Summary Stats
        self.console.print(f"\n[bold]Scan completed in {duration:.2f} seconds.[/bold]")
        self.console.print(f"[bold]Open ports found: {len(results)}[/bold]")
        if closed_count > 0 or filtered_count > 0:
            self.console.print(f"[dim]Not shown: {closed_count} closed, {filtered_count} filtered ports[/dim]")
        
        self.console.print(f"[bold]Aggregated OS Detection: {final_os}[/bold]")
    
    def _display_honeypot_warning(self, honeypot_result):
        """
        Display honeypot detection results with color-coded warning.
        """
        score = honeypot_result.score
        confidence = honeypot_result.confidence
        breakdown = honeypot_result.breakdown
        
        # Color based on score
        if score >= 60:
            border_style = "bold red"
            icon = "⚠️ "
            score_style = "bold red"
        elif score >= 40:
            border_style = "yellow"
            icon = "⚡ "
            score_style = "bold yellow"
        else:
            border_style = "green"
            icon = "✓ "
            score_style = "bold green"
        
        # Build breakdown text
        lines = [f"{icon}[{score_style}]Honeypot Score: {score}/100 ({confidence})[/{score_style}]"]
        
        for check_name, data in breakdown.items():
            check_score = data.get('score', 0)
            max_score = data.get('max', 0)
            reason = data.get('reason', '')
            name_display = check_name.replace('_', ' ').title()
            lines.append(f"  • {name_display}: {check_score}/{max_score} - {reason}")
        
        panel_content = "\n".join(lines)
        self.console.print(Panel(panel_content, title="Honeypot Detection", border_style=border_style))
        
    def show_message(self, msg, style="bold red"):
        self.console.print(f"[{style}]{msg}[/{style}]")

    def show_saved(self, filename):
        self.console.print(f"[dim]Results saved to {filename}[/dim]")
