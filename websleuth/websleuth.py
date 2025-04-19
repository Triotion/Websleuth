#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WebSleuth - Advanced Website OSINT and Penetration Testing Tool
Author: Triotion (https://github.com/Triotion)
License: MIT
"""

import os
import sys
import time
import argparse
import concurrent.futures
from datetime import datetime
from rich.console import Console
from rich.progress import Progress

# Local imports
from websleuth.modules.info_gathering import InfoGathering
from websleuth.modules.subdomain_enum import SubdomainEnum
from websleuth.modules.technology_scanner import TechnologyScanner
from websleuth.modules.content_discovery import ContentDiscovery
from websleuth.modules.security_headers import SecurityHeadersAnalyzer
from websleuth.modules.ssl_checker import SSLChecker
from websleuth.modules.port_scanner import PortScanner
from websleuth.modules.waf_detector import WAFDetector
from websleuth.modules.vuln_scanner import VulnerabilityScanner
from websleuth.modules.screenshot import ScreenshotCapture
from websleuth.modules.dns_security import DNSSecurityScanner
from websleuth.utils.reporter import Reporter
from websleuth.utils.banner import display_banner

console = Console()

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='WebSleuth - Advanced Website OSINT and Penetration Testing Tool',
        epilog='Example: python websleuth.py -u https://example.com -a'
    )
    
    parser.add_argument('-u', '--url', help='Target URL (e.g., https://example.com)')
    parser.add_argument('-a', '--all', action='store_true', help='Run all scans')
    parser.add_argument('-i', '--info', action='store_true', help='Gather basic information')
    parser.add_argument('-s', '--subdomains', action='store_true', help='Enumerate subdomains')
    parser.add_argument('-t', '--technology', action='store_true', help='Detect web technologies')
    parser.add_argument('-c', '--content', action='store_true', help='Discover hidden content')
    parser.add_argument('-sh', '--security-headers', action='store_true', help='Check security headers')
    parser.add_argument('-ssl', '--ssl-check', action='store_true', help='Check SSL/TLS configuration')
    parser.add_argument('-p', '--ports', action='store_true', help='Scan for open ports')
    parser.add_argument('-w', '--waf', action='store_true', help='Detect WAF')
    parser.add_argument('-v', '--vuln', action='store_true', help='Scan for vulnerabilities')
    parser.add_argument('-sc', '--screenshot', action='store_true', help='Capture screenshots')
    parser.add_argument('-dns', '--dns-security', action='store_true', help='Check DNS security configuration')
    parser.add_argument('-o', '--output', help='Output directory', default='output')
    parser.add_argument('-f', '--format', choices=['html', 'json', 'pdf', 'all'], 
                       default='html', help='Report format')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug mode')
    parser.add_argument('-T', '--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('-to', '--timeout', type=int, default=5, help='Connection timeout')
    parser.add_argument('--port-range', help='Port range to scan (e.g., 1-1000)', default='1-1024')
    
    return parser.parse_args()

def validate_url(url):
    """Validate and normalize the URL."""
    if not url:
        console.print("[bold red]Error: URL is required![/bold red]")
        sys.exit(1)
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    return url

def setup_environment(output_dir):
    """Set up the environment for scanning."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = os.path.join(output_dir, f"scan_{timestamp}")
    os.makedirs(scan_dir)
    
    return scan_dir

def run_scanner(args):
    """Run the selected scanners based on command line arguments."""
    url = validate_url(args.url)
    scan_dir = setup_environment(args.output)
    results = {}
    
    console.print(f"[bold green]Starting scan on[/bold green] [bold blue]{url}[/bold blue]")
    console.print(f"[bold green]Results will be saved to[/bold green] [bold blue]{scan_dir}[/bold blue]")
    
    with Progress(expand=True, transient=False, refresh_per_second=10) as progress:
        tasks = []
        
        # Information Gathering
        if args.all or args.info:
            tasks.append(("Information Gathering", InfoGathering(url, args.timeout, args.debug)))
        
        # Subdomain Enumeration
        if args.all or args.subdomains:
            tasks.append(("Subdomain Enumeration", SubdomainEnum(url, args.threads, args.timeout, args.debug)))
        
        # Technology Detection
        if args.all or args.technology:
            tasks.append(("Technology Detection", TechnologyScanner(url, args.timeout, args.debug)))
        
        # Content Discovery
        if args.all or args.content:
            tasks.append(("Content Discovery", ContentDiscovery(url, args.threads, args.timeout, args.debug)))
        
        # Security Headers Analysis
        if args.all or args.security_headers:
            tasks.append(("Security Headers Analysis", SecurityHeadersAnalyzer(url, args.timeout, args.debug)))
        
        # SSL/TLS Check
        if args.all or args.ssl_check:
            tasks.append(("SSL/TLS Check", SSLChecker(url, args.timeout, args.debug)))
        
        # Port Scanning
        if args.all or args.ports:
            # Parse port range
            port_range = (1, 1024)  # Default
            if args.port_range:
                try:
                    start, end = map(int, args.port_range.split('-'))
                    port_range = (start, min(end, 65535))  # Cap at 65535
                except ValueError:
                    console.print(f"[bold yellow]Invalid port range format: {args.port_range}. Using default 1-1024.[/bold yellow]")
            
            tasks.append(("Port Scanning", PortScanner(url, args.threads, args.timeout, args.debug)))
        
        # WAF Detection
        if args.all or args.waf:
            tasks.append(("WAF Detection", WAFDetector(url, args.timeout, args.debug)))
        
        # Vulnerability Scanning
        if args.all or args.vuln:
            tasks.append(("Vulnerability Scanning", VulnerabilityScanner(url, args.threads, args.timeout, args.debug)))
        
        # Screenshot Capture
        if args.all or args.screenshot:
            tasks.append(("Screenshot Capture", ScreenshotCapture(url, args.timeout, args.debug)))
            
        # DNS Security Scanning
        if args.all or args.dns_security:
            tasks.append(("DNS Security", DNSSecurityScanner(url, args.timeout, args.debug)))
        
        # Create progress bars for each task
        task_bars = {name: progress.add_task(f"[cyan]{name}...", total=100) for name, _ in tasks}
        
        # Run tasks in parallel using ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(tasks), args.threads)) as executor:
            future_to_task = {executor.submit(scanner.run): (name, scanner) for name, scanner in tasks}
            
            completed_tasks = 0
            total_tasks = len(tasks)
            
            for future in concurrent.futures.as_completed(future_to_task):
                name, scanner = future_to_task[future]
                try:
                    task_result = future.result()
                    results[name] = task_result
                    progress.update(task_bars[name], completed=100)
                    
                    # Only display completed message if not in quiet mode
                    if not args.quiet:
                        console.print(f"[bold green]✅ {name} completed[/bold green]")
                    
                    completed_tasks += 1
                    if not args.quiet:
                        console.print(f"[bold blue]Progress: {completed_tasks}/{total_tasks} tasks completed[/bold blue]")
                    
                except Exception as e:
                    progress.update(task_bars[name], completed=100)
                    console.print(f"[bold red]❌ {name} failed: {str(e)}[/bold red]")
                    if args.debug:
                        import traceback
                        console.print(traceback.format_exc())
    
    # Generate report
    console.print("[bold yellow]Generating report...[/bold yellow]")
    reporter = Reporter(url, results, scan_dir)
    
    try:
        if args.format == 'all':
            reporter.generate_html_report()
            reporter.generate_json_report()
            reporter.generate_pdf_report()
        elif args.format == 'html':
            reporter.generate_html_report()
        elif args.format == 'json':
            reporter.generate_json_report()
        elif args.format == 'pdf':
            reporter.generate_pdf_report()
    except Exception as e:
        console.print(f"[bold red]Error generating report: {str(e)}[/bold red]")
        if args.debug:
            import traceback
            console.print(traceback.format_exc())
    
    console.print(f"[bold green]Scan completed! Reports saved to {scan_dir}[/bold green]")

def main():
    """Main function."""
    # Display banner
    display_banner()
    
    # Parse arguments
    args = parse_arguments()
    
    try:
        # Run scanner
        run_scanner(args)
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user. Exiting...[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]An error occurred: {str(e)}[/bold red]")
        if args.debug:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main() 