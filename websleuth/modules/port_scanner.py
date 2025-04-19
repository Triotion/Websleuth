#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced Port Scanner Module for WebSleuth
"""

import socket
import threading
import time
import queue
import struct
import sys
import ipaddress
import concurrent.futures
from urllib.parse import urlparse
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, TaskID

console = Console()

# Common service names for known ports
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

# Default port ranges
DEFAULT_PORT_RANGE = (1, 1024)
FULL_PORT_RANGE = (1, 65535)

class PortScanner:
    """Advanced class for scanning open ports on a target website's server."""
    
    def __init__(self, url, threads=50, timeout=3, debug=False, scan_method="tcp_connect"):
        """Initialize the PortScanner class.
        
        Args:
            url (str): The target URL.
            threads (int): Number of threads to use for scanning.
            timeout (int): Connection timeout in seconds.
            debug (bool): Enable debug mode.
            scan_method (str): Scanning method to use ("tcp_connect", "syn", "udp").
        """
        self.url = url
        self.threads = min(threads, 200)  # Limit max threads to 200
        self.timeout = timeout
        self.debug = debug
        self.scan_method = scan_method
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc
        
        # Extract domain without port
        if ":" in self.domain:
            self.domain = self.domain.split(":")[0]
        
        # Default ports to scan
        self.top_ports = list(COMMON_PORTS.keys())
        
        # Resolve domain to IP address
        try:
            self.target_ip = socket.gethostbyname(self.domain)
            if self.debug:
                console.print(f"[bold green]Resolved {self.domain} to {self.target_ip}[/bold green]")
        except socket.gaierror:
            self.target_ip = None
            if self.debug:
                console.print(f"[bold red]Failed to resolve {self.domain}[/bold red]")
        
        self.results = {
            "url": self.url,
            "domain": self.domain,
            "target_ip": self.target_ip,
            "scan_time": "",
            "scan_method": self.scan_method,
            "open_ports": [],
            "filtered_ports": [],
            "closed_ports": [],
            "total_open": 0,
            "total_scanned": 0
        }
        
        # Queue for ports to scan
        self.port_queue = queue.Queue()
    
    def tcp_connect_scan(self, port, progress, task_id):
        """Perform a TCP connect scan on a specific port.
        
        Args:
            port (int): The port to scan.
            progress (Progress): Rich progress instance.
            task_id (TaskID): Task ID for the progress bar.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((self.target_ip, port))
            
            if result == 0:
                # Port is open
                service = COMMON_PORTS.get(port, "Unknown")
                self.results["open_ports"].append({
                    "port": port,
                    "service": service,
                    "state": "open"
                })
                progress.update(task_id, advance=1)
                if self.debug:
                    console.print(f"[bold green]Found open port: {port}/tcp ({service})[/bold green]")
            else:
                # Port is closed
                self.results["closed_ports"].append(port)
                progress.update(task_id, advance=1)
            
            sock.close()
            
        except socket.timeout:
            # Port is filtered
            self.results["filtered_ports"].append(port)
            progress.update(task_id, advance=1)
            if self.debug:
                console.print(f"[yellow]Timeout on port: {port}/tcp[/yellow]")
        except Exception as e:
            # Error occurred
            if self.debug:
                console.print(f"[bold red]Error scanning port {port}: {str(e)}[/bold red]")
            progress.update(task_id, advance=1)
    
    def scan_ports(self, progress, task_id, port_range=None):
        """Scan ports using the specified method.
        
        Args:
            progress (Progress): Rich progress instance.
            task_id (TaskID): Task ID for the progress bar.
            port_range (tuple, optional): Range of ports to scan (start, end).
        """
        if self.target_ip is None:
            console.print("[bold red]Cannot scan ports: Failed to resolve domain name[/bold red]")
            return
        
        if port_range is None:
            port_range = DEFAULT_PORT_RANGE
        
        start_port, end_port = port_range
        total_ports = end_port - start_port + 1
        
        # Update total to scan
        progress.update(task_id, total=total_ports)
        
        if self.debug:
            console.print(f"[bold blue]Starting port scan on {self.target_ip} ({self.domain}) "
                           f"ports {start_port}-{end_port} using {self.threads} threads[/bold blue]")
        
        # Add ports to queue
        for port in range(start_port, end_port + 1):
            self.port_queue.put(port)
        
        # Create thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            while not self.port_queue.empty():
                port = self.port_queue.get()
                if self.scan_method == "tcp_connect":
                    executor.submit(self.tcp_connect_scan, port, progress, task_id)
                # Add other scan methods here in the future
        
        # Update results
        self.results["total_open"] = len(self.results["open_ports"])
        self.results["total_scanned"] = total_ports
    
    def scan_top_ports(self, progress, task_id):
        """Scan the most common ports.
        
        Args:
            progress (Progress): Rich progress instance.
            task_id (TaskID): Task ID for the progress bar.
        """
        if self.target_ip is None:
            console.print("[bold red]Cannot scan ports: Failed to resolve domain name[/bold red]")
            return
        
        total_ports = len(self.top_ports)
        
        # Update total to scan
        progress.update(task_id, total=total_ports)
        
        if self.debug:
            console.print(f"[bold blue]Starting scan of {total_ports} common ports on "
                          f"{self.target_ip} ({self.domain})[/bold blue]")
        
        # Create thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            for port in self.top_ports:
                if self.scan_method == "tcp_connect":
                    executor.submit(self.tcp_connect_scan, port, progress, task_id)
                # Add other scan methods here in the future
        
        # Update results
        self.results["total_open"] = len(self.results["open_ports"])
        self.results["total_scanned"] = total_ports
    
    def scan_port_range(self, start_port, end_port, progress, task_id):
        """Scan a specific range of ports.
        
        Args:
            start_port (int): Start port number.
            end_port (int): End port number.
            progress (Progress): Rich progress instance.
            task_id (TaskID): Task ID for the progress bar.
        """
        self.scan_ports(progress, task_id, port_range=(start_port, end_port))
    
    def run(self):
        """Run port scanning."""
        console.print("[bold blue]Starting port scanning...[/bold blue]")
        
        start_time = time.time()
        
        if self.target_ip:
            with Progress() as progress:
                task_id = progress.add_task("[cyan]Scanning ports...", total=len(self.top_ports))
                
                # Scan common ports
                self.scan_top_ports(progress, task_id)
                
                # Sort open ports by port number
                self.results["open_ports"] = sorted(self.results["open_ports"], key=lambda x: x["port"])
            
            # Record scan duration
            end_time = time.time()
            scan_duration = end_time - start_time
            self.results["scan_time"] = f"{scan_duration:.2f} seconds"
            
            # Print results summary
            if self.debug or self.results["total_open"] > 0:
                console.print(f"[bold green]Found {self.results['total_open']} open ports out of {self.results['total_scanned']} scanned[/bold green]")
                
                if self.results["open_ports"]:
                    for port_info in self.results["open_ports"]:
                        port = port_info["port"]
                        service = port_info["service"]
                        console.print(f"[bold green]  {port}/tcp - {service}[/bold green]")
        else:
            console.print("[bold red]Port scanning failed: Could not resolve target hostname[/bold red]")
        
        console.print(f"[bold green]Port scanning completed for {self.url}[/bold green]")
        return self.results 