#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Information Gathering Module for WebSleuth
"""

import socket
import whois
import dns.resolver
import requests
from urllib.parse import urlparse
from rich.console import Console

console = Console()

class InfoGathering:
    """Class for gathering basic information about a target website."""
    
    def __init__(self, url, timeout=30, debug=False):
        """Initialize the InfoGathering class.
        
        Args:
            url (str): The target URL.
            timeout (int): Connection timeout in seconds.
            debug (bool): Enable debug mode.
        """
        self.url = url
        self.timeout = timeout
        self.debug = debug
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc
        if ":" in self.domain:
            self.domain = self.domain.split(":")[0]
        
        self.results = {
            "domain": self.domain,
            "ip_addresses": [],
            "nameservers": [],
            "mx_records": [],
            "txt_records": [],
            "whois_info": {},
            "http_headers": {},
            "robots_txt": "",
            "sitemap_xml": ""
        }
    
    def get_ip_addresses(self):
        """Get IP addresses for the domain."""
        try:
            ip_addresses = socket.gethostbyname_ex(self.domain)
            self.results["ip_addresses"] = ip_addresses[2]
            if self.debug:
                console.print(f"[bold green]Found IP addresses: {', '.join(ip_addresses[2])}[/bold green]")
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error getting IP addresses: {str(e)}[/bold red]")
    
    def get_dns_records(self):
        """Get DNS records for the domain."""
        try:
            # Get nameservers
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            self.results["nameservers"] = [ns.to_text() for ns in ns_records]
            if self.debug:
                console.print(f"[bold green]Found nameservers: {', '.join(self.results['nameservers'])}[/bold green]")
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error getting nameservers: {str(e)}[/bold red]")
        
        try:
            # Get MX records
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            self.results["mx_records"] = [mx.to_text() for mx in mx_records]
            if self.debug:
                console.print(f"[bold green]Found MX records: {', '.join(self.results['mx_records'])}[/bold green]")
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error getting MX records: {str(e)}[/bold red]")
        
        try:
            # Get TXT records
            txt_records = dns.resolver.resolve(self.domain, 'TXT')
            self.results["txt_records"] = [txt.to_text() for txt in txt_records]
            if self.debug:
                console.print(f"[bold green]Found TXT records: {', '.join(self.results['txt_records'])}[/bold green]")
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error getting TXT records: {str(e)}[/bold red]")
    
    def get_whois_info(self):
        """Get WHOIS information for the domain."""
        try:
            whois_info = whois.whois(self.domain)
            
            # Extract useful information from WHOIS
            self.results["whois_info"] = {
                "registrar": whois_info.registrar,
                "creation_date": whois_info.creation_date,
                "expiration_date": whois_info.expiration_date,
                "updated_date": whois_info.updated_date,
                "name_servers": whois_info.name_servers,
                "status": whois_info.status,
                "emails": whois_info.emails,
                "org": whois_info.org,
                "country": whois_info.country
            }
            
            if self.debug:
                console.print(f"[bold green]Retrieved WHOIS information for {self.domain}[/bold green]")
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error getting WHOIS information: {str(e)}[/bold red]")
    
    def get_http_headers(self):
        """Get HTTP headers from the target website."""
        try:
            response = requests.head(self.url, timeout=self.timeout, allow_redirects=True)
            self.results["http_headers"] = dict(response.headers)
            
            if self.debug:
                console.print(f"[bold green]Retrieved HTTP headers from {self.url}[/bold green]")
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error getting HTTP headers: {str(e)}[/bold red]")
    
    def get_robots_txt(self):
        """Get robots.txt content if available."""
        try:
            robots_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}/robots.txt"
            response = requests.get(robots_url, timeout=self.timeout)
            
            if response.status_code == 200:
                self.results["robots_txt"] = response.text
                if self.debug:
                    console.print(f"[bold green]Retrieved robots.txt from {robots_url}[/bold green]")
            else:
                if self.debug:
                    console.print(f"[bold yellow]No robots.txt found at {robots_url} (Status code: {response.status_code})[/bold yellow]")
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error retrieving robots.txt: {str(e)}[/bold red]")
    
    def get_sitemap_xml(self):
        """Get sitemap.xml content if available."""
        try:
            sitemap_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}/sitemap.xml"
            response = requests.get(sitemap_url, timeout=self.timeout)
            
            if response.status_code == 200:
                self.results["sitemap_xml"] = response.text
                if self.debug:
                    console.print(f"[bold green]Retrieved sitemap.xml from {sitemap_url}[/bold green]")
            else:
                if self.debug:
                    console.print(f"[bold yellow]No sitemap.xml found at {sitemap_url} (Status code: {response.status_code})[/bold yellow]")
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error retrieving sitemap.xml: {str(e)}[/bold red]")
    
    def run(self):
        """Run all information gathering methods."""
        console.print("[bold blue]Starting information gathering...[/bold blue]")
        
        # Run all methods
        self.get_ip_addresses()
        self.get_dns_records()
        self.get_whois_info()
        self.get_http_headers()
        self.get_robots_txt()
        self.get_sitemap_xml()
        
        console.print("[bold green]Information gathering completed[/bold green]")
        return self.results 