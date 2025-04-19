#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Subdomain Enumeration Module for WebSleuth
"""

import os
import re
import dns.resolver
import requests
import concurrent.futures
from urllib.parse import urlparse
from rich.console import Console

console = Console()

class SubdomainEnum:
    """Class for enumerating subdomains of a target domain."""
    
    def __init__(self, url, threads=10, timeout=30, debug=False):
        """Initialize the SubdomainEnum class.
        
        Args:
            url (str): The target URL.
            threads (int): Number of threads to use.
            timeout (int): Connection timeout in seconds.
            debug (bool): Enable debug mode.
        """
        self.url = url
        self.threads = threads
        self.timeout = timeout
        self.debug = debug
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc
        if ":" in self.domain:
            self.domain = self.domain.split(":")[0]
        
        self.results = {
            "domain": self.domain,
            "subdomains": set(),
            "total_found": 0
        }
        
        # Load subdomain wordlist
        current_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_path = os.path.join(current_dir, "..", "utils", "wordlists", "subdomains.txt")
        
        # Default small wordlist in case the file doesn't exist
        self.wordlist = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
            "dns", "dns1", "dns2", "mx", "mx1", "mx2", "webdisk", "admin", "forum",
            "blog", "portal", "beta", "dev", "test", "demo", "host", "app", "api",
            "stage", "staging", "web", "server", "vpn", "cloud", "shop", "store",
            "info", "login", "docs", "support", "help", "media", "images", "img",
            "files", "secure", "internal", "intranet", "corporate", "exchange", "old",
            "new", "mobile", "m", "en", "fr", "de", "es"
        ]
        
        # Try to load the wordlist if it exists
        try:
            if os.path.exists(wordlist_path):
                with open(wordlist_path, 'r') as f:
                    self.wordlist = [line.strip() for line in f if line.strip()]
                if self.debug:
                    console.print(f"[bold green]Loaded {len(self.wordlist)} subdomains from wordlist[/bold green]")
        except Exception as e:
            if self.debug:
                console.print(f"[bold yellow]Using default subdomain wordlist: {str(e)}[/bold yellow]")
    
    def bruteforce_subdomains(self):
        """Bruteforce subdomains using a wordlist."""
        console.print("[bold blue]Starting subdomain bruteforce...[/bold blue]")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for word in self.wordlist:
                subdomain = f"{word}.{self.domain}"
                futures.append(executor.submit(self.check_subdomain, subdomain))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.results["subdomains"].add(result)
                except Exception as e:
                    if self.debug:
                        console.print(f"[bold red]Error in bruteforce: {str(e)}[/bold red]")
        
        if self.debug:
            console.print(f"[bold green]Found {len(self.results['subdomains'])} subdomains via bruteforce[/bold green]")
    
    def check_subdomain(self, subdomain):
        """Check if a subdomain exists using DNS resolution.
        
        Args:
            subdomain (str): The subdomain to check.
            
        Returns:
            str: The subdomain if it exists, None otherwise.
        """
        try:
            dns.resolver.resolve(subdomain, 'A')
            if self.debug:
                console.print(f"[bold green]Found subdomain: {subdomain}[/bold green]")
            return subdomain
        except:
            return None
    
    def search_crt_sh(self):
        """Search for subdomains using crt.sh certificate transparency logs."""
        console.print("[bold blue]Searching crt.sh for subdomains...[/bold blue]")
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name = entry.get('name_value')
                        if name:
                            # Split and clean subdomain names
                            for subdomain in name.split('\n'):
                                subdomain = subdomain.strip().lower()
                                if subdomain.endswith(f".{self.domain}"):
                                    self.results["subdomains"].add(subdomain)
                    
                    if self.debug:
                        console.print(f"[bold green]Found {len(self.results['subdomains'])} subdomains via crt.sh[/bold green]")
                except Exception as e:
                    if self.debug:
                        console.print(f"[bold red]Error parsing crt.sh data: {str(e)}[/bold red]")
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error searching crt.sh: {str(e)}[/bold red]")
    
    def search_dns_dumpster(self):
        """Search for subdomains using DNSDumpster."""
        console.print("[bold blue]Searching DNSDumpster for subdomains...[/bold blue]")
        
        try:
            # Initialize DNSDumpster session
            session = requests.Session()
            r = session.get("https://dnsdumpster.com/", timeout=self.timeout)
            
            # Extract CSRF token
            csrf_token = None
            csrf_regex = r'name="csrfmiddlewaretoken" value="([^"]+)"'
            match = re.search(csrf_regex, r.text)
            if match:
                csrf_token = match.group(1)
            
            if csrf_token:
                # Make search request
                data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'targetip': self.domain,
                    'user': 'free'
                }
                headers = {
                    'Referer': 'https://dnsdumpster.com/',
                }
                
                r = session.post("https://dnsdumpster.com/", data=data, headers=headers, timeout=self.timeout)
                
                # Extract subdomains
                pattern = r'">([^<]*\.' + re.escape(self.domain) + ')</a>'
                for subdomain in re.findall(pattern, r.text):
                    self.results["subdomains"].add(subdomain.strip().lower())
                
                if self.debug:
                    console.print(f"[bold green]Found subdomains via DNSDumpster[/bold green]")
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error searching DNSDumpster: {str(e)}[/bold red]")
    
    def search_alienvault(self):
        """Search for subdomains using AlienVault OTX."""
        console.print("[bold blue]Searching AlienVault OTX for subdomains...[/bold blue]")
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if 'passive_dns' in data:
                    for entry in data['passive_dns']:
                        hostname = entry.get('hostname')
                        if hostname and hostname.endswith(f".{self.domain}"):
                            self.results["subdomains"].add(hostname.strip().lower())
                
                if self.debug:
                    console.print(f"[bold green]Found subdomains via AlienVault OTX[/bold green]")
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error searching AlienVault OTX: {str(e)}[/bold red]")
    
    def run(self):
        """Run all subdomain enumeration methods."""
        console.print("[bold blue]Starting subdomain enumeration...[/bold blue]")
        
        # Run all methods
        self.bruteforce_subdomains()
        self.search_crt_sh()
        self.search_dns_dumpster()
        self.search_alienvault()
        
        # Convert set to list for serialization
        self.results["subdomains"] = list(self.results["subdomains"])
        self.results["total_found"] = len(self.results["subdomains"])
        
        console.print(f"[bold green]Found {self.results['total_found']} unique subdomains for {self.domain}[/bold green]")
        
        return self.results 