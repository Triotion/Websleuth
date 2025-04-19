#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Content Discovery Module for WebSleuth
"""

import os
import re
import requests
import concurrent.futures
from urllib.parse import urlparse, urljoin
from rich.console import Console
from rich.progress import Progress

console = Console()

class ContentDiscovery:
    """Class for discovering hidden content on a target website."""
    
    def __init__(self, url, threads=10, timeout=30, debug=False):
        """Initialize the ContentDiscovery class.
        
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
        self.base_url = f"{self.parsed_url.scheme}://{self.domain}"
        
        # Normalize URL to ensure it ends with a slash for directory checks
        if not self.url.endswith('/'):
            self.url += '/'
        
        self.results = {
            "url": self.url,
            "discovered_paths": [],
            "interesting_files": [],
            "backup_files": [],
            "sensitive_files": [],
            "api_endpoints": [],
            "total_found": 0
        }
        
        # Create session for requests
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        })
        
        # Load wordlists
        self.load_wordlists()
    
    def load_wordlists(self):
        """Load wordlists for content discovery."""
        # Default mini wordlists in case files are not found
        self.directories = [
            "admin", "api", "app", "backup", "cache", "cgi-bin", "config", "data",
            "db", "dev", "docs", "download", "files", "images", "img", "js", "log",
            "login", "media", "old", "panel", "private", "scripts", "src", "static",
            "temp", "test", "tmp", "upload", "uploads", "user", "users", "wp-admin"
        ]
        
        self.files = [
            "admin.php", "backup.sql", "config.php", "db.sql", "debug.log", ".env",
            "index.php.bak", "info.php", "login.php", "phpinfo.php", "robots.txt",
            "server-status", "sitemap.xml", "wp-config.php", "wp-login.php"
        ]
        
        self.backup_extensions = [".bak", ".old", ".backup", ".swp", ".save", "~", ".zip", ".tar.gz"]
        
        self.api_paths = [
            "api/", "api/v1/", "api/v2/", "api/v3/", "rest/", "graphql", "v1/", "v2/",
            "api/users", "api/products", "api/admin", "api/status", "api/config"
        ]
        
        self.sensitive_files = [
            ".git/HEAD", ".git/config", ".env", ".htaccess", ".svn/entries",
            "config.yml", "credentials.json", "db.sqlite", "wp-config.php",
            "server.xml", "web.config", "database.yml", "settings.py"
        ]
        
        # Try to load wordlists from files
        try:
            # Path to wordlists
            current_dir = os.path.dirname(os.path.abspath(__file__))
            wordlists_dir = os.path.join(current_dir, "..", "utils", "wordlists")
            
            # Load directories wordlist
            dirs_path = os.path.join(wordlists_dir, "directories.txt")
            if os.path.exists(dirs_path):
                with open(dirs_path, 'r') as f:
                    self.directories = [line.strip() for line in f if line.strip()]
                if self.debug:
                    console.print(f"[bold green]Loaded {len(self.directories)} directories from wordlist[/bold green]")
            
            # Load files wordlist
            files_path = os.path.join(wordlists_dir, "files.txt")
            if os.path.exists(files_path):
                with open(files_path, 'r') as f:
                    self.files = [line.strip() for line in f if line.strip()]
                if self.debug:
                    console.print(f"[bold green]Loaded {len(self.files)} files from wordlist[/bold green]")
            
            # Load sensitive files wordlist
            sensitive_path = os.path.join(wordlists_dir, "sensitive.txt")
            if os.path.exists(sensitive_path):
                with open(sensitive_path, 'r') as f:
                    self.sensitive_files = [line.strip() for line in f if line.strip()]
                if self.debug:
                    console.print(f"[bold green]Loaded {len(self.sensitive_files)} sensitive files from wordlist[/bold green]")
            
            # Load API endpoints wordlist
            api_path = os.path.join(wordlists_dir, "api_endpoints.txt")
            if os.path.exists(api_path):
                with open(api_path, 'r') as f:
                    self.api_paths = [line.strip() for line in f if line.strip()]
                if self.debug:
                    console.print(f"[bold green]Loaded {len(self.api_paths)} API endpoints from wordlist[/bold green]")
        
        except Exception as e:
            if self.debug:
                console.print(f"[bold yellow]Error loading wordlists: {str(e)}. Using default lists.[/bold yellow]")
    
    def discover_directories(self):
        """Discover directories on the target website."""
        with Progress() as progress:
            task = progress.add_task("[cyan]Discovering directories...", total=len(self.directories))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for directory in self.directories:
                    directory_url = urljoin(self.url, directory + "/")
                    futures.append(executor.submit(self.check_url, directory_url, "directory", task, progress))
                
                for future in concurrent.futures.as_completed(futures):
                    future.result()
            
            if self.debug:
                console.print(f"[bold green]Directory discovery completed. Found: {len([p for p in self.results['discovered_paths'] if p.get('type') == 'directory'])}[/bold green]")
    
    def discover_files(self):
        """Discover files on the target website."""
        with Progress() as progress:
            task = progress.add_task("[cyan]Discovering files...", total=len(self.files))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for file in self.files:
                    file_url = urljoin(self.url, file)
                    futures.append(executor.submit(self.check_url, file_url, "file", task, progress))
                
                for future in concurrent.futures.as_completed(futures):
                    future.result()
            
            if self.debug:
                console.print(f"[bold green]File discovery completed. Found: {len(self.results['interesting_files'])}[/bold green]")
    
    def discover_backup_files(self):
        """Discover backup files on the target website."""
        # Extract files from found paths
        found_files = [p.get("path", "").split("/")[-1] for p in self.results["discovered_paths"] 
                      if p.get("type") == "file" and "/" in p.get("path", "")]
        
        # Add some common files
        test_files = list(set(found_files + ["index.php", "index.html", "config.php", "main.js", "style.css"]))
        
        # Generate backup variations
        backup_tests = []
        for file in test_files:
            if "." in file:
                name, ext = file.rsplit(".", 1)
                for backup_ext in self.backup_extensions:
                    backup_tests.append(f"{name}{backup_ext}")
                    backup_tests.append(f"{file}{backup_ext}")
            else:
                for backup_ext in self.backup_extensions:
                    backup_tests.append(f"{file}{backup_ext}")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Discovering backup files...", total=len(backup_tests))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for backup_file in backup_tests:
                    backup_url = urljoin(self.url, backup_file)
                    futures.append(executor.submit(self.check_url, backup_url, "backup", task, progress))
                
                for future in concurrent.futures.as_completed(futures):
                    future.result()
            
            if self.debug:
                console.print(f"[bold green]Backup file discovery completed. Found: {len(self.results['backup_files'])}[/bold green]")
    
    def discover_sensitive_files(self):
        """Discover sensitive files on the target website."""
        with Progress() as progress:
            task = progress.add_task("[cyan]Discovering sensitive files...", total=len(self.sensitive_files))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for sensitive_file in self.sensitive_files:
                    sensitive_url = urljoin(self.url, sensitive_file)
                    futures.append(executor.submit(self.check_url, sensitive_url, "sensitive", task, progress))
                
                for future in concurrent.futures.as_completed(futures):
                    future.result()
            
            if self.debug:
                console.print(f"[bold green]Sensitive file discovery completed. Found: {len(self.results['sensitive_files'])}[/bold green]")
    
    def discover_api_endpoints(self):
        """Discover API endpoints on the target website."""
        with Progress() as progress:
            task = progress.add_task("[cyan]Discovering API endpoints...", total=len(self.api_paths))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for api_path in self.api_paths:
                    api_url = urljoin(self.url, api_path)
                    futures.append(executor.submit(self.check_url, api_url, "api", task, progress))
                
                for future in concurrent.futures.as_completed(futures):
                    future.result()
            
            if self.debug:
                console.print(f"[bold green]API endpoint discovery completed. Found: {len(self.results['api_endpoints'])}[/bold green]")
    
    def check_url(self, url, url_type, task, progress):
        """Check if a URL exists.
        
        Args:
            url (str): URL to check.
            url_type (str): Type of URL (directory, file, backup, sensitive, api).
            task: Progress task.
            progress: Progress instance.
        """
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            
            # Update progress
            progress.update(task, advance=1)
            
            # Check for existence (status codes 200, 201, 203, 204, 302, 307)
            if response.status_code in [200, 201, 203, 204, 302, 307]:
                content_type = response.headers.get('Content-Type', '').lower()
                content_length = len(response.content)
                
                # Extract path from URL
                path = url.replace(self.base_url, '')
                
                # Store result based on type
                if url_type == "directory":
                    # Verify it's a directory (ends with / or returns HTML)
                    if url.endswith('/') and ('html' in content_type or content_length > 0):
                        self.results["discovered_paths"].append({
                            "path": path,
                            "type": "directory",
                            "status_code": response.status_code,
                            "content_type": content_type,
                            "content_length": content_length
                        })
                        if self.debug:
                            console.print(f"[bold green]Found directory: {path} [{response.status_code}][/bold green]")
                
                elif url_type == "file":
                    # Add to discovered paths and interesting files
                    self.results["discovered_paths"].append({
                        "path": path,
                        "type": "file",
                        "status_code": response.status_code,
                        "content_type": content_type,
                        "content_length": content_length
                    })
                    
                    self.results["interesting_files"].append({
                        "path": path,
                        "status_code": response.status_code,
                        "content_type": content_type,
                        "content_length": content_length
                    })
                    
                    if self.debug:
                        console.print(f"[bold green]Found file: {path} [{response.status_code}][/bold green]")
                
                elif url_type == "backup":
                    self.results["backup_files"].append({
                        "path": path,
                        "status_code": response.status_code,
                        "content_type": content_type,
                        "content_length": content_length
                    })
                    
                    if self.debug:
                        console.print(f"[bold yellow]Found backup file: {path} [{response.status_code}][/bold yellow]")
                
                elif url_type == "sensitive":
                    self.results["sensitive_files"].append({
                        "path": path,
                        "status_code": response.status_code,
                        "content_type": content_type,
                        "content_length": content_length
                    })
                    
                    if self.debug:
                        console.print(f"[bold red]Found sensitive file: {path} [{response.status_code}][/bold red]")
                
                elif url_type == "api":
                    # Check if it's likely an API (returns JSON or has API-like response)
                    is_api = 'json' in content_type or 'api' in path.lower()
                    
                    if is_api:
                        self.results["api_endpoints"].append({
                            "path": path,
                            "status_code": response.status_code,
                            "content_type": content_type,
                            "content_length": content_length
                        })
                        
                        if self.debug:
                            console.print(f"[bold cyan]Found API endpoint: {path} [{response.status_code}][/bold cyan]")
        
        except Exception as e:
            # Skip connection errors or timeouts
            progress.update(task, advance=1)
            if self.debug and isinstance(e, requests.exceptions.RequestException) == False:
                console.print(f"[bold red]Error checking {url}: {str(e)}[/bold red]")
    
    def analyze_robots_sitemap(self):
        """Analyze robots.txt and sitemap.xml for additional paths."""
        # Check robots.txt
        try:
            robots_url = urljoin(self.base_url, "robots.txt")
            response = self.session.get(robots_url, timeout=self.timeout)
            
            if response.status_code == 200:
                content = response.text
                
                # Extract disallowed paths
                disallowed = re.findall(r'Disallow:\s*(.+)', content, re.IGNORECASE)
                for path in disallowed:
                    path = path.strip()
                    if path and path != '/':
                        full_url = urljoin(self.base_url, path)
                        self.results["discovered_paths"].append({
                            "path": path,
                            "type": "from_robots",
                            "source": "robots.txt"
                        })
                        
                        if self.debug:
                            console.print(f"[bold blue]Found path in robots.txt: {path}[/bold blue]")
                
                # Extract sitemaps
                sitemaps = re.findall(r'Sitemap:\s*(.+)', content, re.IGNORECASE)
                
                for sitemap_url in sitemaps:
                    try:
                        if self.debug:
                            console.print(f"[bold blue]Checking sitemap: {sitemap_url}[/bold blue]")
                        
                        sm_response = self.session.get(sitemap_url.strip(), timeout=self.timeout)
                        
                        if sm_response.status_code == 200:
                            # Extract URLs from sitemap
                            urls = re.findall(r'<loc>(.+?)</loc>', sm_response.text)
                            
                            for url in urls:
                                if self.domain in url:
                                    path = url.replace(self.base_url, '')
                                    if path:
                                        self.results["discovered_paths"].append({
                                            "path": path,
                                            "type": "from_sitemap",
                                            "source": sitemap_url
                                        })
                                        
                                        if self.debug:
                                            console.print(f"[bold blue]Found path in sitemap: {path}[/bold blue]")
                    
                    except Exception as e:
                        if self.debug:
                            console.print(f"[bold red]Error processing sitemap {sitemap_url}: {str(e)}[/bold red]")
        
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error analyzing robots.txt: {str(e)}[/bold red]")
    
    def run(self):
        """Run content discovery."""
        console.print("[bold blue]Starting content discovery...[/bold blue]")
        
        # Run all discovery methods
        self.analyze_robots_sitemap()
        self.discover_directories()
        self.discover_files()
        self.discover_sensitive_files()
        self.discover_backup_files()
        self.discover_api_endpoints()
        
        # Update total found
        self.results["total_found"] = (
            len(self.results["discovered_paths"]) +
            len(self.results["interesting_files"]) +
            len(self.results["backup_files"]) +
            len(self.results["sensitive_files"]) +
            len(self.results["api_endpoints"])
        )
        
        console.print(f"[bold green]Content discovery completed for {self.url}[/bold green]")
        console.print(f"[bold green]Total items found: {self.results['total_found']}[/bold green]")
        return self.results 