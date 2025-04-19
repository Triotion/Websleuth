#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced Vulnerability Scanner Module for WebSleuth
"""

import re
import json
import random
import string
import requests
import concurrent.futures
import urllib.parse
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin
from rich.console import Console
from rich.progress import Progress

console = Console()

class VulnerabilityScanner:
    """Advanced class for scanning a target website for common vulnerabilities."""
    
    def __init__(self, url, threads=20, timeout=10, debug=False, scan_depth=2):
        """Initialize the VulnerabilityScanner class.
        
        Args:
            url (str): The target URL.
            threads (int): Number of threads to use.
            timeout (int): Connection timeout in seconds.
            debug (bool): Enable debug mode.
            scan_depth (int): Depth of crawling for vulnerability scanning.
        """
        self.url = url
        self.threads = threads
        self.timeout = timeout
        self.debug = debug
        self.scan_depth = scan_depth
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc
        
        # User agent for requests
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        
        # Set up session with custom headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # URLs to scan
        self.urls_to_scan = set([self.url])
        self.scanned_urls = set()
        
        # Payloads for different vulnerability checks
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '\';alert(1)//\\',
            '*/alert(1)/*',
            '*/alert(1)";//',
            '<img src=x onerror=alert(1)//'
        ]
        
        self.sqli_payloads = [
            "' OR '1'='1", 
            "' OR '1'='1' --", 
            "' OR 1=1 --", 
            "' OR 1=1#", 
            "') OR 1=1 --", 
            "') OR ('1'='1", 
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12 --",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL --"
        ]
        
        self.lfi_payloads = [
            "../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "../../../../../../../windows/win.ini",
            "../../../../../../../../windows/win.ini",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/etc/passwd"
        ]
        
        self.rce_payloads = [
            ';cat /etc/passwd',
            '& cat /etc/passwd',
            '| cat /etc/passwd',
            '|| cat /etc/passwd',
            "'; ping -c 3 localhost; '",
            "& ping -c 3 localhost &",
            "| ping -c 3 localhost |",
            "|| ping -c 3 localhost ||"
        ]
        
        self.results = {
            "url": self.url,
            "scan_info": {
                "urls_scanned": 0,
                "scan_depth": self.scan_depth,
                "threads_used": self.threads
            },
            "vulnerabilities": [],
            "total_vulns": 0,
            "risk_level": "Low",
            "vulnerable_urls": {},
            "vuln_types": {}
        }
    
    def generate_random_string(self, length=10):
        """Generate a random string for testing."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def crawl_website(self, max_urls=100):
        """Crawl the website to find URLs to scan."""
        if self.debug:
            console.print(f"[bold blue]Crawling website: {self.url}[/bold blue]")
        
        visited_urls = set()
        urls_to_visit = set([self.url])
        
        depth = 0
        while depth < self.scan_depth and urls_to_visit and len(visited_urls) < max_urls:
            depth += 1
            current_urls = urls_to_visit.copy()
            urls_to_visit = set()
            
            for url in current_urls:
                if url in visited_urls:
                    continue
                
                visited_urls.add(url)
                
                try:
                    response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    
                    # Skip non-HTML responses
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' not in content_type.lower():
                        continue
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(url, href)
                        
                        # Skip external domains and non-http(s) URLs
                        if not full_url.startswith(('http://', 'https://')):
                            continue
                        
                        parsed_link = urlparse(full_url)
                        if parsed_link.netloc != self.domain:
                            continue
                        
                        # Skip URL fragments
                        full_url = full_url.split('#')[0]
                        
                        if full_url not in visited_urls:
                            urls_to_visit.add(full_url)
                    
                    # Find all forms for potential input points
                    for form in soup.find_all('form'):
                        form_action = form.get('action', '')
                        form_url = urljoin(url, form_action)
                        
                        # Skip external domains
                        parsed_form_url = urlparse(form_url)
                        if parsed_form_url.netloc != self.domain:
                            continue
                        
                        urls_to_visit.add(form_url)
                    
                except Exception as e:
                    if self.debug:
                        console.print(f"[bold red]Error crawling {url}: {str(e)}[/bold red]")
        
        # Add all discovered URLs to scan list
        self.urls_to_scan.update(visited_urls)
        
        if self.debug:
            console.print(f"[bold green]Found {len(self.urls_to_scan)} URLs to scan[/bold green]")
    
    def extract_forms(self, url):
        """Extract forms from a URL for testing."""
        forms = []
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_details = {}
                form_details['action'] = form.get('action', '')
                form_details['method'] = form.get('method', 'get').lower()
                form_details['inputs'] = []
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_type = input_tag.get('type', 'text')
                    input_name = input_tag.get('name', '')
                    input_value = input_tag.get('value', '')
                    
                    # Skip submit buttons and hidden inputs for vulnerability testing
                    if input_type not in ['submit', 'button', 'image']:
                        form_details['inputs'].append({
                            'type': input_type,
                            'name': input_name,
                            'value': input_value
                        })
                
                forms.append(form_details)
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error extracting forms from {url}: {str(e)}[/bold red]")
        
        return forms
    
    def check_xss(self, url, progress, task_id):
        """Check for Cross-Site Scripting vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Extract forms from the page
            forms = self.extract_forms(url)
            progress.update(task_id, advance=1)
            
            # Check XSS in URL parameters
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            if params:
                for param_name, param_values in params.items():
                    for payload in self.xss_payloads:
                        # Create a new parameter dict with the payload
                        test_params = {k: v for k, v in params.items()}
                        test_params[param_name] = [payload]
                        
                        # Construct the test URL
                        query_string = urllib.parse.urlencode(test_params, doseq=True)
                        test_url = url.split('?')[0] + '?' + query_string
                        
                        try:
                            response = self.session.get(test_url, timeout=self.timeout)
                            
                            # Check if the payload is reflected in the response
                            if payload in response.text:
                                vuln = {
                                    "type": "XSS",
                                    "url": url,
                                    "method": "GET",
                                    "param": param_name,
                                    "payload": payload,
                                    "details": f"XSS payload was reflected in the response",
                                    "severity": "High",
                                    "confidence": "Medium"
                                }
                                vulnerabilities.append(vuln)
                                self.add_vulnerability(vuln)
                                break  # Found a working payload, no need to try more
                        except Exception as e:
                            if self.debug:
                                console.print(f"[bold red]Error testing XSS in URL {test_url}: {str(e)}[/bold red]")
            
            # Check XSS in forms
            for form in forms:
                for input_data in form['inputs']:
                    if not input_data['name']:
                        continue
                    
                    for payload in self.xss_payloads:
                        data = {}
                        
                        # Fill all inputs with random data
                        for inp in form['inputs']:
                            if inp['name'] == input_data['name']:
                                data[inp['name']] = payload
                            elif inp['type'] != 'hidden':
                                data[inp['name']] = self.generate_random_string()
                            else:
                                data[inp['name']] = inp['value']
                        
                        try:
                            form_url = urljoin(url, form['action'])
                            
                            if form['method'] == 'post':
                                response = self.session.post(form_url, data=data, timeout=self.timeout)
                            else:
                                response = self.session.get(form_url, params=data, timeout=self.timeout)
                            
                            # Check if the payload is reflected in the response
                            if payload in response.text:
                                vuln = {
                                    "type": "XSS",
                                    "url": url,
                                    "method": form['method'].upper(),
                                    "param": input_data['name'],
                                    "payload": payload,
                                    "details": f"XSS payload was reflected in the response",
                                    "severity": "High",
                                    "confidence": "Medium"
                                }
                                vulnerabilities.append(vuln)
                                self.add_vulnerability(vuln)
                                break  # Found a working payload, no need to try more
                        except Exception as e:
                            if self.debug:
                                console.print(f"[bold red]Error testing XSS in form {form_url}: {str(e)}[/bold red]")
        
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error during XSS check for {url}: {str(e)}[/bold red]")
        
        return vulnerabilities
    
    def check_sqli(self, url, progress, task_id):
        """Check for SQL Injection vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Extract forms from the page
            forms = self.extract_forms(url)
            progress.update(task_id, advance=1)
            
            # Check SQLi in URL parameters
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            if params:
                for param_name, param_values in params.items():
                    for payload in self.sqli_payloads:
                        # Create a new parameter dict with the payload
                        test_params = {k: v for k, v in params.items()}
                        test_params[param_name] = [payload]
                        
                        # Construct the test URL
                        query_string = urllib.parse.urlencode(test_params, doseq=True)
                        test_url = url.split('?')[0] + '?' + query_string
                        
                        try:
                            response = self.session.get(test_url, timeout=self.timeout)
                            
                            # Check for SQL error messages
                            if self.detect_sql_errors(response.text):
                                vuln = {
                                    "type": "SQL Injection",
                                    "url": url,
                                    "method": "GET",
                                    "param": param_name,
                                    "payload": payload,
                                    "details": f"SQL error detected in response",
                                    "severity": "Critical",
                                    "confidence": "Medium"
                                }
                                vulnerabilities.append(vuln)
                                self.add_vulnerability(vuln)
                                break  # Found a working payload, no need to try more
                        except Exception as e:
                            if self.debug:
                                console.print(f"[bold red]Error testing SQLi in URL {test_url}: {str(e)}[/bold red]")
            
            # Check SQLi in forms
            for form in forms:
                for input_data in form['inputs']:
                    if not input_data['name']:
                        continue
                    
                    for payload in self.sqli_payloads:
                        data = {}
                        
                        # Fill all inputs with random data
                        for inp in form['inputs']:
                            if inp['name'] == input_data['name']:
                                data[inp['name']] = payload
                            elif inp['type'] != 'hidden':
                                data[inp['name']] = self.generate_random_string()
                            else:
                                data[inp['name']] = inp['value']
                        
                        try:
                            form_url = urljoin(url, form['action'])
                            
                            if form['method'] == 'post':
                                response = self.session.post(form_url, data=data, timeout=self.timeout)
                            else:
                                response = self.session.get(form_url, params=data, timeout=self.timeout)
                            
                            # Check for SQL error messages
                            if self.detect_sql_errors(response.text):
                                vuln = {
                                    "type": "SQL Injection",
                                    "url": url,
                                    "method": form['method'].upper(),
                                    "param": input_data['name'],
                                    "payload": payload,
                                    "details": f"SQL error detected in response",
                                    "severity": "Critical",
                                    "confidence": "Medium"
                                }
                                vulnerabilities.append(vuln)
                                self.add_vulnerability(vuln)
                                break  # Found a working payload, no need to try more
                        except Exception as e:
                            if self.debug:
                                console.print(f"[bold red]Error testing SQLi in form {form_url}: {str(e)}[/bold red]")
        
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error during SQLi check for {url}: {str(e)}[/bold red]")
        
        return vulnerabilities
    
    def check_lfi(self, url, progress, task_id):
        """Check for Local File Inclusion vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Extract forms from the page
            forms = self.extract_forms(url)
            progress.update(task_id, advance=1)
            
            # Check LFI in URL parameters
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            if params:
                for param_name, param_values in params.items():
                    for payload in self.lfi_payloads:
                        # Create a new parameter dict with the payload
                        test_params = {k: v for k, v in params.items()}
                        test_params[param_name] = [payload]
                        
                        # Construct the test URL
                        query_string = urllib.parse.urlencode(test_params, doseq=True)
                        test_url = url.split('?')[0] + '?' + query_string
                        
                        try:
                            response = self.session.get(test_url, timeout=self.timeout)
                            
                            # Check for LFI signatures
                            if self.detect_lfi(response.text):
                                vuln = {
                                    "type": "Local File Inclusion",
                                    "url": url,
                                    "method": "GET",
                                    "param": param_name,
                                    "payload": payload,
                                    "details": f"LFI detected - file contents found in response",
                                    "severity": "High",
                                    "confidence": "Medium"
                                }
                                vulnerabilities.append(vuln)
                                self.add_vulnerability(vuln)
                                break  # Found a working payload, no need to try more
                        except Exception as e:
                            if self.debug:
                                console.print(f"[bold red]Error testing LFI in URL {test_url}: {str(e)}[/bold red]")
            
            # Check LFI in forms
            for form in forms:
                for input_data in form['inputs']:
                    if not input_data['name']:
                        continue
                    
                    for payload in self.lfi_payloads:
                        data = {}
                        
                        # Fill all inputs with random data
                        for inp in form['inputs']:
                            if inp['name'] == input_data['name']:
                                data[inp['name']] = payload
                            elif inp['type'] != 'hidden':
                                data[inp['name']] = self.generate_random_string()
                            else:
                                data[inp['name']] = inp['value']
                        
                        try:
                            form_url = urljoin(url, form['action'])
                            
                            if form['method'] == 'post':
                                response = self.session.post(form_url, data=data, timeout=self.timeout)
                            else:
                                response = self.session.get(form_url, params=data, timeout=self.timeout)
                            
                            # Check for LFI signatures
                            if self.detect_lfi(response.text):
                                vuln = {
                                    "type": "Local File Inclusion",
                                    "url": url,
                                    "method": form['method'].upper(),
                                    "param": input_data['name'],
                                    "payload": payload,
                                    "details": f"LFI detected - file contents found in response",
                                    "severity": "High",
                                    "confidence": "Medium"
                                }
                                vulnerabilities.append(vuln)
                                self.add_vulnerability(vuln)
                                break  # Found a working payload, no need to try more
                        except Exception as e:
                            if self.debug:
                                console.print(f"[bold red]Error testing LFI in form {form_url}: {str(e)}[/bold red]")
        
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error during LFI check for {url}: {str(e)}[/bold red]")
        
        return vulnerabilities
    
    def detect_sql_errors(self, text):
        """Detect SQL error messages in the response."""
        sql_errors = [
            "SQL syntax.*?MySQL",
            "Warning.*?\\Wmysqli?_",
            "MySQLSyntaxErrorException",
            "valid MySQL result",
            "check the manual that corresponds to your (MySQL|MariaDB) server version",
            "Unknown column '[^']+' in 'field list'",
            "MySqlClient\\.",
            "com\\.mysql\\.jdbc",
            "Zend_Db_(Adapter|Statement)_Mysqli_Exception",
            "Pdo[./_\\\\]Mysql",
            "MySqlException",
            "SQLSTATE\\[\\d+\\]: Syntax error or access violation",
            "SQLSTATE\\[42000\\]",
            "ORA-[0-9][0-9][0-9][0-9]",
            "Oracle error",
            "Oracle.*?Driver",
            "Warning.*?\\Woci_",
            "Warning.*?\\Wora_",
            "Microsoft SQL Server",
            "ODBC SQL Server Driver",
            "SQLServer JDBC Driver",
            "SQLException",
            "Unclosed quotation mark after the character string",
            "PostgreSQL.*?ERROR",
            "Warning.*?\\Wpg_",
            "valid PostgreSQL result",
            "Npgsql\\.",
            "PG::SyntaxError:",
            "org\\.postgresql\\.util\\.PSQLException",
            "ERROR:\\s\\ssyntax error at or near ",
            "ERROR: parser: parse error at or near"
        ]
        
        for error in sql_errors:
            if re.search(error, text, re.IGNORECASE):
                return True
        
        return False
    
    def detect_lfi(self, text):
        """Detect Local File Inclusion signatures in the response."""
        lfi_signatures = [
            "root:x:",
            "daemon:x:",
            "\\[boot loader\\]",
            "\\[operating systems\\]",
            "/bin/bash",
            "HTTP_USER_AGENT",
            "HTTP_ACCEPT",
            "HTTP_HOST",
            "PWD=/"
        ]
        
        for signature in lfi_signatures:
            if re.search(signature, text, re.IGNORECASE):
                return True
        
        return False
    
    def check_for_vulnerabilities(self, url, progress, task_id):
        """Run all vulnerability checks on a single URL."""
        if url in self.scanned_urls:
            progress.update(task_id, advance=3)  # Skip the 3 checks
            return
        
        self.scanned_urls.add(url)
        
        vulnerabilities = []
        
        # Run all the checks
        vulnerabilities.extend(self.check_xss(url, progress, task_id))
        vulnerabilities.extend(self.check_sqli(url, progress, task_id))
        vulnerabilities.extend(self.check_lfi(url, progress, task_id))
        
        return vulnerabilities
    
    def add_vulnerability(self, vuln):
        """Add a vulnerability to the results."""
        self.results["vulnerabilities"].append(vuln)
        self.results["total_vulns"] += 1
        
        # Update vulnerable URLs
        url = vuln["url"]
        if url not in self.results["vulnerable_urls"]:
            self.results["vulnerable_urls"][url] = []
        self.results["vulnerable_urls"][url].append(vuln)
        
        # Update vulnerability types count
        vuln_type = vuln["type"]
        if vuln_type not in self.results["vuln_types"]:
            self.results["vuln_types"][vuln_type] = 0
        self.results["vuln_types"][vuln_type] += 1
        
        # Update risk level based on severities
        if vuln["severity"] == "Critical":
            self.results["risk_level"] = "Critical"
        elif vuln["severity"] == "High" and self.results["risk_level"] != "Critical":
            self.results["risk_level"] = "High"
        elif vuln["severity"] == "Medium" and self.results["risk_level"] not in ["Critical", "High"]:
            self.results["risk_level"] = "Medium"
    
    def run(self):
        """Run vulnerability scanning."""
        console.print("[bold blue]Starting vulnerability scanning...[/bold blue]")
        
        # First crawl the website to find URLs to scan
        self.crawl_website()
        
        # Update scan info
        self.results["scan_info"]["urls_scanned"] = len(self.urls_to_scan)
        
        # Use ThreadPoolExecutor to scan URLs in parallel
        with Progress() as progress:
            # Create a task for tracking progress
            # Each URL has 3 checks (XSS, SQLi, LFI), so total is 3 * number of URLs
            task_id = progress.add_task(
                "[cyan]Scanning for vulnerabilities...", 
                total=len(self.urls_to_scan) * 3
            )
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Submit all URLs for scanning
                futures = []
                for url in self.urls_to_scan:
                    future = executor.submit(self.check_for_vulnerabilities, url, progress, task_id)
                    futures.append(future)
                
                # Wait for all futures to complete
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.debug:
                            console.print(f"[bold red]Error during vulnerability scan: {str(e)}[/bold red]")
        
        # Print summary of findings
        if self.results["total_vulns"] > 0:
            console.print(f"[bold red]Found {self.results['total_vulns']} vulnerabilities![/bold red]")
            
            for vuln_type, count in self.results["vuln_types"].items():
                console.print(f"[bold yellow]{vuln_type}: {count}[/bold yellow]")
            
            console.print(f"[bold red]Risk Level: {self.results['risk_level']}[/bold red]")
        else:
            console.print("[bold green]No vulnerabilities found.[/bold green]")
        
        console.print(f"[bold green]Vulnerability scanning completed for {self.url}[/bold green]")
        return self.results 