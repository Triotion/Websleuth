#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Technology Scanner Module for WebSleuth
"""

import re
import json
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from rich.console import Console

console = Console()

class TechnologyScanner:
    """Class for detecting web technologies used by a target website."""
    
    def __init__(self, url, timeout=30, debug=False):
        """Initialize the TechnologyScanner class.
        
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
        
        self.results = {
            "url": self.url,
            "technologies": [],
            "frameworks": [],
            "cms": None,
            "server": None,
            "languages": [],
            "javascript_libraries": [],
            "analytics": [],
            "cdn": []
        }
        
        # Load technology signatures
        self.load_signatures()
    
    def load_signatures(self):
        """Load technology signatures from files."""
        try:
            # Path to signatures file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            signatures_path = os.path.join(current_dir, "..", "utils", "signatures", "tech_signatures.json")
            
            # Default signatures in case the file doesn't exist
            self.signatures = {
                "cms": {
                    "WordPress": {
                        "html": ["wp-content", "wp-includes"],
                        "headers": {"X-Powered-By": "WordPress"}
                    },
                    "Joomla": {
                        "html": ["/components/com_", "joomla"],
                        "headers": {}
                    },
                    "Drupal": {
                        "html": ["Drupal.settings", "drupal.org"],
                        "headers": {"X-Generator": "Drupal"}
                    },
                    "Shopify": {
                        "html": ["cdn.shopify.com", "shopify.com"],
                        "headers": {}
                    },
                    "Magento": {
                        "html": ["Mage.Cookies", "Magento"],
                        "headers": {}
                    },
                    "Ghost": {
                        "html": ["ghost.io", "content=\"Ghost"],
                        "headers": {}
                    }
                },
                "frameworks": {
                    "React": {"html": ["react.js", "react-dom.js", "reactjs"]},
                    "Angular": {"html": ["ng-app", "angular.js", "angular/", "ng-controller"]},
                    "Vue.js": {"html": ["vue.js", "vuejs"]},
                    "Django": {"html": ["csrfmiddlewaretoken", "__django"]},
                    "Laravel": {"html": ["laravel", "csrf-token"]},
                    "ASP.NET": {
                        "html": ["__VIEWSTATE", "__ASPNETVERSION"],
                        "headers": {"X-AspNet-Version": "", "X-Powered-By": "ASP.NET"}
                    },
                    "Ruby on Rails": {
                        "html": ["rails", "data-turbolinks-track"],
                        "headers": {"X-Powered-By": "Ruby on Rails"}
                    },
                    "Express.js": {
                        "headers": {"X-Powered-By": "Express"}
                    },
                    "Flask": {
                        "headers": {"Server": "Werkzeug"}
                    }
                },
                "servers": {
                    "Apache": {"headers": {"Server": "Apache"}},
                    "Nginx": {"headers": {"Server": "nginx"}},
                    "Microsoft-IIS": {"headers": {"Server": "Microsoft-IIS"}},
                    "LiteSpeed": {"headers": {"Server": "LiteSpeed"}},
                    "Cloudflare": {"headers": {"Server": "cloudflare"}},
                    "Tomcat": {"headers": {"Server": "Apache-Coyote", "X-Powered-By": "Tomcat"}},
                    "Node.js": {"headers": {"X-Powered-By": "Node.js"}}
                },
                "languages": {
                    "PHP": {"headers": {"X-Powered-By": "PHP"}},
                    "ASP.NET": {"headers": {"X-Powered-By": "ASP.NET"}},
                    "Java": {"headers": {"X-Powered-By": "JSP"}}
                },
                "javascript_libraries": {
                    "jQuery": {"html": ["jquery"]},
                    "Bootstrap": {"html": ["bootstrap.min.js", "bootstrap.css"]},
                    "Lodash": {"html": ["lodash.min.js", "lodash.js"]},
                    "Moment.js": {"html": ["moment.js", "moment.min.js"]},
                    "Underscore.js": {"html": ["underscore.js", "underscore-min.js"]},
                    "D3.js": {"html": ["d3.js", "d3.min.js"]},
                    "React": {"html": ["react.js", "react.min.js"]},
                    "Angular": {"html": ["angular.js", "angular.min.js"]},
                    "Vue.js": {"html": ["vue.js", "vue.min.js"]}
                },
                "analytics": {
                    "Google Analytics": {"html": ["google-analytics.com", "ga('create'", "gtag("]},
                    "Hotjar": {"html": ["hotjar", "hjSetting"]},
                    "Mixpanel": {"html": ["mixpanel"]},
                    "New Relic": {"html": ["newrelic"]},
                    "Matomo": {"html": ["matomo.js", "piwik.js"]}
                },
                "cdn": {
                    "Cloudflare": {
                        "headers": {"Server": "cloudflare", "CF-RAY": ""}
                    },
                    "Akamai": {
                        "headers": {"X-Akamai-Transformed": ""}
                    },
                    "Fastly": {
                        "headers": {"Fastly-Debug-Path": "", "X-Served-By": "cache-fastly"}
                    },
                    "Amazon CloudFront": {
                        "headers": {"X-Amz-Cf-Id": "", "Via": "CloudFront"}
                    },
                    "jsDelivr": {
                        "html": ["cdn.jsdelivr.net"]
                    },
                    "cdnjs": {
                        "html": ["cdnjs.cloudflare.com"]
                    },
                    "unpkg": {
                        "html": ["unpkg.com"]
                    }
                }
            }
            
            # Try to load the signatures file if it exists
            if os.path.exists(signatures_path):
                with open(signatures_path, 'r') as f:
                    self.signatures = json.load(f)
                if self.debug:
                    console.print(f"[bold green]Loaded tech signatures from file[/bold green]")
            else:
                if self.debug:
                    console.print(f"[bold yellow]Using default tech signatures[/bold yellow]")
        
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error loading tech signatures: {str(e)}[/bold red]")
    
    def scan_technologies(self):
        """Scan for technologies used by the target website."""
        try:
            # Fetch the webpage
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(self.url, headers=headers, timeout=self.timeout)
            
            # Get response headers and HTML content
            response_headers = response.headers
            html_content = response.text
            
            # Parse HTML content
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Check for server information
            self.detect_server(response_headers)
            
            # Check for languages
            self.detect_languages(response_headers, html_content)
            
            # Check for CMS
            self.detect_cms(response_headers, html_content, soup)
            
            # Check for frameworks
            self.detect_frameworks(response_headers, html_content, soup)
            
            # Check for JavaScript libraries
            self.detect_js_libraries(html_content, soup)
            
            # Check for analytics tools
            self.detect_analytics(html_content, soup)
            
            # Check for CDN
            self.detect_cdn(response_headers, html_content)
            
            # Check for other technologies
            self.detect_other_technologies(response_headers, html_content, soup)
            
            if self.debug:
                console.print(f"[bold green]Technology scanning completed for {self.url}[/bold green]")
        
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error scanning technologies: {str(e)}[/bold red]")
    
    def detect_server(self, headers):
        """Detect the server technology.
        
        Args:
            headers (dict): HTTP response headers.
        """
        # Check Server header
        server = headers.get('Server')
        if server:
            self.results['server'] = server
            
            # Check against known servers
            for server_name, signatures in self.signatures['servers'].items():
                server_headers = signatures.get('headers', {})
                for header, value in server_headers.items():
                    if header in headers and (value == "" or value.lower() in headers[header].lower()):
                        self.results['technologies'].append(server_name)
                        if self.debug:
                            console.print(f"[bold green]Detected server: {server_name}[/bold green]")
    
    def detect_languages(self, headers, html_content):
        """Detect programming languages used by the website.
        
        Args:
            headers (dict): HTTP response headers.
            html_content (str): HTML content of the page.
        """
        # Check headers for language indicators
        for lang, signatures in self.signatures['languages'].items():
            lang_headers = signatures.get('headers', {})
            for header, value in lang_headers.items():
                if header in headers and (value == "" or value.lower() in headers[header].lower()):
                    self.results['languages'].append(lang)
                    self.results['technologies'].append(lang)
                    if self.debug:
                        console.print(f"[bold green]Detected language: {lang}[/bold green]")
        
        # Additional checks based on HTML content
        if "<?php" in html_content:
            if "PHP" not in self.results['languages']:
                self.results['languages'].append("PHP")
                self.results['technologies'].append("PHP")
        
        if "<%@" in html_content or "<%=" in html_content:
            if "JSP" not in self.results['languages']:
                self.results['languages'].append("JSP")
                self.results['technologies'].append("JSP")
    
    def detect_cms(self, headers, html_content, soup):
        """Detect Content Management System (CMS) used by the website.
        
        Args:
            headers (dict): HTTP response headers.
            html_content (str): HTML content of the page.
            soup (BeautifulSoup): Parsed HTML.
        """
        # Check for CMS indicators
        for cms_name, signatures in self.signatures['cms'].items():
            # Check HTML indicators
            html_patterns = signatures.get('html', [])
            for pattern in html_patterns:
                if pattern.lower() in html_content.lower():
                    self.results['cms'] = cms_name
                    self.results['technologies'].append(cms_name)
                    if self.debug:
                        console.print(f"[bold green]Detected CMS: {cms_name}[/bold green]")
                    break
            
            # Check header indicators
            if self.results['cms'] is None:
                cms_headers = signatures.get('headers', {})
                for header, value in cms_headers.items():
                    if header in headers and (value == "" or value.lower() in headers[header].lower()):
                        self.results['cms'] = cms_name
                        self.results['technologies'].append(cms_name)
                        if self.debug:
                            console.print(f"[bold green]Detected CMS: {cms_name}[/bold green]")
                        break
        
        # Check meta generator tag
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            generator_content = meta_generator.get('content').lower()
            
            if 'wordpress' in generator_content and self.results['cms'] is None:
                self.results['cms'] = 'WordPress'
                self.results['technologies'].append('WordPress')
            elif 'drupal' in generator_content and self.results['cms'] is None:
                self.results['cms'] = 'Drupal'
                self.results['technologies'].append('Drupal')
            elif 'joomla' in generator_content and self.results['cms'] is None:
                self.results['cms'] = 'Joomla'
                self.results['technologies'].append('Joomla')
            elif 'shopify' in generator_content and self.results['cms'] is None:
                self.results['cms'] = 'Shopify'
                self.results['technologies'].append('Shopify')
    
    def detect_frameworks(self, headers, html_content, soup):
        """Detect web frameworks used by the website.
        
        Args:
            headers (dict): HTTP response headers.
            html_content (str): HTML content of the page.
            soup (BeautifulSoup): Parsed HTML.
        """
        # Check for framework indicators
        for framework, signatures in self.signatures['frameworks'].items():
            # Check HTML indicators
            html_patterns = signatures.get('html', [])
            for pattern in html_patterns:
                if pattern.lower() in html_content.lower():
                    self.results['frameworks'].append(framework)
                    self.results['technologies'].append(framework)
                    if self.debug:
                        console.print(f"[bold green]Detected framework: {framework}[/bold green]")
                    break
            
            # Check header indicators
            framework_headers = signatures.get('headers', {})
            for header, value in framework_headers.items():
                if header in headers and (value == "" or value.lower() in headers[header].lower()):
                    if framework not in self.results['frameworks']:
                        self.results['frameworks'].append(framework)
                        self.results['technologies'].append(framework)
                        if self.debug:
                            console.print(f"[bold green]Detected framework: {framework}[/bold green]")
    
    def detect_js_libraries(self, html_content, soup):
        """Detect JavaScript libraries used by the website.
        
        Args:
            html_content (str): HTML content of the page.
            soup (BeautifulSoup): Parsed HTML.
        """
        # Check script tags for JS libraries
        script_tags = soup.find_all('script')
        script_srcs = [script.get('src', '') for script in script_tags if script.get('src')]
        
        # Convert to string for easier searching
        script_srcs_str = ' '.join(script_srcs).lower()
        
        # Check for JS library indicators
        for library, signatures in self.signatures['javascript_libraries'].items():
            html_patterns = signatures.get('html', [])
            for pattern in html_patterns:
                if pattern.lower() in html_content.lower() or pattern.lower() in script_srcs_str:
                    if library not in self.results['javascript_libraries']:
                        self.results['javascript_libraries'].append(library)
                        self.results['technologies'].append(library)
                        if self.debug:
                            console.print(f"[bold green]Detected JS library: {library}[/bold green]")
    
    def detect_analytics(self, html_content, soup):
        """Detect analytics tools used by the website.
        
        Args:
            html_content (str): HTML content of the page.
            soup (BeautifulSoup): Parsed HTML.
        """
        # Check for analytics tool indicators
        for tool, signatures in self.signatures['analytics'].items():
            html_patterns = signatures.get('html', [])
            for pattern in html_patterns:
                if pattern.lower() in html_content.lower():
                    if tool not in self.results['analytics']:
                        self.results['analytics'].append(tool)
                        self.results['technologies'].append(tool)
                        if self.debug:
                            console.print(f"[bold green]Detected analytics tool: {tool}[/bold green]")
    
    def detect_cdn(self, headers, html_content):
        """Detect Content Delivery Networks (CDNs) used by the website.
        
        Args:
            headers (dict): HTTP response headers.
            html_content (str): HTML content of the page.
        """
        # Check for CDN indicators
        for cdn, signatures in self.signatures['cdn'].items():
            # Check HTML indicators
            html_patterns = signatures.get('html', [])
            for pattern in html_patterns:
                if pattern.lower() in html_content.lower():
                    if cdn not in self.results['cdn']:
                        self.results['cdn'].append(cdn)
                        self.results['technologies'].append(cdn)
                        if self.debug:
                            console.print(f"[bold green]Detected CDN: {cdn}[/bold green]")
            
            # Check header indicators
            cdn_headers = signatures.get('headers', {})
            for header, value in cdn_headers.items():
                if header in headers and (value == "" or value.lower() in headers[header].lower()):
                    if cdn not in self.results['cdn']:
                        self.results['cdn'].append(cdn)
                        self.results['technologies'].append(cdn)
                        if self.debug:
                            console.print(f"[bold green]Detected CDN: {cdn}[/bold green]")
    
    def detect_other_technologies(self, headers, html_content, soup):
        """Detect other technologies used by the website.
        
        Args:
            headers (dict): HTTP response headers.
            html_content (str): HTML content of the page.
            soup (BeautifulSoup): Parsed HTML.
        """
        # Check for specific technologies not covered by other methods
        
        # Check for AJAX
        if "XMLHttpRequest" in html_content:
            self.results['technologies'].append("AJAX")
        
        # Check for JSON
        if "application/json" in html_content:
            self.results['technologies'].append("JSON")
        
        # Check for PWA
        if soup.find('link', attrs={'rel': 'manifest'}):
            self.results['technologies'].append("Progressive Web App (PWA)")
        
        # Check for service workers
        if "serviceWorker" in html_content:
            self.results['technologies'].append("Service Worker")
        
        # Check for WebSockets
        if "WebSocket" in html_content:
            self.results['technologies'].append("WebSockets")
        
        # Check for GraphQL
        if "graphql" in html_content.lower():
            self.results['technologies'].append("GraphQL")
    
    def run(self):
        """Run the technology scan."""
        console.print("[bold blue]Starting technology scan...[/bold blue]")
        
        # Scan for technologies
        self.scan_technologies()
        
        # Remove duplicates from technologies list
        self.results['technologies'] = list(set(self.results['technologies']))
        
        console.print(f"[bold green]Technology scan completed for {self.url}[/bold green]")
        return self.results 