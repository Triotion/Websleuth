#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Security Headers Analyzer Module for WebSleuth
"""

import requests
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table

console = Console()

class SecurityHeadersAnalyzer:
    """Class for analyzing security headers of a target website."""
    
    def __init__(self, url, timeout=30, debug=False):
        """Initialize the SecurityHeadersAnalyzer class.
        
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
        
        self.security_headers = {
            "Strict-Transport-Security": {
                "description": "HTTP Strict Transport Security (HSTS) forces browsers to use HTTPS on the domain.",
                "recommended": "max-age=31536000; includeSubDomains; preload",
                "severity": "high"
            },
            "Content-Security-Policy": {
                "description": "Content Security Policy (CSP) prevents cross-site scripting (XSS) and other code injection attacks.",
                "recommended": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'; upgrade-insecure-requests;",
                "severity": "high"
            },
            "X-Content-Type-Options": {
                "description": "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
                "recommended": "nosniff",
                "severity": "medium"
            },
            "X-Frame-Options": {
                "description": "Protects against clickjacking by controlling whether a browser is allowed to render a page in a <frame> or <iframe>.",
                "recommended": "SAMEORIGIN",
                "severity": "medium"
            },
            "X-XSS-Protection": {
                "description": "Enables the cross-site scripting (XSS) filter in browsers. Note: Modern browsers phasing this out in favor of CSP.",
                "recommended": "1; mode=block",
                "severity": "low"
            },
            "Referrer-Policy": {
                "description": "Controls what information is included with cross-origin requests.",
                "recommended": "strict-origin-when-cross-origin",
                "severity": "medium"
            },
            "Permissions-Policy": {
                "description": "Controls which browser features and APIs can be used on a site. (Formerly Feature-Policy)",
                "recommended": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
                "severity": "medium"
            },
            "Cache-Control": {
                "description": "Directives for caching mechanisms to prevent sensitive information from being cached.",
                "recommended": "no-store, max-age=0",
                "severity": "low"
            },
            "Cross-Origin-Embedder-Policy": {
                "description": "Prevents loading any cross-origin resources that don't explicitly grant permission.",
                "recommended": "require-corp",
                "severity": "medium"
            },
            "Cross-Origin-Opener-Policy": {
                "description": "Prevents opening cross-origin pages in the same process.",
                "recommended": "same-origin",
                "severity": "medium"
            },
            "Cross-Origin-Resource-Policy": {
                "description": "Prevents other domains from reading the response.",
                "recommended": "same-origin",
                "severity": "medium"
            }
        }
        
        # Legacy and deprecated headers, still check for them
        self.legacy_headers = {
            "X-Content-Security-Policy": {
                "description": "Legacy header for Content-Security-Policy.",
                "recommended": "Use Content-Security-Policy instead",
                "severity": "low"
            },
            "X-WebKit-CSP": {
                "description": "Legacy header for Content-Security-Policy in WebKit browsers.",
                "recommended": "Use Content-Security-Policy instead",
                "severity": "low"
            },
            "Public-Key-Pins": {
                "description": "Deprecated. HTTP Public Key Pinning (HPKP) prevents fraudulent certificates for a website.",
                "recommended": "Deprecated, use Certificate Transparency instead",
                "severity": "low"
            },
            "Expect-CT": {
                "description": "Expect Certificate Transparency (CT) header, used to detect fraudulent certificates.",
                "recommended": "max-age=86400, enforce",
                "severity": "low"
            }
        }
        
        self.results = {
            "url": self.url,
            "headers_present": {},
            "headers_missing": {},
            "headers_invalid": {},
            "score": 0,
            "max_score": 0,
            "grade": "F",
            "summary": ""
        }
    
    def analyze_headers(self):
        """Analyze the security headers of the target website."""
        try:
            # Set up custom headers for the request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # Make the request
            response = requests.head(self.url, headers=headers, timeout=self.timeout, allow_redirects=True)
            
            # If HEAD request doesn't return headers, try a GET request
            if len(response.headers) < 4:  # Arbitrary low number to check if we got enough headers
                response = requests.get(self.url, headers=headers, timeout=self.timeout, allow_redirects=True)
            
            if self.debug:
                console.print(f"[bold green]Retrieved HTTP headers from {self.url}[/bold green]")
            
            # Analyze security headers
            self.check_security_headers(response.headers)
            
            # Analyze legacy headers
            self.check_legacy_headers(response.headers)
            
            # Calculate score and grade
            self.calculate_score()
            
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error analyzing security headers: {str(e)}[/bold red]")
    
    def check_security_headers(self, headers):
        """Check for the presence of security headers.
        
        Args:
            headers (dict): HTTP response headers.
        """
        # For each security header, check if it's present and has a recommended value
        for header, info in self.security_headers.items():
            # Check if header is present (case-insensitive)
            header_present = False
            header_value = None
            
            for response_header, value in headers.items():
                if response_header.lower() == header.lower():
                    header_present = True
                    header_value = value
                    break
            
            if header_present:
                self.results["headers_present"][header] = {
                    "value": header_value,
                    "description": info["description"],
                    "recommended": info["recommended"],
                    "severity": info["severity"]
                }
                
                # Check if header has a valid value
                if self.is_header_valid(header, header_value):
                    if self.debug:
                        console.print(f"[bold green]✅ {header}: {header_value}[/bold green]")
                else:
                    self.results["headers_invalid"][header] = {
                        "value": header_value,
                        "description": info["description"],
                        "recommended": info["recommended"],
                        "severity": info["severity"]
                    }
                    if self.debug:
                        console.print(f"[bold yellow]⚠️ {header}: {header_value} (Invalid value)[/bold yellow]")
            else:
                self.results["headers_missing"][header] = {
                    "description": info["description"],
                    "recommended": info["recommended"],
                    "severity": info["severity"]
                }
                if self.debug:
                    console.print(f"[bold red]❌ {header}: Missing[/bold red]")
    
    def check_legacy_headers(self, headers):
        """Check for the presence of legacy headers.
        
        Args:
            headers (dict): HTTP response headers.
        """
        # For each legacy header, check if it's present
        for header, info in self.legacy_headers.items():
            # Check if header is present (case-insensitive)
            header_present = False
            header_value = None
            
            for response_header, value in headers.items():
                if response_header.lower() == header.lower():
                    header_present = True
                    header_value = value
                    break
            
            if header_present:
                self.results["headers_present"][header] = {
                    "value": header_value,
                    "description": info["description"],
                    "recommended": info["recommended"],
                    "severity": info["severity"],
                    "legacy": True
                }
                
                if self.debug:
                    console.print(f"[bold yellow]ℹ️ {header}: {header_value} (Legacy header)[/bold yellow]")
    
    def is_header_valid(self, header, value):
        """Check if a header has a valid value.
        
        Args:
            header (str): Header name.
            value (str): Header value.
            
        Returns:
            bool: True if the header value is valid, False otherwise.
        """
        # Basic validation for some headers
        if header == "Strict-Transport-Security":
            return "max-age=" in value.lower()
        
        elif header == "Content-Security-Policy":
            # Any CSP is better than none, but should at least have default-src or script-src
            return "default-src" in value.lower() or "script-src" in value.lower()
        
        elif header == "X-Content-Type-Options":
            return value.lower() == "nosniff"
        
        elif header == "X-Frame-Options":
            return value.upper() in ["DENY", "SAMEORIGIN"]
        
        elif header == "X-XSS-Protection":
            return "1" in value
        
        elif header == "Referrer-Policy":
            valid_values = [
                "no-referrer", "no-referrer-when-downgrade", "origin",
                "origin-when-cross-origin", "same-origin", "strict-origin",
                "strict-origin-when-cross-origin", "unsafe-url"
            ]
            return any(val in value.lower() for val in valid_values)
        
        # For other headers, any value is considered valid
        return True
    
    def calculate_score(self):
        """Calculate the security headers score and grade."""
        score = 0
        max_score = 0
        
        # Calculate score based on present, missing, and invalid headers
        for header, info in self.security_headers.items():
            if info["severity"] == "high":
                weight = 3
            elif info["severity"] == "medium":
                weight = 2
            else:  # low
                weight = 1
            
            max_score += weight
            
            if header in self.results["headers_present"] and header not in self.results["headers_invalid"]:
                score += weight
        
        # Calculate score as a percentage
        score_percentage = (score / max_score) * 100 if max_score > 0 else 0
        
        # Determine grade based on score
        if score_percentage >= 90:
            grade = "A+"
        elif score_percentage >= 80:
            grade = "A"
        elif score_percentage >= 70:
            grade = "B"
        elif score_percentage >= 60:
            grade = "C"
        elif score_percentage >= 50:
            grade = "D"
        else:
            grade = "F"
        
        # Generate summary
        missing_high_severity = [header for header in self.results["headers_missing"] 
                                if self.security_headers[header]["severity"] == "high"]
        invalid_high_severity = [header for header in self.results["headers_invalid"] 
                               if self.security_headers[header]["severity"] == "high"]
        
        summary = f"Overall security headers score: {score_percentage:.1f}% ({grade}). "
        
        if missing_high_severity or invalid_high_severity:
            summary += "Critical issues found: "
            if missing_high_severity:
                summary += f"Missing {', '.join(missing_high_severity)}. "
            if invalid_high_severity:
                summary += f"Invalid {', '.join(invalid_high_severity)}. "
        else:
            summary += "No critical security header issues found."
        
        # Store results
        self.results["score"] = score_percentage
        self.results["max_score"] = max_score
        self.results["grade"] = grade
        self.results["summary"] = summary
    
    def print_report(self):
        """Print a report of the security headers analysis."""
        # Create table for present headers
        if self.results["headers_present"]:
            console.print("\n[bold green]Present Security Headers:[/bold green]")
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Header")
            table.add_column("Value")
            table.add_column("Status")
            
            for header, info in self.results["headers_present"].items():
                if header in self.results["headers_invalid"]:
                    status = "⚠️ Invalid"
                    style = "yellow"
                else:
                    status = "✅ Valid"
                    style = "green"
                
                table.add_row(header, info["value"], status, style=style)
            
            console.print(table)
        
        # Create table for missing headers
        if self.results["headers_missing"]:
            console.print("\n[bold red]Missing Security Headers:[/bold red]")
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Header")
            table.add_column("Severity")
            table.add_column("Recommended Value")
            
            for header, info in self.results["headers_missing"].items():
                severity = info["severity"]
                if severity == "high":
                    style = "red"
                elif severity == "medium":
                    style = "yellow"
                else:
                    style = "blue"
                
                table.add_row(header, severity.upper(), info["recommended"], style=style)
            
            console.print(table)
        
        # Print score and grade
        console.print(f"\n[bold]Security Headers Score: {self.results['score']:.1f}% (Grade: {self.results['grade']})[/bold]")
        console.print(f"[italic]{self.results['summary']}[/italic]")
    
    def run(self):
        """Run the security headers analysis."""
        console.print("[bold blue]Starting security headers analysis...[/bold blue]")
        
        # Analyze headers
        self.analyze_headers()
        
        # Print report if in debug mode
        if self.debug:
            self.print_report()
        
        console.print(f"[bold green]Security headers analysis completed for {self.url}[/bold green]")
        return self.results 