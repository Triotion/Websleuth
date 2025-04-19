#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSL/TLS Checker Module for WebSleuth
"""

import socket
import ssl
import datetime
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table

console = Console()

class SSLChecker:
    """Class for checking SSL/TLS configuration of a target website."""
    
    def __init__(self, url, timeout=30, debug=False):
        """Initialize the SSLChecker class.
        
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
            self.domain, self.port = self.domain.split(":")
            self.port = int(self.port)
        else:
            self.port = 443  # Default HTTPS port
        
        self.results = {
            "url": self.url,
            "domain": self.domain,
            "certificate": {},
            "protocols": [],
            "cipher_suites": [],
            "vulnerabilities": [],
            "grade": "Unknown"
        }
        
        # SSL/TLS protocol versions to check
        self.protocol_versions = [
            ("TLSv1.3", ssl.PROTOCOL_TLS),
            ("TLSv1.2", ssl.PROTOCOL_TLSv1_2),
            ("TLSv1.1", ssl.PROTOCOL_TLSv1_1),
            ("TLSv1.0", ssl.PROTOCOL_TLSv1),
            ("SSLv3", ssl.PROTOCOL_SSLv23)
        ]
        
        # Known vulnerabilities to check
        self.vulnerability_checks = {
            "BEAST": self.check_beast,
            "POODLE": self.check_poodle,
            "DROWN": self.check_drown,
            "Heartbleed": self.check_heartbleed,
            "FREAK": self.check_freak,
            "Logjam": self.check_logjam
        }
    
    def check_certificate(self):
        """Check the SSL certificate of the target website."""
        try:
            context = ssl.create_default_context()
            
            # Connect to the server
            with socket.create_connection((self.domain, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    # Get certificate in DER format
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    # Get certificate details
                    subject = cert.subject
                    issuer = cert.issuer
                    not_before = cert.not_valid_before
                    not_after = cert.not_valid_after
                    serial_number = cert.serial_number
                    
                    # Parse subject and issuer
                    subject_str = self._parse_x509_name(subject)
                    issuer_str = self._parse_x509_name(issuer)
                    
                    # Parse SANs (Subject Alternative Names)
                    sans = []
                    for ext in cert.extensions:
                        if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                            sans = ext.value.get_values_for_type(x509.DNSName)
                    
                    # Store certificate details
                    self.results["certificate"] = {
                        "subject": subject_str,
                        "issuer": issuer_str,
                        "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S"),
                        "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S"),
                        "serial_number": hex(serial_number),
                        "sans": sans,
                        "is_expired": datetime.datetime.now() > not_after,
                        "days_left": (not_after - datetime.datetime.now()).days
                    }
                    
                    if self.debug:
                        console.print(f"[bold green]Certificate issuer: {issuer_str}[/bold green]")
                        console.print(f"[bold green]Certificate valid until: {not_after.strftime('%Y-%m-%d')}[/bold green]")
                        
                        if self.results["certificate"]["is_expired"]:
                            console.print(f"[bold red]Certificate is expired![/bold red]")
                        elif self.results["certificate"]["days_left"] < 30:
                            console.print(f"[bold yellow]Certificate expires soon! Days left: {self.results['certificate']['days_left']}[/bold yellow]")
        
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error checking certificate: {str(e)}[/bold red]")
            self.results["certificate"] = {"error": str(e)}
    
    def _parse_x509_name(self, name):
        """Parse X509Name object to string.
        
        Args:
            name: X509Name object.
            
        Returns:
            str: String representation of X509Name.
        """
        result = {}
        
        for attribute in name:
            oid = attribute.oid
            if oid == x509.oid.NameOID.COMMON_NAME:
                result["CN"] = attribute.value
            elif oid == x509.oid.NameOID.ORGANIZATION_NAME:
                result["O"] = attribute.value
            elif oid == x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME:
                result["OU"] = attribute.value
            elif oid == x509.oid.NameOID.COUNTRY_NAME:
                result["C"] = attribute.value
            elif oid == x509.oid.NameOID.STATE_OR_PROVINCE_NAME:
                result["ST"] = attribute.value
            elif oid == x509.oid.NameOID.LOCALITY_NAME:
                result["L"] = attribute.value
        
        # Format as string
        parts = []
        for key, value in result.items():
            parts.append(f"{key}={value}")
        
        return ", ".join(parts)
    
    def check_protocols(self):
        """Check supported SSL/TLS protocols."""
        for protocol_name, protocol in self.protocol_versions:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.domain, self.port), timeout=self.timeout) as sock:
                    try:
                        with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                            version = ssock.version()
                            self.results["protocols"].append({
                                "name": protocol_name,
                                "version": version,
                                "enabled": True
                            })
                            
                            if self.debug:
                                console.print(f"[bold green]Protocol {protocol_name} ({version}) is supported[/bold green]")
                    except ssl.SSLError:
                        # Protocol not supported
                        self.results["protocols"].append({
                            "name": protocol_name,
                            "enabled": False
                        })
                        
                        if self.debug:
                            console.print(f"[bold yellow]Protocol {protocol_name} is not supported[/bold yellow]")
                    except Exception as e:
                        if self.debug:
                            console.print(f"[bold red]Error checking protocol {protocol_name}: {str(e)}[/bold red]")
            
            except Exception as e:
                if self.debug:
                    console.print(f"[bold red]Error creating context for {protocol_name}: {str(e)}[/bold red]")
    
    def check_cipher_suites(self):
        """Check supported cipher suites."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.domain, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cipher = ssock.cipher()
                    
                    self.results["cipher_suites"].append({
                        "name": cipher[0],
                        "version": cipher[1],
                        "bits": cipher[2],
                        "current": True
                    })
                    
                    if self.debug:
                        console.print(f"[bold green]Current cipher: {cipher[0]} - {cipher[1]} ({cipher[2]} bits)[/bold green]")
        
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error checking cipher suites: {str(e)}[/bold red]")
    
    def check_vulnerabilities(self):
        """Check for common SSL/TLS vulnerabilities."""
        for vuln_name, check_func in self.vulnerability_checks.items():
            try:
                is_vulnerable, details = check_func()
                
                if is_vulnerable:
                    self.results["vulnerabilities"].append({
                        "name": vuln_name,
                        "vulnerable": True,
                        "details": details
                    })
                    
                    if self.debug:
                        console.print(f"[bold red]Vulnerable to {vuln_name}: {details}[/bold red]")
                else:
                    if self.debug:
                        console.print(f"[bold green]Not vulnerable to {vuln_name}[/bold green]")
            
            except Exception as e:
                if self.debug:
                    console.print(f"[bold red]Error checking {vuln_name} vulnerability: {str(e)}[/bold red]")
    
    def check_beast(self):
        """Check for BEAST vulnerability (CBC in TLS 1.0)."""
        for protocol in self.results["protocols"]:
            if protocol.get("name") in ["TLSv1.0"] and protocol.get("enabled"):
                return True, "TLS 1.0 is enabled which may be vulnerable to BEAST attack"
        
        return False, ""
    
    def check_poodle(self):
        """Check for POODLE vulnerability (SSLv3)."""
        for protocol in self.results["protocols"]:
            if protocol.get("name") in ["SSLv3"] and protocol.get("enabled"):
                return True, "SSLv3 is enabled which is vulnerable to POODLE attack"
        
        return False, ""
    
    def check_drown(self):
        """Check for DROWN vulnerability (SSLv2)."""
        # This is a simplified check, real check would be more complex
        for protocol in self.results["protocols"]:
            if protocol.get("name") == "SSLv2" and protocol.get("enabled"):
                return True, "SSLv2 is enabled which is vulnerable to DROWN attack"
        
        return False, ""
    
    def check_heartbleed(self):
        """Check for Heartbleed vulnerability."""
        # Simplified check based on OpenSSL version
        # A real check would send a malformed heartbeat request
        for cipher in self.results["cipher_suites"]:
            if "openssl" in cipher.get("name", "").lower() and "1.0.1" in cipher.get("version", ""):
                return True, "OpenSSL version may be vulnerable to Heartbleed"
        
        return False, ""
    
    def check_freak(self):
        """Check for FREAK vulnerability (weak export ciphers)."""
        for cipher in self.results["cipher_suites"]:
            if "export" in cipher.get("name", "").lower():
                return True, "Export cipher suites are enabled which are vulnerable to FREAK attack"
        
        return False, ""
    
    def check_logjam(self):
        """Check for Logjam vulnerability (weak DH key exchange)."""
        for cipher in self.results["cipher_suites"]:
            if "dhe_export" in cipher.get("name", "").lower():
                return True, "DHE export ciphers are enabled which are vulnerable to Logjam attack"
        
        return False, ""
    
    def calculate_grade(self):
        """Calculate security grade based on findings."""
        grade = "A+"
        vulns = len(self.results["vulnerabilities"])
        
        # Check certificate
        cert = self.results.get("certificate", {})
        if cert.get("is_expired", False):
            grade = "F"
        elif cert.get("days_left", 0) < 30:
            grade = "C" if grade in ["A+", "A", "B"] else grade
        
        # Check protocols
        for protocol in self.results.get("protocols", []):
            if protocol.get("name") == "SSLv3" and protocol.get("enabled"):
                grade = "F"
            elif protocol.get("name") == "TLSv1.0" and protocol.get("enabled"):
                grade = "C" if grade in ["A+", "A", "B"] else grade
            elif protocol.get("name") == "TLSv1.1" and protocol.get("enabled"):
                grade = "B" if grade in ["A+", "A"] else grade
        
        # Check vulnerabilities
        if vulns > 0:
            if vulns >= 3:
                grade = "F"
            elif vulns == 2:
                grade = "D" if grade in ["A+", "A", "B", "C"] else grade
            else:
                grade = "C" if grade in ["A+", "A", "B"] else grade
        
        self.results["grade"] = grade
    
    def print_report(self):
        """Print a summary of findings to the console."""
        console.print("\n[bold blue]SSL/TLS Security Report[/bold blue]")
        
        # Print certificate info
        cert = self.results.get("certificate", {})
        if "error" in cert:
            console.print(f"[bold red]Certificate Error: {cert['error']}[/bold red]")
        else:
            console.print(f"[bold]Certificate Issuer:[/bold] {cert.get('issuer', 'Unknown')}")
            console.print(f"[bold]Valid Until:[/bold] {cert.get('not_after', 'Unknown')}")
            
            if cert.get("is_expired", False):
                console.print("[bold red]Certificate is EXPIRED![/bold red]")
            elif cert.get("days_left", 0) < 30:
                console.print(f"[bold yellow]Certificate expires soon! Days left: {cert.get('days_left', 0)}[/bold yellow]")
        
        # Print supported protocols
        protocol_table = Table(title="Supported Protocols")
        protocol_table.add_column("Protocol", style="cyan")
        protocol_table.add_column("Supported", style="green")
        
        for protocol in self.results.get("protocols", []):
            status = "✅" if protocol.get("enabled", False) else "❌"
            color = "green" if status == "✅" and protocol.get("name") not in ["SSLv3", "TLSv1.0"] else "red"
            protocol_table.add_row(protocol.get("name", "Unknown"), f"[{color}]{status}[/{color}]")
        
        console.print(protocol_table)
        
        # Print vulnerabilities
        if self.results.get("vulnerabilities", []):
            console.print("\n[bold red]Vulnerabilities Detected:[/bold red]")
            
            for vuln in self.results["vulnerabilities"]:
                console.print(f"[bold red]● {vuln['name']}:[/bold red] {vuln['details']}")
        else:
            console.print("\n[bold green]No vulnerabilities detected.[/bold green]")
        
        # Print overall grade
        grade = self.results.get("grade", "Unknown")
        grade_color = "green" if grade in ["A+", "A"] else "yellow" if grade in ["B"] else "red"
        console.print(f"\n[bold]Overall Grade:[/bold] [{grade_color}]{grade}[/{grade_color}]")
    
    def run(self):
        """Run SSL/TLS checks."""
        console.print("[bold blue]Starting SSL/TLS checks...[/bold blue]")
        
        # Run all checks
        self.check_certificate()
        self.check_protocols()
        self.check_cipher_suites()
        self.check_vulnerabilities()
        self.calculate_grade()
        
        if self.debug:
            self.print_report()
        
        console.print(f"[bold green]SSL/TLS checks completed for {self.url}[/bold green]")
        return self.results 