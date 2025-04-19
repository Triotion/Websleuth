#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS Security Scanner Module for WebSleuth
"""

import socket
import dns.resolver
import dns.name
import dns.dnssec
import dns.query
import dns.exception
import dns.message
import dns.rdatatype
import concurrent.futures
from urllib.parse import urlparse
from rich.console import Console

console = Console()

class DNSSecurityScanner:
    """Class for scanning DNS security configurations of a target domain."""
    
    def __init__(self, url, timeout=30, debug=False):
        """Initialize the DNSSecurityScanner class.
        
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
        
        # Public DNS resolvers for testing
        self.dns_resolvers = [
            "8.8.8.8",       # Google
            "1.1.1.1",       # Cloudflare
            "9.9.9.9",       # Quad9
            "208.67.222.222" # OpenDNS
        ]
        
        self.results = {
            "domain": self.domain,
            "dns_records": {},
            "dnssec": {
                "enabled": False,
                "validated": False,
                "validation_errors": []
            },
            "caa_records": [],
            "has_caa": False,
            "zone_transfer": {
                "vulnerable": False,
                "servers": [],
                "records": []
            },
            "spf_record": {
                "exists": False,
                "record": "",
                "valid": False,
                "issues": []
            },
            "dmarc_record": {
                "exists": False,
                "record": "",
                "valid": False,
                "issues": []
            },
            "dkim_records": [],
            "overall_score": 0,
            "recommendations": []
        }
    
    def check_dns_records(self):
        """Check various DNS records for the domain."""
        try:
            # Check A records
            try:
                a_records = dns.resolver.resolve(self.domain, 'A')
                self.results["dns_records"]["A"] = [record.to_text() for record in a_records]
                if self.debug:
                    console.print(f"[green]Found A records: {', '.join(self.results['dns_records']['A'])}[/green]")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                self.results["dns_records"]["A"] = []
                if self.debug:
                    console.print(f"[yellow]No A records found: {str(e)}[/yellow]")
            
            # Check AAAA records (IPv6)
            try:
                aaaa_records = dns.resolver.resolve(self.domain, 'AAAA')
                self.results["dns_records"]["AAAA"] = [record.to_text() for record in aaaa_records]
                if self.debug:
                    console.print(f"[green]Found AAAA records: {', '.join(self.results['dns_records']['AAAA'])}[/green]")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                self.results["dns_records"]["AAAA"] = []
                if self.debug:
                    console.print(f"[yellow]No AAAA records found: {str(e)}[/yellow]")
            
            # Check MX records
            try:
                mx_records = dns.resolver.resolve(self.domain, 'MX')
                self.results["dns_records"]["MX"] = [record.to_text() for record in mx_records]
                if self.debug:
                    console.print(f"[green]Found MX records: {', '.join(self.results['dns_records']['MX'])}[/green]")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                self.results["dns_records"]["MX"] = []
                if self.debug:
                    console.print(f"[yellow]No MX records found: {str(e)}[/yellow]")
            
            # Check NS records
            try:
                ns_records = dns.resolver.resolve(self.domain, 'NS')
                self.results["dns_records"]["NS"] = [record.to_text() for record in ns_records]
                if self.debug:
                    console.print(f"[green]Found NS records: {', '.join(self.results['dns_records']['NS'])}[/green]")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                self.results["dns_records"]["NS"] = []
                if self.debug:
                    console.print(f"[yellow]No NS records found: {str(e)}[/yellow]")
            
            # Check TXT records
            try:
                txt_records = dns.resolver.resolve(self.domain, 'TXT')
                self.results["dns_records"]["TXT"] = [record.to_text().strip('"') for record in txt_records]
                if self.debug:
                    console.print(f"[green]Found TXT records: {', '.join(self.results['dns_records']['TXT'])}[/green]")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                self.results["dns_records"]["TXT"] = []
                if self.debug:
                    console.print(f"[yellow]No TXT records found: {str(e)}[/yellow]")
            
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error checking DNS records: {str(e)}[/bold red]")
    
    def check_dnssec(self):
        """Check DNSSEC configuration for the domain."""
        try:
            # Check for DNSKEY records (indicates DNSSEC is enabled)
            try:
                dnskey_records = dns.resolver.resolve(self.domain, 'DNSKEY')
                self.results["dnssec"]["enabled"] = True
                self.results["dns_records"]["DNSKEY"] = [record.to_text() for record in dnskey_records]
                if self.debug:
                    console.print(f"[bold green]DNSSEC is enabled for {self.domain}[/bold green]")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                self.results["dnssec"]["enabled"] = False
                self.results["dns_records"]["DNSKEY"] = []
                if self.debug:
                    console.print(f"[yellow]DNSSEC is not enabled for {self.domain}: {str(e)}[/yellow]")
                
                # Add recommendation for DNSSEC
                self.results["recommendations"].append({
                    "title": "Enable DNSSEC",
                    "description": "DNSSEC provides authentication of DNS records to prevent DNS spoofing attacks.",
                    "severity": "medium"
                })
            
            # Check for DS records (used to create a chain of trust)
            try:
                parent_domain = ".".join(self.domain.split(".")[-2:])
                ds_records = dns.resolver.resolve(self.domain, 'DS')
                self.results["dns_records"]["DS"] = [record.to_text() for record in ds_records]
                if self.debug:
                    console.print(f"[green]Found DS records: {', '.join(self.results['dns_records']['DS'])}[/green]")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                self.results["dns_records"]["DS"] = []
                if self.debug:
                    console.print(f"[yellow]No DS records found: {str(e)}[/yellow]")
            
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error checking DNSSEC: {str(e)}[/bold red]")
    
    def check_caa_records(self):
        """Check CAA (Certificate Authority Authorization) records."""
        try:
            try:
                caa_records = dns.resolver.resolve(self.domain, 'CAA')
                self.results["caa_records"] = [record.to_text() for record in caa_records]
                self.results["has_caa"] = True
                if self.debug:
                    console.print(f"[bold green]Found CAA records: {', '.join(self.results['caa_records'])}[/bold green]")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                self.results["caa_records"] = []
                self.results["has_caa"] = False
                if self.debug:
                    console.print(f"[yellow]No CAA records found: {str(e)}[/yellow]")
                
                # Add recommendation for CAA
                self.results["recommendations"].append({
                    "title": "Add CAA Records",
                    "description": "CAA records specify which Certificate Authorities are allowed to issue certificates for your domain.",
                    "severity": "low"
                })
            
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error checking CAA records: {str(e)}[/bold red]")
    
    def check_zone_transfer(self):
        """Check if zone transfers are allowed (potential security issue)."""
        try:
            # First get the NS records
            if not self.results["dns_records"].get("NS"):
                self.check_dns_records()
            
            nameservers = self.results["dns_records"].get("NS", [])
            
            for ns in nameservers:
                try:
                    # Try zone transfer (AXFR query)
                    z = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, timeout=self.timeout))
                    
                    # If we get here, zone transfer was successful (security issue)
                    self.results["zone_transfer"]["vulnerable"] = True
                    self.results["zone_transfer"]["servers"].append(ns)
                    
                    # Extract records from the zone
                    records = []
                    for name, node in z.nodes.items():
                        for rdataset in node.rdatasets:
                            records.append(f"{name} {rdataset.ttl} {dns.rdataclass.to_text(rdataset.rdclass)} {dns.rdatatype.to_text(rdataset.rdtype)} {rdataset[0]}")
                    
                    self.results["zone_transfer"]["records"] = records[:100]  # Limit to first 100 records
                    
                    if self.debug:
                        console.print(f"[bold red]Zone transfer successful from {ns}! This is a security issue.[/bold red]")
                    
                    # Add critical recommendation
                    self.results["recommendations"].append({
                        "title": "Disable Zone Transfers",
                        "description": f"Zone transfers are allowed from {ns}. This can expose all DNS records to attackers.",
                        "severity": "critical"
                    })
                    
                except Exception as e:
                    # Zone transfer failed (good)
                    if self.debug:
                        console.print(f"[green]Zone transfer not allowed from {ns} (This is good)[/green]")
            
        except Exception as e:
            if self.debug:
                console.print(f"[bold yellow]Error checking zone transfers: {str(e)}[/bold yellow]")
    
    def check_spf_record(self):
        """Check SPF (Sender Policy Framework) record configuration."""
        try:
            # Check TXT records for SPF
            if not self.results["dns_records"].get("TXT"):
                self.check_dns_records()
            
            txt_records = self.results["dns_records"].get("TXT", [])
            
            # Look for SPF record
            spf_records = [r for r in txt_records if r.startswith("v=spf1")]
            
            if spf_records:
                self.results["spf_record"]["exists"] = True
                self.results["spf_record"]["record"] = spf_records[0]
                
                # Basic SPF validation
                spf_record = spf_records[0]
                
                # Check for potential issues
                issues = []
                
                # Check for multiple SPF records
                if len(spf_records) > 1:
                    issues.append("Multiple SPF records found. Only one should exist.")
                
                # Check for missing all mechanism
                if not any(m in spf_record for m in [" -all", " ~all", " ?all", " +all"]):
                    issues.append("SPF record is missing the 'all' mechanism.")
                
                # Check for overly permissive all
                if " +all" in spf_record:
                    issues.append("SPF record uses '+all' which allows any server to send mail. Use '-all' instead.")
                
                # Check for potentially excessive DNS lookups
                lookup_mechanisms = [m for m in spf_record.split() if any(p in m for p in ["include:", "a:", "mx:", "ptr:", "exists:"])]
                if len(lookup_mechanisms) > 10:
                    issues.append("SPF record may exceed the 10 DNS lookup limit.")
                
                self.results["spf_record"]["issues"] = issues
                self.results["spf_record"]["valid"] = len(issues) == 0
                
                if self.debug:
                    if issues:
                        console.print(f"[yellow]SPF record found with issues: {'; '.join(issues)}[/yellow]")
                    else:
                        console.print(f"[green]Valid SPF record found: {spf_record}[/green]")
                
                # Add recommendations for SPF issues
                if issues:
                    self.results["recommendations"].append({
                        "title": "Fix SPF Record Issues",
                        "description": f"Your SPF record has issues: {'; '.join(issues)}",
                        "severity": "medium"
                    })
            else:
                self.results["spf_record"]["exists"] = False
                
                if self.debug:
                    console.print("[yellow]No SPF record found[/yellow]")
                
                # Add recommendation to create SPF
                self.results["recommendations"].append({
                    "title": "Add SPF Record",
                    "description": "SPF records help prevent email spoofing. Create a record with 'v=spf1 <authorized_sources> -all'",
                    "severity": "medium"
                })
            
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error checking SPF record: {str(e)}[/bold red]")
    
    def check_dmarc_record(self):
        """Check DMARC (Domain-based Message Authentication) configuration."""
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            
            try:
                dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
                dmarc_txt_records = [record.to_text().strip('"') for record in dmarc_records]
                
                # Look for DMARC record
                dmarc_records = [r for r in dmarc_txt_records if r.startswith("v=DMARC1")]
                
                if dmarc_records:
                    self.results["dmarc_record"]["exists"] = True
                    self.results["dmarc_record"]["record"] = dmarc_records[0]
                    
                    # Basic DMARC validation
                    dmarc_record = dmarc_records[0]
                    
                    # Check for potential issues
                    issues = []
                    
                    # Check for multiple DMARC records
                    if len(dmarc_records) > 1:
                        issues.append("Multiple DMARC records found. Only one should exist.")
                    
                    # Check for missing required tags
                    if "p=" not in dmarc_record:
                        issues.append("DMARC record is missing the required 'p' (policy) tag.")
                    
                    # Check for potentially weak policy
                    if "p=none" in dmarc_record:
                        issues.append("DMARC policy is set to 'none'. Consider using 'quarantine' or 'reject' for better protection.")
                    
                    # Check for missing or low reporting percentage
                    if "pct=" not in dmarc_record:
                        issues.append("DMARC record is missing the 'pct' tag. Default is 100%.")
                    elif any(p in dmarc_record for p in ["pct=1", "pct=5", "pct=10"]):
                        issues.append("DMARC percentage is set very low. Consider increasing for better protection.")
                    
                    # Check for missing reporting
                    if "rua=" not in dmarc_record and "ruf=" not in dmarc_record:
                        issues.append("DMARC record doesn't specify any reporting mechanisms (rua or ruf).")
                    
                    self.results["dmarc_record"]["issues"] = issues
                    self.results["dmarc_record"]["valid"] = len(issues) == 0
                    
                    if self.debug:
                        if issues:
                            console.print(f"[yellow]DMARC record found with issues: {'; '.join(issues)}[/yellow]")
                        else:
                            console.print(f"[green]Valid DMARC record found: {dmarc_record}[/green]")
                    
                    # Add recommendations for DMARC issues
                    if issues:
                        self.results["recommendations"].append({
                            "title": "Fix DMARC Record Issues",
                            "description": f"Your DMARC record has issues: {'; '.join(issues)}",
                            "severity": "medium"
                        })
                
                else:
                    self.results["dmarc_record"]["exists"] = False
                    
                    if self.debug:
                        console.print("[yellow]No DMARC record found[/yellow]")
                    
                    # Add recommendation to create DMARC
                    self.results["recommendations"].append({
                        "title": "Add DMARC Record",
                        "description": "DMARC helps prevent email spoofing and provides reporting. Create a _dmarc TXT record.",
                        "severity": "medium"
                    })
                
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                self.results["dmarc_record"]["exists"] = False
                
                if self.debug:
                    console.print(f"[yellow]No DMARC record found: {str(e)}[/yellow]")
                
                # Add recommendation to create DMARC
                self.results["recommendations"].append({
                    "title": "Add DMARC Record",
                    "description": "DMARC helps prevent email spoofing and provides reporting. Create a _dmarc TXT record.",
                    "severity": "medium"
                })
            
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error checking DMARC record: {str(e)}[/bold red]")
    
    def calculate_score(self):
        """Calculate overall security score based on findings."""
        score = 100  # Start with perfect score
        
        # DNSSEC
        if not self.results["dnssec"]["enabled"]:
            score -= 15
        
        # CAA Records
        if not self.results["has_caa"]:
            score -= 10
        
        # Zone Transfer
        if self.results["zone_transfer"]["vulnerable"]:
            score -= 30
        
        # SPF
        if not self.results["spf_record"]["exists"]:
            score -= 15
        elif not self.results["spf_record"]["valid"]:
            score -= 10
        
        # DMARC
        if not self.results["dmarc_record"]["exists"]:
            score -= 15
        elif not self.results["dmarc_record"]["valid"]:
            score -= 10
        
        # Ensure score stays within 0-100 range
        score = max(0, min(100, score))
        
        self.results["overall_score"] = score
    
    def run(self):
        """Run DNS security scanning."""
        console.print("[bold blue]Starting DNS security scanning...[/bold blue]")
        
        # Run all checks
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            dns_records_future = executor.submit(self.check_dns_records)
            dnssec_future = executor.submit(self.check_dnssec)
            caa_future = executor.submit(self.check_caa_records)
            zone_transfer_future = executor.submit(self.check_zone_transfer)
            spf_future = executor.submit(self.check_spf_record)
            dmarc_future = executor.submit(self.check_dmarc_record)
            
            # Wait for all checks to complete
            concurrent.futures.wait([
                dns_records_future, dnssec_future, caa_future,
                zone_transfer_future, spf_future, dmarc_future
            ])
        
        # Calculate score
        self.calculate_score()
        
        console.print(f"[bold green]DNS security scanning completed for {self.domain}[/bold green]")
        console.print(f"[bold]Overall DNS security score: {self.results['overall_score']}/100[/bold]")
        
        return self.results 