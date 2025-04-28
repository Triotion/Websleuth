#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reporter Module for WebSleuth
"""

import os
import json
import datetime
from rich.console import Console

console = Console()

# Custom JSON encoder to handle datetime objects
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        return super().default(obj)

class Reporter:
    """Class for generating reports from scan results."""
    
    def __init__(self, url, results, output_dir):
        """Initialize the Reporter class."""
        self.url = url
        self.results = results
        self.output_dir = output_dir
        self.timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Ensure the output directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def generate_html_report(self):
        """Generate a professional HTML report."""
        try:
            # Create HTML content with string formatting instead of f-strings
            html = '<!DOCTYPE html>\n'
            html += '<html lang="en">\n'
            html += '<head>\n'
            html += '    <meta charset="UTF-8">\n'
            html += '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
            html += '    <title>WebSleuth Report - {}</title>\n'.format(self.url)
            html += '    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">\n'
            html += '    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">\n'
            html += '    <link rel="preconnect" href="https://fonts.googleapis.com">\n'
            html += '    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n'
            html += '    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">\n'
            html += '    <style>\n'
            html += '        :root {\n'
            html += '            --primary: #6366f1;\n'
            html += '            --primary-dark: #4f46e5;\n'
            html += '            --primary-light: #a5b4fc;\n'
            html += '            --secondary: #0ea5e9;\n'
            html += '            --secondary-dark: #0284c7;\n'
            html += '            --success: #10b981;\n'
            html += '            --success-light: #d1fae5;\n'
            html += '            --danger: #ef4444;\n'
            html += '            --danger-light: #fee2e2;\n'
            html += '            --warning: #f59e0b;\n'
            html += '            --warning-light: #fef3c7;\n'
            html += '            --info: #3b82f6;\n'
            html += '            --info-light: #dbeafe;\n'
            html += '            --dark: #0f172a;\n'
            html += '            --dark-secondary: #1e293b;\n'
            html += '            --light: #f8fafc;\n'
            html += '            --gray: #64748b;\n'
            html += '            --card-shadow: 0 10px 25px rgba(0, 0, 0, 0.05);\n'
            html += '            --card-hover-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);\n'
            html += '        }\n'
            html += '        body {\n'
            html += '            font-family: "Outfit", sans-serif;\n'
            html += '            background-color: #f1f5f9;\n'
            html += '            color: #0f172a;\n'
            html += '            line-height: 1.6;\n'
            html += '            padding-top: 60px;\n'
            html += '        }\n'
            html += '        .main-wrapper {\n'
            html += '            display: flex;\n'
            html += '            min-height: calc(100vh - 60px);\n'
            html += '        }\n'
            html += '        .sidebar {\n'
            html += '            width: 280px;\n'
            html += '            background: var(--dark);\n'
            html += '            color: #fff;\n'
            html += '            position: fixed;\n'
            html += '            height: 100vh;\n'
            html += '            top: 0;\n'
            html += '            left: 0;\n'
            html += '            overflow-y: auto;\n'
            html += '            z-index: 1000;\n'
            html += '            box-shadow: 2px 0 10px rgba(0, 0, 0, 0.1);\n'
            html += '            transition: transform 0.3s ease;\n'
            html += '        }\n'
            html += '        .sidebar-collapsed {\n'
            html += '            transform: translateX(-280px);\n'
            html += '        }\n'
            html += '        .sidebar-header {\n'
            html += '            padding: 1.5rem;\n'
            html += '            background: linear-gradient(135deg, var(--primary-dark), var(--primary));\n'
            html += '            display: flex;\n'
            html += '            align-items: center;\n'
            html += '            justify-content: space-between;\n'
            html += '        }\n'
            html += '        .sidebar-header h3 {\n'
            html += '            margin: 0;\n'
            html += '            font-weight: 800;\n'
            html += '            font-size: 1.5rem;\n'
            html += '        }\n'
            html += '        .sidebar-content {\n'
            html += '            padding: 1.5rem 0;\n'
            html += '        }\n'
            html += '        .sidebar-menu {\n'
            html += '            list-style: none;\n'
            html += '            padding: 0;\n'
            html += '            margin: 0;\n'
            html += '        }\n'
            html += '        .sidebar-menu li a {\n'
            html += '            color: rgba(255, 255, 255, 0.75);\n'
            html += '            text-decoration: none;\n'
            html += '            display: flex;\n'
            html += '            align-items: center;\n'
            html += '            padding: 0.75rem 1.5rem;\n'
            html += '            transition: all 0.3s;\n'
            html += '            position: relative;\n'
            html += '        }\n'
            html += '        .sidebar-menu li a:hover {\n'
            html += '            color: white;\n'
            html += '            background-color: rgba(255, 255, 255, 0.1);\n'
            html += '        }\n'
            html += '        .sidebar-menu li a.active {\n'
            html += '            color: white;\n'
            html += '            background-color: var(--primary);\n'
            html += '            font-weight: 600;\n'
            html += '        }\n'
            html += '        .sidebar-menu li a i {\n'
            html += '            margin-right: 0.75rem;\n'
            html += '            font-size: 1.1rem;\n'
            html += '            width: 20px;\n'
            html += '            text-align: center;\n'
            html += '        }\n'
            html += '        .content-wrapper {\n'
            html += '            flex: 1;\n'
            html += '            margin-left: 280px;\n'
            html += '            padding: 2rem;\n'
            html += '            transition: margin-left 0.3s ease;\n'
            html += '        }\n'
            html += '        .content-wrapper-expanded {\n'
            html += '            margin-left: 0;\n'
            html += '        }\n'
            html += '        .sidebar-toggle {\n'
            html += '            position: fixed;\n'
            html += '            left: 280px;\n'
            html += '            top: 1rem;\n'
            html += '            z-index: 1001;\n'
            html += '            background-color: var(--primary);\n'
            html += '            border: none;\n'
            html += '            color: white;\n'
            html += '            border-radius: 50%;\n'
            html += '            width: 36px;\n'
            html += '            height: 36px;\n'
            html += '            display: flex;\n'
            html += '            align-items: center;\n'
            html += '            justify-content: center;\n'
            html += '            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);\n'
            html += '            transition: left 0.3s ease;\n'
            html += '        }\n'
            html += '        .sidebar-toggle-collapsed {\n'
            html += '            left: 1rem;\n'
            html += '        }\n'
            html += '        .header {\n'
            html += '            background: linear-gradient(135deg, var(--primary), var(--secondary));\n'
            html += '            color: white;\n'
            html += '            padding: 3rem 2rem;\n'
            html += '            border-radius: 1rem;\n'
            html += '            margin-bottom: 2rem;\n'
            html += '            box-shadow: var(--card-shadow);\n'
            html += '            position: relative;\n'
            html += '            overflow: hidden;\n'
            html += '        }\n'
            html += '        .header::before {\n'
            html += '            content: "";\n'
            html += '            position: absolute;\n'
            html += '            top: -50%;\n'
            html += '            right: -50%;\n'
            html += '            width: 100%;\n'
            html += '            height: 100%;\n'
            html += '            background: rgba(255, 255, 255, 0.1);\n'
            html += '            border-radius: 50%;\n'
            html += '            z-index: 0;\n'
            html += '        }\n'
            html += '        .header h1 {\n'
            html += '            font-weight: 800;\n'
            html += '            font-size: 2.75rem;\n'
            html += '            margin-bottom: 1.5rem;\n'
            html += '            position: relative;\n'
            html += '            z-index: 1;\n'
            html += '        }\n'
            html += '        .header p {\n'
            html += '            position: relative;\n'
            html += '            z-index: 1;\n'
            html += '            opacity: 0.9;\n'
            html += '            font-size: 1.1rem;\n'
            html += '        }\n'
            html += '        .card {\n'
            html += '            border: none;\n'
            html += '            box-shadow: var(--card-shadow);\n'
            html += '            transition: transform 0.3s, box-shadow 0.3s;\n'
            html += '            margin-bottom: 2rem;\n'
            html += '            border-radius: 1rem;\n'
            html += '            overflow: hidden;\n'
            html += '        }\n'
            html += '        .card:hover {\n'
            html += '            transform: translateY(-5px);\n'
            html += '            box-shadow: var(--card-hover-shadow);\n'
            html += '        }\n'
            html += '        .card-header {\n'
            html += '            font-weight: 600;\n'
            html += '            background-color: #fff;\n'
            html += '            border-bottom: 1px solid rgba(0, 0, 0, 0.05);\n'
            html += '            padding: 1.25rem 1.5rem;\n'
            html += '        }\n'
            html += '        .card-body {\n'
            html += '            padding: 1.5rem;\n'
            html += '            background-color: #fff;\n'
            html += '        }\n'
            html += '        .stat-card {\n'
            html += '            text-align: center;\n'
            html += '            padding: 1.75rem;\n'
            html += '            height: 100%;\n'
            html += '            display: flex;\n'
            html += '            flex-direction: column;\n'
            html += '            justify-content: center;\n'
            html += '            align-items: center;\n'
            html += '            transition: all 0.3s;\n'
            html += '        }\n'
            html += '        .stat-card:hover {\n'
            html += '            background-color: var(--primary);\n'
            html += '            color: white;\n'
            html += '        }\n'
            html += '        .stat-card:hover i {\n'
            html += '            background: white;\n'
            html += '            -webkit-background-clip: text;\n'
            html += '            -webkit-text-fill-color: transparent;\n'
            html += '        }\n'
            html += '        .stat-card:hover .count {\n'
            html += '            color: white;\n'
            html += '        }\n'
            html += '        .stat-card:hover .title {\n'
            html += '            color: rgba(255, 255, 255, 0.8);\n'
            html += '        }\n'
            html += '        .stat-card i {\n'
            html += '            font-size: 2.5rem;\n'
            html += '            margin-bottom: 1.5rem;\n'
            html += '            color: var(--primary);\n'
            html += '            background: linear-gradient(135deg, var(--primary), var(--secondary));\n'
            html += '            -webkit-background-clip: text;\n'
            html += '            -webkit-text-fill-color: transparent;\n'
            html += '            transition: all 0.3s;\n'
            html += '        }\n'
            html += '        .stat-card .count {\n'
            html += '            font-size: 3rem;\n'
            html += '            font-weight: 700;\n'
            html += '            margin-bottom: 0.5rem;\n'
            html += '            color: var(--dark);\n'
            html += '            transition: all 0.3s;\n'
            html += '        }\n'
            html += '        .stat-card .title {\n'
            html += '            font-size: 1rem;\n'
            html += '            color: var(--gray);\n'
            html += '            text-transform: uppercase;\n'
            html += '            letter-spacing: 2px;\n'
            html += '            font-weight: 500;\n'
            html += '            transition: all 0.3s;\n'
            html += '        }\n'
            html += '        .footer {\n'
            html += '            text-align: center;\n'
            html += '            padding: 3rem 0;\n'
            html += '            color: var(--gray);\n'
            html += '        }\n'
            html += '        .badge-high { background-color: var(--danger); color: white; }\n'
            html += '        .badge-medium { background-color: var(--warning); color: white; }\n'
            html += '        .badge-low { background-color: var(--success); color: white; }\n'
            html += '        .badge-info { background-color: var(--info); color: white; }\n'
            html += '        pre { background-color: #f8f9fa; padding: 1.5rem; border-radius: 0.75rem; font-size: 0.9rem; overflow: auto; }\n'
            html += '        code.inline { background-color: #f1f5f9; padding: 0.2rem 0.4rem; border-radius: 0.25rem; font-size: 0.9em; color: var(--primary-dark); }\n'
            html += '        .ssl-grade {\n'
            html += '            display: flex;\n'
            html += '            width: 80px;\n'
            html += '            height: 80px;\n'
            html += '            justify-content: center;\n'
            html += '            align-items: center;\n'
            html += '            border-radius: 50%;\n'
            html += '            font-size: 2rem;\n'
            html += '            font-weight: bold;\n'
            html += '            color: white;\n'
            html += '            margin-right: 1.5rem;\n'
            html += '            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);\n'
            html += '        }\n'
            html += '        .ssl-grade-a, .ssl-grade-a-plus { background: linear-gradient(135deg, #10b981, #059669); }\n'
            html += '        .ssl-grade-b { background: linear-gradient(135deg, #4ade80, #22c55e); }\n'
            html += '        .ssl-grade-c { background: linear-gradient(135deg, #fbbf24, #f59e0b); }\n'
            html += '        .ssl-grade-d { background: linear-gradient(135deg, #fb923c, #f97316); }\n'
            html += '        .ssl-grade-f { background: linear-gradient(135deg, #f87171, #ef4444); }\n'
            html += '        .list-group-item { border-left: 0; border-right: 0; padding: 1rem 1.5rem; }\n'
            html += '        .list-group-item:first-child { border-top: 0; border-top-left-radius: 0.75rem; border-top-right-radius: 0.75rem; }\n'
            html += '        .list-group-item:last-child { border-bottom: 0; border-bottom-left-radius: 0.75rem; border-bottom-right-radius: 0.75rem; }\n'
            html += '        .vuln-card { border-left: 4px solid var(--danger); }\n'
            html += '        .nav-pills .nav-link {\n'
            html += '            border-radius: 0.5rem;\n'
            html += '            padding: 0.75rem 1.25rem;\n'
            html += '            color: var(--dark);\n'
            html += '            font-weight: 500;\n'
            html += '            margin-right: 0.5rem;\n'
            html += '            transition: all 0.3s;\n'
            html += '        }\n'
            html += '        .nav-pills .nav-link:hover {\n'
            html += '            background-color: rgba(99, 102, 241, 0.1);\n'
            html += '            color: var(--primary);\n'
            html += '        }\n'
            html += '        .nav-pills .nav-link.active {\n'
            html += '            background-color: var(--primary);\n'
            html += '            color: white;\n'
            html += '        }\n'
            html += '        .table {\n'
            html += '            border-radius: 0.75rem;\n'
            html += '            overflow: hidden;\n'
            html += '            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);\n'
            html += '        }\n'
            html += '        .table th {\n'
            html += '            background-color: #f8fafc;\n'
            html += '            font-weight: 600;\n'
            html += '            color: var(--dark);\n'
            html += '        }\n'
            html += '        .alert {\n'
            html += '            border-radius: 0.75rem;\n'
            html += '            border: none;\n'
            html += '            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.05);\n'
            html += '            padding: 1rem 1.25rem;\n'
            html += '        }\n'
            html += '        .alert-danger {\n'
            html += '            background-color: var(--danger-light);\n'
            html += '            color: #b91c1c;\n'
            html += '        }\n'
            html += '        .alert-warning {\n'
            html += '            background-color: var(--warning-light);\n'
            html += '            color: #b45309;\n'
            html += '        }\n'
            html += '        .alert-success {\n'
            html += '            background-color: var(--success-light);\n'
            html += '            color: #047857;\n'
            html += '        }\n'
            html += '        .alert-info {\n'
            html += '            background-color: var(--info-light);\n'
            html += '            color: #1e40af;\n'
            html += '        }\n'
            html += '        .btn-link {\n'
            html += '            color: var(--gray);\n'
            html += '            transition: all 0.3s;\n'
            html += '        }\n'
            html += '        .btn-link:hover {\n'
            html += '            color: var(--primary);\n'
            html += '            transform: scale(1.1);\n'
            html += '        }\n'
            html += '        .btn-primary {\n'
            html += '            background-color: var(--primary);\n'
            html += '            border-color: var(--primary);\n'
            html += '        }\n'
            html += '        .btn-primary:hover {\n'
            html += '            background-color: var(--primary-dark);\n'
            html += '            border-color: var(--primary-dark);\n'
            html += '        }\n'
            html += '        .btn-outline-primary {\n'
            html += '            color: var(--primary);\n'
            html += '            border-color: var(--primary);\n'
            html += '        }\n'
            html += '        .btn-outline-primary:hover {\n'
            html += '            background-color: var(--primary);\n'
            html += '            border-color: var(--primary);\n'
            html += '        }\n'
            html += '        @media (max-width: 992px) {\n'
            html += '            .sidebar {\n'
            html += '                transform: translateX(-280px);\n'
            html += '            }\n'
            html += '            .sidebar-toggle {\n'
            html += '                left: 1rem;\n'
            html += '            }\n'
            html += '            .content-wrapper {\n'
            html += '                margin-left: 0;\n'
            html += '            }\n'
            html += '        }\n'
            html += '        @media (max-width: 768px) {\n'
            html += '            .header h1 {\n'
            html += '                font-size: 2rem;\n'
            html += '            }\n'
            html += '            .stat-card .count {\n'
            html += '                font-size: 2.5rem;\n'
            html += '            }\n'
            html += '            .ssl-grade {\n'
            html += '                width: 60px;\n'
            html += '                height: 60px;\n'
            html += '                font-size: 1.5rem;\n'
            html += '            }\n'
            html += '        }\n'
            html += '    </style>\n'
            html += '</head>\n'
            html += '<body>\n'
            
            # Define scan modules to display in sidebar
            scan_modules = [
                {'id': 'summary', 'name': 'Summary', 'icon': 'fa-chart-line'},
                {'id': 'security_headers', 'name': 'Security Headers', 'icon': 'fa-shield-alt'},
                {'id': 'ssl_checker', 'name': 'SSL/TLS Check', 'icon': 'fa-lock'},
                {'id': 'technology_scanner', 'name': 'Technology Detection', 'icon': 'fa-code'},
                {'id': 'info_gathering', 'name': 'Information Gathering', 'icon': 'fa-info-circle'},
                {'id': 'dns_security', 'name': 'DNS Security', 'icon': 'fa-server'},
                {'id': 'subdomain_enum', 'name': 'Subdomain Enumeration', 'icon': 'fa-sitemap'},
                {'id': 'port_scanner', 'name': 'Port Scanner', 'icon': 'fa-network-wired'},
                {'id': 'content_discovery', 'name': 'Content Discovery', 'icon': 'fa-folder-open'},
                {'id': 'vuln_scanner', 'name': 'Vulnerability Scanner', 'icon': 'fa-bug'},
                {'id': 'waf_detection', 'name': 'WAF Detection', 'icon': 'fa-fire-alt'},
                {'id': 'screenshot', 'name': 'Screenshot Capture', 'icon': 'fa-camera'}
            ]
            
            # Sidebar
            html += '    <button class="sidebar-toggle" id="sidebarToggle" aria-label="Toggle sidebar">\n'
            html += '        <i class="fas fa-bars"></i>\n'
            html += '    </button>\n'
            
            html += '    <div class="sidebar" id="sidebar">\n'
            html += '        <div class="sidebar-header">\n'
            html += '            <h3><i class="fas fa-shield-alt me-2"></i>WebSleuth</h3>\n'
            html += '        </div>\n'
            
            html += '        <div class="sidebar-content">\n'
            html += '            <div class="px-3 mb-4">\n'
            html += '                <div class="d-flex align-items-center">\n'
            html += '                    <div class="text-white opacity-75 me-2">Target:</div>\n'
            html += '                    <div class="text-white text-truncate fw-bold">{}</div>\n'.format(self.url)
            html += '                </div>\n'
            html += '                <div class="d-flex align-items-center mt-2">\n'
            html += '                    <div class="text-white opacity-75 me-2">Scanned:</div>\n'
            html += '                    <div class="text-white">{}</div>\n'.format(self.timestamp)
            html += '                </div>\n'
            html += '            </div>\n'
            
            html += '            <ul class="sidebar-menu">\n'
            
            for module in scan_modules:
                # Check if the module has results
                has_results = module['id'] in self.results and self.results[module['id']]
                disabled_class = ' opacity-50' if not has_results else ''
                
                html += '                <li>\n'
                html += '                    <a href="#{0}" class="{1}">\n'.format(module['id'], disabled_class)
                html += '                        <i class="fas {0}"></i>{1}\n'.format(module['icon'], module['name'])
                html += '                    </a>\n'
                html += '                </li>\n'
            
            html += '            </ul>\n'
            html += '        </div>\n'
            html += '    </div>\n'
            
            # Main content
            html += '    <div class="content-wrapper" id="contentWrapper">\n'
            
            # Header
            html += '        <div class="header" id="summary">\n'
            html += '            <h1><i class="fas fa-chart-line me-3"></i>WebSleuth Scan Report</h1>\n'
            html += '            <p class="mb-1">Target: <strong>{}</strong></p>\n'.format(self.url)
            html += '            <p>Scan completed on: <strong>{}</strong></p>\n'.format(self.timestamp)
            html += '        </div>\n\n'
            
            # Summary statistics cards
            subdomain_count = self.results.get('subdomain_enum', {}).get('total_found', 0)
            if isinstance(subdomain_count, list):
                subdomain_count = len(subdomain_count)
            elif 'subdomains' in self.results.get('subdomain_enum', {}) and isinstance(self.results['subdomain_enum']['subdomains'], list):
                subdomain_count = len(self.results['subdomain_enum']['subdomains'])
            
            # Vulnerabilities count
            vuln_count = self.results.get('vuln_scanner', {}).get('total_vulns', 0)
            if not vuln_count and 'vuln_scanner' in self.results and isinstance(self.results['vuln_scanner'], dict):
                vuln_list = self.results['vuln_scanner'].get('vulnerabilities', [])
                if isinstance(vuln_list, list):
                    vuln_count = len(vuln_list)
            
            # Content discovery count
            content_count = self.results.get('content_discovery', {}).get('total_found', 0)
            if isinstance(content_count, list):
                content_count = len(content_count)
                
            # Open ports count
            open_ports = self.results.get('port_scanner', {}).get('open_ports', [])
            if not isinstance(open_ports, list):
                open_ports = []
            
            html += '        <div class="row g-4 mb-5">\n'
            
            html += '            <div class="col-md-3 col-sm-6">\n'
            html += '                <div class="card h-100">\n'
            html += '                    <div class="stat-card">\n'
            html += '                        <i class="fas fa-globe"></i>\n'
            html += '                        <div class="count">{}</div>\n'.format(subdomain_count)
            html += '                        <div class="title">Subdomains</div>\n'
            html += '                    </div>\n'
            html += '                </div>\n'
            html += '            </div>\n'
            
            html += '            <div class="col-md-3 col-sm-6">\n'
            html += '                <div class="card h-100">\n'
            html += '                    <div class="stat-card">\n'
            html += '                        <i class="fas fa-bug"></i>\n'
            html += '                        <div class="count">{}</div>\n'.format(vuln_count)
            html += '                        <div class="title">Vulnerabilities</div>\n'
            html += '                    </div>\n'
            html += '                </div>\n'
            html += '            </div>\n'
            
            html += '            <div class="col-md-3 col-sm-6">\n'
            html += '                <div class="card h-100">\n'
            html += '                    <div class="stat-card">\n'
            html += '                        <i class="fas fa-folder-open"></i>\n'
            html += '                        <div class="count">{}</div>\n'.format(content_count)
            html += '                        <div class="title">Content</div>\n'
            html += '                    </div>\n'
            html += '                </div>\n'
            html += '            </div>\n'
            
            html += '            <div class="col-md-3 col-sm-6">\n'
            html += '                <div class="card h-100">\n'
            html += '                    <div class="stat-card">\n'
            html += '                        <i class="fas fa-network-wired"></i>\n'
            html += '                        <div class="count">{}</div>\n'.format(len(open_ports))
            html += '                        <div class="title">Open Ports</div>\n'
            html += '                    </div>\n'
            html += '                </div>\n'
            html += '            </div>\n'
            html += '        </div>\n\n'
            
            # Results summary section
            html += '        <div class="card mb-5">\n'
            html += '            <div class="card-header bg-white d-flex justify-content-between align-items-center">\n'
            html += '                <h4 class="mb-0">Results Summary</h4>\n'
            html += '            </div>\n'
            html += '            <div class="card-body">\n'
            
            # Add tabs for formatted and raw JSON views
            html += '                <ul class="nav nav-pills mb-4" role="tablist">\n'
            html += '                    <li class="nav-item">\n'
            html += '                        <a class="nav-link active" id="formatted-tab" data-bs-toggle="tab" href="#formatted-view" role="tab">Formatted View</a>\n'
            html += '                    </li>\n'
            html += '                    <li class="nav-item">\n'
            html += '                        <a class="nav-link" id="raw-tab" data-bs-toggle="tab" href="#raw-view" role="tab">Raw JSON</a>\n'
            html += '                    </li>\n'
            html += '                </ul>\n'
            
            # Create module navigation buttons
            html += '                <div class="d-flex flex-wrap gap-2 mb-4">\n'
            
            # Define the sections we want to highlight
            key_sections = [
                'security_headers', 'technology_scanner', 'ssl_checker', 
                'info_gathering', 'dns_security', 'subdomain_enum', 
                'port_scanner', 'content_discovery', 'vuln_scanner',
                'waf_detection', 'screenshot'
            ]
            
            for section in key_sections:
                # Convert section name to display name
                display_name = ' '.join(word.capitalize() for word in section.split('_'))
                
                # Determine if this section has data
                has_data = section in self.results and self.results[section]
                opacity = '1' if has_data else '0.6'
                
                # Choose the right icon
                icon = 'fa-file-alt'
                if 'security' in section or 'headers' in section:
                    icon = 'fa-shield-alt'
                elif 'technology' in section:
                    icon = 'fa-code'
                elif 'ssl' in section:
                    icon = 'fa-lock'
                elif 'info' in section:
                    icon = 'fa-info-circle'
                elif 'dns' in section:
                    icon = 'fa-server'
                elif 'subdomain' in section:
                    icon = 'fa-sitemap'
                elif 'port' in section:
                    icon = 'fa-network-wired'
                elif 'content' in section:
                    icon = 'fa-folder-open'
                elif 'vuln' in section:
                    icon = 'fa-bug'
                elif 'screenshot' in section:
                    icon = 'fa-camera'
                elif 'waf' in section:
                    icon = 'fa-fire-alt'
                
                btn_type = 'btn-primary' if has_data else 'btn-outline-primary'
                
                html += '                    <a href="#{0}" class="{2} rounded-pill px-3 py-2 btn-sm" style="opacity: {1}">\n'.format(section, opacity, btn_type)
                html += '                        <i class="fas {0} me-2"></i>{1}\n'.format(icon, display_name)
                html += '                    </a>\n'
                
            html += '                </div>\n'
            
            html += '                <div class="tab-content">\n'
            
            # Formatted view tab
            html += '                    <div class="tab-pane fade show active" id="formatted-view" role="tabpanel">\n'
            
            # Check if all results are empty
            all_empty = True
            for section in key_sections:
                if section in self.results and self.results[section]:
                    all_empty = False
                    break
            
            # Display message when no results available
            if all_empty:
                html += '                        <div class="alert alert-info">\n'
                html += '                            <i class="fas fa-info-circle me-2"></i>No scan results available. Try running the scan with different options.\n'
                html += '                        </div>\n'
            else:
                # Display available sections
                for section_name in key_sections:
                    if section_name in self.results and self.results[section_name]:
                        display_name = ' '.join(word.capitalize() for word in section_name.split('_'))
                        html += '                        <div class="mb-4">\n'
                        html += '                            <h5 class="border-bottom pb-2 text-primary d-flex align-items-center">\n'
                        
                        # Add icon based on section name
                        if 'security' in section_name or 'headers' in section_name:
                            html += '                                <i class="fas fa-shield-alt me-2"></i>'
                        elif 'technology' in section_name:
                            html += '                                <i class="fas fa-code me-2"></i>'
                        elif 'ssl' in section_name:
                            html += '                                <i class="fas fa-lock me-2"></i>'
                        elif 'info' in section_name:
                            html += '                                <i class="fas fa-info-circle me-2"></i>'
                        elif 'dns' in section_name:
                            html += '                                <i class="fas fa-server me-2"></i>'
                        elif 'subdomain' in section_name:
                            html += '                                <i class="fas fa-sitemap me-2"></i>'
                        elif 'port' in section_name:
                            html += '                                <i class="fas fa-network-wired me-2"></i>'
                        elif 'content' in section_name:
                            html += '                                <i class="fas fa-folder-open me-2"></i>'
                        elif 'vuln' in section_name:
                            html += '                                <i class="fas fa-bug me-2"></i>'
                        elif 'screenshot' in section_name:
                            html += '                                <i class="fas fa-camera me-2"></i>'
                        elif 'waf' in section_name:
                            html += '                                <i class="fas fa-fire-alt me-2"></i>'
                        else:
                            html += '                                <i class="fas fa-file-alt me-2"></i>'
                        
                        html += '{}</h5>\n'.format(display_name)
                        
                        # Special handling for each section type
                        if section_name == 'security_headers':
                            self._generate_security_headers_section(html, self.results[section_name])
                        elif section_name == 'ssl_checker':
                            self._generate_ssl_section(html, self.results[section_name])
                        elif section_name == 'technology_scanner':
                            self._generate_technology_section(html, self.results[section_name])
                        elif section_name == 'info_gathering':
                            self._generate_info_gathering_section(html, self.results[section_name])
                        elif section_name == 'subdomain_enum':
                            self._generate_subdomain_section(html, self.results[section_name])
                        elif section_name == 'dns_security':
                            self._generate_dns_security_section(html, self.results[section_name])
                        elif section_name == 'waf_detection':
                            self._generate_waf_section(html, self.results[section_name])
                        elif section_name == 'port_scanner':
                            self._generate_port_scanner_section(html, self.results[section_name])
                        elif section_name == 'content_discovery':
                            self._generate_content_discovery_section(html, self.results[section_name])
                        elif section_name == 'vuln_scanner':
                            self._generate_vuln_scanner_section(html, self.results[section_name])
                        elif section_name == 'screenshot':
                            self._generate_screenshot_section(html, self.results[section_name])
                        else:
                            # Default simple JSON display
                            html += '                        <pre class="language-json rounded">{}</pre>\n'.format(json.dumps(self.results[section_name], indent=4, cls=DateTimeEncoder))
                        
                        html += '                        </div>\n'
                    elif section_name in self.results:
                        # Section exists but has no data
                        display_name = ' '.join(word.capitalize() for word in section_name.split('_'))
                        html += '                        <div class="mb-4">\n'
                        html += '                            <h5 class="border-bottom pb-2 text-primary">{}</h5>\n'.format(display_name)
                        html += '                            <div class="alert alert-secondary">\n'
                        html += '                                <i class="fas fa-info-circle me-2"></i>No {} data available.\n'.format(display_name.lower())
                        html += '                            </div>\n'
                        html += '                        </div>\n'
            
            # Raw JSON view tab
            html += '                    </div>\n'
            html += '                    <div class="tab-pane fade" id="raw-view" role="tabpanel">\n'
            if all_empty:
                html += '                        <div class="alert alert-info">\n'
                html += '                            <i class="fas fa-info-circle me-2"></i>No scan results available.\n'
                html += '                        </div>\n'
            else:
                html += '                        <pre class="language-json rounded">{}</pre>\n'.format(json.dumps(self.results, indent=4, cls=DateTimeEncoder))
            html += '                    </div>\n'
            html += '                </div>\n'
            html += '            </div>\n'
            html += '        </div>\n'
            
            # Special visualization for SSL/TLS
            if 'ssl_checker' in self.results and self.results['ssl_checker']:
                ssl_data = self.results['ssl_checker']
                ssl_grade = ssl_data.get('grade', 'Unknown')
                
                html += '            <div class="card mb-4" id="ssl_checker">\n'
                html += '                <div class="card-header d-flex justify-content-between align-items-center">\n'
                html += '                    <h5 class="mb-0"><i class="fas fa-lock me-2"></i>SSL/TLS Security</h5>\n'
                html += '                    <button class="btn btn-link" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-ssl">\n'
                html += '                        <i class="fas fa-chevron-down"></i>\n'
                html += '                    </button>\n'
                html += '                </div>\n'
                html += '                <div id="collapse-ssl" class="collapse show">\n'
                html += '                    <div class="card-body">\n'
                html += '                        <div class="d-flex align-items-center mb-4">\n'
                
                # SSL Grade visualization
                grade_class = "ssl-grade-a"
                if ssl_grade == "A+" or ssl_grade == "A":
                    grade_class = "ssl-grade-a-plus"
                elif ssl_grade == "B":
                    grade_class = "ssl-grade-b"
                elif ssl_grade == "C":
                    grade_class = "ssl-grade-c"
                elif ssl_grade == "D":
                    grade_class = "ssl-grade-d"
                elif ssl_grade == "F":
                    grade_class = "ssl-grade-f"
                
                html += '                            <div class="ssl-grade {}">{}</div>\n'.format(grade_class, ssl_grade)
                html += '                            <div>\n'
                html += '                                <h4 class="mb-0">SSL/TLS Security Grade</h4>\n'
                
                # Certificate information
                cert_data = ssl_data.get('certificate', {})
                if cert_data:
                    html += '                                <p class="text-muted">Certificate issued by: {}</p>\n'.format(cert_data.get('issuer', 'Unknown'))
                    
                    # Check if certificate is expired or expiring soon
                    if cert_data.get('is_expired', False):
                        html += '                                <div class="alert alert-danger mt-2">Certificate is expired!</div>\n'
                    elif cert_data.get('days_left', 999) < 30:
                        html += '                                <div class="alert alert-warning mt-2">Certificate expires in {} days!</div>\n'.format(cert_data.get('days_left', 0))
                
                html += '                            </div>\n'
                html += '                        </div>\n'
                
                # Protocols table
                html += '                        <h5 class="mt-4 mb-3">Supported Protocols</h5>\n'
                html += '                        <div class="table-responsive mb-4">\n'
                html += '                            <table class="table table-bordered">\n'
                html += '                                <thead>\n'
                html += '                                    <tr>\n'
                html += '                                        <th>Protocol</th>\n'
                html += '                                        <th>Status</th>\n'
                html += '                                        <th>Security</th>\n'
                html += '                                    </tr>\n'
                html += '                                </thead>\n'
                html += '                                <tbody>\n'
                
                protocols = ssl_data.get('protocols', [])
                for protocol in protocols:
                    protocol_name = protocol.get('name', 'Unknown')
                    enabled = protocol.get('enabled', False)
                    
                    # Determine security level
                    security_level = "High"
                    security_class = "text-success"
                    
                    if protocol_name == "SSLv3":
                        security_level = "Insecure"
                        security_class = "text-danger"
                    elif protocol_name == "TLSv1.0":
                        security_level = "Low"
                        security_class = "text-danger"
                    elif protocol_name == "TLSv1.1":
                        security_level = "Medium"
                        security_class = "text-warning"
                    
                    status = "Enabled" if enabled else "Disabled"
                    status_class = "text-danger" if (enabled and (protocol_name == "SSLv3" or protocol_name == "TLSv1.0")) else "text-success"
                    
                    html += '                                    <tr>\n'
                    html += '                                        <td><span class="fw-medium">{}</span></td>\n'.format(protocol_name)
                    html += '                                        <td class="{}"><i class="fas fa-{} me-2"></i>{}</td>\n'.format(
                        status_class, "check" if enabled else "times", status
                    )
                    html += '                                        <td class="{}"><span class="fw-medium">{}</span></td>\n'.format(security_class, security_level)
                    html += '                                    </tr>\n'
                
                html += '                                </tbody>\n'
                html += '                            </table>\n'
                html += '                        </div>\n'
                
                # Vulnerabilities
                vulnerabilities = ssl_data.get('vulnerabilities', [])
                if vulnerabilities:
                    html += '                        <h5 class="mt-4 mb-3">Vulnerabilities</h5>\n'
                    
                    for vuln in vulnerabilities:
                        html += '                        <div class="alert alert-danger mb-3">\n'
                        html += '                            <h6 class="alert-heading fw-bold"><i class="fas fa-exclamation-triangle me-2"></i>{}</h6>\n'.format(vuln.get('name', 'Unknown'))
                        html += '                            <p class="mb-0">{}</p>\n'.format(vuln.get('details', ''))
                        html += '                        </div>\n'
                
                html += '                    </div>\n'
                html += '                </div>\n'
                html += '            </div>\n\n'
            
            # Special visualization for Technology Scanner
            if 'technology_scanner' in self.results and self.results['technology_scanner']:
                tech_data = self.results['technology_scanner']
                
                html += '            <div class="card mb-4" id="technology_scanner">\n'
                html += '                <div class="card-header d-flex justify-content-between align-items-center">\n'
                html += '                    <h5 class="mb-0"><i class="fas fa-code me-2"></i>Technologies</h5>\n'
                html += '                    <button class="btn btn-link" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-tech">\n'
                html += '                        <i class="fas fa-chevron-down"></i>\n'
                html += '                    </button>\n'
                html += '                </div>\n'
                html += '                <div id="collapse-tech" class="collapse show">\n'
                html += '                    <div class="card-body">\n'
                html += '                        <div class="row g-4">\n'
                
                # Server section
                html += '                            <div class="col-md-4 mb-4">\n'
                html += '                                <div class="card h-100 border-0 shadow-sm">\n'
                html += '                                    <div class="card-header bg-white">\n'
                html += '                                        <h6 class="mb-0"><i class="fas fa-server me-2 text-primary"></i>Server</h6>\n'
                html += '                                    </div>\n'
                html += '                                    <div class="card-body">\n'
                
                if tech_data.get('server'):
                    html += '                                        <p class="mb-0 fw-medium">{}</p>\n'.format(tech_data.get('server'))
                else:
                    html += '                                        <p class="text-muted mb-0">Not detected</p>\n'
                
                html += '                                    </div>\n'
                html += '                                </div>\n'
                html += '                            </div>\n'
                
                # CMS section
                html += '                            <div class="col-md-4 mb-4">\n'
                html += '                                <div class="card h-100 border-0 shadow-sm">\n'
                html += '                                    <div class="card-header bg-white">\n'
                html += '                                        <h6 class="mb-0"><i class="fas fa-th-large me-2 text-primary"></i>CMS</h6>\n'
                html += '                                    </div>\n'
                html += '                                    <div class="card-body">\n'
                
                if tech_data.get('cms'):
                    html += '                                        <p class="mb-0 fw-medium">{}</p>\n'.format(tech_data.get('cms'))
                else:
                    html += '                                        <p class="text-muted mb-0">Not detected</p>\n'
                
                html += '                                    </div>\n'
                html += '                                </div>\n'
                html += '                            </div>\n'
                
                # Programming languages section
                html += '                            <div class="col-md-4 mb-4">\n'
                html += '                                <div class="card h-100 border-0 shadow-sm">\n'
                html += '                                    <div class="card-header bg-white">\n'
                html += '                                        <h6 class="mb-0"><i class="fas fa-code me-2 text-primary"></i>Languages</h6>\n'
                html += '                                    </div>\n'
                html += '                                    <div class="card-body">\n'
                
                if tech_data.get('languages'):
                    html += '                                        <ul class="list-unstyled mb-0">\n'
                    for lang in tech_data.get('languages', []):
                        html += '                                            <li class="mb-2"><span class="badge bg-primary-subtle text-primary me-2"><i class="fas fa-circle me-1 small"></i>{}</span></li>\n'.format(lang)
                    html += '                                        </ul>\n'
                else:
                    html += '                                        <p class="text-muted mb-0">Not detected</p>\n'
                
                html += '                                    </div>\n'
                html += '                                </div>\n'
                html += '                            </div>\n'
                
                # Frameworks section
                html += '                            <div class="col-md-4 mb-4">\n'
                html += '                                <div class="card h-100 border-0 shadow-sm">\n'
                html += '                                    <div class="card-header bg-white">\n'
                html += '                                        <h6 class="mb-0"><i class="fas fa-layer-group me-2 text-success"></i>Frameworks</h6>\n'
                html += '                                    </div>\n'
                html += '                                    <div class="card-body">\n'
                
                if tech_data.get('frameworks'):
                    html += '                                        <ul class="list-unstyled mb-0">\n'
                    for framework in tech_data.get('frameworks', []):
                        html += '                                            <li class="mb-2"><span class="badge bg-success-subtle text-success me-2"><i class="fas fa-circle me-1 small"></i>{}</span></li>\n'.format(framework)
                    html += '                                        </ul>\n'
                else:
                    html += '                                        <p class="text-muted mb-0">Not detected</p>\n'
                
                html += '                                    </div>\n'
                html += '                                </div>\n'
                html += '                            </div>\n'
                
                # JavaScript libraries section
                html += '                            <div class="col-md-4 mb-4">\n'
                html += '                                <div class="card h-100 border-0 shadow-sm">\n'
                html += '                                    <div class="card-header bg-white">\n'
                html += '                                        <h6 class="mb-0"><i class="fab fa-js me-2 text-warning"></i>JavaScript Libraries</h6>\n'
                html += '                                    </div>\n'
                html += '                                    <div class="card-body">\n'
                
                if tech_data.get('javascript_libraries'):
                    html += '                                        <ul class="list-unstyled mb-0">\n'
                    for lib in tech_data.get('javascript_libraries', []):
                        html += '                                            <li class="mb-2"><span class="badge bg-warning-subtle text-warning me-2"><i class="fas fa-circle me-1 small"></i>{}</span></li>\n'.format(lib)
                    html += '                                        </ul>\n'
                else:
                    html += '                                        <p class="text-muted mb-0">Not detected</p>\n'
                
                html += '                                    </div>\n'
                html += '                                </div>\n'
                html += '                            </div>\n'
                
                # Analytics & CDN section
                html += '                            <div class="col-md-4 mb-4">\n'
                html += '                                <div class="card h-100 border-0 shadow-sm">\n'
                html += '                                    <div class="card-header bg-white">\n'
                html += '                                        <h6 class="mb-0"><i class="fas fa-chart-line me-2 text-info"></i>Analytics & CDN</h6>\n'
                html += '                                    </div>\n'
                html += '                                    <div class="card-body">\n'
                
                if tech_data.get('analytics') or tech_data.get('cdn'):
                    html += '                                        <ul class="list-unstyled mb-0">\n'
                    
                    for analytics in tech_data.get('analytics', []):
                        html += '                                            <li class="mb-2"><span class="badge bg-info-subtle text-info me-2"><i class="fas fa-chart-bar me-1 small"></i>{}</span></li>\n'.format(analytics)
                    
                    for cdn in tech_data.get('cdn', []):
                        html += '                                            <li class="mb-2"><span class="badge bg-secondary-subtle text-secondary me-2"><i class="fas fa-cloud me-1 small"></i>{}</span></li>\n'.format(cdn)
                    
                    html += '                                        </ul>\n'
                else:
                    html += '                                        <p class="text-muted mb-0">Not detected</p>\n'
                
                html += '                                    </div>\n'
                html += '                                </div>\n'
                html += '                            </div>\n'
                
                html += '                        </div>\n'
                html += '                    </div>\n'
                html += '                </div>\n'
                html += '            </div>\n\n'
            
            # Create collapsible sections for each scan result
            for module_name, results in self.results.items():
                # Skip the modules we've already handled specially
                if module_name in ['ssl_checker', 'technology_scanner'] or not results:
                    continue
                
                html += '            <div class="card mb-4" id="{}">\n'.format(module_name)
                html += '                <div class="card-header d-flex justify-content-between align-items-center">\n'
                html += '                    <h5 class="mb-0">\n'
                
                # Add appropriate icon based on module name
                if 'info' in module_name:
                    html += '                        <i class="fas fa-info-circle me-2 text-info"></i>'
                elif 'subdomain' in module_name:
                    html += '                        <i class="fas fa-sitemap me-2 text-primary"></i>'
                elif 'content' in module_name:
                    html += '                        <i class="fas fa-folder-open me-2 text-warning"></i>'
                elif 'header' in module_name:
                    html += '                        <i class="fas fa-heading me-2 text-success"></i>'
                elif 'port' in module_name:
                    html += '                        <i class="fas fa-network-wired me-2 text-danger"></i>'
                elif 'waf' in module_name:
                    html += '                        <i class="fas fa-shield-alt me-2 text-primary"></i>'
                elif 'vuln' in module_name:
                    html += '                        <i class="fas fa-bug me-2 text-danger"></i>'
                elif 'screenshot' in module_name:
                    html += '                        <i class="fas fa-camera me-2 text-success"></i>'
                elif 'dns' in module_name:
                    html += '                        <i class="fas fa-server me-2 text-warning"></i>'
                else:
                    html += '                        <i class="fas fa-file-alt me-2 text-secondary"></i>'
                
                # Format module name for display
                display_name = ' '.join(word.capitalize() for word in module_name.split('_'))
                html += '{}</h5>\n'.format(display_name)
                html += '                    <button class="btn btn-link" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-{}">\n'.format(module_name)
                html += '                        <i class="fas fa-chevron-down"></i>\n'
                html += '                    </button>\n'
                html += '                </div>\n'
                html += '                <div id="collapse-{}" class="collapse show">\n'.format(module_name)
                html += '                    <div class="card-body">\n'
                
                # Special handling for screenshots
                if module_name == 'screenshot':
                    html += '                        <div class="row g-4">\n'
                    screenshots = results.get('screenshots', [])
                    for screenshot in screenshots:
                        html += '                            <div class="col-md-6 mb-4">\n'
                        html += '                                <div class="card border-0 shadow-sm">\n'
                        html += '                                    <div class="card-header bg-white">{}</div>\n'.format(screenshot.get('url', 'Screenshot'))
                        html += '                                    <img src="{}" class="card-img-top img-fluid" alt="Screenshot">\n'.format(screenshot.get('path', ''))
                        html += '                                </div>\n'
                        html += '                            </div>\n'
                    html += '                        </div>\n'
                else:
                    html += '                        <pre class="language-json rounded">{}</pre>\n'.format(json.dumps(results, indent=4, cls=DateTimeEncoder))
                
                html += '                    </div>\n'
                html += '                </div>\n'
                html += '            </div>\n\n'
            
            # Footer
            html += '            <div class="footer">\n'
            html += '                <p class="mb-2">Generated by <strong>WebSleuth</strong> - Advanced Website OSINT and Penetration Testing Tool</p>\n'
            html += '                <p class="mb-0"><a href="https://github.com/Triotion/websleuth" class="text-decoration-none" target="_blank"><i class="fab fa-github me-1"></i>GitHub</a> | <a href="https://github.com/Triotion" class="text-decoration-none" target="_blank">Author: Triotion</a></p>\n'
            html += '            </div>\n'
            html += '        </div>\n'
            
            # JavaScript
            html += '        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>\n'
            html += '        <script>\n'
            html += '            // Initialize collapsible elements\n'
            html += '            document.addEventListener("DOMContentLoaded", function() {\n'
            html += '                // Sidebar toggle functionality\n'
            html += '                const sidebar = document.getElementById("sidebar");\n'
            html += '                const contentWrapper = document.getElementById("contentWrapper");\n'
            html += '                const sidebarToggle = document.getElementById("sidebarToggle");\n'
            html += '                \n'
            html += '                if (sidebarToggle) {\n'
            html += '                    sidebarToggle.addEventListener("click", function() {\n'
            html += '                        sidebar.classList.toggle("sidebar-collapsed");\n'
            html += '                        contentWrapper.classList.toggle("content-wrapper-expanded");\n'
            html += '                        sidebarToggle.classList.toggle("sidebar-toggle-collapsed");\n'
            html += '                    });\n'
            html += '                }\n'
            html += '                \n'
            html += '                // Active sidebar link\n'
            html += '                const sidebarLinks = document.querySelectorAll(".sidebar-menu a");\n'
            html += '                const sections = document.querySelectorAll(".card[id]");\n'
            html += '                \n'
            html += '                function setActiveLink() {\n'
            html += '                    let current = "";\n'
            html += '                    const scrollY = window.pageYOffset;\n'
            html += '                    \n'
            html += '                    sections.forEach(section => {\n'
            html += '                        const sectionTop = section.offsetTop - 100;\n'
            html += '                        const sectionHeight = section.offsetHeight;\n'
            html += '                        \n'
            html += '                        if (scrollY >= sectionTop && scrollY < sectionTop + sectionHeight) {\n'
            html += '                            current = section.getAttribute("id");\n'
            html += '                        }\n'
            html += '                    });\n'
            html += '                    \n'
            html += '                    // Default to Summary if nothing is active\n'
            html += '                    if (!current) {\n'
            html += '                        current = "summary";\n'
            html += '                    }\n'
            html += '                    \n'
            html += '                    sidebarLinks.forEach(link => {\n'
            html += '                        link.classList.remove("active");\n'
            html += '                        const href = link.getAttribute("href").substring(1);\n'
            html += '                        if (href === current) {\n'
            html += '                            link.classList.add("active");\n'
            html += '                        }\n'
            html += '                    });\n'
            html += '                }\n'
            html += '                \n'
            html += '                window.addEventListener("scroll", setActiveLink);\n'
            html += '                setActiveLink(); // Set active link on page load\n'
            html += '                \n'
            html += '                // Initialize collapsible sections\n'
            html += '                var collapseElements = document.querySelectorAll(".collapse");\n'
            html += '                collapseElements.forEach(function(el) {\n'
            html += '                    el.addEventListener("shown.bs.collapse", function() {\n'
            html += '                        var button = el.previousElementSibling.querySelector(".fas");\n'
            html += '                        if (button) button.classList.replace("fa-chevron-down", "fa-chevron-up");\n'
            html += '                    });\n'
            html += '                    el.addEventListener("hidden.bs.collapse", function() {\n'
            html += '                        var button = el.previousElementSibling.querySelector(".fas");\n'
            html += '                        if (button) button.classList.replace("fa-chevron-up", "fa-chevron-down");\n'
            html += '                    });\n'
            html += '                });\n'
            
            # Smooth scrolling
            html += '                // Smooth scrolling for anchor links\n'
            html += '                document.querySelectorAll(\'a[href^="#"]\').forEach(anchor => {\n'
            html += '                    anchor.addEventListener("click", function(e) {\n'
            html += '                        e.preventDefault();\n'
            html += '                        const target = document.querySelector(this.getAttribute("href"));\n'
            html += '                        if (target) {\n'
            html += '                            window.scrollTo({\n'
            html += '                                top: target.offsetTop - 70,\n'
            html += '                                behavior: "smooth"\n'
            html += '                            });\n'
            html += '                            \n'
            html += '                            // Update active link manually\n'
            html += '                            sidebarLinks.forEach(link => {\n'
            html += '                                link.classList.remove("active");\n'
            html += '                            });\n'
            html += '                            this.classList.add("active");\n'
            html += '                        }\n'
            html += '                    });\n'
            html += '                });\n'
            
            # Add animation effects
            html += '                // Add animation effects\n'
            html += '                const animateCards = () => {\n'
            html += '                    const cards = document.querySelectorAll(".card");\n'
            html += '                    cards.forEach((card, index) => {\n'
            html += '                        setTimeout(() => {\n'
            html += '                            card.style.opacity = "1";\n'
            html += '                            card.style.transform = "translateY(0)";\n'
            html += '                        }, index * 100);\n'
            html += '                    });\n'
            html += '                };\n'
            html += '                \n'
            html += '                // Initialize cards with opacity 0 and transform\n'
            html += '                const cards = document.querySelectorAll(".card");\n'
            html += '                cards.forEach(card => {\n'
            html += '                    card.style.opacity = "0";\n'
            html += '                    card.style.transform = "translateY(20px)";\n'
            html += '                    card.style.transition = "opacity 0.5s ease, transform 0.5s ease";\n'
            html += '                });\n'
            html += '                \n'
            html += '                // Run animations after a short delay\n'
            html += '                setTimeout(animateCards, 300);\n'
            html += '            });\n'
            html += '        </script>\n'
            html += '    </div>\n'
            html += '</body>\n'
            html += '</html>'
            
            # Write to file
            report_path = os.path.join(self.output_dir, 'report.html')
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html)
                
            console.print(f'[bold green]HTML report saved to {report_path}[/bold green]')
            return report_path
            
        except Exception as e:
            console.print(f'[bold red]Error generating HTML report: {str(e)}[/bold red]')
            return None
    
    def generate_json_report(self):
        """Generate a JSON report."""
        try:
            report_data = {
                'target': self.url,
                'timestamp': self.timestamp,
                'results': self.results
            }
            
            report_path = os.path.join(self.output_dir, 'report.json')
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4, cls=DateTimeEncoder)
            
            console.print(f'[bold green]JSON report saved to {report_path}[/bold green]')
            return report_path
            
        except Exception as e:
            console.print(f'[bold red]Error generating JSON report: {str(e)}[/bold red]')
            return None
    
    def generate_pdf_report(self):
        """Generate a PDF report (stub)."""
        console.print('[bold yellow]PDF report generation is not yet implemented in this simplified version.[/bold yellow]')
        return None

    def _generate_security_headers_section(self, html, data):
        """Generate HTML for security headers section."""
        if 'headers_present' in data and data['headers_present']:
            html += '                            <div class="table-responsive">\n'
            html += '                                <table class="table table-striped">\n'
            html += '                                    <thead class="table-light">\n'
            html += '                                        <tr>\n'
            html += '                                            <th>Header</th>\n'
            html += '                                            <th>Value</th>\n'
            html += '                                            <th>Status</th>\n'
            html += '                                            <th>Description</th>\n'
            html += '                                        </tr>\n'
            html += '                                    </thead>\n'
            html += '                                    <tbody>\n'
            
            for header, details in data['headers_present'].items():
                value = details.get('value', '')
                description = details.get('description', '')
                severity = details.get('severity', 'medium')
                
                status_class = 'bg-success' if severity == 'high' else 'bg-warning' if severity == 'medium' else 'bg-info'
                
                html += '                                        <tr>\n'
                html += '                                            <td><strong>{}</strong></td>\n'.format(header)
                html += '                                            <td><code class="bg-light px-2 py-1 rounded">{}</code></td>\n'.format(value)
                html += '                                            <td><span class="badge {}">{}</span></td>\n'.format(status_class, severity.upper())
                html += '                                            <td>{}</td>\n'.format(description)
                html += '                                        </tr>\n'
            
            html += '                                    </tbody>\n'
            html += '                                </table>\n'
            html += '                            </div>\n'
        else:
            html += '                            <div class="alert alert-info">\n'
            html += '                                <i class="fas fa-info-circle me-2"></i>No security headers found.\n'
            html += '                            </div>\n'
    
    def _generate_ssl_section(self, html, data):
        """Generate HTML for SSL/TLS check section."""
        # SSL Grade visualization
        if 'grade' in data:
            grade = data.get('grade', 'Unknown')
            grade_class = 'ssl-grade-a'
            if grade == "A+" or grade == "A":
                grade_class = "ssl-grade-a-plus"
            elif grade == "B":
                grade_class = "ssl-grade-b"
            elif grade == "C":
                grade_class = "ssl-grade-c"
            elif grade == "D":
                grade_class = "ssl-grade-d"
            elif grade == "F":
                grade_class = "ssl-grade-f"
            
            html += '                            <div class="d-flex align-items-center mb-3">\n'
            html += '                                <div class="ssl-grade {} me-3">{}</div>\n'.format(grade_class, grade)
            html += '                                <div><strong>SSL/TLS Security Grade</strong></div>\n'
            html += '                            </div>\n'
        
        # Certificate info
        if 'certificate' in data and data['certificate']:
            cert_data = data['certificate']
            html += '                            <div class="card border-0 bg-light mb-3">\n'
            html += '                                <div class="card-body">\n'
            html += '                                    <h5 class="card-title mb-3">Certificate Information</h5>\n'
            
            if 'issuer' in cert_data:
                html += '                                    <p class="mb-2"><strong>Issuer:</strong> {}</p>\n'.format(cert_data['issuer'])
            
            if 'not_after' in cert_data:
                html += '                                    <p class="mb-2"><strong>Valid Until:</strong> {}</p>\n'.format(cert_data['not_after'])
            
            if 'is_expired' in cert_data:
                if cert_data['is_expired']:
                    html += '                                    <div class="alert alert-danger mb-0 mt-2">Certificate is expired!</div>\n'
                elif cert_data.get('days_left', 999) < 30:
                    html += '                                    <div class="alert alert-warning mb-0 mt-2">Certificate expires in {} days!</div>\n'.format(cert_data['days_left'])
            
            html += '                                </div>\n'
            html += '                            </div>\n'
        
        # Vulnerabilities
        if 'vulnerabilities' in data and data['vulnerabilities']:
            html += '                            <div class="mt-3">\n'
            html += '                                <h5 class="mb-3">SSL/TLS Vulnerabilities</h5>\n'
            
            for vuln in data['vulnerabilities']:
                html += '                                <div class="alert alert-danger mb-2">\n'
                html += '                                    <strong><i class="fas fa-exclamation-triangle me-2"></i>{}</strong>\n'.format(vuln.get('name', 'Unknown'))
                html += '                                    <p class="mb-0 mt-1">{}</p>\n'.format(vuln.get('details', ''))
                html += '                                </div>\n'
            
            html += '                            </div>\n'
        elif 'vulnerabilities' in data:
            html += '                            <div class="alert alert-success mt-3">\n'
            html += '                                <i class="fas fa-check-circle me-2"></i>No SSL/TLS vulnerabilities detected.\n'
            html += '                            </div>\n'
    
    def _generate_technology_section(self, html, data):
        """Generate HTML for technology detection section."""
        html += '                            <div class="row g-3">\n'
        
        # Server
        if 'server' in data and data['server']:
            html += '                                <div class="col-md-6 col-lg-4">\n'
            html += '                                    <div class="card h-100 border-0 bg-light">\n'
            html += '                                        <div class="card-body">\n'
            html += '                                            <h6 class="card-title mb-3"><i class="fas fa-server me-2 text-primary"></i>Server</h6>\n'
            html += '                                            <p class="card-text font-monospace">{}</p>\n'.format(data['server'])
            html += '                                        </div>\n'
            html += '                                    </div>\n'
            html += '                                </div>\n'
        
        # CMS
        if 'cms' in data and data['cms']:
            html += '                                <div class="col-md-6 col-lg-4">\n'
            html += '                                    <div class="card h-100 border-0 bg-light">\n'
            html += '                                        <div class="card-body">\n'
            html += '                                            <h6 class="card-title mb-3"><i class="fas fa-th-large me-2 text-primary"></i>CMS</h6>\n'
            html += '                                            <p class="card-text font-monospace">{}</p>\n'.format(data['cms'])
            html += '                                        </div>\n'
            html += '                                    </div>\n'
            html += '                                </div>\n'
        
        # Languages
        if 'languages' in data and data['languages']:
            html += '                                <div class="col-md-6 col-lg-4">\n'
            html += '                                    <div class="card h-100 border-0 bg-light">\n'
            html += '                                        <div class="card-body">\n'
            html += '                                            <h6 class="card-title mb-3"><i class="fas fa-code me-2 text-primary"></i>Languages</h6>\n'
            html += '                                            <div class="d-flex flex-wrap gap-1">\n'
            
            for lang in data['languages']:
                html += '                                                <span class="badge bg-primary-subtle text-primary px-2 py-1">{}</span>\n'.format(lang)
            
            html += '                                            </div>\n'
            html += '                                        </div>\n'
            html += '                                    </div>\n'
            html += '                                </div>\n'
        
        # Frameworks
        if 'frameworks' in data and data['frameworks']:
            html += '                                <div class="col-md-6 col-lg-4">\n'
            html += '                                    <div class="card h-100 border-0 bg-light">\n'
            html += '                                        <div class="card-body">\n'
            html += '                                            <h6 class="card-title mb-3"><i class="fas fa-layer-group me-2 text-success"></i>Frameworks</h6>\n'
            html += '                                            <div class="d-flex flex-wrap gap-1">\n'
            
            for framework in data['frameworks']:
                html += '                                                <span class="badge bg-success-subtle text-success px-2 py-1">{}</span>\n'.format(framework)
            
            html += '                                            </div>\n'
            html += '                                        </div>\n'
            html += '                                    </div>\n'
            html += '                                </div>\n'
        
        html += '                            </div>\n'
        
        # If no technologies were detected
        if not any(k in data and data[k] for k in ['server', 'cms', 'languages', 'frameworks', 'javascript_libraries']):
            html += '                            <div class="alert alert-info mt-3">\n'
            html += '                                <i class="fas fa-info-circle me-2"></i>No technologies detected on this website.\n'
            html += '                            </div>\n'
    
    def _generate_info_gathering_section(self, html, data):
        """Generate HTML for information gathering section."""
        html += '                            <div class="card border-0 bg-light">\n'
        html += '                                <div class="card-body">\n'
        
        has_data = False
        
        if 'ip_address' in data and data['ip_address']:
            has_data = True
            html += '                                    <p class="mb-2"><strong>IP Address:</strong> <code class="bg-dark text-light px-2 py-1 rounded">{}</code></p>\n'.format(data['ip_address'])
        
        if 'location' in data and data['location']:
            has_data = True
            html += '                                    <p class="mb-2"><strong>Location:</strong> {}</p>\n'.format(data['location'])
        
        if 'org' in data and data['org']:
            has_data = True
            html += '                                    <p class="mb-2"><strong>Organization:</strong> {}</p>\n'.format(data['org'])
        
        if 'asn' in data and data['asn']:
            has_data = True
            html += '                                    <p class="mb-2"><strong>ASN:</strong> {}</p>\n'.format(data['asn'])
        
        if 'hostname' in data and data['hostname']:
            has_data = True
            html += '                                    <p class="mb-2"><strong>Hostname:</strong> {}</p>\n'.format(data['hostname'])
        
        if not has_data:
            html += '                                    <div class="alert alert-info mb-0">\n'
            html += '                                        <i class="fas fa-info-circle me-2"></i>No information available.\n'
            html += '                                    </div>\n'
        
        html += '                                </div>\n'
        html += '                            </div>\n'
    
    def _generate_subdomain_section(self, html, data):
        """Generate HTML for subdomain enumeration section."""
        if 'subdomains' in data and data['subdomains']:
            subdomains = data['subdomains']
            total = len(subdomains)
            
            html += '                            <p class="mb-3">Found {} subdomain{}</p>\n'.format(total, 's' if total != 1 else '')
            
            if total > 0:
                html += '                            <div class="table-responsive">\n'
                html += '                                <table class="table table-striped table-sm">\n'
                html += '                                    <thead class="table-light">\n'
                html += '                                        <tr>\n'
                html += '                                            <th>Subdomain</th>\n'
                html += '                                            <th class="text-end">Status</th>\n'
                html += '                                        </tr>\n'
                html += '                                    </thead>\n'
                html += '                                    <tbody>\n'
                
                for subdomain in subdomains:
                    html += '                                        <tr>\n'
                    html += '                                            <td><code class="bg-light px-2 py-1 rounded">{}</code></td>\n'.format(subdomain)
                    html += '                                            <td class="text-end"><span class="badge bg-success">Active</span></td>\n'
                    html += '                                        </tr>\n'
                
                html += '                                    </tbody>\n'
                html += '                                </table>\n'
                html += '                            </div>\n'
        else:
            html += '                            <div class="alert alert-info">\n'
            html += '                                <i class="fas fa-info-circle me-2"></i>No subdomains were found.\n'
            html += '                            </div>\n'
    
    def _generate_dns_security_section(self, html, data):
        """Generate HTML for DNS security section."""
        if isinstance(data, dict):
            has_data = False
            
            # DNS Records
            if 'records' in data and data['records']:
                has_data = True
                html += '                            <h5 class="mb-3">DNS Records</h5>\n'
                html += '                            <div class="table-responsive mb-4">\n'
                html += '                                <table class="table table-striped table-sm">\n'
                html += '                                    <thead class="table-light">\n'
                html += '                                        <tr>\n'
                html += '                                            <th>Type</th>\n'
                html += '                                            <th>Value</th>\n'
                html += '                                        </tr>\n'
                html += '                                    </thead>\n'
                html += '                                    <tbody>\n'
                
                for record_type, records in data['records'].items():
                    if records:
                        for record in records:
                            html += '                                        <tr>\n'
                            html += '                                            <td><strong>{}</strong></td>\n'.format(record_type)
                            html += '                                            <td><code class="bg-light px-2 py-1 rounded">{}</code></td>\n'.format(record)
                            html += '                                        </tr>\n'
                
                html += '                                    </tbody>\n'
                html += '                                </table>\n'
                html += '                            </div>\n'
            
            # DNSSEC
            if 'dnssec' in data:
                has_data = True
                if data['dnssec']:
                    html += '                            <div class="alert alert-success mb-3">\n'
                    html += '                                <i class="fas fa-shield-alt me-2"></i>DNSSEC is enabled for this domain.\n'
                    html += '                            </div>\n'
                else:
                    html += '                            <div class="alert alert-warning mb-3">\n'
                    html += '                                <i class="fas fa-exclamation-triangle me-2"></i>DNSSEC is not enabled for this domain.\n'
                    html += '                            </div>\n'
            
            # Zone Transfer
            if 'zone_transfer' in data:
                has_data = True
                if data['zone_transfer'].get('vulnerable', False):
                    html += '                            <div class="alert alert-danger mb-3">\n'
                    html += '                                <i class="fas fa-exclamation-triangle me-2"></i>Domain is vulnerable to zone transfer attacks!\n'
                    html += '                            </div>\n'
                else:
                    html += '                            <div class="alert alert-success mb-3">\n'
                    html += '                                <i class="fas fa-check-circle me-2"></i>Domain is not vulnerable to zone transfer attacks.\n'
                    html += '                            </div>\n'
            
            if not has_data:
                html += '                            <div class="alert alert-info">\n'
                html += '                                <i class="fas fa-info-circle me-2"></i>No DNS security information available.\n'
                html += '                            </div>\n'
        else:
            html += '                            <div class="alert alert-info">\n'
            html += '                                <i class="fas fa-info-circle me-2"></i>No DNS security information available.\n'
            html += '                            </div>\n'
    
    def _generate_waf_section(self, html, data):
        """Generate HTML for WAF detection section."""
        if isinstance(data, dict):
            html += '                            <div class="card border-0 bg-light">\n'
            html += '                                <div class="card-body">\n'
            
            if 'waf_detected' in data:
                if data['waf_detected']:
                    html += '                                    <div class="alert alert-warning mb-3">\n'
                    html += '                                        <i class="fas fa-shield-alt me-2"></i>Web Application Firewall (WAF) detected!\n'
                    html += '                                    </div>\n'
                    
                    if 'waf_name' in data and data['waf_name']:
                        html += '                                    <p class="mb-2"><strong>WAF Name:</strong> {}</p>\n'.format(data['waf_name'])
                    
                    if 'waf_details' in data and data['waf_details']:
                        html += '                                    <p class="mb-2"><strong>WAF Details:</strong> {}</p>\n'.format(data['waf_details'])
                else:
                    html += '                                    <div class="alert alert-info mb-0">\n'
                    html += '                                        <i class="fas fa-info-circle me-2"></i>No Web Application Firewall (WAF) detected.\n'
                    html += '                                    </div>\n'
            else:
                html += '                                    <div class="alert alert-info mb-0">\n'
                html += '                                        <i class="fas fa-info-circle me-2"></i>WAF detection information not available.\n'
                html += '                                    </div>\n'
            
            html += '                                </div>\n'
            html += '                            </div>\n'
        else:
            html += '                            <div class="alert alert-info">\n'
            html += '                                <i class="fas fa-info-circle me-2"></i>WAF detection information not available.\n'
            html += '                            </div>\n'

    def _generate_port_scanner_section(self, html, data):
        """Generate HTML for port scanner section."""
        if 'open_ports' in data and data['open_ports']:
            ports = data['open_ports']
            html += '                            <div class="table-responsive">\n'
            html += '                                <table class="table table-striped table-sm">\n'
            html += '                                    <thead class="table-light">\n'
            html += '                                        <tr>\n'
            html += '                                            <th>Port</th>\n'
            html += '                                            <th>Service</th>\n'
            html += '                                            <th>Status</th>\n'
            html += '                                        </tr>\n'
            html += '                                    </thead>\n'
            html += '                                    <tbody>\n'
            
            for port in ports:
                port_num = port.get('port', '')
                service = port.get('service', '')
                status = port.get('status', 'open')
                
                html += '                                        <tr>\n'
                html += '                                            <td><code class="bg-light px-2 py-1 rounded">{}</code></td>\n'.format(port_num)
                html += '                                            <td>{}</td>\n'.format(service)
                html += '                                            <td><span class="badge bg-success">{}</span></td>\n'.format(status)
                html += '                                        </tr>\n'
            
            html += '                                    </tbody>\n'
            html += '                                </table>\n'
            html += '                            </div>\n'
        else:
            html += '                            <div class="alert alert-info">\n'
            html += '                                <i class="fas fa-info-circle me-2"></i>No open ports were found.\n'
            html += '                            </div>\n'
    
    def _generate_content_discovery_section(self, html, data):
        """Generate HTML for content discovery section."""
        if 'discovered_urls' in data and data['discovered_urls']:
            urls = data['discovered_urls']
            total = len(urls)
            
            html += '                            <p class="mb-3">Found {} URL{}</p>\n'.format(total, 's' if total != 1 else '')
            
            if total > 0:
                html += '                            <div class="table-responsive">\n'
                html += '                                <table class="table table-striped table-sm">\n'
                html += '                                    <thead class="table-light">\n'
                html += '                                        <tr>\n'
                html += '                                            <th>URL</th>\n'
                html += '                                            <th>Status</th>\n'
                html += '                                        </tr>\n'
                html += '                                    </thead>\n'
                html += '                                    <tbody>\n'
                
                for url_data in urls:
                    if isinstance(url_data, str):
                        url = url_data
                        status = "200"
                    else:
                        url = url_data.get('url', '')
                        status = url_data.get('status', '200')
                    
                    status_class = "bg-success"
                    if str(status).startswith('3'):
                        status_class = "bg-info"
                    elif str(status).startswith('4'):
                        status_class = "bg-warning"
                    elif str(status).startswith('5'):
                        status_class = "bg-danger"
                    
                    html += '                                        <tr>\n'
                    html += '                                            <td><code class="bg-light px-2 py-1 rounded">{}</code></td>\n'.format(url)
                    html += '                                            <td><span class="badge {}">{}</span></td>\n'.format(status_class, status)
                    html += '                                        </tr>\n'
                
                html += '                                    </tbody>\n'
                html += '                                </table>\n'
                html += '                            </div>\n'
        else:
            html += '                            <div class="alert alert-info">\n'
            html += '                                <i class="fas fa-info-circle me-2"></i>No content was discovered.\n'
            html += '                            </div>\n'
    
    def _generate_vuln_scanner_section(self, html, data):
        """Generate HTML for vulnerability scanner section."""
        has_data = False
        
        if 'vulnerabilities' in data and data['vulnerabilities']:
            has_data = True
            vulns = data['vulnerabilities']
            
            html += '                            <div class="mb-4">\n'
            html += '                                <h6 class="mb-3">Detected Vulnerabilities</h6>\n'
            
            for vuln in vulns:
                severity = vuln.get('severity', 'medium').lower()
                severity_class = "danger" if severity == "high" else "warning" if severity == "medium" else "info"
                
                html += '                                <div class="alert alert-{} mb-3">\n'.format(severity_class)
                html += '                                    <h6 class="alert-heading fw-bold">{}</h6>\n'.format(vuln.get('name', 'Unknown Vulnerability'))
                if 'description' in vuln:
                    html += '                                    <p>{}</p>\n'.format(vuln.get('description', ''))
                if 'details' in vuln:
                    html += '                                    <p class="mb-0">{}</p>\n'.format(vuln.get('details', ''))
                html += '                                </div>\n'
            
            html += '                            </div>\n'
        
        if 'cves' in data and data['cves']:
            has_data = True
            cves = data['cves']
            
            html += '                            <div class="mb-3">\n'
            html += '                                <h6 class="mb-3">Common Vulnerabilities and Exposures (CVEs)</h6>\n'
            
            html += '                                <div class="table-responsive">\n'
            html += '                                    <table class="table table-striped table-sm">\n'
            html += '                                        <thead class="table-light">\n'
            html += '                                            <tr>\n'
            html += '                                                <th>CVE ID</th>\n'
            html += '                                                <th>Severity</th>\n'
            html += '                                                <th>Description</th>\n'
            html += '                                            </tr>\n'
            html += '                                        </thead>\n'
            html += '                                        <tbody>\n'
            
            for cve in cves:
                cve_id = cve.get('id', 'Unknown')
                severity = cve.get('severity', 'medium').lower()
                description = cve.get('description', '')
                
                severity_class = "danger" if severity == "high" else "warning" if severity == "medium" else "info"
                
                html += '                                            <tr>\n'
                html += '                                                <td><code class="bg-light px-2 py-1 rounded">{}</code></td>\n'.format(cve_id)
                html += '                                                <td><span class="badge bg-{}">{}</span></td>\n'.format(severity_class, severity.upper())
                html += '                                                <td>{}</td>\n'.format(description)
                html += '                                            </tr>\n'
            
            html += '                                        </tbody>\n'
            html += '                                    </table>\n'
            html += '                                </div>\n'
            html += '                            </div>\n'
        
        if not has_data:
            html += '                            <div class="alert alert-success">\n'
            html += '                                <i class="fas fa-check-circle me-2"></i>No vulnerabilities were detected.\n'
            html += '                            </div>\n'
    
    def _generate_screenshot_section(self, html, data):
        """Generate HTML for screenshot section."""
        if 'screenshots' in data and data['screenshots']:
            screenshots = data['screenshots']
            
            html += '                            <div class="row g-4">\n'
            
            for screenshot in screenshots:
                url = screenshot.get('url', 'Screenshot')
                path = screenshot.get('path', '')
                
                html += '                                <div class="col-md-6 mb-4">\n'
                html += '                                    <div class="card border-0 shadow-sm">\n'
                html += '                                        <div class="card-header bg-white">\n'
                html += '                                            <span class="text-truncate">{}</span>\n'.format(url)
                html += '                                        </div>\n'
                html += '                                        <img src="{}" class="card-img-top img-fluid" alt="Screenshot of {}">\n'.format(path, url)
                html += '                                    </div>\n'
                html += '                                </div>\n'
            
            html += '                            </div>\n'
        else:
            html += '                            <div class="alert alert-info">\n'
            html += '                                <i class="fas fa-info-circle me-2"></i>No screenshots were captured.\n'
            html += '                            </div>\n'
