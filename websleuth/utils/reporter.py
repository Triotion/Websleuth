#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reporter Module for WebSleuth
"""

import os
import json
import datetime
from rich.console import Console
from jinja2 import Environment, FileSystemLoader

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
        """Initialize the Reporter class.
        
        Args:
            url (str): The target URL.
            results (dict): The scan results.
            output_dir (str): The output directory.
        """
        self.url = url
        self.results = results
        self.output_dir = output_dir
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Ensure the output directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def generate_html_report(self):
        """Generate an HTML report of the scan results."""
        try:
            # Create a modern HTML report template
            report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSleuth Report - {self.url}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/apexcharts@3.40.0/dist/apexcharts.css">
    <style>
        :root {{
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --accent-color: #2ecc71;
            --danger-color: #e74c3c;
            --warning-color: #f39c12;
            --success-color: #27ae60;
            --info-color: #2980b9;
            --dark-color: #1a1a1a;
            --light-color: #f8f9fa;
            --border-radius: 10px;
            --card-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            --transition-speed: 0.3s;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--primary-color);
            background-color: #f0f2f5;
            margin: 0;
            padding: 0;
        }}
        
        .navbar {{
            background: linear-gradient(135deg, var(--primary-color), var(--info-color));
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            position: sticky;
            top: 0;
            z-index: 1000;
            padding: 15px 0;
        }}
        
        .navbar-brand {{
            font-weight: bold;
            font-size: 1.5rem;
            color: white !important;
        }}
        
        .navbar .nav-link {{
            color: rgba(255, 255, 255, 0.85) !important;
            margin: 0 10px;
            transition: all 0.3s ease;
        }}
        
        .navbar .nav-link:hover {{
            color: white !important;
            transform: translateY(-2px);
        }}
        
        .navbar .btn-search {{
            background-color: rgba(255, 255, 255, 0.2);
            border: none;
            color: white;
            border-radius: 50px;
            padding: 0.375rem 1rem;
        }}
        
        .container {{
            max-width: 1300px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .report-header {{
            background: linear-gradient(135deg, var(--secondary-color), var(--primary-color));
            color: white;
            border-radius: var(--border-radius);
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: var(--card-shadow);
            position: relative;
            overflow: hidden;
        }}
        
        .report-header::after {{
            content: '';
            position: absolute;
            bottom: 0;
            right: 0;
            width: 150px;
            height: 150px;
            background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white" opacity="0.1"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>') no-repeat center center;
            opacity: 0.2;
        }}
        
        .report-header h1 {{
            font-weight: 700;
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}
        
        .report-header p {{
            font-size: 1.2rem;
            opacity: 0.9;
            margin-bottom: 0;
        }}
        
        .report-section {{
            background-color: white;
            border-radius: var(--border-radius);
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: var(--card-shadow);
            transition: all var(--transition-speed) ease;
            border-top: 4px solid var(--secondary-color);
        }}
        
        .report-section:hover {{
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
            transform: translateY(-2px);
        }}
        
        .report-section h3 {{
            margin-top: 0;
            border-bottom: 2px solid #eee;
            padding-bottom: 15px;
            color: var(--secondary-color);
            display: flex;
            align-items: center;
            font-weight: 600;
        }}
        
        .report-section h3 i {{
            margin-right: 10px;
            background-color: var(--secondary-color);
            color: white;
            width: 36px;
            height: 36px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
        }}
        
        .table {{
            width: 100%;
            margin-bottom: 20px;
            border-radius: 5px;
            overflow: hidden;
        }}
        
        .table th {{
            background-color: var(--secondary-color);
            color: white;
            padding: 12px;
            text-align: left;
        }}
        
        .table td {{
            padding: 12px;
            border-bottom: 1px solid #f2f2f2;
            vertical-align: middle;
        }}
        
        .table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        
        .table tr:hover {{
            background-color: #f1f1f1;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 50px;
            font-size: 0.75em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .badge-high {{
            background-color: var(--danger-color);
            color: white;
        }}
        
        .badge-medium {{
            background-color: var(--warning-color);
            color: white;
        }}
        
        .badge-low {{
            background-color: var(--success-color);
            color: white;
        }}
        
        .badge-info {{
            background-color: var(--info-color);
            color: white;
        }}
        
        pre {{
            background-color: #f8f8f8;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            overflow: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            max-height: 400px;
        }}
        
        .summary-cards {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            flex: 1;
            min-width: 200px;
            background-color: white;
            border-radius: var(--border-radius);
            padding: 20px;
            box-shadow: var(--card-shadow);
            text-align: center;
            transition: all var(--transition-speed) ease;
            position: relative;
            overflow: hidden;
            border-bottom: 3px solid var(--secondary-color);
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }}
        
        .summary-card i {{
            font-size: 2rem;
            margin-bottom: 15px;
            background: linear-gradient(135deg, var(--secondary-color), var(--info-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .summary-card h4 {{
            margin: 0;
            font-size: 1.1rem;
            color: var(--primary-color);
            font-weight: 600;
        }}
        
        .summary-card p {{
            font-size: 2rem;
            font-weight: bold;
            margin: 10px 0 0;
            color: var(--primary-color);
        }}
        
        .chart-container {{
            width: 100%;
            height: 300px;
            margin-bottom: 20px;
        }}
        
        .nav-tabs {{
            border-bottom: 2px solid #eee;
            margin-bottom: 20px;
        }}
        
        .nav-tabs .nav-link {{
            border: none;
            color: var(--primary-color);
            font-weight: 500;
            padding: 10px 15px;
            border-radius: 0;
            margin-right: 5px;
            transition: all var(--transition-speed) ease;
        }}
        
        .nav-tabs .nav-link:hover {{
            color: var(--secondary-color);
            border-bottom: 2px solid var(--secondary-color);
        }}
        
        .nav-tabs .nav-link.active {{
            color: var(--secondary-color);
            background-color: transparent;
            border-bottom: 2px solid var(--secondary-color);
        }}
        
        .sidebar {{
            background-color: white;
            border-radius: var(--border-radius);
            padding: 20px;
            box-shadow: var(--card-shadow);
            position: sticky;
            top: 100px;
        }}
        
        .sidebar-item {{
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 5px;
            transition: all var(--transition-speed) ease;
            cursor: pointer;
        }}
        
        .sidebar-item:hover {{
            background-color: #f5f5f5;
        }}
        
        .sidebar-item.active {{
            background-color: var(--secondary-color);
            color: white;
        }}
        
        .search-box {{
            margin-bottom: 20px;
        }}
        
        .search-box input {{
            border-radius: 50px;
            padding: 10px 20px;
            border: 1px solid #eee;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
            transition: all var(--transition-speed) ease;
        }}
        
        .search-box input:focus {{
            box-shadow: 0 2px 15px rgba(52, 152, 219, 0.2);
            border-color: var(--secondary-color);
        }}
        
        .vuln-card {{
            background-color: white;
            border-radius: var(--border-radius);
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: var(--card-shadow);
            border-left: 4px solid var(--danger-color);
            transition: all var(--transition-speed) ease;
        }}
        
        .vuln-card:hover {{
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
        }}
        
        .vuln-card h4 {{
            margin-top: 0;
            color: var(--danger-color);
            font-weight: 600;
        }}
        
        .vuln-card-medium {{
            border-left-color: var(--warning-color);
        }}
        
        .vuln-card-medium h4 {{
            color: var(--warning-color);
        }}
        
        .vuln-card-low {{
            border-left-color: var(--success-color);
        }}
        
        .vuln-card-low h4 {{
            color: var(--success-color);
        }}
        
        .ssl-grade {{
            display: inline-block;
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background-color: #eee;
            text-align: center;
            line-height: 60px;
            font-size: 1.8rem;
            font-weight: bold;
            margin-right: 20px;
        }}
        
        .ssl-grade-a, .ssl-grade-a-plus {{
            background-color: var(--success-color);
            color: white;
        }}
        
        .ssl-grade-b {{
            background-color: #4caf50;
            color: white;
        }}
        
        .ssl-grade-c {{
            background-color: var(--warning-color);
            color: white;
        }}
        
        .ssl-grade-d {{
            background-color: #ff9800;
            color: white;
        }}
        
        .ssl-grade-f {{
            background-color: var(--danger-color);
            color: white;
        }}
        
        .screenshot-container {{
            margin-top: 20px;
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }}
        
        .screenshot-item {{
            border-radius: var(--border-radius);
            overflow: hidden;
            box-shadow: var(--card-shadow);
            transition: all var(--transition-speed) ease;
        }}
        
        .screenshot-item:hover {{
            transform: scale(1.03);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }}
        
        .screenshot-img {{
            width: 100%;
            height: 200px;
            object-fit: cover;
            border-bottom: 1px solid #eee;
        }}
        
        .screenshot-info {{
            padding: 15px;
            background-color: white;
        }}
        
        .screenshot-info h5 {{
            margin-top: 0;
            font-weight: 600;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        
        .dataTables_wrapper {{
            padding: 10px 0;
        }}
        
        .dataTables_filter input {{
            border-radius: 50px;
            padding: 5px 10px;
            border: 1px solid #eee;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding: 25px 0;
            color: #666;
            border-top: 1px solid #eee;
            background-color: white;
        }}
        
        .footer a {{
            color: var(--secondary-color);
            text-decoration: none;
        }}
        
        .footer a:hover {{
            text-decoration: underline;
        }}
        
        @media (max-width: 768px) {{
            .summary-cards {{
                flex-direction: column;
            }}
            
            .report-header h1 {{
                font-size: 1.8rem;
            }}
            
            .sidebar {{
                position: relative;
                top: 0;
                margin-bottom: 20px;
            }}
        }}
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="#">
                <i class="fas fa-shield-alt me-2"></i> WebSleuth
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="#info"><i class="fas fa-info-circle me-1"></i> Info</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#vulnerabilities"><i class="fas fa-bug me-1"></i> Vulnerabilities</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#security"><i class="fas fa-lock me-1"></i> Security</a>
                    </li>
                </ul>
                <div class="ms-3 d-none d-lg-block">
                    <input type="text" class="form-control btn-search" id="reportSearch" placeholder="Search report...">
                </div>
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="report-header">
            <h1><i class="fas fa-chart-line me-2"></i> WebSleuth Scan Report</h1>
            <p class="mb-1">Target: <strong>{self.url}</strong></p>
            <p>Scan completed on: <strong>{self.timestamp}</strong></p>
        </div>
        
        <div class="row">
            <div class="col-lg-9">
                <!-- Summary Cards -->
                <div class="summary-cards">
                    <div class="summary-card">
                        <i class="fas fa-globe"></i>
                        <h4>Subdomains</h4>
                        <p>{self.results.get('subdomain_enum', {}).get('total_found', 0)}</p>
                    </div>
                    <div class="summary-card">
                        <i class="fas fa-bug"></i>
                        <h4>Vulnerabilities</h4>
                        <p>{self.results.get('vuln_scanner', {}).get('total_vulns', 0)}</p>
                    </div>
                    <div class="summary-card">
                        <i class="fas fa-folder"></i>
                        <h4>Discovered Paths</h4>
                        <p>{self.results.get('content_discovery', {}).get('total_found', 0)}</p>
                    </div>
                    <div class="summary-card">
                        <i class="fas fa-network-wired"></i>
                        <h4>Open Ports</h4>
                        <p>{len(self.results.get('port_scanner', {}).get('open_ports', []))}</p>
                    </div>
                </div>
"""

# Continue with the rest of the implementation...
# Add sections for information gathering, vulnerabilities, etc.

# Close the HTML document
report_html += """
            </div>
            <div class="col-lg-3">
                <div class="sidebar">
                    <div class="search-box">
                        <input type="text" class="form-control" placeholder="Search sections...">
                    </div>
                    <h5>Report Sections</h5>
                    <div class="sidebar-item active">
                        <i class="fas fa-chart-bar me-2"></i> Summary
                    </div>
                    <div class="sidebar-item">
                        <i class="fas fa-info-circle me-2"></i> Information Gathering
                    </div>
                    <div class="sidebar-item">
                        <i class="fas fa-sitemap me-2"></i> Subdomains
                    </div>
                    <div class="sidebar-item">
                        <i class="fas fa-code me-2"></i> Technologies
                    </div>
                    <div class="sidebar-item">
                        <i class="fas fa-folder-open me-2"></i> Content Discovery
                    </div>
                    <div class="sidebar-item">
                        <i class="fas fa-shield-alt me-2"></i> Security Headers
                    </div>
                    <div class="sidebar-item">
                        <i class="fas fa-lock me-2"></i> SSL/TLS
                    </div>
                    <div class="sidebar-item">
                        <i class="fas fa-network-wired me-2"></i> Ports
                    </div>
                    <div class="sidebar-item">
                        <i class="fas fa-bug me-2"></i> Vulnerabilities
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="footer">
        <p>Generated by <strong>WebSleuth</strong> - Advanced Website OSINT and Penetration Testing Tool</p>
        <p>Author: <a href="https://github.com/Triotion" target="_blank">Triotion</a></p>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.4.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/apexcharts@3.40.0/dist/apexcharts.min.js"></script>
    <script>
        $(document).ready(function() {
            // Initialize DataTables for all tables
            $('.table').DataTable({
                responsive: true,
                order: [],
                pageLength: 10,
                lengthMenu: [5, 10, 25, 50],
                language: {
                    search: "<i class='fas fa-search'></i> _INPUT_",
                    searchPlaceholder: "Search..."
                }
            });
            
            // Smooth scrolling for anchor links
            $('a[href^="#"]').on('click', function(event) {
                event.preventDefault();
                $('html, body').animate({
                    scrollTop: $($.attr(this, 'href')).offset().top - 80
                }, 500);
            });
            
            // Sidebar active state
            $('.sidebar-item').on('click', function() {
                $('.sidebar-item').removeClass('active');
                $(this).addClass('active');
            });
            
            // Search functionality
            $('#reportSearch').on('keyup', function() {
                var value = $(this).val().toLowerCase();
                $('.report-section, .vuln-card').filter(function() {
                    $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1);
                });
            });
            
            // Sidebar section search
            $('.search-box input').on('keyup', function() {
                var value = $(this).val().toLowerCase();
                $('.sidebar-item').filter(function() {
                    $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1);
                });
            });
        });
    </script>
</body>
</html>
"""
            
            # Write the HTML report to a file
            report_path = os.path.join(self.output_dir, 'report.html')
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_html)
            
            console.print(f"[bold green]HTML report saved to {report_path}[/bold green]")
            return report_path
            
        except Exception as e:
            console.print(f"[bold red]Error generating HTML report: {str(e)}[/bold red]")
            return None
    
    def generate_json_report(self):
        """Generate a JSON report of the scan results."""
        try:
            report_data = {
                "target": self.url,
                "timestamp": self.timestamp,
                "results": self.results
            }
            
            report_path = os.path.join(self.output_dir, 'report.json')
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4, cls=DateTimeEncoder)
            
            console.print(f"[bold green]JSON report saved to {report_path}[/bold green]")
            return report_path
            
        except Exception as e:
            console.print(f"[bold red]Error generating JSON report: {str(e)}[/bold red]")
            return None
    
    def generate_pdf_report(self):
        """Generate a PDF report of the scan results."""
        try:
            # For PDF generation, we'll use the HTML report and convert it
            # Since this requires additional dependencies, we'll just leave a stub
            html_report_path = self.generate_html_report()
            
            if html_report_path:
                pdf_report_path = os.path.join(self.output_dir, 'report.pdf')
                
                console.print("[bold yellow]PDF generation requires additional libraries.[/bold yellow]")
                console.print("[bold yellow]To generate PDF reports, install 'weasyprint' package.[/bold yellow]")
                console.print("[bold yellow]Then modify this method to use weasyprint for HTML to PDF conversion.[/bold yellow]")
                
                # Commented implementation for anyone who wants to add PDF support
                """
                from weasyprint import HTML
                HTML(html_report_path).write_pdf(pdf_report_path)
                console.print(f"[bold green]PDF report saved to {pdf_report_path}[/bold green]")
                """
                
                return pdf_report_path
            
        except Exception as e:
            console.print(f"[bold red]Error generating PDF report: {str(e)}[/bold red]")
            return None 