#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Screenshot Capture Module for WebSleuth
"""

import os
import time
import base64
from urllib.parse import urlparse
from rich.console import Console
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, WebDriverException

console = Console()

class ScreenshotCapture:
    """Class for capturing screenshots of a target website and its subdomains."""
    
    def __init__(self, url, timeout=30, debug=False, resolution=(1920, 1080)):
        """Initialize the ScreenshotCapture class.
        
        Args:
            url (str): The target URL.
            timeout (int): Connection timeout in seconds.
            debug (bool): Enable debug mode.
            resolution (tuple): Screenshot resolution (width, height).
        """
        self.url = url
        self.timeout = timeout
        self.debug = debug
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc
        self.resolution = resolution
        
        self.results = {
            "url": self.url,
            "screenshots": [],
            "total_captured": 0,
            "errors": []
        }
        
        # Create output directory for screenshots
        output_dir = os.path.join("output", "screenshots")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        self.output_dir = output_dir
        
        # Driver setup
        self.driver = None
    
    def setup_driver(self):
        """Set up the webdriver for screenshots."""
        try:
            # Configure Chrome options
            chrome_options = Options()
            chrome_options.add_argument("--headless")  # Run in headless mode
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--disable-infobars")
            chrome_options.add_argument("--disable-notifications")
            chrome_options.add_argument(f"--window-size={self.resolution[0]},{self.resolution[1]}")
            chrome_options.add_argument(f"--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
            
            # Set up the driver
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # Set page load timeout
            self.driver.set_page_load_timeout(self.timeout)
            
            if self.debug:
                console.print("[bold green]WebDriver setup successful[/bold green]")
            
            return True
        
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error setting up WebDriver: {str(e)}[/bold red]")
            
            # Add fallback message to inform about manual installation
            console.print("[bold yellow]If ChromeDriver fails to install automatically, please install it manually:[/bold yellow]")
            console.print("[yellow]1. Download ChromeDriver from https://chromedriver.chromium.org/downloads[/yellow]")
            console.print("[yellow]2. Make sure it matches your Chrome version[/yellow]")
            console.print("[yellow]3. Place it in your PATH[/yellow]")
            
            self.results["errors"].append(f"WebDriver setup failed: {str(e)}")
            return False
    
    def capture_screenshot(self, url, output_path, filename):
        """Capture a screenshot of a URL.
        
        Args:
            url (str): URL to capture.
            output_path (str): Output directory path.
            filename (str): Output filename.
            
        Returns:
            dict: Screenshot details or None if failed.
        """
        if not self.driver:
            if self.debug:
                console.print("[bold red]WebDriver not initialized[/bold red]")
            return None
        
        try:
            # Navigate to the URL
            if self.debug:
                console.print(f"[bold blue]Capturing screenshot of {url}...[/bold blue]")
            
            self.driver.get(url)
            
            # Wait for page to load
            time.sleep(3)
            
            # Capture screenshot
            screenshot_path = os.path.join(output_path, filename)
            self.driver.save_screenshot(screenshot_path)
            
            # Also capture as base64 for reports
            screenshot_base64 = self.driver.get_screenshot_as_base64()
            
            # Get page title
            try:
                title = self.driver.title
            except:
                title = "Unknown"
            
            if self.debug:
                console.print(f"[bold green]Screenshot saved to {screenshot_path}[/bold green]")
            
            return {
                "url": url,
                "path": screenshot_path,
                "filename": filename,
                "title": title,
                "base64": screenshot_base64
            }
        
        except TimeoutException:
            if self.debug:
                console.print(f"[bold yellow]Timeout while loading {url}[/bold yellow]")
            self.results["errors"].append(f"Timeout capturing {url}")
            return None
        
        except WebDriverException as e:
            if self.debug:
                console.print(f"[bold red]WebDriver error for {url}: {str(e)}[/bold red]")
            self.results["errors"].append(f"WebDriver error: {str(e)}")
            return None
        
        except Exception as e:
            if self.debug:
                console.print(f"[bold red]Error capturing {url}: {str(e)}[/bold red]")
            self.results["errors"].append(f"Error capturing {url}: {str(e)}")
            return None
    
    def capture_main_url(self):
        """Capture a screenshot of the main URL."""
        # Generate a filename from the domain
        filename = f"{self.domain.replace(':', '_')}_main.png"
        
        # Capture the screenshot
        screenshot = self.capture_screenshot(self.url, self.output_dir, filename)
        
        if screenshot:
            self.results["screenshots"].append(screenshot)
            self.results["total_captured"] += 1
    
    def capture_subdomains(self, subdomains):
        """Capture screenshots of subdomains.
        
        Args:
            subdomains (list): List of subdomains to capture.
        """
        if not subdomains:
            if self.debug:
                console.print("[bold yellow]No subdomains provided for screenshot capture[/bold yellow]")
            return
        
        if self.debug:
            console.print(f"[bold blue]Capturing screenshots of {len(subdomains)} subdomains...[/bold blue]")
        
        for subdomain in subdomains:
            # Skip if already captured
            if any(s.get("url", "").lower() == subdomain.lower() for s in self.results["screenshots"]):
                continue
            
            # Create URL if needed
            if not subdomain.startswith(("http://", "https://")):
                subdomain_url = f"https://{subdomain}"
                fallback_url = f"http://{subdomain}"
            else:
                subdomain_url = subdomain
                protocol = "https://" if "https://" in subdomain else "http://"
                domain = subdomain.replace(protocol, "")
                fallback_url = f"{'http://' if 'https://' in protocol else 'https://'}{domain}"
            
            # Generate filename
            parsed = urlparse(subdomain_url)
            filename = f"{parsed.netloc.replace(':', '_')}.png"
            
            # Try to capture screenshot
            screenshot = self.capture_screenshot(subdomain_url, self.output_dir, filename)
            
            # If HTTPS fails, try HTTP as fallback
            if not screenshot and subdomain_url.startswith("https://"):
                if self.debug:
                    console.print(f"[bold yellow]HTTPS failed, trying HTTP for {subdomain}[/bold yellow]")
                
                fallback_filename = f"{parsed.netloc.replace(':', '_')}_http.png"
                screenshot = self.capture_screenshot(fallback_url, self.output_dir, fallback_filename)
            
            if screenshot:
                self.results["screenshots"].append(screenshot)
                self.results["total_captured"] += 1
    
    def run(self, subdomains=None):
        """Run screenshot capture.
        
        Args:
            subdomains (list, optional): List of subdomains to capture screenshots of.
        """
        console.print("[bold blue]Starting screenshot capture...[/bold blue]")
        
        # Setup webdriver
        if not self.setup_driver():
            console.print("[bold red]Failed to set up WebDriver. Screenshots will not be captured.[/bold red]")
            console.print("[bold yellow]Make sure Chrome or Chromium is installed on your system.[/bold yellow]")
            console.print(f"[bold green]Screenshot capture completed for {self.url}[/bold green]")
            return self.results
        
        try:
            # Capture main URL
            self.capture_main_url()
            
            # Capture subdomains if provided
            if subdomains:
                self.capture_subdomains(subdomains)
            
            console.print(f"[bold green]Captured {self.results['total_captured']} screenshots[/bold green]")
        
        finally:
            # Always close the driver
            if self.driver:
                try:
                    self.driver.quit()
                    if self.debug:
                        console.print("[bold green]WebDriver closed successfully[/bold green]")
                except:
                    pass
        
        console.print(f"[bold green]Screenshot capture completed for {self.url}[/bold green]")
        return self.results 