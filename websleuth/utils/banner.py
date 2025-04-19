#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Banner module for WebSleuth
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

def display_banner():
    """Display the WebSleuth banner."""
    console = Console()
    
    banner = """
██╗    ██╗███████╗██████╗ ███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗
██║    ██║██╔════╝██╔══██╗██╔════╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║
██║ █╗ ██║█████╗  ██████╔╝███████╗██║     █████╗  ██║   ██║   ██║   ███████║
██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║
╚███╔███╔╝███████╗██████╔╝███████║███████╗███████╗╚██████╔╝   ██║   ██║  ██║
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
    """
    
    text = Text()
    text.append(banner, style="bold blue")
    text.append("\n\n")
    text.append("Advanced Website OSINT and Penetration Testing Tool", style="bold cyan")
    text.append("\n")
    text.append("Author: ", style="yellow")
    text.append("Triotion (https://github.com/Triotion)", style="bold yellow")
    text.append("\n")
    text.append("Version: ", style="yellow")
    text.append("1.0.0", style="bold yellow")
    
    panel = Panel(
        text,
        border_style="green",
        title="[bold red]WebSleuth[/bold red]",
        title_align="center",
        subtitle="[italic]Ethical use only[/italic]",
        subtitle_align="center"
    )
    
    console.print(panel)
    console.print("\n") 