#!/usr/bin/env python3
"""
dashboard.py - Cyberpunk launcher UI pentru scanare VNC

Rulează:
    python dashboard.py
"""
import subprocess
import sys
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text
import questionary

CYBERPUNK = "bold magenta on black"

console = Console()

def cyberpunk_banner():
    banner = Text("""
██╗   ██╗███╗   ██╗ ██████╗      ███████╗ ██████╗ █████╗ ███╗   ██╗
██║   ██║████╗  ██║██╔════╝      ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║██╔██╗ ██║██║  ███╗     ███████╗██║     ███████║██╔██╗ ██║
██║   ██║██║╚██╗██║██║   ██║     ╚════██║██║     ██╔══██║██║╚██╗██║
╚██████╔╝██║ ╚████║╚██████╔╝     ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝      ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    """, style=CYBERPUNK)
    console.print(banner)
    console.print(Panel("[bold cyan]VNC SCANNER LAUNCHER[/bold cyan]", style="bold magenta"))

def main():
    cyberpunk_banner()
    # Întrebări interactive
    ip_range = questionary.text("[CYBERPUNK] Range IP (ex: 109.177.*.*):").ask()
    threads = questionary.text("[CYBERPUNK] Threads per scan [50]:", default="50").ask()
    batch = questionary.text("[CYBERPUNK] Batch size [25]:", default="25").ask()
    max_parallel = questionary.text("[CYBERPUNK] Max parallel [4]:", default="4").ask()
    # Confirmare
    console.print(Panel(f"[bold cyan]Range:[/bold cyan] {ip_range}\n[bold cyan]Threads:[/bold cyan] {threads}\n[bold cyan]Batch:[/bold cyan] {batch}\n[bold cyan]Max parallel:[/bold cyan] {max_parallel}", title="[bold magenta]Ready?[/bold magenta]", style=CYBERPUNK))
    if not questionary.confirm("Lansez scanarea? (Y/n)").ask():
        console.print("[bold red]Anulat![/bold red]")
        sys.exit(0)
    # Rulează launcher.py cu parametrii aleși
    cmd = [
        sys.executable, "launcher.py",
        "--range", ip_range,
        "--threads", threads,
        "--batch", batch,
        "--max-parallel", max_parallel
    ]
    console.print(Panel("[bold green]Pornesc scanarea...[/bold green]", style=CYBERPUNK))
    subprocess.run(cmd)

if __name__ == "__main__":
    main() 