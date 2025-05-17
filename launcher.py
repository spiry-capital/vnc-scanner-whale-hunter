#!/usr/bin/env python3
"""
launcher.py - Cyberpunk launcher UI pentru scanare VNC pe range-uri mari, cu progres live prin multiprocessing.Queue

Rulează:
    python launcher.py
"""
import sys
import os
import time
import ipaddress
from multiprocessing import Pool, Manager
from rich.console import Console
from rich.console import Group
from rich.panel import Panel
from rich.text import Text
import questionary
from rich.live import Live
from rich.table import Table
from rich.align import Align
from rich.style import Style
import random
import re
from scan import scan_worker
from rich.box import DOUBLE
import itertools

CYBERPUNK = "bold magenta on black"
console = Console()
CYBER_BANNER = """
[bold magenta]███ LIVE DATA ███[/bold magenta]
"""

# --------- Functii de split ---------
def split_range(base_range):
    parts = base_range.split('.')
    wildcards = [i for i, p in enumerate(parts) if p == '*']
    if not wildcards:
        return [base_range]
    split_idx = wildcards[0]
    subranges = []
    for i in range(256):
        new_parts = parts[:]
        new_parts[split_idx] = str(i)
        subranges.append('.'.join(new_parts))
    return subranges

def cidr_to_wildcards(cidr):
    net = ipaddress.IPv4Network(cidr, strict=False)
    if net.prefixlen <= 24:
        subnets = list(net.subnets(new_prefix=24))
        return [str(subnet.network_address).rsplit('.', 1)[0] + '.*' for subnet in subnets]
    else:
        return [str(net.network_address).rsplit('.', 1)[0] + '.*']

def get_ips_per_subrange(ip_range):
    parts = ip_range.split('.')
    wildcard_count = parts.count('*')
    if wildcard_count == 1:
        return 256
    elif wildcard_count == 2:
        return 256*256
    elif wildcard_count == 3:
        return 256*256*256
    else:
        return 1

# --------- Functia de scanare (slave) ---------
def run_scan(subrange, threads, batch, timeout, progress_dict, subrange_id, port, total):
    scan_path = os.path.join(os.path.dirname(__file__), 'scan.py')
    print(f"[DEBUG] Pornesc scan.py pentru subrange {subrange_id} ({subrange}) cu total={total} (scan_path={scan_path})")
    cmd = [
        sys.executable, scan_path,
        "--range", subrange,
        "--port", str(port),
        "--threads", str(threads),
        "--no-ui",
        "--progress-id", str(subrange_id),
        "--use-manager-dict",
        "--total", str(total)
    ]
    if timeout:
        cmd += ["--timeout", str(timeout)]
    import pickle
    env = os.environ.copy()
    env["PROGRESS_DICT_ADDR"] = pickle.dumps(progress_dict)._hex()
    print(f"[DEBUG] CMD: {' '.join(cmd)}")
    subprocess.run(cmd, env=env)

def matrix_rain_line(width=60):
    # Generate a random matrix rain line with more color
    chars = "01"
    colors = ["green", "cyan", "yellow"]
    return "".join(f"[{random.choice(colors)}]{random.choice(chars)}[/]" for _ in range(width))

def parse_progress_line(line):
    regex = r"Progress: (\d+)/(\d+) \| Found: (\d+) \| Timeouts: (\d+) \| Errors: (\d+) \| Rate: ([0-9.]+) \| ETA: ([0-9:]+)"
    m = re.match(regex, line)
    if not m:
        return None
    return {
        "progress": int(m.group(1)),
        "total": int(m.group(2)),
        "found": int(m.group(3)),
        "timeouts": int(m.group(4)),
        "errors": int(m.group(5)),
        "rate": float(m.group(6)),
        "eta": m.group(7)
    }

def matrix_rain_frame(width=60, height=6, prev=None):
    # Animate vertical rain: shift previous lines down, add new line on top
    if prev is None:
        prev = [matrix_rain_line(width) for _ in range(height)]
    else:
        prev = [matrix_rain_line(width)] + prev[:-1]
    # Dynamic highlights: randomly highlight a few columns
    highlight_cols = set(random.sample(range(width), k=random.randint(2, 6)))
    frame = []
    for y, line in enumerate(prev):
        chars = []
        i = 0
        in_tag = False
        color = None
        while i < len(line):
            if line[i] == '[':
                in_tag = True
                tag_start = i
                tag_end = line.find(']', i)
                color = line[tag_start+1:tag_end]
                chars.append(line[tag_start:tag_end+1])
                i = tag_end+1
                continue
            if line[i] == '/' and in_tag:
                tag_end = line.find(']', i)
                chars.append(line[i:tag_end+1])
                in_tag = False
                color = None
                i = tag_end+1
                continue
            if not in_tag and color:
                col_idx = len([c for c in chars if c not in ('[green]','[cyan]','[yellow]','[/]')])
                if col_idx in highlight_cols and y == 0:
                    chars.append(f"[magenta]{line[i]}[/magenta]")
                elif col_idx in highlight_cols and y == len(prev)-1:
                    chars.append(f"[white]{line[i]}[/white]")
                else:
                    chars.append(line[i])
            else:
                chars.append(line[i])
            i += 1
        frame.append(''.join(chars))
    return frame, prev

# --------- Master UI (sumar global, file-based) ---------
def master_ui(subranges, progress_dict, total_total, refresh=1):
    rain_state = None
    with Live(console=console, refresh_per_second=10, screen=True) as live:
        finished = 0
        while finished < len(subranges):
            # Read all progress from dict
            stats = [progress_dict.get(idx, {'progress': 0, 'total': 1, 'found': 0, 'timeouts': 0, 'errors': 0, 'rate': 0.0, 'eta': '00:00:00'}) for idx in range(len(subranges))]
            total_progress = sum(d['progress'] for d in stats)
            total_found = sum(d['found'] for d in stats)
            total_timeouts = sum(d['timeouts'] for d in stats)
            total_errors = sum(d['errors'] for d in stats)
            total_rate = sum(d['rate'] for d in stats)
            total_eta_seconds = max([
                int(d['eta'].split(':')[0])*3600 + int(d['eta'].split(':')[1])*60 + int(d['eta'].split(':')[2])
                for d in stats if d['eta'] != '00:00:00'] + [0])
            eta_h = total_eta_seconds // 3600
            eta_m = (total_eta_seconds % 3600) // 60
            eta_s = total_eta_seconds % 60
            eta_str = f"{eta_h:02}:{eta_m:02}:{eta_s:02}"
            active = sum(1 for d in stats if d['progress'] < d['total'])
            finished = sum(1 for d in stats if d['progress'] >= d['total'])
            # Top 3 subranges by rate
            top_subranges = sorted(enumerate(stats), key=lambda x: -x[1]['rate'])[:3]
            # Animated matrix rain
            rain_lines, rain_state = matrix_rain_frame(60, 6, rain_state)
            # Cyberpunk banner
            banner = Text.from_markup(CYBER_BANNER, justify="center")
            # Global stats table
            stats_table = Table.grid(expand=True)
            stats_table.add_row(
                f"[bold green]Progress:[/bold green] [bold white on green]{total_progress}/{total_total}[/]",
                f"[bold cyan]Found:[/bold cyan] [bold white on cyan]{total_found}[/]",
                f"[bold magenta]Timeouts:[/bold magenta] [bold white on magenta]{total_timeouts}[/]",
                f"[bold red]Errors:[/bold red] [bold white on red]{total_errors}[/]",
                f"[bold yellow]Rate:[/bold yellow] [bold black on yellow]{total_rate:.2f} IPs/sec[/]",
                f"[bold white]ETA:[/bold white] [bold black on white]{eta_str}[/]",
                f"[bold blue]Active:[/bold blue] [bold white on blue]{active}/{len(subranges)}[/]"
            )
            # Top subranges table with alternating row colors
            sub_table = Table(title="[bold magenta]Top 3 Fastest Subranges[/bold magenta]", show_header=True, header_style="bold green", box=None, pad_edge=True)
            sub_table.add_column("Subrange", style="cyan", justify="center")
            sub_table.add_column("Progress", style="green", justify="center")
            sub_table.add_column("Rate", style="yellow", justify="center")
            for i, (idx, d) in enumerate(top_subranges):
                row_style = "on #222222" if i % 2 == 0 else "on #111111"
                sub_table.add_row(
                    f"[bold]{subranges[idx]}[/bold]",
                    f"[bold]{d['progress']}/{d['total']}[/bold]",
                    f"[bold]{d['rate']:.2f}[/bold]",
                    style=row_style
                )
            # Compose panel
            panel = Panel(
                Align.center(
                    Group(
                        banner,
                        *[Align.center(Text.from_markup(line)) for line in rain_lines],
                        Text("", style="bold white"),
                        Align.center(stats_table),
                        Text("", style="bold white"),
                        Align.center(sub_table),
                        Text("", style="bold white"),
                        *[Align.center(Text.from_markup(line)) for line in rain_lines],
                        Align.center(Text("by SPAWNY666", style="dim magenta"))
                    )
                ),
                title="[bold magenta]VNC GLOBAL SEEKER[/bold magenta]",
                border_style="bright_magenta",
                box=DOUBLE,
                padding=(1,2)
            )
            live.update(panel)
            if finished == len(subranges):
                break
            time.sleep(refresh)
    console.clear()
    console.print(Panel("[bold green]Scanare completă! Toate subrange-urile au fost procesate.[/bold green]", style=CYBERPUNK))

# --------- Cyberpunk Banner ---------
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

# --------- Main (UI Interactiv) ---------
def main():
    cyberpunk_banner()
    ip_range = questionary.text("[CYBERPUNK] Range IP (ex: 109.177.*.* sau 5.107.0.0/16):").ask().strip()
    threads = int(questionary.text("[CYBERPUNK] Threads per scan [50]:", default="50").ask().strip())
    batch = int(questionary.text("[CYBERPUNK] Batch size [25]:", default="25").ask().strip())
    max_parallel = int(questionary.text("[CYBERPUNK] Max parallel [4]:", default="4").ask().strip())
    timeout = float(questionary.text("[CYBERPUNK] Timeout [5]:", default="5").ask().strip())
    console.print(Panel(f"[bold cyan]Range:[/bold cyan] {ip_range}\n[bold cyan]Threads:[/bold cyan] {threads}\n[bold cyan]Batch:[/bold cyan] {batch}\n[bold cyan]Max parallel:[/bold cyan] {max_parallel}\n[bold cyan]Timeout:[/bold cyan] {timeout}", title="[bold magenta]Ready?[/bold magenta]", style=CYBERPUNK))
    if not questionary.confirm("Lansez scanarea? (Y/n)").ask():
        console.print("[bold red]Anulat![bold red]")
        sys.exit(0)
    if '/' in ip_range:
        wildcard_ranges = cidr_to_wildcards(ip_range)
    else:
        wildcard_ranges = [ip_range]
    subranges = []
    subranges_totals = []
    for wildcard in wildcard_ranges:
        if wildcard.count('*') == 1:
            subranges.append(wildcard)
            subranges_totals.append(get_ips_per_subrange(wildcard))
        else:
            for s in split_range(wildcard):
                subranges.append(s)
                subranges_totals.append(get_ips_per_subrange(s))
    total_total = sum(subranges_totals)
    manager = Manager()
    progress_dict = manager.dict()
    with Pool(processes=max_parallel) as pool:
        pool.starmap_async(
            scan_worker,
            [(subr, 5900, timeout, threads, subranges_totals[idx], progress_dict, idx) for idx, subr in enumerate(subranges)]
        )
        master_ui(subranges, progress_dict, total_total, refresh=1)

if __name__ == "__main__":
    main() 