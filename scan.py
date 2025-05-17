from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from matrix_ui import found_box, matrix_progress_highlight, cyberpunk_summary
import time
from itertools import islice
from collections import deque
from rich.console import Console, Group
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
import random

def scan_ip(ip, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                sock.sendall(b"RFB 003.003\n")
                banner = sock.recv(12)
                if banner.startswith(b"RFB"):
                    sock.close()
                    return ip, None
            except Exception as e:
                sock.close()
                return None, str(e)
        elif result == 111:
            sock.close()
            return None, 'refused'
        elif result == 110:
            sock.close()
            return None, 'timeout'
        else:
            sock.close()
            return None, f'error_{result}'
    except Exception as e:
        return None, str(e)
    return None, 'unknown'

def batcher(iterable, n):
    it = iter(iterable)
    while True:
        batch = list(islice(it, n))
        if not batch:
            break
        yield batch

def matrix_line(width=40):
    return "[green]" + "".join(random.choice("01") for _ in range(width)) + "[/green]"

def scan_range(ip_iter, port, timeout, threads, total):
    found_count = 0
    current = 0
    timeout_count = 0
    error_count = 0
    start_time = time.time()
    logf = open("output/live.log", "a")
    console = Console()
    with Live(console=console, refresh_per_second=10) as live:
        with open("output/ips.txt", "a") as f:
            for ip_batch in batcher(ip_iter, 10000):
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = {executor.submit(scan_ip, ip, port, timeout): ip for ip in ip_batch}
                    for future in as_completed(futures):
                        result, err = future.result()
                        current += 1
                        elapsed = time.time() - start_time
                        rate = current / elapsed if elapsed > 0 else 0
                        if result:
                            f.write(result + "\n")
                            f.flush()
                            found_count += 1
                            matrix_progress_highlight(current, total)
                            found_box(found_count, result, "-")
                            logf.write(f"FOUND {result}\n")
                        else:
                            if err == 'timeout':
                                timeout_count += 1
                                # nu mai loghez TIMEOUT
                            elif err == 'refused':
                                logf.write(f"REFUSED {futures[future]}\n")
                            else:
                                error_count += 1
                                logf.write(f"ERROR {futures[future]}: {err}\n")
                        # Statistica live cyberpunk
                        if current % 100 == 0 or current == total:
                            table = Table.grid()
                            table.add_row(
                                f"[bold green]Progress:[/bold green] {current}/{total}",
                                f"[bold cyan]Found:[/bold cyan] {found_count}",
                                f"[bold magenta]Timeouts:[/bold magenta] {timeout_count}",
                                f"[bold red]Errors:[/bold red] {error_count}",
                                f"[bold yellow]Rate:[/bold yellow] {rate:.2f} IPs/sec"
                            )
                            panel = Panel(
                                Group(
                                    matrix_line(),
                                    table,
                                    matrix_line()
                                ),
                                title="[bold green]MATRIX LIVE STATS[/bold green]",
                                border_style="bright_green"
                            )
                            live.update(panel)
    logf.close()
    duration = time.time() - start_time
    print()  # newline după progresbar
    cyberpunk_summary(found_count, total, duration, mode="SCAN")
    return None 