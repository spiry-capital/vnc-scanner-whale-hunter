from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from matrix_ui import found_box, matrix_progress_highlight, cyberpunk_summary
import time
from itertools import islice
from rich.console import Console, Group
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
import random
from config import DEFAULT_CONFIG
import argparse
import multiprocessing
import multiprocessing.managers
import os
import sys
import ipaddress
import pickle

def scan_ip(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            try:
                sock.sendall(b"RFB 003.003\n")
                banner = sock.recv(12)
                if banner.startswith(b"RFB"):
                    return ip, None
            except Exception as e:
                return None, str(e)
    except socket.timeout:
        return None, 'timeout'
    except ConnectionRefusedError:
        return None, 'refused'
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
    batch_size = DEFAULT_CONFIG.get("scan_batch_size", 10000)
    with Live(console=console, refresh_per_second=10) as live:
        with open("output/ips.txt", "a") as f:
            for ip_batch in batcher(ip_iter, batch_size):
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = {executor.submit(scan_ip, ip, port, timeout): ip for ip in ip_batch}
                    for future in as_completed(futures):
                        result, err = future.result()
                        current += 1
                        elapsed = time.time() - start_time
                        rate = current / elapsed if elapsed > 0 else 0
                        ips_left = total - current
                        eta_seconds = int(ips_left / rate) if rate > 0 else 0
                        eta_h = eta_seconds // 3600
                        eta_m = (eta_seconds % 3600) // 60
                        eta_s = eta_seconds % 60
                        eta_str = f"{eta_h:02}:{eta_m:02}:{eta_s:02}"
                        if ips_left <= 0:
                            eta_str = "00:00:00"
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
                            elif err == 'refused':
                                logf.write(f"REFUSED {futures[future]}\n")
                                error_count += 1
                            elif err and err != 'unknown':
                                error_count += 1
                                logf.write(f"ERROR {futures[future]}: {err}\n")
                        # Statistica live cyberpunk - actualizez după fiecare rezultat
                        table = Table.grid()
                        table.add_row(
                            f"[bold green]Progress:[/bold green] {current}/{total}",
                            f"[bold cyan]Found:[/bold cyan] {found_count}",
                            f"[bold magenta]Timeouts:[/bold magenta] {timeout_count}",
                            f"[bold red]Errors:[/bold red] {error_count}",
                            f"[bold yellow]Rate:[/bold yellow] {rate:.2f} IPs/sec",
                            f"[bold white]ETA:[/bold white] {eta_str}"
                        )
                        panel = Panel(
                            Group(
                                matrix_line(),
                                table,
                                matrix_line()
                            ),
                            title=f"[bold green]MATRIX LIVE STATS[/bold green] [bold yellow]Threads: {threads} Batch: {batch_size}[/bold yellow]",
                            border_style="bright_green"
                        )
                        live.update(panel)
                time.sleep(0.05)  # delay mic între batch-uri
    logf.close()
    duration = time.time() - start_time
    print()  # newline după progresbar
    cyberpunk_summary(found_count, total, duration, mode="SCAN")
    return None

def scan_range_no_ui(ip_iter, port, timeout, threads, total, progress_file=None):
    found_count = 0
    current = 0
    timeout_count = 0
    error_count = 0
    start_time = time.time()
    logf = open("output/live.log", "a")
    batch_size = DEFAULT_CONFIG.get("scan_batch_size", 10000)
    print(f"[DEBUG scan.py] progress_file={progress_file}")
    with open("output/ips.txt", "a") as f:
        for ip_batch in batcher(ip_iter, batch_size):
            print(f"[DEBUG scan.py] batch: {ip_batch}")
            if not ip_batch:
                print(f"[DEBUG scan.py] batch gol!")
            batch_start = current
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(scan_ip, ip, port, timeout): ip for ip in ip_batch}
                for future in as_completed(futures):
                    result, err = future.result()
                    current += 1
                    elapsed = time.time() - start_time
                    rate = current / elapsed if elapsed > 0 else 0
                    ips_left = total - current
                    eta_seconds = int(ips_left / rate) if rate > 0 else 0
                    eta_h = eta_seconds // 3600
                    eta_m = (eta_seconds % 3600) // 60
                    eta_s = eta_seconds % 60
                    eta_str = f"{eta_h:02}:{eta_m:02}:{eta_s:02}"
                    if ips_left <= 0:
                        eta_str = "00:00:00"
                    if result:
                        f.write(result + "\n")
                        f.flush()
                        found_count += 1
                        logf.write(f"FOUND {result}\n")
                    else:
                        if err == 'timeout':
                            timeout_count += 1
                        elif err == 'refused':
                            logf.write(f"REFUSED {futures[future]}\n")
                            error_count += 1
                        elif err and err != 'unknown':
                            error_count += 1
                            logf.write(f"ERROR {futures[future]}: {err}\n")
            # Scrie progresul în fișier, dacă e cazul (doar la finalul batch-ului)
            if progress_file:
                try:
                    with open(progress_file, "w") as pf:
                        pf.write(f"Progress: {current}/{total} | Found: {found_count} | Timeouts: {timeout_count} | Errors: {error_count} | Rate: {rate:.2f} | ETA: {eta_str}\n")
                    print(f"[DEBUG scan.py] Am scris progres batch la {progress_file}")
                except Exception as e:
                    print(f"[DEBUG scan.py] Eroare la scrierea progresului in {progress_file}: {e}")
            time.sleep(0.05)
    logf.close()
    duration = time.time() - start_time
    print()  # newline după progresbar
    cyberpunk_summary(found_count, total, duration, mode="SCAN")
    return None

def scan_range_queue(ip_iter, port, timeout, threads, total, subrange_id, queue):
    found_count = 0
    current = 0
    timeout_count = 0
    error_count = 0
    start_time = time.time()
    logf = open("output/live.log", "a")
    batch_size = DEFAULT_CONFIG.get("scan_batch_size", 10000)
    with open("output/ips.txt", "a") as f:
        for ip_batch in batcher(ip_iter, batch_size):
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(scan_ip, ip, port, timeout): ip for ip in ip_batch}
                for future in as_completed(futures):
                    result, err = future.result()
                    current += 1
                    elapsed = time.time() - start_time
                    rate = current / elapsed if elapsed > 0 else 0
                    ips_left = total - current
                    eta_seconds = int(ips_left / rate) if rate > 0 else 0
                    eta_h = eta_seconds // 3600
                    eta_m = (eta_seconds % 3600) // 60
                    eta_s = eta_seconds % 60
                    eta_str = f"{eta_h:02}:{eta_m:02}:{eta_s:02}"
                    if ips_left <= 0:
                        eta_str = "00:00:00"
                    if result:
                        f.write(result + "\n")
                        f.flush()
                        found_count += 1
                        logf.write(f"FOUND {result}\n")
                    else:
                        if err == 'timeout':
                            timeout_count += 1
                        elif err == 'refused':
                            logf.write(f"REFUSED {futures[future]}\n")
                            error_count += 1
                        elif err and err != 'unknown':
                            error_count += 1
                            logf.write(f"ERROR {futures[future]}: {err}\n")
            # Trimite progresul în queue la finalul batch-ului
            queue.put((subrange_id, current, found_count, timeout_count, error_count, rate, eta_str))
            time.sleep(0.05)
    logf.close()
    duration = time.time() - start_time
    print()  # newline după progresbar
    cyberpunk_summary(found_count, total, duration, mode="SCAN")
    return None

def scan_range_manager(ip_iter, port, timeout, threads, total, progress_dict, progress_id):
    found_count = 0
    current = 0
    timeout_count = 0
    error_count = 0
    start_time = time.time()
    logf = open("output/live.log", "a")
    batch_size = DEFAULT_CONFIG.get("scan_batch_size", 10000)
    with open("output/ips.txt", "a") as f:
        for ip_batch in batcher(ip_iter, batch_size):
            batch_start = current
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(scan_ip, ip, port, timeout): ip for ip in ip_batch}
                for future in as_completed(futures):
                    result, err = future.result()
                    current += 1
                    elapsed = time.time() - start_time
                    rate = current / elapsed if elapsed > 0 else 0
                    ips_left = total - current
                    eta_seconds = int(ips_left / rate) if rate > 0 else 0
                    eta_h = eta_seconds // 3600
                    eta_m = (eta_seconds % 3600) // 60
                    eta_s = eta_seconds % 60
                    eta_str = f"{eta_h:02}:{eta_m:02}:{eta_s:02}"
                    if ips_left <= 0:
                        eta_str = "00:00:00"
                    if result:
                        f.write(result + "\n")
                        f.flush()
                        found_count += 1
                        logf.write(f"FOUND {result}\n")
                    else:
                        if err == 'timeout':
                            timeout_count += 1
                        elif err == 'refused':
                            logf.write(f"REFUSED {futures[future]}\n")
                            error_count += 1
                        elif err and err != 'unknown':
                            error_count += 1
                            logf.write(f"ERROR {futures[future]}: {err}\n")
            # Update progress in manager dict
            progress_dict[progress_id] = {
                'progress': current,
                'total': total,
                'found': found_count,
                'timeouts': timeout_count,
                'errors': error_count,
                'rate': rate,
                'eta': eta_str
            }
            time.sleep(0.05)
    logf.close()
    duration = time.time() - start_time
    print()  # newline după progresbar
    cyberpunk_summary(found_count, total, duration, mode="SCAN")
    return None

def ip_range_generator(ip_range: str):
    ip_range = ip_range.strip()
    if '/' in ip_range:
        # CIDR
        try:
            net = ipaddress.IPv4Network(ip_range, strict=False)
            for ip in net:
                yield str(ip)
        except Exception as e:
            raise ValueError(f"Invalid CIDR range: {ip_range} ({e})")
    else:
        # Wildcard
        parts = ip_range.split('.')
        if len(parts) != 4:
            raise ValueError(f"Invalid wildcard range: {ip_range}")
        ranges = []
        for part in parts:
            part = part.strip()
            if part == '*':
                ranges.append(range(0, 256))
            elif part.isdigit() and 0 <= int(part) <= 255:
                ranges.append([int(part)])
            else:
                raise ValueError(f"Invalid octet in range: {part}")
        for a in ranges[0]:
            for b in ranges[1]:
                for c in ranges[2]:
                    for d in ranges[3]:
                        yield f"{a}.{b}.{c}.{d}"

def count_ips_in_range(ip_range: str):
    ip_range = ip_range.strip()
    if '/' in ip_range:
        try:
            net = ipaddress.IPv4Network(ip_range, strict=False)
            return net.num_addresses
        except Exception as e:
            raise ValueError(f"Invalid CIDR range: {ip_range} ({e})")
    else:
        parts = ip_range.split('.')
        if len(parts) != 4:
            raise ValueError(f"Invalid wildcard range: {ip_range}")
        total = 1
        for part in parts:
            part = part.strip()
            if part == '*':
                total *= 256
            elif part.isdigit() and 0 <= int(part) <= 255:
                continue
            else:
                raise ValueError(f"Invalid octet in range: {part}")
        return total

def scan_worker(subrange, port, timeout, threads, total, progress_dict, progress_id):
    ip_gen = ip_range_generator(subrange)
    found_count = 0
    current = 0
    timeout_count = 0
    error_count = 0
    start_time = time.time()
    logf = open("output/live.log", "a")
    batch_size = DEFAULT_CONFIG.get("scan_batch_size", 10000)
    with open("output/ips.txt", "a") as f:
        for ip_batch in batcher(ip_gen, batch_size):
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(scan_ip, ip, port, timeout): ip for ip in ip_batch}
                for future in as_completed(futures):
                    result, err = future.result()
                    current += 1
                    elapsed = time.time() - start_time
                    rate = current / elapsed if elapsed > 0 else 0
                    ips_left = total - current
                    eta_seconds = int(ips_left / rate) if rate > 0 else 0
                    eta_h = eta_seconds // 3600
                    eta_m = (eta_seconds % 3600) // 60
                    eta_s = eta_seconds % 60
                    eta_str = f"{eta_h:02}:{eta_m:02}:{eta_s:02}"
                    if ips_left <= 0:
                        eta_str = "00:00:00"
                    if result:
                        f.write(result + "\n")
                        f.flush()
                        found_count += 1
                        logf.write(f"FOUND {result}\n")
                    else:
                        if err == 'timeout':
                            timeout_count += 1
                        elif err == 'refused':
                            logf.write(f"REFUSED {futures[future]}\n")
                            error_count += 1
                        elif err and err != 'unknown':
                            error_count += 1
                            logf.write(f"ERROR {futures[future]}: {err}\n")
            progress_dict[progress_id] = {
                'progress': current,
                'total': total,
                'found': found_count,
                'timeouts': timeout_count,
                'errors': error_count,
                'rate': rate,
                'eta': eta_str
            }
            time.sleep(0.05)
    logf.close()
    duration = time.time() - start_time
    print()  # newline după progresbar
    cyberpunk_summary(found_count, total, duration, mode="SCAN")
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--range", type=str, required=True, help="Range of IPs to scan (wildcard or CIDR)")
    parser.add_argument("--port", type=int, required=True, help="Port to scan")
    parser.add_argument("--timeout", type=float, required=True, help="Timeout for each scan")
    parser.add_argument("--threads", type=int, required=True, help="Number of threads to use")
    parser.add_argument("--progress-file", type=str, default=None, help="Fișierul de progres pentru acest subrange")
    parser.add_argument("--progress-id", type=int, default=None, help="ID-ul subrange-ului pentru progres")
    parser.add_argument("--no-ui", action="store_true", help="Dezactivează UI-ul (pentru rulare batch/slave)")
    parser.add_argument("--use-manager-dict", action="store_true", help="Folosește multiprocessing.Manager.dict pentru progres live")
    parser.add_argument("--total", type=int, default=None, help="Numărul total de IP-uri pentru acest subrange")
    args = parser.parse_args()

    try:
        ip_gen = ip_range_generator(args.range)
        total_ips = count_ips_in_range(args.range)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    # Manager.dict mode
    if args.use_manager_dict and args.progress_id is not None:
        import os
        import binascii
        dict_hex = os.environ.get("PROGRESS_DICT_ADDR")
        if dict_hex:
            progress_dict = pickle.loads(bytes.fromhex(dict_hex))
            # Use --total if provided, else fallback
            total = args.total if args.total is not None else total_ips
            print(f"[DEBUG scan.py] STARTED scan_range_manager for progress_id={args.progress_id}, total={total}")
            def scan_range_manager_debug(*a, **kw):
                result = scan_range_manager(*a, **kw)
                print(f"[DEBUG scan.py] scan_range_manager finished for progress_id={args.progress_id}")
                return result
            def scan_range_manager_with_debug(ip_iter, port, timeout, threads, total, progress_dict, progress_id):
                found_count = 0
                current = 0
                timeout_count = 0
                error_count = 0
                start_time = time.time()
                logf = open("output/live.log", "a")
                batch_size = DEFAULT_CONFIG.get("scan_batch_size", 10000)
                with open("output/ips.txt", "a") as f:
                    for ip_batch in batcher(ip_iter, batch_size):
                        batch_start = current
                        with ThreadPoolExecutor(max_workers=threads) as executor:
                            futures = {executor.submit(scan_ip, ip, port, timeout): ip for ip in ip_batch}
                            for future in as_completed(futures):
                                result, err = future.result()
                                current += 1
                                elapsed = time.time() - start_time
                                rate = current / elapsed if elapsed > 0 else 0
                                ips_left = total - current
                                eta_seconds = int(ips_left / rate) if rate > 0 else 0
                                eta_h = eta_seconds // 3600
                                eta_m = (eta_seconds % 3600) // 60
                                eta_s = eta_seconds % 60
                                eta_str = f"{eta_h:02}:{eta_m:02}:{eta_s:02}"
                                if ips_left <= 0:
                                    eta_str = "00:00:00"
                                if result:
                                    f.write(result + "\n")
                                    f.flush()
                                    found_count += 1
                                    logf.write(f"FOUND {result}\n")
                                else:
                                    if err == 'timeout':
                                        timeout_count += 1
                                    elif err == 'refused':
                                        logf.write(f"REFUSED {futures[future]}\n")
                                        error_count += 1
                                    elif err and err != 'unknown':
                                        error_count += 1
                                        logf.write(f"ERROR {futures[future]}: {err}\n")
                        # Update progress in manager dict
                        progress_dict[progress_id] = {
                            'progress': current,
                            'total': total,
                            'found': found_count,
                            'timeouts': timeout_count,
                            'errors': error_count,
                            'rate': rate,
                            'eta': eta_str
                        }
                        print(f"[DEBUG scan.py] Updated progress_dict[{progress_id}] = {progress_dict[progress_id]}")
                        time.sleep(0.05)
                logf.close()
                duration = time.time() - start_time
                print()  # newline după progresbar
                cyberpunk_summary(found_count, total, duration, mode="SCAN")
                return None
            scan_range_manager_with_debug(ip_gen, args.port, args.timeout, args.threads, total, progress_dict, args.progress_id)
        else:
            print("[ERROR] --use-manager-dict set but PROGRESS_DICT_ADDR missing in env!")
            sys.exit(1)
    elif args.progress_file:
        scan_range_no_ui(ip_gen, args.port, args.timeout, args.threads, total_ips, progress_file=args.progress_file)
    else:
        scan_range(ip_gen, args.port, args.timeout, args.threads, total_ips)

    # ... restul codului ... 