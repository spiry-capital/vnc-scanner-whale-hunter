from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from matrix_ui import matrix_progress, found_box, matrix_progress_highlight, cyberpunk_summary
import time
from itertools import islice

def scan_ip(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = sock.recv(12)
            if banner.startswith(b"RFB"):
                return ip
    except Exception:
        return None

def batcher(iterable, n):
    it = iter(iterable)
    while True:
        batch = list(islice(it, n))
        if not batch:
            break
        yield batch

def scan_range(ip_iter, port, timeout, threads, total):
    found_count = 0
    current = 0
    start_time = time.time()
    with open("output/ips.txt", "a") as f:
        for ip_batch in batcher(ip_iter, 10000):
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(scan_ip, ip, port, timeout): ip for ip in ip_batch}
                for future in as_completed(futures):
                    result = future.result()
                    current += 1
                    if result:
                        f.write(result + "\n")
                        f.flush()
                        found_count += 1
                        matrix_progress_highlight(current, total)
                        found_box(found_count, result, "-")
                    else:
                        matrix_progress(current, total)
    duration = time.time() - start_time
    cyberpunk_summary(found_count, total, duration, mode="SCAN")
    return None 