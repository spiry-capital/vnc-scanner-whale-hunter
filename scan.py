from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from matrix_ui import matrix_progress, found_box, matrix_progress_highlight, cyberpunk_summary
import time

def scan_ip(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = sock.recv(12)
            if banner.startswith(b"RFB"):
                return ip
    except Exception:
        return None

def scan_range(ip_iter, port, timeout, threads, total):
    found = []
    current = 0
    start_time = time.time()
    with open("output/ips.txt", "a") as f:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_ip, ip, port, timeout): ip for ip in ip_iter}
            for future in as_completed(futures):
                result = future.result()
                current += 1
                if result:
                    found.append(result)
                    f.write(result + "\n")
                    f.flush()
                    matrix_progress_highlight(current, total)
                    found_box(len(found), result, "-")
                else:
                    matrix_progress(current, total)
    duration = time.time() - start_time
    cyberpunk_summary(len(found), total, duration, mode="SCAN")
    return found 