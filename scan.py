from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
from matrix_ui import matrix_progress, found_box, matrix_progress_highlight, cyberpunk_summary
import time
from itertools import islice
from collections import deque

def scan_ip(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = sock.recv(12)
            if banner.startswith(b"RFB"):
                return ip, None
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

def scan_range(ip_iter, port, timeout, threads, total):
    found_count = 0
    current = 0
    timeout_count = 0
    error_count = 0
    start_time = time.time()
    logf = open("output/live.log", "a")
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
                        matrix_progress(current, total)
                        if err == 'timeout':
                            timeout_count += 1
                        elif err == 'refused':
                            logf.write(f"REFUSED {futures[future]}\n")
                        else:
                            error_count += 1
                            logf.write(f"ERROR {futures[future]}: {err}\n")
                    # Afișare live status
                    if current % 100 == 0 or current == total:
                        print(f"\rProgress: {current}/{total} | Found: {found_count} | Timeouts: {timeout_count} | Errors: {error_count} | Rate: {rate:.2f} IPs/sec", end="")
    logf.close()
    duration = time.time() - start_time
    print()  # newline după progresbar
    cyberpunk_summary(found_count, total, duration, mode="SCAN")
    return None 