import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from itertools import islice
import ipaddress
import os
import itertools

def batcher(iterable, n):
    it = iter(iterable)
    while True:
        batch = list(islice(it, n))
        if not batch:
            break
        yield batch

def ip_range_generator(ip_range):
    if '/' in ip_range:
        net = ipaddress.IPv4Network(ip_range, strict=False)
        for ip in net.hosts():
            yield str(ip)
    else:
        parts = ip_range.split('.')
        ranges = []
        for part in parts:
            if part == '*':
                ranges.append(range(0, 256))
            else:
                ranges.append([int(part)])
        for ip in itertools.product(*ranges):
            yield '.'.join(str(x) for x in ip)

def scan_rdp_ip(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return ip, None
    except socket.timeout:
        return None, 'timeout'
    except ConnectionRefusedError:
        return None, 'refused'
    except Exception as e:
        return None, str(e)
    return None, 'unknown'

def scan_worker(subrange, port, timeout, threads, total, progress_dict, progress_id):
    ip_gen = ip_range_generator(subrange)
    found_count = 0
    current = 0
    timeout_count = 0
    error_count = 0
    start_time = time.time()
    os.makedirs('output', exist_ok=True)
    batch_size = 10000
    with open('output/rdp_ips.txt', 'a') as f:
        for ip_batch in batcher(ip_gen, batch_size):
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(scan_rdp_ip, ip, port, timeout): ip for ip in ip_batch}
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
                    else:
                        if err == 'timeout':
                            timeout_count += 1
                        elif err == 'refused':
                            error_count += 1
                        elif err and err != 'unknown':
                            error_count += 1
                    progress_dict[progress_id] = {
                        'progress': current,
                        'total': total,
                        'found': found_count,
                        'timeouts': timeout_count,
                        'errors': error_count,
                        'rate': rate,
                        'eta': eta_str
                    }
                    time.sleep(0.01)
    duration = time.time() - start_time
    return None 