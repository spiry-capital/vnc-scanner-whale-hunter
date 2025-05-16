import sys
import time
import random

GREEN = "\033[32m"
RESET = "\033[0m"
BOLD = "\033[1m"

def matrix_banner():
    banner = [
        "  .========.",
        "  ||_______||",
        "  || ////  ||",
        "  ||_////  ||",
        "  '========'",
        "     ||||",
        " ^^^^^^^^^^",
        "  VNC SCANNER HUNTER"
    ]
    for line in banner:
        print(GREEN + BOLD + line.center(60) + RESET)
        time.sleep(0.05)
    print()

def matrix_stream(lines=10, width=60, duration=1.5):
    charset = "01"
    end_time = time.time() + duration
    while time.time() < end_time:
        for _ in range(lines):
            print(GREEN + "".join(random.choice(charset) for _ in range(width)) + RESET)
        time.sleep(0.05)
        sys.stdout.write("\033[F" * lines)
    sys.stdout.write("\033[E" * lines)

def matrix_progress(current, total, width=40):
    GREEN = "\033[32m"
    RESET = "\033[0m"
    filled = int(width * current // total)
    bar = GREEN + "[" + "#" * filled + "." * (width - filled) + "]" + RESET
    sys.stdout.write(f"\r{bar} {current}/{total}")
    sys.stdout.flush()
    if current == total:
        print()

def matrix_progress_highlight(current, total, width=40):
    PINK = "\033[38;2;255;0;255m"
    RESET = "\033[0m"
    filled = int(width * current // total)
    bar = PINK + "[" + "#" * filled + "." * (width - filled) + "]" + RESET
    sys.stdout.write(f"\r{bar} {current}/{total}")
    sys.stdout.flush()
    time.sleep(0.12)

def found_box(count, ip, pwd):
    CYBER = "\033[38;2;0;255;255m"
    PINK = "\033[38;2;255;0;255m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    box = f"{CYBER}{BOLD}┌{'─'*30}┐\n"
    box += f"│  {PINK}FOUND #{count}{CYBER}{' '*(20-len(str(count)))}│\n"
    box += f"│  IP: {ip}{' '*(22-len(ip))}│\n"
    box += f"│  PASS: {pwd}{' '*(19-len(pwd))}│\n"
    box += f"└{'─'*30}┘{RESET}"
    print("\n" + box)

def cyberpunk_summary(found_count, total, duration, mode="SCAN"):
    CYBER = "\033[38;2;0;255;255m"
    PINK = "\033[38;2;255;0;255m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    box = f"{CYBER}{BOLD}┌{'═'*36}┐\n"
    box += f"│   {PINK}{mode} SUMMARY{CYBER}{' '*(22-len(mode))}│\n"
    box += f"│   FOUND: {PINK}{found_count}{CYBER} / {total}{' '*(17-len(str(found_count)))}│\n"
    box += f"│   DURATION: {PINK}{duration:.2f}s{CYBER}{' '*(17-len(f'{duration:.2f}'))}│\n"
    box += f"└{'═'*36}┘{RESET}"
    print("\n" + box) 