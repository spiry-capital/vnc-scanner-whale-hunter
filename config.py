import os

DEFAULT_CONFIG = {
    "scan_range": "64.*.*.*",
    "scan_port": 5900,
    "scan_timeout": 7,
    "scan_threads": 1000,
    "brute_threads": 50,
    "brute_timeout": 3,
    "auto_save": True,
    "auto_brute": True,
    "passwords": ["1234", "admin", "password", "1", "12345"]
}

def ensure_dirs():
    os.makedirs("output", exist_ok=True)
    os.makedirs("input", exist_ok=True) 