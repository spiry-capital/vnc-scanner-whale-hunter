import os

DEFAULT_CONFIG = {
    "scan_range": "109.177.*.*",
    "scan_port": 5900,
    "scan_timeout": 10,
    "scan_threads": 1000,
    "brute_threads": 250,
    "brute_timeout": 15,
    "auto_save": True,
    "auto_brute": True,
    "passwords": ["1234", "admin", "password", "1", "nustiparola", "12345"],
    "scan_batch_size": 5000,
    "scan_min_batch": 500
}

def ensure_dirs():
    os.makedirs("output", exist_ok=True)
    os.makedirs("input", exist_ok=True) 