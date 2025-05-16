# Matrix VNC Scanner & Brute

## Instalare

```bash
pip install -r requirements.txt
```

## Utilizare

Scanare:
```bash
python main.py --scan --range 192.168.1.* --port 5900 --threads 200
```

Brute-force:
```bash
python main.py --brute --passwords 1234 admin password
```

Poți combina scanarea și brute-force:
```bash
python main.py --scan --brute
```

Rezultatele se salvează în `output/ips.txt` și `output/results.txt`.
 
