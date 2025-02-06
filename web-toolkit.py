#!/usr/bin/env python3
import os
import sys
import sqlite3
import time
import re
import logging
import getpass
import hashlib
import argparse
import subprocess
import socket
import platform
import paramiko
import ipaddress
import unittest
from typing import List, Optional
from cryptography.fernet import Fernet
import datetime

logging.basicConfig(
    filename='web_toolkit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

home_dir = os.path.expanduser("~")
db_dir = os.path.join(home_dir, 'Documents', 'WebToolkitDB')
db_path = os.path.join(db_dir, 'web_toolkit.db')
if not os.path.exists(db_dir):
    os.makedirs(db_dir)

conn = sqlite3.connect(db_path)

GITHUB_REPO = "https://github.com/byfranke/web-toolkit"

# --------------------- Database Setup ---------------------
def init_db():
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            encryption_key TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        '''
    )
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            project_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            encrypted_note BLOB NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(id)
        )
        '''
    )
    conn.commit()

# --------------------- Encryption Helpers ---------------------
def gen_key():
    return Fernet.generate_key()

def enc_data(data: str, key: bytes) -> bytes:
    return Fernet(key).encrypt(data.encode())

def dec_data(data: bytes, key: bytes) -> str:
    return Fernet(key).decrypt(data).decode()

# --------------------- Project Management ---------------------
def create_project():
    while True:
        name = input("Project name: ")
        if not name.strip():
            print("Invalid name.")
            continue
        pwd = getpass.getpass("Set a password for this project: ")
        c_pwd = getpass.getpass("Confirm password: ")
        if pwd != c_pwd:
            print("Passwords do not match.")
            continue
        key = gen_key()
        pwh = hashlib.sha256(pwd.encode()).hexdigest()
        conn.execute(
            '''
            INSERT INTO projects (name, encryption_key, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            ''',
            (
                name,
                key,
                pwh,
                datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            )
        )
        conn.commit()
        print("Project created.")
        break

def list_projects():
    cursor = conn.execute('SELECT id, name, created_at FROM projects')
    rows = cursor.fetchall()
    if not rows:
        print("No projects found.")
        return []
    for row in rows:
        print(f"{row[0]} - {row[1]} (Created at: {row[2]})")
    return rows

def get_project_by_id(pid: int):
    c = conn.execute(
        'SELECT id, name, encryption_key, password_hash FROM projects WHERE id = ?',
        (pid,)
    )
    return c.fetchone()

def pick_project_id() -> int:
    rows = list_projects()
    if not rows:
        return 0
    pid_str = input("\nChoose project ID (0=none): ")
    if pid_str.isdigit():
        return int(pid_str)
    return 0

def store_note_in_project(project_id: int, content: str):
    data = get_project_by_id(project_id)
    if not data:
        print("Invalid project.")
        return
    pid, pname, enc_key, _ = data
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    note_text = f"============##============\n{ts}\n{content}"
    enc_note = enc_data(note_text, enc_key)
    conn.execute(
        '''
        INSERT INTO notes (project_id, timestamp, encrypted_note)
        VALUES (?, ?, ?)
        ''',
        (pid, ts, enc_note)
    )
    conn.commit()
    print(f"Data saved to project: {pname}")

def open_project():
    pid = pick_project_id()
    if pid == 0:
        return
    row = get_project_by_id(pid)
    if not row:
        print("Project not found.")
        return
    pwd = getpass.getpass("Enter the project password: ")
    if hashlib.sha256(pwd.encode()).hexdigest() != row[3]:
        print("Wrong password.")
        return

    while True:
        print("\n1 - Add Note")
        print("2 - List Notes")
        print("3 - Delete Project")
        print("4 - Export Note")
        print("5 - Return to previous menu")
        choice = input("Choose an option: ")
        if choice == '1':
            text = input("New note content: ")
            ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            enc_note = enc_data(text, row[2])
            conn.execute(
                '''
                INSERT INTO notes (project_id, timestamp, encrypted_note)
                VALUES (?, ?, ?)
                ''',
                (pid, ts, enc_note)
            )
            conn.commit()
            print("Note added.")
        elif choice == '2':
            manage_notes_in_project(pid, row[2])
        elif choice == '3':
            conn.execute('DELETE FROM notes WHERE project_id = ?', (pid,))
            conn.execute('DELETE FROM projects WHERE id = ?', (pid,))
            conn.commit()
            print("Project deleted.")
            return
        elif choice == '4':
            export_note(pid, row[2])
        else:
            break

def manage_notes_in_project(pid: int, enc_key: bytes):
    lcur = conn.execute('SELECT id, timestamp, encrypted_note FROM notes WHERE project_id = ?', (pid,))
    notes = lcur.fetchall()
    if not notes:
        print("No notes in this project.")
        return
    for n in notes:
        print(f"{n[0]} - {n[1]}")

    while True:
        nid_str = input("Enter note ID to read/edit (0 to cancel): ")
        if not nid_str.isdigit():
            print("Invalid input.")
            continue
        nid = int(nid_str)
        if nid == 0:
            break
        fcur = conn.execute(
            'SELECT encrypted_note FROM notes WHERE id = ? AND project_id = ?',
            (nid, pid)
        )
        note_row = fcur.fetchone()
        if not note_row:
            print("Note not found.")
            continue
        try:
            dec_note = dec_data(note_row[0], enc_key)
            print(f"\nNote {nid} content:\n{dec_note}")
            print("\n1 - Edit")
            print("2 - Delete")
            print("3 - Return to notes list")
            nopt = input("Option: ")
            if nopt == '1':
                new_data = input("New content: ")
                print("1 - Append")
                print("2 - Replace")
                ed_opt = input("Choose: ")
                if ed_opt == '1':
                    final_data = dec_note + "\n" + new_data
                elif ed_opt == '2':
                    final_data = new_data
                else:
                    print("Invalid.")
                    continue
                enc_note2 = enc_data(final_data, enc_key)
                conn.execute(
                    'UPDATE notes SET encrypted_note = ? WHERE id = ?',
                    (enc_note2, nid)
                )
                conn.commit()
                print("Note updated.")
            elif nopt == '2':
                conn.execute('DELETE FROM notes WHERE id = ?', (nid,))
                conn.commit()
                print("Note deleted.")
            else:
                pass
        except:
            print("Error decrypting note.")

def export_note(pid: int, enc_key: bytes):
    lcur = conn.execute('SELECT id, timestamp FROM notes WHERE project_id = ?', (pid,))
    notes = lcur.fetchall()
    if not notes:
        print("No notes.")
        return

    for n in notes:
        print(f"{n[0]} - {n[1]}")

    nid = input("Enter note ID to export: ")
    if not nid.isdigit():
        print("Invalid.")
        return
    nid = int(nid)
    ecur = conn.execute(
        'SELECT encrypted_note FROM notes WHERE id = ? AND project_id = ?',
        (nid, pid)
    )
    erow = ecur.fetchone()
    if not erow:
        print("Note not found.")
        return
    try:
        dec_note = dec_data(erow[0], enc_key)
        path = input("Export path (directory or file), empty=current dir: ")
        if not path:
            path = os.path.join(os.getcwd(), f"note_{nid}.txt")
        if os.path.isdir(path):
            fname = f"note_{nid}_{int(time.time())}.txt"
            path = os.path.join(path, fname)
        with open(path, 'w') as f:
            f.write(dec_note)
        print(f"Exported to {path}")
    except:
        print("Error decrypting note.")

# --------------------- Dependencies & Tools ---------------------
def install_dependencies():
    logging.info("Installing necessary tools...")
    if platform.system() == "Linux":
        if check_tool_installed("apt-get"):
            try:
                subprocess.run(['sudo', 'apt-get', 'update'], check=True)
                for t in ['nmap','sqlmap','wget','curl']:
                    if not check_tool_installed(t):
                        subprocess.run(['sudo','apt-get','install',t,'-y'], check=True)
                logging.info("Installed with apt-get.")
            except:
                logging.exception("Error installing with apt-get.")
        elif check_tool_installed("pacman"):
            try:
                subprocess.run(['sudo','pacman','-Syu','--noconfirm'], check=True)
                for t in ['nmap','sqlmap','wget','curl']:
                    if not check_tool_installed(t):
                        subprocess.run(['sudo','pacman','-S','--noconfirm',t], check=True)
                logging.info("Installed with pacman.")
            except:
                logging.exception("Error installing with pacman.")
        else:
            print("No supported package manager (apt-get or pacman).")
    elif platform.system() == "Windows":
        print("Install tools manually on Windows.")
    else:
        print("Unsupported OS.")

def check_tool_installed(tool: str) -> bool:
    try:
        if platform.system() == "Windows":
            subprocess.run(['where', tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        else:
            subprocess.run(['which', tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except:
        return False

def capture_cmd_output(cmd: List[str]) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
        out = p.stdout
        err = p.stderr
        combined = out if out else ""
        if err:
            combined += "\n[stderr]\n" + err
        return combined.strip()
    except Exception as e:
        return f"Error running {cmd}: {e}"

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

def validate_domain(domain: str) -> bool:
    pattern = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
    return bool(pattern.match(domain))

def validate_url(url: str) -> bool:
    pattern = re.compile(r'^https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^/]*)*$')
    return bool(pattern.match(url))

def query_whois(domain: str) -> str:
    if not validate_domain(domain):
        return "Invalid domain."
    try:
        import whois
        w = whois.whois(domain)
        return str(w)
    except:
        return "WHOIS error."

class RateLimiter:
    def __init__(self, max_calls: int, time_frame: int):
        self.max_calls = max_calls
        self.time_frame = time_frame
        self.calls = []
    def __call__(self, func):
        def wrapper(*args, **kwargs):
            now = time.time()
            self.calls = [c for c in self.calls if c > now - self.time_frame]
            if len(self.calls) >= self.max_calls:
                time.sleep(self.time_frame - (now - self.calls[0]))
            self.calls.append(now)
            return func(*args, **kwargs)
        return wrapper

@RateLimiter(10,60)
def smtp_enum(ip:str, wl:Optional[List[str]]=None) -> str:
    if not validate_ip(ip):
        return "Invalid IP."
    if not wl:
        wl=["admin","guest","info"]
    result = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip,25))
        banner = s.recv(1024).decode(errors='ignore')
        result.append(f"Banner: {banner}")
        for user in wl:
            s.send(f"VRFY {user}\r\n".encode())
            r = s.recv(1024).decode(errors='ignore')
            if "252" in r:
                result.append(f"User found: {user}")
        s.close()
    except Exception as e:
        result.append(f"SMTP enumeration error: {e}")
    return "\n".join(result)

def ssh_enum(ip:str) -> str:
    if not validate_ip(ip):
        return "Invalid IP."
    user = input("SSH user: ")
    pwd = getpass.getpass("SSH password: ")
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    output = []
    try:
        c.connect(ip, username=user, password=pwd)
        output.append("SSH login success.")
    except paramiko.AuthenticationException:
        output.append("SSH auth error.")
    except Exception as e:
        output.append(f"SSH error: {e}")
    finally:
        c.close()
    return "\n".join(output)

def run_webrecon(url: str) -> str:
    if not check_tool_installed("wget"):
        return "wget not installed."
    out = capture_cmd_output(['wget', '-m', '-e', 'robots=off', url])
    out_final = ["[webrecon wget output]", out, "\nAnalyzing Page..."]

    pattern = re.compile(r'(username|user_name|userid|user_id|login|password|passwd|pass_word|pwd|secret|auth|access_token)', re.IGNORECASE)
    hits = []
    for root, _, files in os.walk('.'):
        for f in files:
            fp = os.path.join(root, f)
            try:
                with open(fp, 'r', encoding='utf-8') as fdata:
                    for i, line in enumerate(fdata, 1):
                        if pattern.search(line):
                            hits.append(f"{fp}:{i}:{line.strip()}")
            except:
                pass
    if hits:
        out_final.append("[Potential sensitive info found:]")
        out_final.extend(hits)
    else:
        out_final.append("No significant patterns found.")
    return "\n".join(out_final)

def web_recon(url: str) -> str:
    if not validate_url(url):
        return "Invalid URL."
    return run_webrecon(url)

def sql_injection_test(url:str) -> str:
    if not validate_url(url):
        return "Invalid URL."
    if not check_tool_installed("sqlmap"):
        return "sqlmap not installed."
    return capture_cmd_output([
        'sqlmap','-u',url,'--dbs',
        '--tamper=space2comment','--random-agent',
        '--forms','--crawl=2'
    ])

def scan_web_full(target:str) -> str:
    if not (validate_ip(target) or validate_domain(target) or validate_url(target)):
        return "Invalid target."
    outputs = []
    sep = "\n============##============\n"

    if check_tool_installed("whatweb"):
        outputs.append("[whatweb output]\n" + capture_cmd_output(["whatweb", target]))
    else:
        outputs.append("whatweb not installed.")

    outputs.append("[webrecon output]\n" + run_webrecon(target))

    if check_tool_installed("nmap"):
        out_nmap = capture_cmd_output([
            "sudo","nmap","-v","-D","RND:25","-sS",
            "--top-ports=25","--open","-T2","-Pn",target
        ])
        outputs.append("[nmap output]\n" + out_nmap)
    else:
        outputs.append("nmap not installed.")

    if check_tool_installed("dirsearch"):
        out_dirsearch = capture_cmd_output([
            "dirsearch","-u",target,"-i","200,301,302,401","--random-agent"
        ])
        outputs.append("[dirsearch output]\n" + out_dirsearch)
    else:
        outputs.append("dirsearch not installed.")

    if check_tool_installed("curl"):
        out_curl = capture_cmd_output(["curl","-v","-X","OPTIONS",target])
        outputs.append("[curl OPTIONS output]\n" + out_curl)
    else:
        outputs.append("curl not installed.")

    if check_tool_installed("nuclei-hunter"):
        out_nuc = capture_cmd_output(["nuclei-hunter",target,"http"])
        outputs.append("[nuclei-hunter output]\n" + out_nuc)
    else:
        outputs.append("nuclei-hunter not installed.")

    if check_tool_installed("nmap"):
        out_nmap_vuln = capture_cmd_output([
            "sudo","nmap","-v","--open","-sSCV","-Pn",
            "-O",target,"--script=vuln"
        ])
        outputs.append("[nmap vuln output]\n" + out_nmap_vuln)
    else:
        outputs.append("nmap not installed for vuln scan.")

    return sep.join(outputs)

def nuclei_hunter_scan(domain:str, template:str) -> str:
    if not validate_domain(domain):
        return "Invalid domain."
    if not (check_tool_installed("subfinder") and check_tool_installed("nuclei")):
        return "subfinder or nuclei not installed."
    try:
        sf = subprocess.run(["subfinder","-d",domain], capture_output=True, text=True, check=True).stdout
        template_path = os.path.join(
            os.path.expanduser("~"),
            ".local","nuclei-templates",template
        )
        out = subprocess.run(["nuclei","-t",template_path,"-c","50"], input=sf, text=True, capture_output=True)
        return "[nuclei-hunter scan]\n"+ out.stdout + (("\n[stderr]\n"+out.stderr) if out.stderr else "")
    except Exception as e:
        return f"Error in nuclei_hunter_scan: {e}"

def scan_web_silence(target:str) -> str:
    if not (validate_ip(target) or validate_domain(target) or validate_url(target)):
        return "Invalid target."
    if not check_tool_installed("nmap"):
        return "nmap not installed."
    return capture_cmd_output([
        "sudo","nmap","-v","-D","RND:25","-sS","--top-ports=25",
        "--open","-T2","-Pn",target
    ])

def do_smtp_enum():
    ip = input("IP: ")
    res = smtp_enum(ip)
    ask_store_result("SMTP Enumeration", ip, res)

def do_ssh_enum():
    ip = input("IP: ")
    res = ssh_enum(ip)
    ask_store_result("SSH Enumeration", ip, res)

def do_web_recon():
    url = input("URL: ")
    out = web_recon(url)
    ask_store_result("Web Recon", url, out)

def do_sql_injection_test():
    url = input("URL: ")
    out = sql_injection_test(url)
    ask_store_result("SQL Injection Test", url, out)

def do_full_scan():
    tgt = input("Target: ")
    out = scan_web_full(tgt)
    ask_store_result("Full Web Scan", tgt, out)

def do_nuclei_hunter():
    d = input("Domain: ")
    t = input("Template: ")
    res = nuclei_hunter_scan(d, t)
    ask_store_result("Nuclei Hunter", d, res)

def do_silence_scan():
    tgt = input("Target: ")
    res = scan_web_silence(tgt)
    ask_store_result("Silent Web Scan", tgt, res)

def do_whois():
    d = input("Domain: ")
    out = query_whois(d)
    ask_store_result("WHOIS Query", d, out)

def ask_store_result(scan_name: str, target: str, result_data: str):
    combined = f"{scan_name} on: {target}\n\n{result_data}"
    print("\nScan completed.\n")
    pid = pick_project_id()
    if pid != 0:
        store_note_in_project(pid, combined)
    else:
        print("Scan results not stored in any project.")

def menu_scan():
    while True:
        print("\n1 - Full Web Scan")
        print("2 - Web Recon")
        print("3 - SQLi Test")
        print("4 - SMTP Enum")
        print("5 - SSH Enum")
        print("6 - Nuclei Hunter")
        print("7 - Silent Scan")
        print("8 - WHOIS Query")
        print("9 - Return")
        c = input("Choose: ")
        if c=='1':
            do_full_scan()
        elif c=='2':
            do_web_recon()
        elif c=='3':
            do_sql_injection_test()
        elif c=='4':
            do_smtp_enum()
        elif c=='5':
            do_ssh_enum()
        elif c=='6':
            do_nuclei_hunter()
        elif c=='7':
            do_silence_scan()
        elif c=='8':
            do_whois()
        else:
            break

def update_toolkit():
    print("\n[*] Checking for the latest version on GitHub...")
    TEMP_DIR = os.path.join("/tmp", f"web_toolkit_temp_{int(time.time())}")
    try:
        subprocess.run(["git", "clone", GITHUB_REPO, TEMP_DIR], check=True)
    except Exception as e:
        print(f"[!] Failed to clone repository: {e}")
        return

    backup_dir = f"Obsolete_{int(time.time())}"
    os.makedirs(backup_dir, exist_ok=True)

    print(f"[*] Moving old files to {backup_dir}...")
    for f in os.listdir('.'):
        if f not in (
            os.path.basename(sys.argv[0]),
            'web_toolkit.log',
            db_dir,
            backup_dir,
            '.git'
        ):
            try:
                if os.path.isfile(f) or os.path.isdir(f):
                    subprocess.run(["mv", f, backup_dir])
            except:
                pass

    for f in os.listdir(TEMP_DIR):
        src = os.path.join(TEMP_DIR, f)
        dst = os.path.join('.', f)
        subprocess.run(["mv", src, dst])

    subprocess.run(["rm", "-rf", TEMP_DIR])
    print(f"[+] Updated to the latest version from GitHub. Old files moved to '{backup_dir}'.")

def show_banner():
    banner = r"""
___________________oo_____________oo____________________ooo___oo______oo___oo____
oo_______o__ooooo__oooooo_________oo_____ooooo___ooooo___oo___oo___o_______oo____
oo__oo___o_oo____o_oo___oo_______oooo___oo___oo_oo___oo__oo___oo__o___oo__oooo___
oo__oo___o_ooooooo_oo___oo_ooooo__oo____oo___oo_oo___oo__oo___oooo____oo___oo____
_oo_oo__o__oo______oo___oo________oo__o_oo___oo_oo___oo__oo___oo__o___oo___oo__o_
__oo__oo____ooooo__oooooo__________ooo___ooooo___ooooo__ooooo_oo___o_oooo___ooo__
_________________________________________________________________________________

                              WEB-TOOLKIT byfranke
---------------------------------------------------------------------------------
"""
    print(banner)

def show_help():
    print("""
HELP / HOW TO USE:

1) MANAGE PROJECTS:
   - Create Project: Creates a password-protected project to store notes and scan results.
   - Open Project (view/edit notes): Lists notes, allows reading/editing/exporting, etc.

2) SCAN TOOLS:
   - Full Web Scan: Combines multiple tools (whatweb, webrecon, nmap, etc.) 
   - Web Recon: Uses wget to mirror a site, searches for specific patterns 
   - SQLi Test: Quick check for SQL injection with sqlmap
   - SMTP Enum: VRFY user enumeration on an SMTP server
   - SSH Enum: Tests SSH login with provided credentials
   - Nuclei Hunter: Subfinder + Nuclei template-based scanning
   - Silent Scan: Minimal, stealthy nmap scan
   - WHOIS Query: Looks up domain registration details

3) INSTALL DEPENDENCIES:
   - Installs nmap, sqlmap, wget, curl if missing (only Debian/Arch supported)

4) UPDATE TOOLKIT:
   - Pulls the latest version from GitHub

STORING RESULTS:
After scans, you can choose a project to encrypt and store your output.

EXAMPLE STEPS:
   - Create a project and set a password
   - Perform Full Web Scan
   - Save results to the project
   - Later, open the project to view or export

CLI USAGE:
   --install
   --scan-full <target>
   --web <url>
   --sql <url>
   --smtp <ip>
   --ssh <ip>
   --nuclei-scan <domain> <template>
   --scan-silence <target>
   --whois <domain>
   --update (updates the toolkit to the latest version)
""")

def main_menu():
    while True:
        try:
            show_banner()
            print("1 - Manage Projects")
            print("2 - Scan Tools")
            print("3 - Install Dependencies")
            print("4 - Help")
            print("5 - Update Toolkit")
            print("6 - Exit")
            choice = input("Choose: ")
            if choice=='1':
                while True:
                    print("\n1 - Create Project")
                    print("2 - Open Project (view/edit notes)")
                    print("3 - Return to main menu")
                    c2 = input("Choose: ")
                    if c2=='1':
                        create_project()
                    elif c2=='2':
                        open_project()
                    else:
                        break
            elif choice=='2':
                menu_scan()
            elif choice=='3':
                install_dependencies()
            elif choice=='4':
                show_help()
            elif choice=='5':
                update_toolkit()
            elif choice=='6':
                break
            else:
                print("Invalid.")
        except KeyboardInterrupt:
            print("\nInterrupted.")
            break

def main():
    init_db()
    parser = argparse.ArgumentParser(description="Web Toolkit")
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--scan-full', type=str)
    parser.add_argument('--web', type=str)
    parser.add_argument('--sql', type=str)
    parser.add_argument('--smtp', type=str)
    parser.add_argument('--ssh', type=str)
    parser.add_argument('--nuclei-scan', nargs=2, metavar=('DOMAIN','TEMPLATE'))
    parser.add_argument('--scan-silence', type=str)
    parser.add_argument('--whois', type=str)
    parser.add_argument('--update', action='store_true', help='Update the toolkit from GitHub.')
    args = parser.parse_args()

    if args.install:
        install_dependencies()
    elif args.scan_full:
        res = scan_web_full(args.scan_full)
        print(res)
    elif args.web:
        out = web_recon(args.web)
        print(out)
    elif args.sql:
        out = sql_injection_test(args.sql)
        print(out)
    elif args.smtp:
        res = smtp_enum(args.smtp)
        print(res)
    elif args.ssh:
        print("SSH enumeration requires interactive user/password input. Use the menu instead.")
    elif args.nuclei_scan:
        out = nuclei_hunter_scan(args.nuclei_scan[0], args.nuclei_scan[1])
        print(out)
    elif args.scan_silence:
        out = scan_web_silence(args.scan_silence)
        print(out)
    elif args.whois:
        print(query_whois(args.whois))
    elif args.update:
        update_toolkit()
    else:
        main_menu()

class Tests(unittest.TestCase):
    def test_validate_ip(self):
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertFalse(validate_ip("999.999.999.999"))
    def test_validate_domain(self):
        self.assertTrue(validate_domain("example.com"))
        self.assertFalse(validate_domain("invalid_domain"))
    def test_validate_url(self):
        self.assertTrue(validate_url("http://example.com"))
        self.assertFalse(validate_url("example.com"))

if __name__=="__main__":
    if "--test" in sys.argv:
        sys.argv.remove("--test")
        unittest.main()
    else:
        main()
