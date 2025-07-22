#!/usr/bin/env python3
"""
Web-Toolkit Professional - Advanced Web Security Testing Framework

A comprehensive toolkit for web security assessment, penetration testing,
and vulnerability analysis with encrypted project management capabilities.

Author: byfranke.com
Version: 2.0
License: MIT
"""

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
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
from rich.columns import Columns
from tabulate import tabulate

# Path import for file operations
from pathlib import Path
import json
import requests
import shlex

# Try to import enhanced modules
try:
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))
    from cve_intelligence import analyze_scan_for_cves, get_cve_summary_table, CVEIntelligence
    from project_manager import ProjectManager, EncryptedFileManager
    from validators import InputValidator, SecurityValidator
    CVE_SUPPORT = True
    ENHANCED_PROJECTS = True
    print("[INFO] Enhanced CVE detection and project management loaded")
except ImportError as e:
    print(f"[WARNING] Enhanced features not available: {e}")
    print("[INFO] Install requirements: pip install -r requirements.txt")
    CVE_SUPPORT = False
    ENHANCED_PROJECTS = False

# Secure logging configuration
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    filename='logs/web_toolkit.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'
)

console = Console()

# Secure database configuration
db_dir = 'database'
os.makedirs(db_dir, exist_ok=True)
db_path = os.path.join(db_dir, 'web_toolkit.db')

# Enable WAL mode for better concurrency and security
conn = sqlite3.connect(db_path)
conn.execute('PRAGMA journal_mode=WAL;')
conn.execute('PRAGMA foreign_keys=ON;')
conn.execute('PRAGMA secure_delete=ON;')

GITHUB_REPO = "https://github.com/byfranke/web-toolkit"

def safe_input(prompt: str) -> Optional[str]:
    """Secure input handler with validation"""
    try:
        user_input = input(prompt)
        # Basic input sanitization
        if len(user_input) > 1000:  # Prevent buffer overflow
            print("[ERROR] Input too long")
            return None
        return user_input.strip()
    except KeyboardInterrupt:
        print("\n[INFO] Operation cancelled by user")
        return None

def safe_getpass(prompt: str) -> Optional[str]:
    """Secure password input handler"""
    try:
        password = getpass.getpass(prompt)
        if len(password) > 500:  # Reasonable password length limit
            print("[ERROR] Password too long")
            return None
        return password
    except KeyboardInterrupt:
        print("\n[INFO] Operation cancelled by user")
        return None

def check_tool_installed(tool: str) -> bool:
    """Check if a security tool is installed on the system"""
    try:
        # Sanitize tool name to prevent command injection
        tool_clean = shlex.quote(tool)
        
        if platform.system() == "Windows":
            result = subprocess.run(['where', tool_clean], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, 
                                  check=True,
                                  timeout=10)
        else:
            result = subprocess.run(['which', tool_clean], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, 
                                  check=True,
                                  timeout=10)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False

def init_db():
    """Initialize database with secure configuration"""
    # Create projects table with proper constraints
    conn.execute('''CREATE TABLE IF NOT EXISTS projects (
                      id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      name TEXT NOT NULL UNIQUE, 
                      encryption_key TEXT NOT NULL, 
                      password_hash TEXT NOT NULL, 
                      created_at TEXT NOT NULL,
                      modified_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create notes table with foreign key constraints
    conn.execute('''CREATE TABLE IF NOT EXISTS notes (
                      id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      project_id INTEGER NOT NULL, 
                      timestamp TEXT NOT NULL, 
                      encrypted_note BLOB NOT NULL,
                      note_hash TEXT,
                      FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE)''')
    
    # Create indexes for better performance
    conn.execute('''CREATE INDEX IF NOT EXISTS idx_notes_project_id 
                    ON notes(project_id)''')
    conn.execute('''CREATE INDEX IF NOT EXISTS idx_projects_name 
                    ON projects(name)''')
    
    conn.commit()

def generate_encryption_key() -> bytes:
    """Generate a cryptographically secure encryption key"""
    return Fernet.generate_key()

def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypt data using Fernet symmetric encryption"""
    try:
        fernet = Fernet(key)
        return fernet.encrypt(data.encode('utf-8'))
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        raise

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypt data using Fernet symmetric encryption"""
    try:
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_data)
        return decrypted.decode('utf-8')
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        raise

def create_project():
    """Create a new encrypted project with secure authentication"""
    console.print("\n[bold blue]CREATE NEW PROJECT[/bold blue]")
    
    while True:
        name = safe_input("Project name: ")
        if name is None or not name.strip():
            console.print("[red]Invalid project name[/red]")
            continue
            
        # Check if project name already exists
        cursor = conn.execute('SELECT id FROM projects WHERE name = ?', (name,))
        if cursor.fetchone():
            console.print("[red]Project name already exists[/red]")
            continue
            
        pwd = safe_getpass("Set project password: ")
        if pwd is None:
            continue
            
        if len(pwd) < 8:
            console.print("[red]Password must be at least 8 characters[/red]")
            continue
            
        c_pwd = safe_getpass("Confirm password: ")
        if c_pwd is None:
            continue
            
        if pwd != c_pwd:
            console.print("[red]Passwords do not match[/red]")
            continue
            
        try:
            key = generate_encryption_key()
            # Use bcrypt for password hashing instead of SHA256
            import bcrypt
            pwh = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            conn.execute("INSERT INTO projects (name, encryption_key, password_hash, created_at, modified_at) VALUES (?, ?, ?, ?, ?)",
                        (name, key, pwh, 
                         datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                         datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
            
            console.print(f"[green]Project '{name}' created successfully[/green]")
            logging.info(f"New project created: {name}")
            break
            
        except Exception as e:
            console.print(f"[red]Error creating project: {e}[/red]")
            logging.error(f"Project creation failed: {e}")
            break

def list_projects():
    """Display all available projects in a formatted table"""
    cursor = conn.execute('SELECT id, name, created_at, modified_at FROM projects ORDER BY created_at DESC')
    rows = cursor.fetchall()
    
    if not rows:
        console.print("[yellow]No projects found[/yellow]")
        return []
    
    # Create professional table display
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("ID", width=8)
    table.add_column("Project Name", width=25)
    table.add_column("Created", width=16)
    table.add_column("Last Modified", width=16)
    
    for row in rows:
        created = datetime.datetime.strptime(row[2], '%Y-%m-%d %H:%M:%S').strftime('%m/%d/%Y %H:%M')
        modified = datetime.datetime.strptime(row[3], '%Y-%m-%d %H:%M:%S').strftime('%m/%d/%Y %H:%M') if row[3] else 'N/A'
        
        table.add_row(
            str(row[0]),
            row[1][:22] + "..." if len(row[1]) > 22 else row[1],
            created,
            modified
        )
    
    console.print(table)
    return rows

def get_project_by_id(pid: int):
    """Retrieve project data by ID"""
    cursor = conn.execute('SELECT id, name, encryption_key, password_hash FROM projects WHERE id = ?', (pid,))
    return cursor.fetchone()

def pick_project_id() -> int:
    """Allow user to select a project from available options"""
    console.print("\n[bold blue]SELECT PROJECT[/bold blue]")
    rows = list_projects()
    
    if not rows:
        return 0
    
    pid_str = safe_input("\nEnter project ID (0 for none): ")
    if pid_str is None:
        return 0
        
    if pid_str.isdigit():
        pid = int(pid_str)
        # Validate that the project ID exists
        if any(row[0] == pid for row in rows):
            return pid
        else:
            console.print("[red]Invalid project ID[/red]")
            return 0
    
    return 0

def store_note_in_project(project_id: int, content: str):
    """Store encrypted note in project"""
    data = get_project_by_id(project_id)
    if not data:
        console.print("[red]Invalid project[/red]")
        return
        
    pid, pname, enc_key, _ = data
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    note_text = f"============##============\n{ts}\n{content}"
    enc_note = encrypt_data(note_text, enc_key)
    
    conn.execute("INSERT INTO notes (project_id, timestamp, encrypted_note) VALUES (?, ?, ?)", 
                (pid, ts, enc_note))
    conn.commit()
    
    console.print(f"[green]Data saved to project: {pname}[/green]")

def open_project():
    """Open and unlock an encrypted project"""
    pid = pick_project_id()
    if pid == 0:
        return
        
    row = get_project_by_id(pid)
    if not row:
        console.print("[red]Project not found[/red]")
        return
        
    pwd = safe_getpass("Enter project password: ")
    if pwd is None:
        return
    
    # Verify password using bcrypt
    try:
        import bcrypt
        if not bcrypt.checkpw(pwd.encode('utf-8'), row[3].encode('utf-8')):
            console.print("[red]Invalid password[/red]")
            return
    except:
        # Fallback to SHA256 for backward compatibility
        if hashlib.sha256(pwd.encode()).hexdigest() != row[3]:
            console.print("[red]Invalid password[/red]")
            return
    
    project_id, project_name, encryption_key, _ = row
    
    # Initialize enhanced project manager if available
    if ENHANCED_PROJECTS:
        file_manager = EncryptedFileManager(project_id, encryption_key, project_name)
        console.print(f"\n[bold green]Project '{project_name}' unlocked successfully[/bold green]")
        enhanced_project_menu(file_manager, project_id, project_name)
    else:
        # Fallback to original project management
        basic_project_menu(pid, row)

def enhanced_project_menu(file_manager: 'EncryptedFileManager', project_id: int, project_name: str):
    """Enhanced project menu with file management capabilities"""
    while True:
        console.clear()
        console.print(f"\n[bold blue]PROJECT: {project_name.upper()}[/bold blue]")
        console.print("=" * 60)
        
        # Show project statistics
        if hasattr(file_manager, 'get_project_statistics'):
            try:
                stats = file_manager.get_project_statistics()
                console.print(f"[cyan]Files: {stats['total_files']} | Size: {stats['total_size']//1024}KB | Categories: {len(stats['files_by_category'])}[/cyan]")
            except:
                pass
        
        console.print("\n[bold yellow]PROJECT MANAGEMENT[/bold yellow]")
        print("1  - Create Note")
        print("2  - List All Files")
        print("3  - Search Files")
        print("4  - Browse by Category")
        print("5  - Browse by Tags")
        print("6  - Upload File")
        print("7  - Export File")
        print("8  - Project Statistics")
        print("9  - Timeline/History")
        print("10 - Delete File")
        
        console.print("\n[bold yellow]PENTEST OPERATIONS[/bold yellow]")
        print("11 - Store Scan Results")
        print("12 - View Vulnerabilities")
        print("13 - Generate Report")
        print("14 - Export Project")
        print("15 - Delete Project")
        
        print("\n16 - Return to main menu")
        
        choice = safe_input("\nChoose option: ")
        if choice is None:
            break
        
        try:
            if choice == '1':
                create_note_in_project(file_manager)
            elif choice == '2':
                list_files_in_project(file_manager)
            elif choice == '3':
                search_files_in_project(file_manager)
            elif choice == '4':
                browse_by_category(file_manager)
            elif choice == '5':
                browse_by_tags(file_manager)
            elif choice == '6':
                upload_file_to_project(file_manager)
            elif choice == '7':
                export_file_from_project(file_manager)
            elif choice == '8':
                show_project_statistics(file_manager)
            elif choice == '9':
                show_project_timeline(file_manager)
            elif choice == '10':
                delete_file_from_project(file_manager)
            elif choice == '11':
                store_scan_results_enhanced(file_manager)
            elif choice == '12':
                view_vulnerabilities_in_project(file_manager)
            elif choice == '13':
                generate_project_report(file_manager, project_name)
            elif choice == '14':
                export_entire_project(file_manager, project_name)
            elif choice == '15':
                if confirm_project_deletion(project_name):
                    delete_project_enhanced(project_id, file_manager)
                    return
            elif choice == '16':
                break
            else:
                console.print("[bold red]Invalid option[/bold red]")
                
        except Exception as e:
            console.print(f"[bold red]Error: {e}[/bold red]")
            input("Press Enter to continue...")

# Placeholder functions for enhanced features (these would be implemented in modules)
def create_note_in_project(file_manager):
    """Create a structured note in the project"""
    console.print("\n[bold blue]CREATE NEW NOTE[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def list_files_in_project(file_manager):
    """List all files in the project"""
    console.print("\n[bold blue]PROJECT FILES[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def search_files_in_project(file_manager):
    """Search files in the project"""
    console.print("\n[bold blue]SEARCH PROJECT FILES[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def browse_by_category(file_manager):
    """Browse files by category"""
    console.print("\n[bold blue]BROWSE BY CATEGORY[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def browse_by_tags(file_manager):
    """Browse files by tags"""
    console.print("\n[bold blue]BROWSE BY TAGS[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def upload_file_to_project(file_manager):
    """Upload a file to the project"""
    console.print("\n[bold blue]UPLOAD FILE TO PROJECT[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def export_file_from_project(file_manager):
    """Export a file from the project"""
    console.print("\n[bold blue]EXPORT FILE FROM PROJECT[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def show_project_statistics(file_manager):
    """Show detailed project statistics"""
    console.print("\n[bold blue]PROJECT STATISTICS[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def show_project_timeline(file_manager):
    """Show project timeline/history"""
    console.print("\n[bold blue]PROJECT TIMELINE[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def delete_file_from_project(file_manager):
    """Delete a file from the project"""
    console.print("\n[bold blue]DELETE FILE FROM PROJECT[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def store_scan_results_enhanced(file_manager):
    """Store scan results with enhanced categorization"""
    console.print("\n[bold blue]STORE SCAN RESULTS[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def view_vulnerabilities_in_project(file_manager):
    """View vulnerabilities found in the project"""
    console.print("\n[bold blue]PROJECT VULNERABILITIES[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def generate_project_report(file_manager, project_name: str):
    """Generate a comprehensive project report"""
    console.print("\n[bold blue]GENERATE PROJECT REPORT[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def export_entire_project(file_manager, project_name: str):
    """Export entire project as encrypted archive"""
    console.print("\n[bold blue]EXPORT ENTIRE PROJECT[/bold blue]")
    console.print("[yellow]Enhanced features require additional modules[/yellow]")
    input("Press Enter to continue...")

def confirm_project_deletion(project_name: str) -> bool:
    """Confirm project deletion with safety checks"""
    console.print(f"\n[bold red]DELETE PROJECT: {project_name}[/bold red]")
    console.print("[bold]WARNING: This action cannot be undone![/bold]")
    
    confirmation = safe_input(f"Type '{project_name}' to confirm deletion: ")
    if confirmation != project_name:
        console.print("[red]Project name doesn't match - deletion cancelled[/red]")
        return False
    
    final_confirm = safe_input("Type 'DELETE' to permanently remove this project: ")
    if final_confirm != 'DELETE':
        console.print("[red]Final confirmation failed - deletion cancelled[/red]")
        return False
    
    return True

def delete_project_enhanced(project_id: int, file_manager):
    """Delete project with enhanced cleanup"""
    try:
        # Clean up file manager data
        if hasattr(file_manager, 'cleanup_project'):
            file_manager.cleanup_project()
        
        # Remove from database
        conn.execute('DELETE FROM notes WHERE project_id = ?', (project_id,))
        conn.execute('DELETE FROM projects WHERE id = ?', (project_id,))
        conn.commit()
        
        console.print("[bold green]Project deleted successfully[/bold green]")
        
    except Exception as e:
        console.print(f"[bold red]Error deleting project: {e}[/bold red]")
    
    input("Press Enter to continue...")

def basic_project_menu(pid: int, row: tuple):
    """Fallback basic project menu for when enhanced features aren't available"""
    while True:
        console.print("\n[bold blue]BASIC PROJECT MENU[/bold blue]")
        print("1 - Add Note")
        print("2 - List Notes")
        print("3 - Delete Project")
        print("4 - Export Note")
        print("5 - Return to previous menu")
        
        choice = safe_input("Choose an option: ")
        if choice is None:
            break
            
        if choice == '1':
            text = safe_input("New note content: ")
            if text is None:
                continue
            ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            enc_note = encrypt_data(text, row[2])
            conn.execute("INSERT INTO notes (project_id, timestamp, encrypted_note) VALUES (?, ?, ?)", 
                        (pid, ts, enc_note))
            conn.commit()
            console.print("[green]Note added[/green]")
        elif choice == '2':
            manage_notes_in_project(pid, row[2])
        elif choice == '3':
            conn.execute('DELETE FROM notes WHERE project_id = ?', (pid,))
            conn.execute('DELETE FROM projects WHERE id = ?', (pid,))
            conn.commit()
            console.print("[green]Project deleted[/green]")
            return
        elif choice == '4':
            export_note(pid, row[2])
        else:
            break

def manage_notes_in_project(pid: int, enc_key: bytes):
    """Manage notes within a project"""
    cursor = conn.execute('SELECT id, timestamp, encrypted_note FROM notes WHERE project_id = ?', (pid,))
    notes = cursor.fetchall()
    
    if not notes:
        console.print("[yellow]No notes in this project[/yellow]")
        return
    
    console.print("\n[bold blue]PROJECT NOTES[/bold blue]")
    for note in notes:
        print(f"{note[0]} - {note[1]}")
    
    while True:
        nid_str = safe_input("Enter note ID to read/edit (0 to cancel): ")
        if nid_str is None:
            break
            
        if not nid_str.isdigit():
            console.print("[red]Invalid input[/red]")
            continue
            
        nid = int(nid_str)
        if nid == 0:
            break
            
        note_cursor = conn.execute('SELECT encrypted_note FROM notes WHERE id = ? AND project_id = ?', (nid, pid))
        note_row = note_cursor.fetchone()
        
        if not note_row:
            console.print("[red]Note not found[/red]")
            continue
            
        try:
            dec_note = decrypt_data(note_row[0], enc_key)
        except Exception:
            console.print("[red]Error decrypting note[/red]")
            continue
            
        print(f"\nNote {nid} content:\n{dec_note}")
        
        print("\n1 - Edit")
        print("2 - Delete")
        print("3 - Return to notes list")
        
        nopt = safe_input("Option: ")
        if nopt is None:
            break
            
        if nopt == '1':
            new_data = safe_input("New content: ")
            if new_data is None:
                continue
                
            print("1 - Append")
            print("2 - Replace")
            ed_opt = safe_input("Choose: ")
            
            if ed_opt == '1':
                final_data = dec_note + "\n" + new_data
            elif ed_opt == '2':
                final_data = new_data
            else:
                console.print("[red]Invalid option[/red]")
                continue
                
            enc_note2 = encrypt_data(final_data, enc_key)
            conn.execute('UPDATE notes SET encrypted_note = ? WHERE id = ?', (enc_note2, nid))
            conn.commit()
            console.print("[green]Note updated[/green]")
            
        elif nopt == '2':
            conn.execute('DELETE FROM notes WHERE id = ?', (nid,))
            conn.commit()
            console.print("[green]Note deleted[/green]")
        else:
            continue

def export_note(pid: int, enc_key: bytes):
    """Export a note to a file"""
    cursor = conn.execute('SELECT id, timestamp FROM notes WHERE project_id = ?', (pid,))
    notes = cursor.fetchall()
    
    if not notes:
        console.print("[yellow]No notes[/yellow]")
        return
    
    for note in notes:
        print(f"{note[0]} - {note[1]}")
    
    nid_str = safe_input("Enter note ID to export: ")
    if nid_str is None or not nid_str.isdigit():
        console.print("[red]Invalid input[/red]")
        return
    
    nid = int(nid_str)
    export_cursor = conn.execute('SELECT encrypted_note FROM notes WHERE id = ? AND project_id = ?', (nid, pid))
    export_row = export_cursor.fetchone()
    
    if not export_row:
        console.print("[red]Note not found[/red]")
        return
    
    try:
        dec_note = decrypt_data(export_row[0], enc_key)
    except Exception:
        console.print("[red]Error decrypting note[/red]")
        return
    
    path = safe_input("Export path (directory or file), empty=current dir: ")
    if path is None:
        return
    
    if not path:
        path = os.path.join(os.getcwd(), f"note_{nid}.txt")
    
    if os.path.isdir(path):
        fname = f"note_{nid}_{int(time.time())}.txt"
        path = os.path.join(path, fname)
    
    try:
        with open(path, 'w') as f:
            f.write(dec_note)
        console.print(f"[green]Exported to {path}[/green]")
    except Exception as e:
        console.print(f"[red]Export failed: {e}[/red]")

def capture_cmd_output(cmd: List[str]) -> str:
    """Safely execute command and capture output"""
    # Sanitize command arguments
    safe_cmd = [shlex.quote(arg) for arg in cmd]
    
    print(f"\n[INFO] Executing: {' '.join(safe_cmd)}")
    print("[PROGRESS] ", end="", flush=True)
    
    lines_buffer = []
    try:
        # Use timeout to prevent hanging
        process = subprocess.Popen(safe_cmd, 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE, 
                                 text=True,
                                 timeout=300)  # 5 minute timeout
        
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                print(".", end="", flush=True)
                lines_buffer.append(line)
                
        stderr_output = process.stderr.read()
        if stderr_output:
            lines_buffer.append(f"\n[STDERR]\n{stderr_output}")
            
        print("\n[COMPLETED]")
        return "".join(lines_buffer)
        
    except subprocess.TimeoutExpired:
        process.kill()
        return f"[ERROR] Command timeout: {' '.join(safe_cmd)}"
    except Exception as e:
        logging.error(f"Command execution failed: {e}")
        return f"[ERROR] Failed to execute {' '.join(safe_cmd)}: {e}"

def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_domain(domain: str) -> bool:
    """Validate domain name format"""
    if len(domain) > 255:
        return False
    pattern = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    return bool(pattern.match(domain))

def validate_url(url: str) -> bool:
    """Validate URL format"""
    if len(url) > 2048:  # Reasonable URL length limit
        return False
    pattern = re.compile(r'^https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^/]*)*$')
    return bool(pattern.match(url))

def query_whois(domain: str) -> str:
    """Query WHOIS information for a domain"""
    if not validate_domain(domain):
        return "[ERROR] Invalid domain"
        
    try:
        import whois
        w = whois.whois(domain)
        return str(w)
    except ImportError:
        return "[ERROR] WHOIS library not installed"
    except Exception:
        return "[ERROR] WHOIS query failed"

class RateLimiter:
    """Rate limiting decorator to prevent service abuse"""
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

@RateLimiter(10, 60)
def smtp_enum(ip: str, wordlist: Optional[List[str]] = None) -> str:
    """Enumerate SMTP users using VRFY command"""
    if not validate_ip(ip):
        return "[ERROR] Invalid IP address"
        
    if not wordlist:
        wordlist = ["admin", "guest", "info", "root", "user", "test"]
    
    result = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, 25))
        
        banner = sock.recv(1024).decode(errors='ignore')
        result.append(f"[BANNER] {banner.strip()}")
        
        for user in wordlist:
            try:
                sock.send(f"VRFY {user}\r\n".encode())
                response = sock.recv(1024).decode(errors='ignore')
                
                if "252" in response or "250" in response:
                    result.append(f"[FOUND] User: {user}")
                elif "550" in response:
                    result.append(f"[NOT FOUND] User: {user}")
                else:
                    result.append(f"[UNKNOWN] User: {user} - {response.strip()}")
                    
            except Exception as e:
                result.append(f"[ERROR] Testing user {user}: {e}")
                
        sock.close()
        
    except Exception as e:
        result.append(f"[ERROR] SMTP enumeration failed: {e}")
    
    return "\n".join(result)

def ssh_enum(ip: str) -> str:
    """Test SSH authentication"""
    if not validate_ip(ip):
        return "[ERROR] Invalid IP address"
        
    user = safe_input("SSH username: ")
    if user is None:
        return "[ERROR] No username provided"
        
    pwd = safe_getpass("SSH password: ")
    if pwd is None:
        return "[ERROR] No password provided"
    
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        client.connect(ip, username=user, password=pwd, timeout=10)
        client.close()
        
        return f"[SUCCESS] SSH login successful for {user}@{ip}"
        
    except paramiko.AuthenticationException:
        return f"[FAILED] SSH authentication failed for {user}@{ip}"
    except paramiko.SSHException as e:
        return f"[ERROR] SSH connection error: {e}"
    except Exception as e:
        return f"[ERROR] SSH enumeration error: {e}"

def run_webrecon(url: str) -> str:
    """Perform web reconnaissance using wget"""
    if not validate_url(url):
        return "[ERROR] Invalid URL"
        
    if not check_tool_installed("wget"):
        return "[ERROR] wget not installed"
    
    try:
        # Create temporary directory for download
        temp_dir = f"/tmp/webrecon_{int(time.time())}"
        os.makedirs(temp_dir, exist_ok=True)
        
        # Change to temp directory
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        # Run wget with safe parameters
        wget_output = capture_cmd_output(['wget', '-r', '-l', '1', '-np', '-nd', '--user-agent=Mozilla/5.0', url])
        
        # Analyze downloaded files for sensitive patterns
        pattern = re.compile(r'(username|user_name|userid|user_id|login|password|passwd|pass_word|pwd|secret|auth|access_token)', re.IGNORECASE)
        hits = []
        
        for file in os.listdir('.'):
            if os.path.isfile(file):
                try:
                    with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f, 1):
                            if pattern.search(line):
                                hits.append(f"{file}:{line_num}:{line.strip()}")
                except Exception:
                    continue
        
        # Clean up
        os.chdir(original_dir)
        subprocess.run(['rm', '-rf', temp_dir], check=False)
        
        result = [f"[WGET OUTPUT]\n{wget_output}", "\n[ANALYSIS]"]
        
        if hits:
            result.append("[POTENTIAL SENSITIVE INFO FOUND]")
            result.extend(hits[:20])  # Limit to first 20 hits
        else:
            result.append("[INFO] No sensitive patterns detected")
        
        return "\n".join(result)
        
    except Exception as e:
        return f"[ERROR] Web reconnaissance failed: {e}"

def web_recon(url: str) -> str:
    """Web reconnaissance wrapper"""
    return run_webrecon(url)

def sql_injection_test(url: str) -> str:
    """Test for SQL injection vulnerabilities"""
    if not validate_url(url):
        return "[ERROR] Invalid URL"
        
    if not check_tool_installed("sqlmap"):
        return "[ERROR] sqlmap not installed"
    
    try:
        return capture_cmd_output([
            'sqlmap', '-u', url, 
            '--dbs', 
            '--tamper=space2comment', 
            '--random-agent', 
            '--forms', 
            '--crawl=2',
            '--batch',
            '--risk=1',
            '--level=1'
        ])
    except Exception as e:
        return f"[ERROR] SQL injection test failed: {e}"

def scan_web_full(target: str) -> str:
    """Comprehensive web security scan"""
    if not (validate_ip(target) or validate_domain(target) or validate_url(target)):
        return "[ERROR] Invalid target"
    
    console.print(f"\n[bold blue]Starting comprehensive scan of: {target}[/bold blue]")
    
    outputs = []
    separator = "\n" + "="*80 + "\n"
    
    # WhatWeb fingerprinting
    if check_tool_installed("whatweb"):
        console.print("[yellow]Running WhatWeb fingerprinting...[/yellow]")
        whatweb_output = capture_cmd_output(["whatweb", target])
        outputs.append(f"[WHATWEB OUTPUT]\n{whatweb_output}")
    else:
        outputs.append("[WARNING] whatweb not installed")
    
    # Web reconnaissance
    console.print("[yellow]Running Web reconnaissance...[/yellow]")
    webrecon_output = run_webrecon(target)
    outputs.append(f"[WEBRECON OUTPUT]\n{webrecon_output}")
    
    # Nmap port scan
    if check_tool_installed("nmap"):
        console.print("[yellow]Running Nmap port scan...[/yellow]")
        nmap_output = capture_cmd_output([
            "nmap", "-v", "-sS", "--top-ports=1000", 
            "--open", "-T3", "-Pn", target
        ])
        outputs.append(f"[NMAP OUTPUT]\n{nmap_output}")
    else:
        outputs.append("[WARNING] nmap not installed")
    
    # Gobuster directory enumeration
    if check_tool_installed("gobuster"):
        console.print("[yellow]Running Gobuster directory enumeration...[/yellow]")
        default_wordlist = "/usr/share/dirb/wordlists/common.txt"
        if not os.path.exists(default_wordlist):
            default_wordlist = "/usr/share/wordlists/dirb/common.txt"
        
        if os.path.exists(default_wordlist):
            gobuster_output = capture_cmd_output([
                "gobuster", "dir", "-u", target, 
                "-w", default_wordlist, "-t", "50"
            ])
            outputs.append(f"[GOBUSTER OUTPUT]\n{gobuster_output}")
        else:
            outputs.append("[WARNING] gobuster wordlist not found")
    else:
        outputs.append("[WARNING] gobuster not installed")
    
    # HTTP headers check
    if check_tool_installed("curl"):
        console.print("[yellow]Checking HTTP headers...[/yellow]")
        curl_output = capture_cmd_output(["curl", "-I", "-s", target])
        outputs.append(f"[HTTP HEADERS]\n{curl_output}")
    else:
        outputs.append("[WARNING] curl not installed")
    
    # Nuclei vulnerability scan
    if check_tool_installed("nuclei"):
        console.print("[yellow]Running Nuclei vulnerability scan...[/yellow]")
        nuclei_output = capture_cmd_output([
            "nuclei", "-u", target, "-c", "50", "-silent"
        ])
        outputs.append(f"[NUCLEI OUTPUT]\n{nuclei_output}")
    else:
        outputs.append("[WARNING] nuclei not installed")
    
    console.print("\n[bold green]Comprehensive scan completed[/bold green]")
    
    return separator.join(outputs)

def nuclei_hunter_scan(domain: str, template: str) -> str:
    """Run Nuclei with specific template after subdomain discovery"""
    if not validate_domain(domain):
        return "[ERROR] Invalid domain"
        
    if not check_tool_installed("nuclei"):
        return "[ERROR] nuclei not installed"
    
    try:
        # Try to use subfinder if available, otherwise use domain directly
        if check_tool_installed("subfinder"):
            console.print("[yellow]Discovering subdomains...[/yellow]")
            subfinder_result = subprocess.run(
                ["subfinder", "-d", domain, "-silent"], 
                capture_output=True, text=True, check=True
            )
            targets = subfinder_result.stdout.strip()
        else:
            targets = domain
        
        if not targets:
            return "[ERROR] No targets found"
        
        # Run nuclei with specified template
        nuclei_cmd = ["nuclei", "-c", "50", "-silent"]
        if template and template != "all":
            nuclei_cmd.extend(["-t", template])
        
        nuclei_result = subprocess.run(
            nuclei_cmd, 
            input=targets, 
            text=True, 
            capture_output=True
        )
        
        output = f"[NUCLEI HUNTER SCAN]\n{nuclei_result.stdout}"
        if nuclei_result.stderr:
            output += f"\n[STDERR]\n{nuclei_result.stderr}"
        
        return output
        
    except Exception as e:
        return f"[ERROR] Nuclei hunter scan failed: {e}"

def scan_web_silence(target: str) -> str:
    """Silent web scanning with minimal footprint"""
    if not (validate_ip(target) or validate_domain(target) or validate_url(target)):
        return "[ERROR] Invalid target"
        
    if not check_tool_installed("nmap"):
        return "[ERROR] nmap not installed"
    
    try:
        return capture_cmd_output([
            "nmap", "-sS", "--top-ports=100", 
            "--open", "-T2", "-Pn", "-f", target
        ])
    except Exception as e:
        return f"[ERROR] Silent scan failed: {e}"

# Wrapper functions for menu operations
def do_smtp_enum():
    """SMTP enumeration menu wrapper"""
    ip = safe_input("Target IP address: ")
    if ip is None:
        return
    
    result = smtp_enum(ip)
    ask_store_result("SMTP Enumeration", ip, result)

def do_ssh_enum():
    """SSH enumeration menu wrapper"""
    ip = safe_input("Target IP address: ")
    if ip is None:
        return
    
    result = ssh_enum(ip)
    ask_store_result("SSH Assessment", ip, result)

def do_web_recon():
    """Web reconnaissance menu wrapper"""
    url = safe_input("Target URL: ")
    if url is None:
        return
    
    result = web_recon(url)
    ask_store_result("Web Reconnaissance", url, result)

def do_sql_injection_test():
    """SQL injection test menu wrapper"""
    url = safe_input("Target URL: ")
    if url is None:
        return
    
    result = sql_injection_test(url)
    ask_store_result("SQL Injection Test", url, result)

def do_full_scan():
    """Full web scan menu wrapper"""
    target = safe_input("Target (IP/domain/URL): ")
    if target is None:
        return
    
    result = scan_web_full(target)
    ask_store_result("Comprehensive Web Scan", target, result)

def do_nuclei_hunter():
    """Nuclei hunter menu wrapper"""
    domain = safe_input("Target domain: ")
    if domain is None:
        return
    
    template = safe_input("Nuclei template (or 'all' for default): ")
    if template is None:
        return
    
    result = nuclei_hunter_scan(domain, template)
    ask_store_result("Nuclei Hunter Scan", domain, result)

def do_silence_scan():
    """Silent scan menu wrapper"""
    target = safe_input("Target (IP/domain/URL): ")
    if target is None:
        return
    
    result = scan_web_silence(target)
    ask_store_result("Silent Web Scan", target, result)

def do_whois():
    """WHOIS query menu wrapper"""
    domain = safe_input("Target domain: ")
    if domain is None:
        return
    
    result = query_whois(domain)
    ask_store_result("WHOIS Information", domain, result)

def do_gobuster():
    """Gobuster scan menu wrapper"""
    url = safe_input("Target URL: ")
    if url is None:
        return
    
    wordlist = safe_input("Wordlist path (default: /usr/share/dirb/wordlists/common.txt): ")
    if wordlist is None:
        return
    
    if not wordlist:
        wordlist = "/usr/share/dirb/wordlists/common.txt"
    
    if not os.path.exists(wordlist):
        console.print("[red]Wordlist not found[/red]")
        return
    
    try:
        result = capture_cmd_output([
            "gobuster", "dir", "-u", url, 
            "-w", wordlist, "-t", "50"
        ])
        ask_store_result("Directory Discovery", url, result)
    except Exception as e:
        console.print(f"[red]Gobuster scan failed: {e}[/red]")

def ask_store_result(scan_name: str, target: str, result_data: str):
    """Prompt user to store scan results in encrypted project"""
    combined = f"=== {scan_name.upper()} ===\nTarget: {target}\nTimestamp: {datetime.datetime.now().isoformat()}\n\n{result_data}"
    
    console.print("\n[green]Scan completed successfully[/green]")
    
    store_choice = safe_input("Store results in project? (y/n): ")
    if store_choice and store_choice.lower() == 'y':
        pid = pick_project_id()
        if pid != 0:
            store_note_in_project(pid, combined)
            console.print("[green]Results stored in encrypted project[/green]")
        else:
            console.print("[yellow]No project selected - results not stored[/yellow]")
    else:
        console.print("[yellow]Results not stored[/yellow]")

def update_toolkit():
    """Update toolkit from GitHub repository"""
    console.print("\n[yellow]Checking for latest version on GitHub...[/yellow]")
    
    temp_dir = os.path.join("/tmp", f"web_toolkit_temp_{int(time.time())}")
    
    try:
        # Clone repository
        subprocess.run(["git", "clone", GITHUB_REPO, temp_dir], 
                      check=True, capture_output=True)
        
        # Create backup directory
        backup_dir = f"backup_{int(time.time())}"
        os.makedirs(backup_dir, exist_ok=True)
        
        console.print(f"[yellow]Creating backup in {backup_dir}...[/yellow]")
        
        # Backup current files
        for item in os.listdir('.'):
            if item not in (os.path.basename(sys.argv[0]), 'logs', 'database', backup_dir, '.git'):
                try:
                    subprocess.run(["cp", "-r", item, backup_dir], check=False)
                except:
                    pass
        
        # Copy new files
        for item in os.listdir(temp_dir):
            src = os.path.join(temp_dir, item)
            dst = os.path.join('.', item)
            try:
                subprocess.run(["cp", "-r", src, dst], check=False)
            except:
                pass
        
        # Cleanup
        subprocess.run(["rm", "-rf", temp_dir], check=False)
        
        console.print(f"[green]Updated to latest version from GitHub[/green]")
        console.print(f"[yellow]Backup created in '{backup_dir}'[/yellow]")
        
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to clone repository: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Update failed: {e}[/red]")

def show_banner():
    """Display professional application banner"""
    banner = """
================================================================================
                            WEB-TOOLKIT PROFESSIONAL                           
                        Advanced Web Security Testing Framework                
================================================================================
                               Version 2.0 - byfranke.com                     
                          Professional Penetration Testing Suite               
================================================================================
"""
    console.print(banner)

def show_help():
    """Display comprehensive help documentation"""
    help_text = """
================================================================================
                           WEB-TOOLKIT PROFESSIONAL HELP                      
================================================================================

OVERVIEW:
The Web-Toolkit Professional is an advanced security testing framework designed
for comprehensive web application penetration testing and vulnerability assessment.

MAIN FEATURES:

1. PROJECT MANAGEMENT:
   - Create Project: Creates password-protected projects with encrypted storage
   - Open Project: Access, view, edit, and manage encrypted project data
   - Encrypted Storage: All scan results and notes are encrypted using Fernet

2. SECURITY SCANNING TOOLS:
   - Full Web Scan: Comprehensive multi-tool scanning (nmap, nuclei, gobuster)
   - Web Reconnaissance: Website mirroring and pattern analysis
   - SQL Injection Testing: Automated SQLi detection using sqlmap
   - SMTP Enumeration: User enumeration via SMTP VRFY commands
   - SSH Assessment: SSH service testing and authentication
   - Nuclei Hunter: Template-based vulnerability scanning
   - Silent Scanning: Stealthy reconnaissance operations
   - WHOIS Information: Domain registration data retrieval
   - Directory Discovery: Web directory and file enumeration

3. SECURITY FEATURES:
   - Input Validation: Comprehensive input sanitization
   - Command Injection Prevention: Safe command execution
   - Encrypted Database: SQLite with WAL mode and secure delete
   - Rate Limiting: Protection against service disruption
   - Secure Password Handling: bcrypt for password hashing

USAGE MODES:

Interactive Mode:
   Run without parameters to access the interactive menu system.
   Navigate using numeric options and follow prompts.

Command Line Mode:
   --scan-full <target>     : Comprehensive target scanning
   --web <url>              : Web reconnaissance
   --sql <url>              : SQL injection testing
   --smtp <ip>              : SMTP user enumeration
   --ssh <ip>               : SSH service assessment
   --nuclei-scan <domain> <template> : Nuclei template scanning
   --scan-silence <target>  : Silent scanning mode
   --whois <domain>         : Domain information lookup
   --update                 : Update toolkit from repository

REQUIREMENTS:
- Python 3.8+
- Required tools: nmap, nuclei, gobuster, sqlmap, whatweb, curl
- Python packages: cryptography, rich, paramiko, requests, bcrypt

SECURITY CONSIDERATIONS:
- All project data is encrypted using Fernet symmetric encryption
- Input validation prevents command injection attacks
- Database uses WAL mode for improved security
- Logging includes security event tracking
- Rate limiting prevents service abuse

For additional support and documentation, visit: byfranke.com
================================================================================
"""
    console.print(help_text)
    input("Press Enter to continue...")

def main_menu():
    """Display and handle main application menu"""
    while True:
        show_banner()
        console.print("\n[bold blue]MAIN MENU[/bold blue]")
        print("1 - Project Management")
        print("2 - Security Scanning Tools")
        print("3 - Help & Documentation")
        print("4 - Update Toolkit")
        print("5 - Exit Application")
        
        choice = safe_input("\nSelect option: ")
        if choice is None:
            break
            
        if choice == '1':
            project_management_menu()
        elif choice == '2':
            security_scanning_menu()
        elif choice == '3':
            show_help()
        elif choice == '4':
            update_toolkit()
        elif choice == '5':
            console.print("\n[green]Thank you for using Web-Toolkit Professional[/green]")
            break
        else:
            console.print("\n[red]Invalid option. Please select 1-5.[/red]")
            input("Press Enter to continue...")

def project_management_menu():
    """Handle project management operations"""
    while True:
        console.print("\n[bold blue]PROJECT MANAGEMENT[/bold blue]")
        print("1 - Create New Project")
        print("2 - Open Existing Project")
        print("3 - List All Projects")
        print("4 - Return to Main Menu")
        
        choice = safe_input("\nSelect option: ")
        if choice is None:
            break
            
        if choice == '1':
            create_project()
        elif choice == '2':
            open_project()
        elif choice == '3':
            list_projects()
            input("Press Enter to continue...")
        elif choice == '4':
            break
        else:
            console.print("\n[red]Invalid option. Please select 1-4.[/red]")
            input("Press Enter to continue...")

def security_scanning_menu():
    """Handle security scanning operations"""
    while True:
        console.print("\n[bold blue]SECURITY SCANNING TOOLS[/bold blue]")
        print("1 - Full Web Scan (Comprehensive)")
        print("2 - Web Reconnaissance")
        print("3 - SQL Injection Testing")
        print("4 - SMTP User Enumeration")
        print("5 - SSH Service Assessment")
        print("6 - Nuclei Vulnerability Scan")
        print("7 - Silent Scanning Mode")
        print("8 - WHOIS Domain Lookup")
        print("9 - Directory Discovery (Gobuster)")
        print("10 - Return to Main Menu")
        
        choice = safe_input("\nSelect option: ")
        if choice is None:
            break
            
        if choice == '1':
            do_full_scan()
        elif choice == '2':
            do_web_recon()
        elif choice == '3':
            do_sql_injection_test()
        elif choice == '4':
            do_smtp_enum()
        elif choice == '5':
            do_ssh_enum()
        elif choice == '6':
            do_nuclei_hunter()
        elif choice == '7':
            do_silence_scan()
        elif choice == '8':
            do_whois()
        elif choice == '9':
            do_gobuster()
        elif choice == '10':
            break
        else:
            console.print("\n[red]Invalid option. Please select 1-10.[/red]")
            input("Press Enter to continue...")

def main():
    """Main application entry point"""
    # Initialize database
    init_db()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Web-Toolkit Professional - Advanced Web Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--scan-full', type=str, metavar='TARGET',
                       help='Comprehensive target scanning')
    parser.add_argument('--web', type=str, metavar='URL',
                       help='Web reconnaissance')
    parser.add_argument('--sql', type=str, metavar='URL',
                       help='SQL injection testing')
    parser.add_argument('--smtp', type=str, metavar='IP',
                       help='SMTP user enumeration')
    parser.add_argument('--ssh', type=str, metavar='IP',
                       help='SSH service assessment')
    parser.add_argument('--nuclei-scan', nargs=2, metavar=('DOMAIN', 'TEMPLATE'),
                       help='Nuclei template scanning')
    parser.add_argument('--scan-silence', type=str, metavar='TARGET',
                       help='Silent scanning mode')
    parser.add_argument('--whois', type=str, metavar='DOMAIN',
                       help='Domain information lookup')
    parser.add_argument('--update', action='store_true',
                       help='Update toolkit from repository')
    
    args = parser.parse_args()
    
    # Handle command line arguments
    if args.scan_full:
        result = scan_web_full(args.scan_full)
        print(result)
    elif args.web:
        result = web_recon(args.web)
        print(result)
    elif args.sql:
        result = sql_injection_test(args.sql)
        print(result)
    elif args.smtp:
        result = smtp_enum(args.smtp)
        print(result)
    elif args.ssh:
        console.print("[yellow]SSH enumeration requires interactive input. Use the menu instead.[/yellow]")
    elif args.nuclei_scan:
        result = nuclei_hunter_scan(args.nuclei_scan[0], args.nuclei_scan[1])
        print(result)
    elif args.scan_silence:
        result = scan_web_silence(args.scan_silence)
        print(result)
    elif args.whois:
        result = query_whois(args.whois)
        print(result)
    elif args.update:
        update_toolkit()
    else:
        # Start interactive menu
        main_menu()

class SecurityTests(unittest.TestCase):
    """Unit tests for security functions"""
    
    def test_validate_ip(self):
        """Test IP address validation"""
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("10.0.0.1"))
        self.assertTrue(validate_ip("2001:db8::1"))
        self.assertFalse(validate_ip("999.999.999.999"))
        self.assertFalse(validate_ip("invalid_ip"))
        self.assertFalse(validate_ip(""))
        
    def test_validate_domain(self):
        """Test domain name validation"""
        self.assertTrue(validate_domain("example.com"))
        self.assertTrue(validate_domain("test.example.org"))
        self.assertTrue(validate_domain("sub.domain.co.uk"))
        self.assertFalse(validate_domain("invalid_domain"))
        self.assertFalse(validate_domain(""))
        self.assertFalse(validate_domain("a" * 256))  # Too long
        
    def test_validate_url(self):
        """Test URL validation"""
        self.assertTrue(validate_url("http://example.com"))
        self.assertTrue(validate_url("https://test.example.org/path"))
        self.assertFalse(validate_url("ftp://example.com"))
        self.assertFalse(validate_url("example.com"))
        self.assertFalse(validate_url(""))
        self.assertFalse(validate_url("a" * 2049))  # Too long

if __name__ == "__main__":
    if "--test" in sys.argv:
        sys.argv.remove("--test")
        unittest.main()
    else:
        main()
