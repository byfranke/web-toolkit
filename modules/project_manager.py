#!/usr/bin/env python3
"""
Professional Project File Manager
Encrypted file system for penetration testing projects
"""

import os
import json
import sqlite3
import datetime
import shutil
import tempfile
import mimetypes
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from cryptography.fernet import Fernet
from dataclasses import dataclass, asdict
import zipfile
import hashlib

@dataclass
class FileMetadata:
    """File metadata structure"""
    file_id: str
    filename: str
    file_type: str
    file_size: int
    mime_type: str
    created_at: str
    modified_at: str
    tags: List[str]
    description: str
    checksum: str

@dataclass
class ProjectStructure:
    """Project directory structure"""
    name: str
    path: str
    file_count: int
    total_size: int
    created_at: str
    last_accessed: str

class EncryptedFileManager:
    """Professional encrypted file manager for pentest projects"""
    
    def __init__(self, project_id: int, encryption_key: bytes, project_name: str):
        self.project_id = project_id
        self.encryption_key = encryption_key
        self.project_name = project_name
        self.fernet = Fernet(encryption_key)
        
        # Create project directory structure
        self.base_path = Path.home() / 'Documents' / 'WebToolkitProjects' / f'project_{project_id}'
        self._init_project_structure()
        
        # Initialize file database
        self.db_path = self.base_path / '.project_files.db'
        self.conn = sqlite3.connect(str(self.db_path))
        self._init_file_database()
    
    def _init_project_structure(self):
        """Initialize professional project directory structure"""
        directories = [
            'reconnaissance',          # Recon results
            'reconnaissance/nmap',     # Nmap scans
            'reconnaissance/nuclei',   # Nuclei results
            'reconnaissance/web',      # Web enumeration
            'reconnaissance/dns',      # DNS enumeration
            'vulnerability_assessment', # Vulnerability data
            'vulnerability_assessment/cves', # CVE details
            'vulnerability_assessment/exploits', # Exploit attempts
            'exploitation',            # Exploitation results
            'exploitation/shells',     # Shell access logs
            'exploitation/loot',       # Extracted data
            'post_exploitation',       # Post-exploitation
            'post_exploitation/persistence', # Persistence mechanisms
            'post_exploitation/privilege_escalation', # PrivEsc
            'reporting',               # Reports and documentation
            'reporting/screenshots',   # Evidence screenshots
            'reporting/templates',     # Report templates
            'tools',                   # Custom tools/scripts
            'tools/payloads',          # Custom payloads
            'tools/wordlists',         # Custom wordlists
            'client_data',             # Client-specific data
            'methodology',             # Testing methodology
            'timeline',                # Project timeline
            'notes'                    # General notes
        ]
        
        for directory in directories:
            dir_path = self.base_path / directory
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def _init_file_database(self):
        """Initialize encrypted file metadata database"""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS project_files (
                file_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                mime_type TEXT,
                created_at TEXT NOT NULL,
                modified_at TEXT NOT NULL,
                tags TEXT,
                description TEXT,
                checksum TEXT,
                is_encrypted BOOLEAN DEFAULT 1,
                category TEXT
            )
        ''')
        
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS project_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                file_id TEXT,
                metadata TEXT
            )
        ''')
        
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS project_tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tag_name TEXT UNIQUE NOT NULL,
                tag_color TEXT,
                description TEXT
            )
        ''')
        
        # Add default tags
        default_tags = [
            ('critical', '#dc3545', 'Critical findings'),
            ('high', '#fd7e14', 'High priority items'),
            ('medium', '#ffc107', 'Medium priority items'),
            ('low', '#28a745', 'Low priority items'),
            ('info', '#17a2b8', 'Informational items'),
            ('exploit', '#6f42c1', 'Exploitation related'),
            ('credentials', '#e83e8c', 'Credentials and sensitive data'),
            ('network', '#20c997', 'Network related'),
            ('web', '#fd7e14', 'Web application related'),
            ('report', '#6c757d', 'Reporting materials')
        ]
        
        for tag_name, color, desc in default_tags:
            self.conn.execute('''
                INSERT OR IGNORE INTO project_tags (tag_name, tag_color, description)
                VALUES (?, ?, ?)
            ''', (tag_name, color, desc))
        
        self.conn.commit()
    
    def save_file(self, file_path: str, content: bytes, category: str = 'general', 
                  tags: List[str] = None, description: str = '') -> str:
        """Save encrypted file to project"""
        if tags is None:
            tags = []
        
        filename = os.path.basename(file_path)
        file_id = hashlib.sha256(f"{filename}{datetime.datetime.now().isoformat()}".encode()).hexdigest()[:16]
        
        # Determine file category and path
        category_path = self._get_category_path(category)
        full_path = self.base_path / category_path / f"{file_id}_{filename}.enc"
        
        # Encrypt and save file
        encrypted_content = self.fernet.encrypt(content)
        with open(full_path, 'wb') as f:
            f.write(encrypted_content)
        
        # Calculate checksum
        checksum = hashlib.md5(content).hexdigest()
        
        # Get MIME type
        mime_type, _ = mimetypes.guess_type(filename)
        if mime_type is None:
            mime_type = 'application/octet-stream'
        
        # Store metadata
        self.conn.execute('''
            INSERT INTO project_files 
            (file_id, filename, file_path, file_type, file_size, mime_type,
             created_at, modified_at, tags, description, checksum, category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            file_id, filename, str(full_path), self._get_file_type(filename),
            len(content), mime_type, datetime.datetime.now().isoformat(),
            datetime.datetime.now().isoformat(), json.dumps(tags),
            description, checksum, category
        ))
        
        # Add to timeline
        self._add_timeline_event('file_created', f'File created: {filename}', file_id)
        
        self.conn.commit()
        return file_id
    
    def get_file(self, file_id: str) -> Tuple[Optional[bytes], Optional[FileMetadata]]:
        """Retrieve and decrypt file"""
        cursor = self.conn.execute('SELECT * FROM project_files WHERE file_id = ?', (file_id,))
        row = cursor.fetchone()
        
        if not row:
            return None, None
        
        file_path = row[2]
        if not os.path.exists(file_path):
            return None, None
        
        # Read and decrypt file
        with open(file_path, 'rb') as f:
            encrypted_content = f.read()
        
        try:
            content = self.fernet.decrypt(encrypted_content)
        except Exception:
            return None, None
        
        # Create metadata
        metadata = FileMetadata(
            file_id=row[0], filename=row[1], file_type=row[3],
            file_size=row[4], mime_type=row[5], created_at=row[6],
            modified_at=row[7], tags=json.loads(row[8]) if row[8] else [],
            description=row[9] or '', checksum=row[10]
        )
        
        # Update access time
        self._add_timeline_event('file_accessed', f'File accessed: {metadata.filename}', file_id)
        
        return content, metadata
    
    def list_files(self, category: str = None, tags: List[str] = None) -> List[FileMetadata]:
        """List files with optional filtering"""
        query = 'SELECT * FROM project_files WHERE 1=1'
        params = []
        
        if category:
            query += ' AND category = ?'
            params.append(category)
        
        if tags:
            # Filter by tags (files that have ALL specified tags)
            for tag in tags:
                query += ' AND tags LIKE ?'
                params.append(f'%"{tag}"%')
        
        query += ' ORDER BY modified_at DESC'
        
        cursor = self.conn.execute(query, params)
        files = []
        
        for row in cursor.fetchall():
            metadata = FileMetadata(
                file_id=row[0], filename=row[1], file_type=row[3],
                file_size=row[4], mime_type=row[5], created_at=row[6],
                modified_at=row[7], tags=json.loads(row[8]) if row[8] else [],
                description=row[9] or '', checksum=row[10]
            )
            files.append(metadata)
        
        return files
    
    def delete_file(self, file_id: str) -> bool:
        """Delete file and metadata"""
        cursor = self.conn.execute('SELECT filename, file_path FROM project_files WHERE file_id = ?', (file_id,))
        row = cursor.fetchone()
        
        if not row:
            return False
        
        filename, file_path = row
        
        # Delete physical file
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete from database
        self.conn.execute('DELETE FROM project_files WHERE file_id = ?', (file_id,))
        
        # Add to timeline
        self._add_timeline_event('file_deleted', f'File deleted: {filename}', file_id)
        
        self.conn.commit()
        return True
    
    def create_note(self, title: str, content: str, tags: List[str] = None) -> str:
        """Create a note file"""
        if tags is None:
            tags = ['note']
        
        note_content = f"# {title}\n\nCreated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nTags: {', '.join(tags)}\n\n---\n\n{content}"
        
        return self.save_file(
            f"{title.replace(' ', '_').lower()}.md",
            note_content.encode('utf-8'),
            'notes',
            tags,
            f"Note: {title}"
        )
    
    def export_project(self, export_path: str) -> bool:
        """Export entire project as encrypted archive"""
        try:
            with zipfile.ZipFile(export_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add project metadata
                project_info = {
                    'project_name': self.project_name,
                    'project_id': self.project_id,
                    'export_date': datetime.datetime.now().isoformat(),
                    'version': '2.0'
                }
                
                zipf.writestr('project_info.json', json.dumps(project_info, indent=2))
                
                # Add database
                zipf.write(str(self.db_path), '.project_files.db')
                
                # Add all files
                for root, dirs, files in os.walk(self.base_path):
                    for file in files:
                        if file != '.project_files.db':  # Skip database (already added)
                            file_path = os.path.join(root, file)
                            arc_path = os.path.relpath(file_path, self.base_path)
                            zipf.write(file_path, arc_path)
            
            self._add_timeline_event('project_exported', f'Project exported to: {export_path}')
            return True
            
        except Exception as e:
            print(f"Export failed: {e}")
            return False
    
    def get_project_statistics(self) -> Dict[str, Any]:
        """Get comprehensive project statistics"""
        stats = {
            'total_files': 0,
            'total_size': 0,
            'files_by_category': {},
            'files_by_type': {},
            'recent_activity': [],
            'tag_usage': {},
            'timeline_summary': {}
        }
        
        # File statistics
        cursor = self.conn.execute('''
            SELECT category, file_type, file_size, tags FROM project_files
        ''')
        
        for row in cursor.fetchall():
            category, file_type, file_size, tags_json = row
            stats['total_files'] += 1
            stats['total_size'] += file_size
            
            # Category stats
            stats['files_by_category'][category] = stats['files_by_category'].get(category, 0) + 1
            
            # File type stats
            stats['files_by_type'][file_type] = stats['files_by_type'].get(file_type, 0) + 1
            
            # Tag usage
            if tags_json:
                tags = json.loads(tags_json)
                for tag in tags:
                    stats['tag_usage'][tag] = stats['tag_usage'].get(tag, 0) + 1
        
        # Recent activity
        cursor = self.conn.execute('''
            SELECT timestamp, event_type, description 
            FROM project_timeline 
            ORDER BY timestamp DESC 
            LIMIT 10
        ''')
        
        stats['recent_activity'] = [
            {'timestamp': row[0], 'event_type': row[1], 'description': row[2]}
            for row in cursor.fetchall()
        ]
        
        return stats
    
    def search_files(self, query: str) -> List[FileMetadata]:
        """Search files by filename, description, or tags"""
        search_query = '''
            SELECT * FROM project_files 
            WHERE filename LIKE ? OR description LIKE ? OR tags LIKE ?
            ORDER BY modified_at DESC
        '''
        
        search_term = f'%{query}%'
        cursor = self.conn.execute(search_query, (search_term, search_term, search_term))
        
        files = []
        for row in cursor.fetchall():
            metadata = FileMetadata(
                file_id=row[0], filename=row[1], file_type=row[3],
                file_size=row[4], mime_type=row[5], created_at=row[6],
                modified_at=row[7], tags=json.loads(row[8]) if row[8] else [],
                description=row[9] or '', checksum=row[10]
            )
            files.append(metadata)
        
        return files
    
    def _get_category_path(self, category: str) -> str:
        """Get directory path for category"""
        category_mapping = {
            'reconnaissance': 'reconnaissance',
            'nmap': 'reconnaissance/nmap',
            'nuclei': 'reconnaissance/nuclei',
            'web': 'reconnaissance/web',
            'dns': 'reconnaissance/dns',
            'vulnerabilities': 'vulnerability_assessment',
            'cves': 'vulnerability_assessment/cves',
            'exploits': 'vulnerability_assessment/exploits',
            'exploitation': 'exploitation',
            'shells': 'exploitation/shells',
            'loot': 'exploitation/loot',
            'post_exploitation': 'post_exploitation',
            'persistence': 'post_exploitation/persistence',
            'privesc': 'post_exploitation/privilege_escalation',
            'reporting': 'reporting',
            'screenshots': 'reporting/screenshots',
            'tools': 'tools',
            'payloads': 'tools/payloads',
            'wordlists': 'tools/wordlists',
            'client_data': 'client_data',
            'notes': 'notes',
            'general': 'notes'
        }
        
        return category_mapping.get(category, 'notes')
    
    def _get_file_type(self, filename: str) -> str:
        """Determine file type from filename"""
        extension = os.path.splitext(filename)[1].lower()
        
        type_mapping = {
            '.txt': 'text', '.md': 'text', '.log': 'text',
            '.json': 'data', '.xml': 'data', '.csv': 'data',
            '.png': 'image', '.jpg': 'image', '.jpeg': 'image', '.gif': 'image',
            '.pdf': 'document', '.doc': 'document', '.docx': 'document',
            '.py': 'script', '.sh': 'script', '.ps1': 'script',
            '.zip': 'archive', '.tar': 'archive', '.gz': 'archive',
            '.pcap': 'network', '.cap': 'network',
            '.exe': 'executable', '.dll': 'executable'
        }
        
        return type_mapping.get(extension, 'unknown')
    
    def _add_timeline_event(self, event_type: str, description: str, file_id: str = None, metadata: Dict = None):
        """Add event to project timeline"""
        self.conn.execute('''
            INSERT INTO project_timeline (timestamp, event_type, description, file_id, metadata)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            datetime.datetime.now().isoformat(),
            event_type,
            description,
            file_id,
            json.dumps(metadata) if metadata else None
        ))

class ProjectManager:
    """High-level project manager for multiple clients"""
    
    def __init__(self, db_connection):
        self.conn = db_connection
    
    def get_project_file_manager(self, project_id: int) -> Optional[EncryptedFileManager]:
        """Get file manager for specific project"""
        cursor = self.conn.execute(
            'SELECT name, encryption_key FROM projects WHERE id = ?', 
            (project_id,)
        )
        row = cursor.fetchone()
        
        if row:
            project_name, encryption_key = row
            return EncryptedFileManager(project_id, encryption_key, project_name)
        
        return None
    
    def create_project_template(self, project_id: int, template_type: str = 'standard'):
        """Create initial project structure with templates"""
        file_manager = self.get_project_file_manager(project_id)
        if not file_manager:
            return False
        
        templates = {
            'standard': [
                ('methodology/testing_methodology.md', self._get_methodology_template()),
                ('reporting/executive_summary_template.md', self._get_executive_summary_template()),
                ('reporting/technical_report_template.md', self._get_technical_report_template()),
                ('notes/initial_notes.md', self._get_initial_notes_template()),
            ],
            'web_app': [
                ('methodology/web_app_methodology.md', self._get_webapp_methodology_template()),
                ('reconnaissance/web/urls_to_test.txt', '# URLs to test\n'),
                ('tools/web_payloads.txt', self._get_web_payloads_template()),
            ],
            'network': [
                ('methodology/network_methodology.md', self._get_network_methodology_template()),
                ('reconnaissance/network_ranges.txt', '# Network ranges to scan\n'),
                ('tools/network_payloads.txt', self._get_network_payloads_template()),
            ]
        }
        
        if template_type in templates:
            for file_path, content in templates[template_type]:
                filename = os.path.basename(file_path)
                category = os.path.dirname(file_path).replace('/', '_') if '/' in file_path else 'general'
                
                file_manager.save_file(
                    filename,
                    content.encode('utf-8'),
                    category,
                    ['template', template_type],
                    f'Template file: {filename}'
                )
        
        return True
    
    def _get_methodology_template(self) -> str:
        return """# Penetration Testing Methodology

## Project Information
- **Client:** [CLIENT_NAME]
- **Project Start:** [START_DATE]
- **Project End:** [END_DATE]
- **Tester:** [TESTER_NAME]

## Scope
- **In Scope:** 
  - [LIST_TARGETS]
- **Out of Scope:**
  - [LIST_EXCLUSIONS]

## Testing Phases

### 1. Information Gathering
- [ ] Passive reconnaissance
- [ ] Active reconnaissance
- [ ] DNS enumeration
- [ ] Subdomain discovery

### 2. Vulnerability Assessment
- [ ] Port scanning
- [ ] Service enumeration
- [ ] Vulnerability scanning
- [ ] Web application testing

### 3. Exploitation
- [ ] Exploit validation
- [ ] Privilege escalation
- [ ] Post-exploitation

### 4. Reporting
- [ ] Executive summary
- [ ] Technical findings
- [ ] Recommendations
- [ ] Appendices

## Notes
[METHODOLOGY_NOTES]
"""
    
    def _get_executive_summary_template(self) -> str:
        return """# Executive Summary

## Project Overview
[CLIENT_NAME] engaged our team to conduct a penetration test of their [SYSTEM_TYPE] environment. This assessment was performed to identify security vulnerabilities and provide recommendations for improving the overall security posture.

## Scope of Work
The assessment included:
- [SCOPE_DETAILS]

## Key Findings
### Critical Issues
- [CRITICAL_FINDINGS]

### High Priority Issues
- [HIGH_FINDINGS]

### Medium Priority Issues
- [MEDIUM_FINDINGS]

## Risk Assessment
[OVERALL_RISK_ASSESSMENT]

## Recommendations
1. [RECOMMENDATION_1]
2. [RECOMMENDATION_2]
3. [RECOMMENDATION_3]

## Conclusion
[CONCLUSION]
"""
    
    def _get_technical_report_template(self) -> str:
        return """# Technical Report

## Methodology
[TESTING_METHODOLOGY]

## Findings

### [VULNERABILITY_NAME]
**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]
**CVSS Score:** [SCORE]
**CVE:** [CVE_ID if applicable]

**Description:**
[DETAILED_DESCRIPTION]

**Impact:**
[IMPACT_ASSESSMENT]

**Affected Systems:**
- [AFFECTED_SYSTEM_1]
- [AFFECTED_SYSTEM_2]

**Proof of Concept:**
```
[POC_CODE_OR_STEPS]
```

**Remediation:**
[REMEDIATION_STEPS]

**References:**
- [REFERENCE_1]
- [REFERENCE_2]

---

## Appendices
### Appendix A: Scan Results
[RAW_SCAN_DATA]

### Appendix B: Tool Output
[TOOL_OUTPUT]
"""
    
    def _get_initial_notes_template(self) -> str:
        return f"""# Initial Project Notes

**Created:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Project Setup
- [ ] Scope confirmed
- [ ] Testing environment prepared
- [ ] Tools configured
- [ ] Communication channels established

## Initial Observations
[INITIAL_OBSERVATIONS]

## Questions for Client
- [QUESTION_1]
- [QUESTION_2]

## Action Items
- [ ] [ACTION_ITEM_1]
- [ ] [ACTION_ITEM_2]

## Contacts
- **Primary Contact:** [NAME] ([EMAIL])
- **Technical Contact:** [NAME] ([EMAIL])
"""
    
    def _get_webapp_methodology_template(self) -> str:
        return """# Web Application Testing Methodology

## OWASP Testing Framework

### Information Gathering
- [ ] Manually explore the application
- [ ] Spider/crawl for missed or hidden content
- [ ] Check for files that expose content (robots.txt, sitemap.xml)
- [ ] Check the caches of major search engines
- [ ] Check for sensitive information in page comments

### Authentication Testing
- [ ] Test for bypassing authentication schema
- [ ] Test for default credentials
- [ ] Test for account enumeration
- [ ] Test for weak lock out mechanism

### Session Management Testing
- [ ] Test for bypassing session management schema
- [ ] Test for cookies attributes
- [ ] Test for session fixation
- [ ] Test for session timeout

### Input Validation Testing
- [ ] Test for reflected cross site scripting
- [ ] Test for stored cross site scripting
- [ ] Test for SQL injection
- [ ] Test for command injection
- [ ] Test for buffer overflow
"""
    
    def _get_network_methodology_template(self) -> str:
        return """# Network Penetration Testing Methodology

## Network Discovery
- [ ] Network enumeration
- [ ] Port scanning (TCP/UDP)
- [ ] Service identification
- [ ] Operating system fingerprinting

## Service Enumeration
- [ ] Banner grabbing
- [ ] Service-specific enumeration
- [ ] Default credentials testing
- [ ] Anonymous access testing

## Vulnerability Assessment
- [ ] Automated vulnerability scanning
- [ ] Manual testing of identified services
- [ ] Configuration review
- [ ] Patch level assessment

## Exploitation
- [ ] Exploit validation
- [ ] Privilege escalation
- [ ] Lateral movement
- [ ] Data collection
"""
    
    def _get_web_payloads_template(self) -> str:
        return """# Web Application Payloads

## XSS Payloads
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')

## SQL Injection Payloads
' OR '1'='1
' UNION SELECT NULL--
'; DROP TABLE users--

## Command Injection
; ls -la
| whoami
& ping -c 4 127.0.0.1
"""
    
    def _get_network_payloads_template(self) -> str:
        return """# Network Testing Payloads

## Common Passwords
admin
password
123456
password123
admin123

## Default Credentials
admin:admin
root:root
administrator:password
guest:guest

## SMB Null Session
smbclient -L //target -N
enum4linux target
"""
