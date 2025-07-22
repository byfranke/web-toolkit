#!/usr/bin/env python3
"""
CVE Detection and Vulnerability Intelligence Module
Professional CVE tracking and vulnerability correlation system
"""

import json
import re
import requests
import sqlite3
import datetime
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
import logging

@dataclass
class CVEInfo:
    """Structured CVE information"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    vector: str
    published_date: str
    modified_date: str
    references: List[str]
    affected_products: List[str]
    exploit_available: bool = False
    poc_available: bool = False
    
@dataclass
class VulnerabilityMatch:
    """Vulnerability match from scan results"""
    cve_id: str
    tool_name: str
    target: str
    service: str
    port: int
    confidence: str  # high, medium, low
    evidence: str
    timestamp: str
    remediation: Optional[str] = None

class CVEDatabase:
    """Local CVE database for fast lookups"""
    
    def __init__(self, db_path: str = "cve_database.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self._init_database()
        
    def _init_database(self):
        """Initialize CVE database schema"""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                vector TEXT,
                published_date TEXT,
                modified_date TEXT,
                refs TEXT,
                affected_products TEXT,
                exploit_available BOOLEAN,
                poc_available BOOLEAN,
                last_updated TEXT
            )
        ''')
        
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                tool_name TEXT,
                target TEXT,
                service TEXT,
                port INTEGER,
                confidence TEXT,
                evidence TEXT,
                timestamp TEXT,
                remediation TEXT,
                project_id INTEGER,
                FOREIGN KEY(cve_id) REFERENCES cves(cve_id)
            )
        ''')
        self.conn.commit()
    
    def update_cve_info(self, cve_info: CVEInfo):
        """Update or insert CVE information"""
        self.conn.execute('''
            INSERT OR REPLACE INTO cves 
            (cve_id, description, severity, cvss_score, vector, published_date, 
             modified_date, references, affected_products, exploit_available, 
             poc_available, last_updated) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            cve_info.cve_id, cve_info.description, cve_info.severity,
            cve_info.cvss_score, cve_info.vector, cve_info.published_date,
            cve_info.modified_date, json.dumps(cve_info.references),
            json.dumps(cve_info.affected_products), cve_info.exploit_available,
            cve_info.poc_available, datetime.datetime.now().isoformat()
        ))
        self.conn.commit()
    
    def get_cve_info(self, cve_id: str) -> Optional[CVEInfo]:
        """Retrieve CVE information"""
        cursor = self.conn.execute('SELECT * FROM cves WHERE cve_id = ?', (cve_id,))
        row = cursor.fetchone()
        if row:
            return CVEInfo(
                cve_id=row[0], description=row[1], severity=row[2],
                cvss_score=row[3], vector=row[4], published_date=row[5],
                modified_date=row[6], references=json.loads(row[7]),
                affected_products=json.loads(row[8]), exploit_available=row[9],
                poc_available=row[10]
            )
        return None
    
    def store_vulnerability_match(self, vuln_match: VulnerabilityMatch, project_id: int):
        """Store vulnerability match in project"""
        self.conn.execute('''
            INSERT INTO vulnerability_matches 
            (cve_id, tool_name, target, service, port, confidence, evidence, 
             timestamp, remediation, project_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            vuln_match.cve_id, vuln_match.tool_name, vuln_match.target,
            vuln_match.service, vuln_match.port, vuln_match.confidence,
            vuln_match.evidence, vuln_match.timestamp, vuln_match.remediation,
            project_id
        ))
        self.conn.commit()

class CVEIntelligence:
    """CVE Intelligence and correlation system"""
    
    def __init__(self):
        self.cve_db = CVEDatabase()
        self.cve_patterns = {
            'nmap_vuln_scripts': [
                r'CVE-(\d{4}-\d{4,7})',
                r'(\d{4}-\d{4,7})',  # CVE without prefix
                r'VULNERABLE:\s*([^\s]+)',
            ],
            'nuclei_templates': [
                r'cve-(\d{4}-\d{4,7})',
                r'"cve":\s*"([^"]+)"',
                r'CVE-(\d{4}-\d{4,7})',
            ],
            'general_patterns': [
                r'CVE-(\d{4}-\d{4,7})',
                r'vulnerability[^:]*:\s*([^\n]+)',
                r'EXPLOIT[^:]*:\s*([^\n]+)',
            ]
        }
    
    def extract_cves_from_nmap(self, nmap_output: str) -> List[VulnerabilityMatch]:
        """Extract CVEs from Nmap vulnerability script output"""
        vulnerabilities = []
        lines = nmap_output.split('\n')
        current_service = ""
        current_port = 0
        
        for line in lines:
            # Extract service and port information
            port_match = re.search(r'(\d+)/tcp\s+open\s+(\w+)', line)
            if port_match:
                current_port = int(port_match.group(1))
                current_service = port_match.group(2)
            
            # Look for vulnerability patterns
            for pattern in self.cve_patterns['nmap_vuln_scripts']:
                matches = re.findall(pattern, line, re.IGNORECASE)
                for match in matches:
                    cve_id = match if match.startswith('CVE-') else f'CVE-{match}'
                    
                    # Determine confidence based on context
                    confidence = 'high' if 'VULNERABLE' in line.upper() else 'medium'
                    
                    vuln = VulnerabilityMatch(
                        cve_id=cve_id,
                        tool_name='nmap',
                        target="",  # Will be set by caller
                        service=current_service,
                        port=current_port,
                        confidence=confidence,
                        evidence=line.strip(),
                        timestamp=datetime.datetime.now().isoformat()
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def extract_cves_from_nuclei(self, nuclei_output: str) -> List[VulnerabilityMatch]:
        """Extract CVEs from Nuclei JSON output"""
        vulnerabilities = []
        
        for line in nuclei_output.split('\n'):
            if line.strip().startswith('{'):
                try:
                    data = json.loads(line)
                    template_id = data.get('template-id', '')
                    
                    # Extract CVE from template ID or info
                    cve_matches = []
                    for pattern in self.cve_patterns['nuclei_templates']:
                        cve_matches.extend(re.findall(pattern, json.dumps(data), re.IGNORECASE))
                    
                    if cve_matches:
                        cve_id = cve_matches[0]
                        if not cve_id.startswith('CVE-'):
                            cve_id = f'CVE-{cve_id}'
                        
                        severity = data.get('info', {}).get('severity', 'info')
                        confidence = 'high' if severity in ['high', 'critical'] else 'medium'
                        
                        vuln = VulnerabilityMatch(
                            cve_id=cve_id,
                            tool_name='nuclei',
                            target=data.get('matched-at', ''),
                            service='web',
                            port=80,  # Default for web
                            confidence=confidence,
                            evidence=f"Template: {template_id}, Severity: {severity}",
                            timestamp=datetime.datetime.now().isoformat()
                        )
                        vulnerabilities.append(vuln)
                        
                except json.JSONDecodeError:
                    continue
        
        return vulnerabilities
    
    def fetch_cve_details(self, cve_id: str) -> Optional[CVEInfo]:
        """Fetch CVE details from NIST NVD API"""
        # First check local database
        cve_info = self.cve_db.get_cve_info(cve_id)
        if cve_info:
            return cve_info
        
        try:
            # Fetch from NIST NVD API
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and data['vulnerabilities']:
                    cve_data = data['vulnerabilities'][0]['cve']
                    
                    # Extract CVSS score
                    cvss_score = 0.0
                    cvss_vector = ""
                    metrics = cve_data.get('metrics', {})
                    
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss_data['baseScore']
                        cvss_vector = cvss_data['vectorString']
                    elif 'cvssMetricV2' in metrics:
                        cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                        cvss_score = cvss_data['baseScore']
                        cvss_vector = cvss_data['vectorString']
                    
                    # Determine severity
                    if cvss_score >= 9.0:
                        severity = 'critical'
                    elif cvss_score >= 7.0:
                        severity = 'high'
                    elif cvss_score >= 4.0:
                        severity = 'medium'
                    else:
                        severity = 'low'
                    
                    # Extract references
                    references = []
                    for ref in cve_data.get('references', []):
                        references.append(ref.get('url', ''))
                    
                    cve_info = CVEInfo(
                        cve_id=cve_id,
                        description=cve_data.get('descriptions', [{}])[0].get('value', ''),
                        severity=severity,
                        cvss_score=cvss_score,
                        vector=cvss_vector,
                        published_date=cve_data.get('published', ''),
                        modified_date=cve_data.get('lastModified', ''),
                        references=references,
                        affected_products=[],  # Would need additional parsing
                        exploit_available=False,  # Would need exploit database check
                        poc_available=False
                    )
                    
                    # Cache in local database
                    self.cve_db.update_cve_info(cve_info)
                    return cve_info
                    
        except Exception as e:
            logging.error(f"Error fetching CVE details for {cve_id}: {e}")
        
        return None
    
    def generate_vulnerability_report(self, vulnerabilities: List[VulnerabilityMatch]) -> Dict:
        """Generate comprehensive vulnerability report"""
        report = {
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'unique_cves': set(),
                'affected_services': set(),
                'ports_affected': set()
            },
            'vulnerabilities': [],
            'recommendations': []
        }
        
        for vuln in vulnerabilities:
            # Get detailed CVE information
            cve_info = self.fetch_cve_details(vuln.cve_id)
            
            if cve_info:
                # Update summary counts
                if cve_info.severity == 'critical':
                    report['summary']['critical_count'] += 1
                elif cve_info.severity == 'high':
                    report['summary']['high_count'] += 1
                elif cve_info.severity == 'medium':
                    report['summary']['medium_count'] += 1
                else:
                    report['summary']['low_count'] += 1
                
                report['summary']['unique_cves'].add(vuln.cve_id)
                report['summary']['affected_services'].add(vuln.service)
                report['summary']['ports_affected'].add(vuln.port)
                
                # Add detailed vulnerability info
                vuln_detail = {
                    'cve_id': vuln.cve_id,
                    'severity': cve_info.severity,
                    'cvss_score': cve_info.cvss_score,
                    'description': cve_info.description,
                    'service': vuln.service,
                    'port': vuln.port,
                    'confidence': vuln.confidence,
                    'evidence': vuln.evidence,
                    'references': cve_info.references[:3],  # First 3 references
                    'detected_by': vuln.tool_name
                }
                report['vulnerabilities'].append(vuln_detail)
        
        # Convert sets to lists for JSON serialization
        report['summary']['unique_cves'] = list(report['summary']['unique_cves'])
        report['summary']['affected_services'] = list(report['summary']['affected_services'])
        report['summary']['ports_affected'] = list(report['summary']['ports_affected'])
        
        # Generate recommendations
        if report['summary']['critical_count'] > 0:
            report['recommendations'].append("CRITICAL: Immediate patching required for critical vulnerabilities")
        if report['summary']['high_count'] > 0:
            report['recommendations'].append("HIGH: Schedule patching within 24-48 hours for high-severity issues")
        if report['summary']['medium_count'] > 0:
            report['recommendations'].append("MEDIUM: Plan remediation within 30 days for medium-severity vulnerabilities")
        
        return report

# Integration functions for the main toolkit
def analyze_scan_for_cves(tool_name: str, scan_output: str, target: str) -> List[VulnerabilityMatch]:
    """Main function to analyze scan output for CVEs"""
    cve_intel = CVEIntelligence()
    vulnerabilities = []
    
    if tool_name == 'nmap':
        vulnerabilities = cve_intel.extract_cves_from_nmap(scan_output)
    elif tool_name == 'nuclei':
        vulnerabilities = cve_intel.extract_cves_from_nuclei(scan_output)
    
    # Set target for all vulnerabilities
    for vuln in vulnerabilities:
        if not vuln.target:
            vuln.target = target
    
    return vulnerabilities

def get_cve_summary_table(vulnerabilities: List[VulnerabilityMatch]) -> str:
    """Generate a formatted table of CVEs found"""
    if not vulnerabilities:
        return "No CVEs detected in scan results."
    
    cve_intel = CVEIntelligence()
    table_data = []
    
    for vuln in vulnerabilities[:10]:  # Limit to top 10 for display
        cve_info = cve_intel.fetch_cve_details(vuln.cve_id)
        if cve_info:
            table_data.append([
                vuln.cve_id,
                cve_info.severity.upper(),
                f"{cve_info.cvss_score:.1f}",
                vuln.service,
                vuln.port,
                vuln.tool_name
            ])
    
    if table_data:
        from tabulate import tabulate
        headers = ['CVE ID', 'Severity', 'CVSS', 'Service', 'Port', 'Tool']
        return tabulate(table_data, headers=headers, tablefmt='grid')
    
    return "CVE details could not be retrieved."
