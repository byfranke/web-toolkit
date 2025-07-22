#!/usr/bin/env python3
"""
Professional reporting module for Web-Toolkit
Generates comprehensive reports in multiple formats
"""

import json
import csv
import datetime
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import xml.etree.ElementTree as ET

@dataclass
class ScanResult:
    """Standardized scan result structure"""
    tool_name: str
    target: str
    timestamp: str
    status: str  # success, error, timeout
    raw_output: str
    parsed_data: Optional[Dict] = None
    vulnerabilities: List[Dict] = None
    metadata: Optional[Dict] = None

class ReportGenerator:
    """Professional report generator"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_executive_summary(self, results: List[ScanResult]) -> Dict:
        """Generate executive summary from scan results"""
        summary = {
            'scan_date': datetime.datetime.now().isoformat(),
            'total_scans': len(results),
            'successful_scans': sum(1 for r in results if r.status == 'success'),
            'failed_scans': sum(1 for r in results if r.status == 'error'),
            'targets_scanned': list(set(r.target for r in results)),
            'tools_used': list(set(r.tool_name for r in results)),
            'total_vulnerabilities': 0,
            'high_risk_count': 0,
            'medium_risk_count': 0,
            'low_risk_count': 0
        }
        
        # Count vulnerabilities by severity
        for result in results:
            if result.vulnerabilities:
                summary['total_vulnerabilities'] += len(result.vulnerabilities)
                for vuln in result.vulnerabilities:
                    severity = vuln.get('severity', 'low').lower()
                    if severity in ['critical', 'high']:
                        summary['high_risk_count'] += 1
                    elif severity == 'medium':
                        summary['medium_risk_count'] += 1
                    else:
                        summary['low_risk_count'] += 1
        
        return summary
    
    def export_json(self, results: List[ScanResult], filename: str = None) -> str:
        """Export results to JSON format"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"web_toolkit_report_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        report_data = {
            'metadata': {
                'generated_by': 'Web-Toolkit',
                'version': '2.0',
                'timestamp': datetime.datetime.now().isoformat()
            },
            'executive_summary': self.generate_executive_summary(results),
            'detailed_results': [asdict(result) for result in results]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def export_html(self, results: List[ScanResult], filename: str = None) -> str:
        """Export results to HTML format"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"web_toolkit_report_{timestamp}.html"
        
        filepath = os.path.join(self.output_dir, filename)
        summary = self.generate_executive_summary(results)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web-Toolkit Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; border-bottom: 2px solid #333; padding-bottom: 20px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .metric {{ display: inline-block; margin: 10px; padding: 15px; background: white; border-radius: 5px; text-align: center; min-width: 120px; }}
        .high-risk {{ color: #dc3545; font-weight: bold; }}
        .medium-risk {{ color: #fd7e14; font-weight: bold; }}
        .low-risk {{ color: #28a745; font-weight: bold; }}
        .scan-result {{ margin: 20px 0; padding: 15px; border-left: 4px solid #007bff; background: #f8f9fa; }}
        .vulnerability {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .code {{ background: #f8f9fa; padding: 10px; font-family: monospace; white-space: pre-wrap; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Web-Toolkit Security Assessment Report</h1>
            <p>Generated on {summary['scan_date']}</p>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="metric">
                <h3>{summary['total_scans']}</h3>
                <p>Total Scans</p>
            </div>
            <div class="metric">
                <h3>{summary['successful_scans']}</h3>
                <p>Successful</p>
            </div>
            <div class="metric">
                <h3>{summary['total_vulnerabilities']}</h3>
                <p>Vulnerabilities</p>
            </div>
            <div class="metric high-risk">
                <h3>{summary['high_risk_count']}</h3>
                <p>High Risk</p>
            </div>
            <div class="metric medium-risk">
                <h3>{summary['medium_risk_count']}</h3>
                <p>Medium Risk</p>
            </div>
            <div class="metric low-risk">
                <h3>{summary['low_risk_count']}</h3>
                <p>Low Risk</p>
            </div>
        </div>
        
        <h2>Detailed Results</h2>
"""
        
        for result in results:
            status_class = "success" if result.status == "success" else "error"
            html_content += f"""
        <div class="scan-result">
            <h3>{result.tool_name} - {result.target}</h3>
            <p><strong>Status:</strong> <span class="{status_class}">{result.status}</span></p>
            <p><strong>Timestamp:</strong> {result.timestamp}</p>
            
"""
            
            if result.vulnerabilities:
                html_content += "<h4>Vulnerabilities Found:</h4>"
                for vuln in result.vulnerabilities:
                    severity_class = f"{vuln.get('severity', 'low').lower()}-risk"
                    html_content += f"""
            <div class="vulnerability {severity_class}">
                <strong>{vuln.get('name', 'Unknown Vulnerability')}</strong> 
                (Severity: {vuln.get('severity', 'Low')})
                <p>{vuln.get('description', 'No description available')}</p>
            </div>
"""
            
            html_content += f"""
            <h4>Raw Output:</h4>
            <div class="code">{result.raw_output[:1000]}{'...' if len(result.raw_output) > 1000 else ''}</div>
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath
    
    def export_csv(self, results: List[ScanResult], filename: str = None) -> str:
        """Export results to CSV format"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"web_toolkit_report_{timestamp}.csv"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Tool', 'Target', 'Timestamp', 'Status', 'Vulnerabilities Count', 'Output Length'])
            
            for result in results:
                vuln_count = len(result.vulnerabilities) if result.vulnerabilities else 0
                writer.writerow([
                    result.tool_name,
                    result.target,
                    result.timestamp,
                    result.status,
                    vuln_count,
                    len(result.raw_output)
                ])
        
        return filepath
    
    def export_xml(self, results: List[ScanResult], filename: str = None) -> str:
        """Export results to XML format"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"web_toolkit_report_{timestamp}.xml"
        
        filepath = os.path.join(self.output_dir, filename)
        
        root = ET.Element("web_toolkit_report")
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "generated_by").text = "Web-Toolkit"
        ET.SubElement(metadata, "version").text = "2.0"
        ET.SubElement(metadata, "timestamp").text = datetime.datetime.now().isoformat()
        
        results_elem = ET.SubElement(root, "results")
        
        for result in results:
            result_elem = ET.SubElement(results_elem, "scan_result")
            ET.SubElement(result_elem, "tool_name").text = result.tool_name
            ET.SubElement(result_elem, "target").text = result.target
            ET.SubElement(result_elem, "timestamp").text = result.timestamp
            ET.SubElement(result_elem, "status").text = result.status
            ET.SubElement(result_elem, "raw_output").text = result.raw_output
            
            if result.vulnerabilities:
                vulns_elem = ET.SubElement(result_elem, "vulnerabilities")
                for vuln in result.vulnerabilities:
                    vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
                    for key, value in vuln.items():
                        ET.SubElement(vuln_elem, key).text = str(value)
        
        tree = ET.ElementTree(root)
        tree.write(filepath, encoding='utf-8', xml_declaration=True)
        
        return filepath

def create_vulnerability_entry(name: str, severity: str, description: str, **kwargs) -> Dict:
    """Helper function to create standardized vulnerability entries"""
    vuln = {
        'name': name,
        'severity': severity.lower(),
        'description': description,
        'discovered_at': datetime.datetime.now().isoformat()
    }
    vuln.update(kwargs)
    return vuln
