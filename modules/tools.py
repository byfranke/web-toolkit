#!/usr/bin/env python3
"""
Enhanced tools module for Web-Toolkit
Professional implementation with better error handling and parallel execution
"""

import subprocess
import threading
import time
import json
import os
import tempfile
import concurrent.futures
from typing import List, Dict, Optional, Callable, Any
from dataclasses import dataclass
from contextlib import contextmanager
import queue
import signal

@dataclass
class ToolResult:
    """Standardized tool execution result"""
    tool_name: str
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    execution_time: float
    success: bool

class ToolExecutor:
    """Professional tool executor with advanced features"""
    
    def __init__(self, max_workers: int = 4, default_timeout: int = 300):
        self.max_workers = max_workers
        self.default_timeout = default_timeout
        self.progress_callback: Optional[Callable] = None
    
    def set_progress_callback(self, callback: Callable):
        """Set callback function for progress updates"""
        self.progress_callback = callback
    
    @contextmanager
    def timeout_handler(self, timeout: int):
        """Context manager for handling command timeouts"""
        def timeout_signal(signum, frame):
            raise TimeoutError(f"Command timed out after {timeout} seconds")
        
        old_handler = signal.signal(signal.SIGALRM, timeout_signal)
        signal.alarm(timeout)
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    
    def execute_tool(self, tool_name: str, command: List[str], 
                    timeout: Optional[int] = None, 
                    cwd: Optional[str] = None,
                    env: Optional[Dict] = None) -> ToolResult:
        """Execute a single tool with comprehensive error handling"""
        if timeout is None:
            timeout = self.default_timeout
        
        start_time = time.time()
        
        try:
            if self.progress_callback:
                self.progress_callback(f"Starting {tool_name}")
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=env or os.environ.copy()
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                stderr += f"\n[TIMEOUT] Command killed after {timeout} seconds"
                exit_code = -1
            
            execution_time = time.time() - start_time
            success = exit_code == 0
            
            if self.progress_callback:
                status = "completed" if success else "failed"
                self.progress_callback(f"{tool_name} {status} in {execution_time:.2f}s")
            
            return ToolResult(
                tool_name=tool_name,
                command=command,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                execution_time=execution_time,
                success=success
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return ToolResult(
                tool_name=tool_name,
                command=command,
                exit_code=-2,
                stdout="",
                stderr=f"Execution error: {str(e)}",
                execution_time=execution_time,
                success=False
            )
    
    def execute_parallel(self, commands: List[Dict]) -> List[ToolResult]:
        """Execute multiple tools in parallel"""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_command = {}
            
            for cmd_info in commands:
                future = executor.submit(
                    self.execute_tool,
                    cmd_info['tool_name'],
                    cmd_info['command'],
                    cmd_info.get('timeout'),
                    cmd_info.get('cwd'),
                    cmd_info.get('env')
                )
                future_to_command[future] = cmd_info
            
            for future in concurrent.futures.as_completed(future_to_command):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    cmd_info = future_to_command[future]
                    error_result = ToolResult(
                        tool_name=cmd_info['tool_name'],
                        command=cmd_info['command'],
                        exit_code=-3,
                        stdout="",
                        stderr=f"Future execution error: {str(e)}",
                        execution_time=0,
                        success=False
                    )
                    results.append(error_result)
        
        return results

class AdvancedScanner:
    """Advanced scanning capabilities"""
    
    def __init__(self):
        self.executor = ToolExecutor()
        self.temp_dir = tempfile.mkdtemp(prefix="webtoolkit_")
    
    def __del__(self):
        """Cleanup temporary directory"""
        import shutil
        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def advanced_nmap_scan(self, target: str, scan_type: str = "full") -> ToolResult:
        """Advanced Nmap scanning with multiple techniques"""
        scan_profiles = {
            "quick": ["-sS", "--top-ports=1000", "-T4"],
            "full": ["-sS", "-sV", "-sC", "-A", "-T3", "--script=vuln"],
            "stealth": ["-sS", "-f", "-D", "RND:10", "-T1"],
            "udp": ["-sU", "--top-ports=100", "-T3"],
            "comprehensive": ["-sS", "-sU", "-sV", "-sC", "-A", "-O", "--script=vuln", "-T3"]
        }
        
        base_cmd = ["nmap", "-v", "--open", "-Pn"]
        scan_options = scan_profiles.get(scan_type, scan_profiles["full"])
        
        command = base_cmd + scan_options + [target]
        
        return self.executor.execute_tool("nmap_advanced", command, timeout=600)
    
    def nuclei_comprehensive_scan(self, target: str, template_dir: str = None) -> ToolResult:
        """Comprehensive Nuclei scan with multiple templates"""
        if not template_dir:
            template_dir = os.path.expanduser("~/.local/nuclei-templates")
        
        command = [
            "nuclei",
            "-u", target,
            "-t", template_dir,
            "-c", "50",
            "-rate-limit", "10",
            "-timeout", "10",
            "-retries", "2",
            "-json"
        ]
        
        return self.executor.execute_tool("nuclei_comprehensive", command, timeout=900)
    
    def gobuster_multi_mode(self, target: str, wordlists: List[str] = None) -> List[ToolResult]:
        """Multi-mode Gobuster scanning"""
        if not wordlists:
            wordlists = [
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
            ]
        
        commands = []
        
        # Directory enumeration
        for i, wordlist in enumerate(wordlists):
            if os.path.exists(wordlist):
                commands.append({
                    'tool_name': f'gobuster_dir_{i+1}',
                    'command': [
                        "gobuster", "dir",
                        "-u", target,
                        "-w", wordlist,
                        "-t", "50",
                        "-x", "php,html,txt,asp,aspx,jsp",
                        "--random-agent"
                    ],
                    'timeout': 600
                })
        
        # Subdomain enumeration (if target is a domain)
        if not target.startswith('http'):
            commands.append({
                'tool_name': 'gobuster_dns',
                'command': [
                    "gobuster", "dns",
                    "-d", target,
                    "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                    "-t", "50"
                ],
                'timeout': 300
            })
        
        return self.executor.execute_parallel(commands)
    
    def comprehensive_web_scan(self, target: str) -> Dict[str, ToolResult]:
        """Comprehensive web application scan"""
        scan_commands = []
        
        # Technology identification
        scan_commands.append({
            'tool_name': 'whatweb',
            'command': ["whatweb", "-a", "3", target]
        })
        
        # SSL/TLS analysis
        if target.startswith('https'):
            scan_commands.append({
                'tool_name': 'sslyze',
                'command': ["sslyze", "--regular", target]
            })
        
        # HTTP headers analysis
        scan_commands.append({
            'tool_name': 'curl_headers',
            'command': ["curl", "-I", "-L", "-k", target]
        })
        
        # Robots.txt check
        scan_commands.append({
            'tool_name': 'robots_check',
            'command': ["curl", "-L", "-k", f"{target}/robots.txt"]
        })
        
        # Security headers check
        scan_commands.append({
            'tool_name': 'security_headers',
            'command': ["curl", "-I", "-L", "-k", "-H", "User-Agent: WebToolkit-Scanner", target]
        })
        
        results = self.executor.execute_parallel(scan_commands)
        return {result.tool_name: result for result in results}
    
    def vulnerability_assessment(self, target: str) -> Dict[str, Any]:
        """Comprehensive vulnerability assessment"""
        assessment_results = {
            'target': target,
            'timestamp': time.time(),
            'scans_performed': [],
            'vulnerabilities_found': [],
            'recommendations': []
        }
        
        # Nmap vulnerability scan
        nmap_result = self.advanced_nmap_scan(target, "comprehensive")
        assessment_results['scans_performed'].append(nmap_result)
        
        # Nuclei scan
        nuclei_result = self.nuclei_comprehensive_scan(target)
        assessment_results['scans_performed'].append(nuclei_result)
        
        # Web-specific scans
        if target.startswith('http'):
            web_results = self.comprehensive_web_scan(target)
            assessment_results['scans_performed'].extend(web_results.values())
        
        # Parse results for vulnerabilities
        assessment_results['vulnerabilities_found'] = self._parse_vulnerabilities(
            assessment_results['scans_performed']
        )
        
        # Generate recommendations
        assessment_results['recommendations'] = self._generate_recommendations(
            assessment_results['vulnerabilities_found']
        )
        
        return assessment_results
    
    def _parse_vulnerabilities(self, scan_results: List[ToolResult]) -> List[Dict]:
        """Parse scan results to extract vulnerability information"""
        vulnerabilities = []
        
        for result in scan_results:
            if not result.success:
                continue
            
            # Parse Nuclei JSON output
            if result.tool_name.startswith('nuclei') and result.stdout:
                try:
                    for line in result.stdout.strip().split('\n'):
                        if line.startswith('{'):
                            vuln_data = json.loads(line)
                            vulnerabilities.append({
                                'source': 'nuclei',
                                'name': vuln_data.get('template-id', 'Unknown'),
                                'severity': vuln_data.get('info', {}).get('severity', 'info'),
                                'description': vuln_data.get('info', {}).get('description', ''),
                                'matched_at': vuln_data.get('matched-at', ''),
                                'raw_data': vuln_data
                            })
                except json.JSONDecodeError:
                    pass
            
            # Parse Nmap output for vulnerabilities
            elif result.tool_name.startswith('nmap') and 'VULNERABLE' in result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'VULNERABLE' in line:
                        vulnerabilities.append({
                            'source': 'nmap',
                            'name': line.strip(),
                            'severity': 'medium',  # Default severity
                            'description': f'Nmap detected vulnerability: {line.strip()}',
                            'raw_data': line
                        })
        
        return vulnerabilities
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Generic recommendations
        if vulnerabilities:
            recommendations.append("Conduct regular security assessments")
            recommendations.append("Implement a vulnerability management program")
            recommendations.append("Keep all software and systems updated")
        
        # Specific recommendations based on vulnerability types
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts.get('critical', 0) > 0:
            recommendations.append("CRITICAL: Address critical vulnerabilities immediately")
        
        if severity_counts.get('high', 0) > 0:
            recommendations.append("HIGH PRIORITY: Schedule immediate patching for high-severity issues")
        
        if severity_counts.get('medium', 0) > 0:
            recommendations.append("Plan remediation for medium-severity vulnerabilities within 30 days")
        
        return recommendations

# Tool availability checker
class ToolChecker:
    """Check availability of external tools"""
    
    REQUIRED_TOOLS = {
        'nmap': 'Network mapper for port scanning',
        'nuclei': 'Vulnerability scanner based on templates',
        'gobuster': 'Directory/file & DNS busting tool',
        'whatweb': 'Web application fingerprinting',
        'curl': 'Command line tool for transferring data',
        'wget': 'Network downloader',
        'sqlmap': 'Automatic SQL injection tool'
    }
    
    @classmethod
    def check_tool_availability(cls) -> Dict[str, bool]:
        """Check which tools are available on the system"""
        availability = {}
        
        for tool in cls.REQUIRED_TOOLS:
            try:
                subprocess.run(['which', tool], capture_output=True, check=True)
                availability[tool] = True
            except (subprocess.CalledProcessError, FileNotFoundError):
                availability[tool] = False
        
        return availability
    
    @classmethod
    def get_missing_tools(cls) -> List[str]:
        """Get list of missing tools"""
        availability = cls.check_tool_availability()
        return [tool for tool, available in availability.items() if not available]
    
    @classmethod
    def install_missing_tools(cls) -> bool:
        """Attempt to install missing tools (Linux only)"""
        missing_tools = cls.get_missing_tools()
        
        if not missing_tools:
            return True
        
        try:
            # Try apt-get (Debian/Ubuntu)
            subprocess.run(['sudo', 'apt-get', 'update'], check=True, capture_output=True)
            for tool in missing_tools:
                subprocess.run(['sudo', 'apt-get', 'install', '-y', tool], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            try:
                # Try pacman (Arch Linux)
                for tool in missing_tools:
                    subprocess.run(['sudo', 'pacman', '-S', '--noconfirm', tool], check=True, capture_output=True)
                return True
            except subprocess.CalledProcessError:
                return False
