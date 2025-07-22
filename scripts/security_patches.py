#!/usr/bin/env python3
"""
Security Patches for Web-Toolkit
This file applies critical security fixes to the main web-toolkit.py
"""

import re
import shlex
import logging
from typing import List, Optional

class SecurityPatcher:
    """Applies security patches to vulnerable code"""
    
    @staticmethod
    def patch_command_injection(cmd_args: List[str]) -> List[str]:
        """Patch command injection vulnerabilities"""
        patched_args = []
        
        for arg in cmd_args:
            # Validate argument length
            if len(arg) > 1000:
                raise ValueError("Argument too long - potential attack")
            
            # Check for dangerous characters
            dangerous_chars = [';', '|', '&', '`', '$', '(', ')', '<', '>', '\n', '\r']
            for char in dangerous_chars:
                if char in arg:
                    logging.warning(f"Dangerous character '{char}' found in argument: {arg}")
                    raise ValueError(f"Dangerous character found: {char}")
            
            # Quote the argument safely
            patched_args.append(shlex.quote(arg))
        
        return patched_args
    
    @staticmethod
    def patch_sql_injection(query: str, params: tuple) -> tuple:
        """Ensure SQL queries use parameterized statements"""
        # Check for dangerous patterns in query
        dangerous_patterns = [
            r".*\+.*",  # String concatenation
            r".*%.*%.*",  # String formatting
            r".*\.format\(",  # .format() usage
            r".*f['\"].*"  # f-string usage in SQL
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, query):
                logging.error(f"Potentially unsafe SQL query: {query}")
                raise ValueError("SQL query contains unsafe patterns")
        
        # Ensure query uses ? placeholders
        placeholder_count = query.count('?')
        if placeholder_count != len(params):
            raise ValueError("Parameter count mismatch in SQL query")
        
        return query, params
    
    @staticmethod
    def patch_path_traversal(file_path: str, base_dir: str) -> str:
        """Prevent path traversal attacks"""
        import os
        from pathlib import Path
        
        # Normalize the path
        normalized_path = os.path.normpath(file_path)
        
        # Check for dangerous patterns
        if '..' in normalized_path or normalized_path.startswith('/'):
            raise ValueError("Path traversal attempt detected")
        
        # Ensure path is within base directory
        full_path = os.path.join(base_dir, normalized_path)
        canonical_base = os.path.realpath(base_dir)
        canonical_path = os.path.realpath(full_path)
        
        if not canonical_path.startswith(canonical_base):
            raise ValueError("Path outside of allowed directory")
        
        return canonical_path
    
    @staticmethod
    def validate_input_sanitization(user_input: str, input_type: str) -> bool:
        """Validate that input is properly sanitized"""
        if input_type == 'ip':
            return SecurityPatcher._validate_ip(user_input)
        elif input_type == 'domain':
            return SecurityPatcher._validate_domain(user_input)
        elif input_type == 'url':
            return SecurityPatcher._validate_url(user_input)
        else:
            return False
    
    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Validate IP address"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            # Block private ranges for security
            if ip_obj.is_private or ip_obj.is_loopback:
                return False
            return True
        except ValueError:
            return False
    
    @staticmethod
    def _validate_domain(domain: str) -> bool:
        """Validate domain name"""
        if len(domain) > 253 or len(domain) < 1:
            return False
        
        # Check for suspicious patterns
        suspicious = ['.local', '.localhost', '.internal', '..']
        if any(pattern in domain.lower() for pattern in suspicious):
            return False
        
        pattern = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
        return bool(pattern.match(domain))
    
    @staticmethod
    def _validate_url(url: str) -> bool:
        """Validate URL"""
        if len(url) > 2048:
            return False
        
        if not url.startswith(('http://', 'https://')):
            return False
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return SecurityPatcher._validate_domain(parsed.hostname) if parsed.hostname else False
        except Exception:
            return False

# Example usage for patching existing code
def secure_subprocess_run(tool: str, args: List[str]) -> str:
    """Secure wrapper for subprocess execution"""
    
    # Whitelist of allowed tools
    ALLOWED_TOOLS = [
        'nmap', 'nuclei', 'gobuster', 'whatweb', 'curl', 'wget',
        'subfinder', 'sqlmap', 'dig', 'host', 'ncat'
    ]
    
    if tool not in ALLOWED_TOOLS:
        raise ValueError(f"Tool '{tool}' not allowed")
    
    # Patch arguments for security
    try:
        patched_args = SecurityPatcher.patch_command_injection(args)
    except ValueError as e:
        logging.error(f"Security patch failed: {e}")
        raise
    
    # Build secure command
    cmd = [tool] + patched_args
    
    # Log for audit
    logging.info(f"Executing secure command: {cmd}")
    
    # Execute with timeout and security constraints
    import subprocess
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
            check=False
        )
        return result.stdout + (result.stderr if result.stderr else "")
    except subprocess.TimeoutExpired:
        logging.warning(f"Command timed out: {cmd}")
        return "Command timed out"
    except Exception as e:
        logging.error(f"Command execution failed: {e}")
        return f"Command failed: {e}"

def secure_database_query(conn, query: str, params: tuple):
    """Secure database query execution"""
    try:
        # Apply SQL injection patch
        safe_query, safe_params = SecurityPatcher.patch_sql_injection(query, params)
        
        # Execute with error handling
        cursor = conn.execute(safe_query, safe_params)
        return cursor.fetchall()
        
    except ValueError as e:
        logging.error(f"SQL security error: {e}")
        raise
    except Exception as e:
        logging.error(f"Database error: {e}")
        raise

# Security configuration
SECURITY_CONFIG = {
    'max_input_length': 1000,
    'max_password_attempts': 3,
    'session_timeout': 1800,  # 30 minutes
    'log_file': 'security_events.log',
    'audit_enabled': True
}

if __name__ == "__main__":
    print("🛡️ Security patches loaded")
    print("Apply these patches to web-toolkit.py for enhanced security")
