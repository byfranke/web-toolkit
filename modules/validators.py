#!/usr/bin/env python3
"""
Advanced validation module for Web-Toolkit
Provides comprehensive input validation and sanitization
"""

import re
import ipaddress
import socket
import urllib.parse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class ValidationResult:
    """Result of validation operation"""
    is_valid: bool
    error_message: Optional[str] = None
    sanitized_value: Optional[str] = None
    metadata: Optional[Dict] = None

class AdvancedValidator:
    """Advanced validator with comprehensive checks"""
    
    # Regex patterns
    PATTERNS = {
        'domain': re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'),
        'url': re.compile(r'^https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^/]*)*$'),
        'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        'mac_address': re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'),
        'port': re.compile(r'^[0-9]+$'),
    }
    
    @classmethod
    def validate_ip(cls, ip_str: str) -> ValidationResult:
        """Validate IP address with detailed information"""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            metadata = {
                'version': ip_obj.version,
                'is_private': ip_obj.is_private if hasattr(ip_obj, 'is_private') else False,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved if hasattr(ip_obj, 'is_reserved') else False,
            }
            return ValidationResult(
                is_valid=True, 
                sanitized_value=str(ip_obj),
                metadata=metadata
            )
        except ValueError as e:
            return ValidationResult(is_valid=False, error_message=f"Invalid IP address: {e}")
    
    @classmethod
    def validate_domain(cls, domain: str) -> ValidationResult:
        """Validate domain with DNS resolution check"""
        domain = domain.strip().lower()
        
        # Basic format check
        if not cls.PATTERNS['domain'].match(domain):
            return ValidationResult(is_valid=False, error_message="Invalid domain format")
        
        # Length checks
        if len(domain) > 253:
            return ValidationResult(is_valid=False, error_message="Domain name too long")
        
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63:
                return ValidationResult(is_valid=False, error_message="Domain label too long")
        
        # DNS resolution check
        try:
            socket.gethostbyname(domain)
            dns_resolvable = True
        except socket.gaierror:
            dns_resolvable = False
        
        metadata = {
            'labels': labels,
            'tld': labels[-1],
            'dns_resolvable': dns_resolvable
        }
        
        return ValidationResult(
            is_valid=True, 
            sanitized_value=domain,
            metadata=metadata
        )
    
    @classmethod
    def validate_url(cls, url: str) -> ValidationResult:
        """Validate URL with comprehensive parsing"""
        try:
            parsed = urllib.parse.urlparse(url)
            
            if not parsed.scheme in ['http', 'https']:
                return ValidationResult(is_valid=False, error_message="URL must use HTTP or HTTPS")
            
            if not parsed.netloc:
                return ValidationResult(is_valid=False, error_message="URL must have a valid host")
            
            # Validate the host part
            host = parsed.hostname
            if host:
                # Check if it's an IP or domain
                ip_result = cls.validate_ip(host)
                domain_result = cls.validate_domain(host)
                
                if not (ip_result.is_valid or domain_result.is_valid):
                    return ValidationResult(is_valid=False, error_message="Invalid host in URL")
            
            metadata = {
                'scheme': parsed.scheme,
                'host': parsed.hostname,
                'port': parsed.port,
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment
            }
            
            return ValidationResult(
                is_valid=True, 
                sanitized_value=url,
                metadata=metadata
            )
            
        except Exception as e:
            return ValidationResult(is_valid=False, error_message=f"URL parsing error: {e}")
    
    @classmethod
    def validate_port(cls, port: str) -> ValidationResult:
        """Validate port number"""
        if not port.isdigit():
            return ValidationResult(is_valid=False, error_message="Port must be numeric")
        
        port_int = int(port)
        if not (1 <= port_int <= 65535):
            return ValidationResult(is_valid=False, error_message="Port must be between 1 and 65535")
        
        # Common port metadata
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL"
        }
        
        metadata = {
            'service': common_ports.get(port_int, "Unknown"),
            'is_privileged': port_int < 1024,
            'is_ephemeral': port_int >= 49152
        }
        
        return ValidationResult(
            is_valid=True, 
            sanitized_value=str(port_int),
            metadata=metadata
        )
    
    @classmethod
    def validate_target(cls, target: str) -> ValidationResult:
        """Universal target validator (IP, domain, or URL)"""
        target = target.strip()
        
        # Try URL first
        url_result = cls.validate_url(target)
        if url_result.is_valid:
            url_result.metadata['type'] = 'url'
            return url_result
        
        # Try IP
        ip_result = cls.validate_ip(target)
        if ip_result.is_valid:
            ip_result.metadata['type'] = 'ip'
            return ip_result
        
        # Try domain
        domain_result = cls.validate_domain(target)
        if domain_result.is_valid:
            domain_result.metadata['type'] = 'domain'
            return domain_result
        
        return ValidationResult(
            is_valid=False, 
            error_message="Target must be a valid IP address, domain, or URL"
        )

def validate_wordlist_file(filepath: str) -> ValidationResult:
    """Validate wordlist file exists and is readable"""
    import os
    
    if not os.path.exists(filepath):
        return ValidationResult(is_valid=False, error_message="Wordlist file not found")
    
    if not os.path.isfile(filepath):
        return ValidationResult(is_valid=False, error_message="Path is not a file")
    
    try:
        with open(filepath, 'r') as f:
            lines = sum(1 for _ in f)
        
        metadata = {
            'line_count': lines,
            'size_bytes': os.path.getsize(filepath)
        }
        
        return ValidationResult(
            is_valid=True,
            sanitized_value=filepath,
            metadata=metadata
        )
    except IOError as e:
        return ValidationResult(is_valid=False, error_message=f"Cannot read file: {e}")

# Convenience functions for backward compatibility
def validate_ip(ip: str) -> bool:
    """Simple IP validation for backward compatibility"""
    return AdvancedValidator.validate_ip(ip).is_valid

def validate_domain(domain: str) -> bool:
    """Simple domain validation for backward compatibility"""
    return AdvancedValidator.validate_domain(domain).is_valid

def validate_url(url: str) -> bool:
    """Simple URL validation for backward compatibility"""
    return AdvancedValidator.validate_url(url).is_valid
