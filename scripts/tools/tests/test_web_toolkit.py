#!/usr/bin/env python3
"""
Unit tests for Web-Toolkit Pro
Comprehensive testing suite for validation, tools, and reporting modules
"""

import unittest
import sys
import os

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))

from validators import AdvancedValidator, ValidationResult
from reporting import ReportGenerator, ScanResult, create_vulnerability_entry
from tools import ToolChecker

class TestAdvancedValidator(unittest.TestCase):
    """Test the advanced validator module"""
    
    def setUp(self):
        self.validator = AdvancedValidator()
    
    def test_valid_ip_addresses(self):
        """Test valid IP address validation"""
        valid_ips = ["192.168.1.1", "10.0.0.1", "8.8.8.8", "2001:db8::1"]
        
        for ip in valid_ips:
            result = self.validator.validate_ip(ip)
            self.assertTrue(result.is_valid, f"IP {ip} should be valid")
            self.assertIsNotNone(result.metadata)
    
    def test_invalid_ip_addresses(self):
        """Test invalid IP address validation"""
        invalid_ips = ["999.999.999.999", "not.an.ip", "192.168.1", ""]
        
        for ip in invalid_ips:
            result = self.validator.validate_ip(ip)
            self.assertFalse(result.is_valid, f"IP {ip} should be invalid")
    
    def test_valid_domains(self):
        """Test valid domain validation"""
        valid_domains = ["example.com", "subdomain.example.org", "test-domain.co.uk"]
        
        for domain in valid_domains:
            result = self.validator.validate_domain(domain)
            self.assertTrue(result.is_valid, f"Domain {domain} should be valid")
    
    def test_invalid_domains(self):
        """Test invalid domain validation"""
        invalid_domains = ["invalid_domain", "too.long." + "a" * 250, ""]
        
        for domain in invalid_domains:
            result = self.validator.validate_domain(domain)
            self.assertFalse(result.is_valid, f"Domain {domain} should be invalid")
    
    def test_valid_urls(self):
        """Test valid URL validation"""
        valid_urls = [
            "http://example.com",
            "https://subdomain.example.org/path",
            "https://192.168.1.1:8080/test"
        ]
        
        for url in valid_urls:
            result = self.validator.validate_url(url)
            self.assertTrue(result.is_valid, f"URL {url} should be valid")
    
    def test_invalid_urls(self):
        """Test invalid URL validation"""
        invalid_urls = ["not-a-url", "ftp://example.com", "https://", ""]
        
        for url in invalid_urls:
            result = self.validator.validate_url(url)
            self.assertFalse(result.is_valid, f"URL {url} should be invalid")
    
    def test_port_validation(self):
        """Test port number validation"""
        valid_ports = ["80", "443", "8080", "65535"]
        invalid_ports = ["0", "65536", "not-a-port", "-1"]
        
        for port in valid_ports:
            result = self.validator.validate_port(port)
            self.assertTrue(result.is_valid, f"Port {port} should be valid")
        
        for port in invalid_ports:
            result = self.validator.validate_port(port)
            self.assertFalse(result.is_valid, f"Port {port} should be invalid")

class TestReportGenerator(unittest.TestCase):
    """Test the report generator module"""
    
    def setUp(self):
        self.generator = ReportGenerator("test_reports")
        self.sample_results = [
            ScanResult(
                tool_name="test_tool",
                target="example.com",
                timestamp="2023-01-01T00:00:00",
                status="success",
                raw_output="Test output",
                vulnerabilities=[
                    create_vulnerability_entry(
                        name="Test Vulnerability",
                        severity="high",
                        description="Test description"
                    )
                ]
            )
        ]
    
    def test_executive_summary_generation(self):
        """Test executive summary generation"""
        summary = self.generator.generate_executive_summary(self.sample_results)
        
        self.assertIn('scan_date', summary)
        self.assertIn('total_scans', summary)
        self.assertIn('total_vulnerabilities', summary)
        self.assertEqual(summary['total_scans'], 1)
        self.assertEqual(summary['total_vulnerabilities'], 1)
        self.assertEqual(summary['high_risk_count'], 1)
    
    def test_json_export(self):
        """Test JSON report export"""
        filepath = self.generator.export_json(self.sample_results, "test_report.json")
        self.assertTrue(os.path.exists(filepath))
        
        # Clean up
        if os.path.exists(filepath):
            os.remove(filepath)
    
    def test_html_export(self):
        """Test HTML report export"""
        filepath = self.generator.export_html(self.sample_results, "test_report.html")
        self.assertTrue(os.path.exists(filepath))
        
        # Verify HTML content
        with open(filepath, 'r') as f:
            content = f.read()
            self.assertIn('<html', content)
            self.assertIn('Web-Toolkit Security Report', content)
        
        # Clean up
        if os.path.exists(filepath):
            os.remove(filepath)
    
    def test_csv_export(self):
        """Test CSV report export"""
        filepath = self.generator.export_csv(self.sample_results, "test_report.csv")
        self.assertTrue(os.path.exists(filepath))
        
        # Clean up
        if os.path.exists(filepath):
            os.remove(filepath)
    
    def tearDown(self):
        """Clean up test directory"""
        import shutil
        if os.path.exists("test_reports"):
            shutil.rmtree("test_reports")

class TestToolChecker(unittest.TestCase):
    """Test the tool checker module"""
    
    def test_check_tool_availability(self):
        """Test tool availability checking"""
        availability = ToolChecker.check_tool_availability()
        
        self.assertIsInstance(availability, dict)
        self.assertTrue(len(availability) > 0)
        
        # Check that all required tools are in the results
        for tool in ToolChecker.REQUIRED_TOOLS:
            self.assertIn(tool, availability)
    
    def test_get_missing_tools(self):
        """Test getting list of missing tools"""
        missing = ToolChecker.get_missing_tools()
        self.assertIsInstance(missing, list)

class TestVulnerabilityEntry(unittest.TestCase):
    """Test vulnerability entry creation"""
    
    def test_create_vulnerability_entry(self):
        """Test creating vulnerability entries"""
        vuln = create_vulnerability_entry(
            name="Test Vuln",
            severity="high",
            description="Test description",
            cve="CVE-2023-0001"
        )
        
        self.assertEqual(vuln['name'], "Test Vuln")
        self.assertEqual(vuln['severity'], "high")
        self.assertEqual(vuln['description'], "Test description")
        self.assertEqual(vuln['cve'], "CVE-2023-0001")
        self.assertIn('discovered_at', vuln)

if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestAdvancedValidator,
        TestReportGenerator,
        TestToolChecker,
        TestVulnerabilityEntry
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with error code if tests failed
    sys.exit(0 if result.wasSuccessful() else 1)
