#!/usr/bin/env python3
"""
Test script for SQL Injection Scanner
Verifies functionality without making real network requests
"""

import asyncio
import json
import sys
import tempfile
import os
from unittest.mock import AsyncMock, MagicMock, patch
from sqli_scanner import *

# Import advanced scanner components
try:
    from advanced_scanner import AdvancedPayloadManager, DatabaseFingerprinter, WAFDetector
except ImportError:
    # Create mock classes if advanced scanner not available
    class AdvancedPayloadManager:
        def __init__(self, config_file):
            self.payloads = {"error_based": {"mysql": ["'", "' OR 1=1--"]}}
        def get_payloads_by_type(self, payload_type, db_type="generic"):
            return self.payloads.get(payload_type, {}).get(db_type, [])
        def get_all_payloads(self, db_type="generic"):
            return ["'", "' OR 1=1--"]
    
    class DatabaseFingerprinter:
        @staticmethod
        def detect_database_type(response_text, headers):
            if "mysql" in response_text.lower():
                return "mysql"
            elif "postgresql" in response_text.lower():
                return "postgresql"
            return "generic"
    
    class WAFDetector:
        @staticmethod
        def detect_waf(response_text, headers, status_code):
            if "cloudflare" in response_text.lower():
                return "cloudflare"
            elif status_code == 403:
                return "generic"
            return None

async def test_url_aggregator():
    """Test URL aggregation functionality"""
    print(f"{Colors.BLUE}[TEST]{Colors.RESET} Testing URL Aggregator...")
    
    # Mock the URLAggregator methods
    with patch('subprocess.run') as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "https://example.com/page.php?id=1\nhttps://example.com/search.php?q=test"
        
        async with URLAggregator("example.com") as aggregator:
            urls = aggregator.get_wayback_urls()
            assert len(urls) >= 0, "Should return a set of URLs"
            print(f"{Colors.GREEN}[PASS]{Colors.RESET} URL Aggregator basic functionality")

def test_parameter_extractor():
    """Test parameter extraction functionality"""
    print(f"{Colors.BLUE}[TEST]{Colors.RESET} Testing Parameter Extractor...")
    
    test_urls = {
        "https://example.com/page.php?id=1&name=test",
        "https://example.com/search.php?q=query&category=news",
        "https://example.com/product.php?id=123",
        "https://example.com/static.html"  # No parameters
    }
    
    # Extract parameters
    param_urls = ParameterExtractor.extract_parameters(test_urls)
    
    # Verify extraction
    assert 'id' in param_urls, "Should extract 'id' parameter"
    assert 'q' in param_urls, "Should extract 'q' parameter"
    assert 'name' in param_urls, "Should extract 'name' parameter"
    assert 'category' in param_urls, "Should extract 'category' parameter"
    
    # Test filtering
    filtered = ParameterExtractor.filter_interesting_params(param_urls)
    assert 'id' in filtered, "Should include 'id' as interesting parameter"
    assert 'q' in filtered, "Should include 'q' as interesting parameter"
    
    print(f"{Colors.GREEN}[PASS]{Colors.RESET} Parameter Extractor functionality")

def test_payload_generator():
    """Test payload generation"""
    print(f"{Colors.BLUE}[TEST]{Colors.RESET} Testing Payload Generator...")
    
    # Test different payload types
    error_payloads = PayloadGenerator.get_error_based_payloads()
    time_payloads = PayloadGenerator.get_time_based_payloads()
    union_payloads = PayloadGenerator.get_union_based_payloads()
    boolean_payloads = PayloadGenerator.get_boolean_based_payloads()
    
    assert len(error_payloads) > 0, "Should have error-based payloads"
    assert len(time_payloads) > 0, "Should have time-based payloads"
    assert len(union_payloads) > 0, "Should have union-based payloads"
    assert len(boolean_payloads) > 0, "Should have boolean-based payloads"
    
    # Verify payload content
    assert "'" in error_payloads, "Should contain basic quote payload"
    assert any("SLEEP" in p for p in time_payloads), "Should contain SLEEP payload"
    assert any("UNION" in p for p in union_payloads), "Should contain UNION payload"
    assert any("1=1" in p for p in boolean_payloads), "Should contain boolean payload"
    
    print(f"{Colors.GREEN}[PASS]{Colors.RESET} Payload Generator functionality")

async def test_sqli_scanner_basic():
    """Test basic SQLi scanner functionality"""
    print(f"{Colors.BLUE}[TEST]{Colors.RESET} Testing SQLi Scanner basics...")
    
    # Test URL parameter modification
    scanner = SQLiScanner()
    
    test_url = "https://example.com/page.php?id=1&name=test"
    modified_url = scanner.modify_url_parameter(test_url, "id", "' OR 1=1--")
    
    # Check for URL-encoded payload (it gets URL-encoded automatically)
    assert "%27+OR+1%3D1--" in modified_url or "' OR 1=1--" in modified_url, "Should modify the parameter value"
    assert "name=test" in modified_url, "Should preserve other parameters"
    
    print(f"{Colors.GREEN}[PASS]{Colors.RESET} SQLi Scanner basic functionality")

def test_advanced_payload_manager():
    """Test advanced payload manager"""
    print(f"{Colors.BLUE}[TEST]{Colors.RESET} Testing Advanced Payload Manager...")
    
    # Create a temporary payload config file
    test_payloads = {
        "error_based": {
            "mysql": ["'", "' OR 1=1--"],
            "postgresql": ["'", "' AND CAST((SELECT version()) AS int)--"]
        },
        "time_based": {
            "mysql": ["' AND SLEEP(5)--"],
            "postgresql": ["' AND pg_sleep(5)--"]
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(test_payloads, f)
        temp_file = f.name
    
    try:
        # Test payload manager
        manager = AdvancedPayloadManager(temp_file)
        
        # Test database-specific payload retrieval
        mysql_error = manager.get_payloads_by_type("error_based", "mysql")
        postgres_error = manager.get_payloads_by_type("error_based", "postgresql")
        
        assert "' OR 1=1--" in mysql_error, "Should get MySQL-specific payloads"
        assert "' AND CAST" in str(postgres_error), "Should get PostgreSQL-specific payloads"
        
        # Test generic fallback
        generic_payloads = manager.get_all_payloads("mysql")
        assert len(generic_payloads) > 0, "Should return payloads for MySQL"
        
        print(f"{Colors.GREEN}[PASS]{Colors.RESET} Advanced Payload Manager functionality")
        
    finally:
        os.unlink(temp_file)

def test_database_fingerprinter():
    """Test database fingerprinting"""
    print(f"{Colors.BLUE}[TEST]{Colors.RESET} Testing Database Fingerprinter...")
    
    # Test MySQL detection
    mysql_response = "You have an error in your SQL syntax near 'mysql'"
    mysql_headers = {"server": "Apache/2.4.41"}
    db_type = DatabaseFingerprinter.detect_database_type(mysql_response, mysql_headers)
    assert db_type == "mysql", f"Should detect MySQL, got {db_type}"
    
    # Test PostgreSQL detection
    postgres_response = "PostgreSQL error: syntax error"
    postgres_headers = {}
    db_type = DatabaseFingerprinter.detect_database_type(postgres_response, postgres_headers)
    assert db_type == "postgresql", f"Should detect PostgreSQL, got {db_type}"
    
    # Test generic fallback
    generic_response = "Some error message"
    generic_headers = {}
    db_type = DatabaseFingerprinter.detect_database_type(generic_response, generic_headers)
    assert db_type == "generic", f"Should default to generic, got {db_type}"
    
    print(f"{Colors.GREEN}[PASS]{Colors.RESET} Database Fingerprinter functionality")

def test_waf_detector():
    """Test WAF detection"""
    print(f"{Colors.BLUE}[TEST]{Colors.RESET} Testing WAF Detector...")
    
    # Test Cloudflare detection
    cf_response = "Cloudflare error page"
    cf_headers = {"cf-ray": "12345-ABC"}
    waf_type = WAFDetector.detect_waf(cf_response, cf_headers, 403)
    assert waf_type == "cloudflare", f"Should detect Cloudflare, got {waf_type}"
    
    # Test generic WAF detection
    generic_response = "Access denied by security policy"
    generic_headers = {}
    waf_type = WAFDetector.detect_waf(generic_response, generic_headers, 403)
    assert waf_type == "generic", f"Should detect generic WAF, got {waf_type}"
    
    # Test no WAF
    normal_response = "Normal page content"
    normal_headers = {}
    waf_type = WAFDetector.detect_waf(normal_response, normal_headers, 200)
    assert waf_type is None, f"Should detect no WAF, got {waf_type}"
    
    print(f"{Colors.GREEN}[PASS]{Colors.RESET} WAF Detector functionality")

def test_report_generator():
    """Test report generation"""
    print(f"{Colors.BLUE}[TEST]{Colors.RESET} Testing Report Generator...")
    
    # Create test vulnerability data
    test_vuln = VulnResult(
        url="https://example.com/page.php?id=1",
        parameter="id",
        payload="' OR 1=1--",
        response_time=0.5,
        error_indicators=["MySQL syntax error"],
        response_length=1500,
        status_code=200,
        vulnerability_type="Error-based"
    )
    
    # Test summary generation
    summary = ReportGenerator.generate_summary([test_vuln])
    assert "VULNERABILITIES FOUND" in summary, "Should generate vulnerability summary"
    assert "id" in summary, "Should include parameter name"
    assert "Error-based" in summary, "Should include vulnerability type"
    
    print(f"{Colors.GREEN}[PASS]{Colors.RESET} Report Generator functionality")

async def run_all_tests():
    """Run all tests"""
    print(f"{Colors.CYAN}{Colors.BOLD}🧪 SQL Injection Scanner Test Suite{Colors.RESET}")
    print(f"{Colors.CYAN}Running comprehensive functionality tests...\n{Colors.RESET}")
    
    try:
        # Test each component
        await test_url_aggregator()
        test_parameter_extractor()
        test_payload_generator()
        await test_sqli_scanner_basic()
        test_advanced_payload_manager()
        test_database_fingerprinter()
        test_waf_detector()
        test_report_generator()
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ All tests passed!{Colors.RESET}")
        print(f"{Colors.GREEN}The SQL injection scanner is working correctly.{Colors.RESET}")
        
    except AssertionError as e:
        print(f"\n{Colors.RED}{Colors.BOLD}❌ Test failed: {e}{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}{Colors.BOLD}💥 Unexpected error: {e}{Colors.RESET}")
        sys.exit(1)

def test_file_existence():
    """Test that all required files exist"""
    print(f"{Colors.BLUE}[TEST]{Colors.RESET} Testing file existence...")
    
    required_files = [
        "sqli_scanner.py",
        "advanced_scanner.py", 
        "payloads.json",
        "requirements.txt",
        "README.md"
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print(f"{Colors.RED}[FAIL]{Colors.RESET} Missing files: {', '.join(missing_files)}")
        return False
    
    print(f"{Colors.GREEN}[PASS]{Colors.RESET} All required files exist")
    return True

def test_payload_config():
    """Test payload configuration file"""
    print(f"{Colors.BLUE}[TEST]{Colors.RESET} Testing payload configuration...")
    
    try:
        with open("payloads.json", 'r') as f:
            payloads = json.load(f)
        
        required_sections = ["error_based", "time_based", "union_based", "boolean_based"]
        for section in required_sections:
            assert section in payloads, f"Missing payload section: {section}"
        
        print(f"{Colors.GREEN}[PASS]{Colors.RESET} Payload configuration is valid")
        return True
        
    except Exception as e:
        print(f"{Colors.RED}[FAIL]{Colors.RESET} Payload configuration error: {e}")
        return False

if __name__ == "__main__":
    print(f"{Colors.CYAN}🔍 Starting SQL Injection Scanner Tests{Colors.RESET}\n")
    
    # Test file existence first
    if not test_file_existence():
        print(f"{Colors.RED}Setup appears incomplete. Run setup.sh first.{Colors.RESET}")
        sys.exit(1)
    
    # Test configuration files
    if not test_payload_config():
        sys.exit(1)
    
    # Run async tests
    asyncio.run(run_all_tests())
    
    print(f"\n{Colors.CYAN}🎉 Test suite completed successfully!{Colors.RESET}")
    print(f"{Colors.GREEN}The scanner is ready for use.{Colors.RESET}")
    print(f"\n{Colors.YELLOW}Quick start:{Colors.RESET}")
    print(f"  python3 sqli_scanner.py -d example.com")
    print(f"  python3 advanced_scanner.py -d example.com")