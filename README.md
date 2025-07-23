# Advanced SQL Injection Scanner for Domain-Based Reconnaissance

A high-performance and precise security tool designed to automate the end-to-end process of SQL Injection discovery across an entire domain. This tool intelligently gathers URLs using multiple reconnaissance sources, filters and extracts injectable parameters, and performs advanced payload-based testing to detect SQL injection vulnerabilities with minimal false positives.

## 🚀 Key Features

- **🔗 Multi-source URL aggregation** - Wayback Machine, GAU, Katana, and common endpoints
- **🧠 Smart parameter extraction** - Intelligent filtering and deduplication of URL parameters  
- **🚀 Fast automated SQLi detection** - Custom and well-known payloads with concurrent testing
- **📊 Clear vulnerability reporting** - Highlighting vulnerable parameters and endpoints
- **⚙️ Modular architecture** - Extensible design for custom scanning logic
- **🛡️ Database fingerprinting** - MySQL, PostgreSQL, MSSQL, Oracle, SQLite detection
- **🔥 WAF detection & bypass** - Automatic detection and evasion attempts
- **📈 Confidence scoring** - Advanced vulnerability rating system

## 📋 Requirements

- Python 3.7+
- Required Python packages (see requirements.txt)
- Optional tools for enhanced reconnaissance:
  - `gau` (GetAllURLs)
  - `katana` (Web crawler)

## 🛠️ Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd sql-injection-scanner
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Install external tools for enhanced URL discovery:
```bash
# Install GAU
go install github.com/lc/gau/v2/cmd/gau@latest

# Install Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## 🚦 Quick Start

### Basic Usage

Scan a domain with default settings:
```bash
python sqli_scanner.py -d example.com
```

### Advanced Usage

Use the enhanced scanner with database fingerprinting:
```bash
python advanced_scanner.py -d example.com
```

## 📖 Usage Examples

### Basic Scanner (`sqli_scanner.py`)

1. **Basic domain scan:**
```bash
python sqli_scanner.py -d example.com
```

2. **High-performance scan with more threads:**
```bash
python sqli_scanner.py -d example.com -t 50 --delay 0.1
```

3. **Skip external tools (faster startup):**
```bash
python sqli_scanner.py -d example.com --skip-tools
```

4. **Scan URLs from file:**
```bash
python sqli_scanner.py -d example.com --urls-file urls.txt
```

5. **Verbose output with custom report:**
```bash
python sqli_scanner.py -d example.com -v --output my_report.json
```

### Advanced Scanner (`advanced_scanner.py`)

1. **Enhanced scan with fingerprinting:**
```bash
python advanced_scanner.py -d example.com
```

2. **Aggressive scanning mode:**
```bash
python advanced_scanner.py -d example.com --aggressive
```

3. **Custom payload configuration:**
```bash
python advanced_scanner.py -d example.com --payloads custom_payloads.json
```

4. **High-concurrency enterprise scan:**
```bash
python advanced_scanner.py -d example.com -t 100 --delay 0.05
```

## 🎯 Command Line Options

### Basic Scanner Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain to scan (required) |
| `-t, --threads` | Number of concurrent threads (default: 20) |
| `--delay` | Delay between requests in seconds (default: 0.1) |
| `--skip-tools` | Skip external tools (GAU, Katana) |
| `--urls-file` | File containing URLs to test (one per line) |
| `--output` | Output file for JSON report |
| `-v, --verbose` | Verbose output |

### Advanced Scanner Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain to scan (required) |
| `-t, --threads` | Number of concurrent threads (default: 20) |
| `--delay` | Delay between requests (default: 0.2s) |
| `--payloads` | Payload configuration file (default: payloads.json) |
| `--urls-file` | File containing URLs to test |
| `--output` | Output file for JSON report |
| `--aggressive` | Use more aggressive scanning |
| `--skip-tools` | Skip external reconnaissance tools |
| `-v, --verbose` | Verbose output |

## 🔧 Configuration

### Payload Configuration

The advanced scanner uses a JSON configuration file (`payloads.json`) to manage SQL injection payloads. You can customize payloads for different:

- **Database types:** MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- **Attack vectors:** Error-based, Time-based, Union-based, Boolean-based
- **Evasion techniques:** WAF bypass, Filter bypass, Second-order

Example payload structure:
```json
{
  "error_based": {
    "mysql": ["'", "' OR 1=1--", "' UNION SELECT NULL--"],
    "postgresql": ["'", "' OR 1=1--", "' AND CAST((SELECT version()) AS int)--"]
  },
  "time_based": {
    "mysql": ["' AND SLEEP(5)--", "' OR SLEEP(5)--"],
    "mssql": ["'; WAITFOR DELAY '00:00:05'--"]
  }
}
```

### URL Input File Format

When using `--urls-file`, provide URLs one per line:
```
https://example.com/page.php?id=1
https://example.com/search.php?q=test&category=news
https://example.com/product.php?id=123&action=view
```

## 📊 Output and Reporting

### Console Output

The scanner provides real-time feedback with color-coded messages:

- 🔵 **[INFO]** - General information
- 🟡 **[WARNING]** - Warnings and issues  
- 🟢 **[SUCCESS]** - Successful operations
- 🔴 **[ERROR]** - Errors and failures
- 🟢 **[VULN]** - Vulnerability discovered
- 🟡 **[TESTING]** - Currently testing parameter

### JSON Reports

Detailed JSON reports are automatically generated containing:

- Scan metadata (domain, timestamp, totals)
- Vulnerability details (URL, parameter, payload, evidence)
- Confidence ratings (for advanced scanner)
- Database and WAF detection results

Example report structure:
```json
{
  "scan_info": {
    "domain": "example.com",
    "timestamp": "2024-01-15T10:30:00",
    "total_vulnerabilities": 5,
    "detected_database": "mysql",
    "detected_waf": null
  },
  "vulnerabilities": [
    {
      "url": "https://example.com/page.php?id=1",
      "parameter": "id",
      "payload": "' OR 1=1--",
      "vulnerability_type": "Error-based (confidence: 85%)",
      "evidence": ["Error: MySQL syntax error"],
      "response_time": 0.245
    }
  ]
}
```

## 🧠 Advanced Features

### Database Fingerprinting

The advanced scanner automatically detects the target database technology:

- **MySQL/MariaDB** - Identifies MySQL-specific errors and functions
- **PostgreSQL** - Detects PostgreSQL syntax and error messages  
- **Microsoft SQL Server** - Recognizes MSSQL-specific responses
- **Oracle** - Identifies Oracle database indicators
- **SQLite** - Detects SQLite-specific error patterns

### WAF Detection & Bypass

Automatic detection of Web Application Firewalls:

- **Cloudflare** - CF-Ray headers and response patterns
- **AWS WAF** - AWS-specific blocking responses
- **Akamai** - Ghost headers and reference patterns
- **Imperva/Incapsula** - Security response signatures
- **ModSecurity** - Open-source WAF patterns
- **Generic** - Common firewall indicators

When a WAF is detected, the scanner automatically:
- Switches to evasion payloads
- Uses encoding and obfuscation techniques
- Attempts comment-based bypasses
- Employs case variation strategies

### Confidence Scoring

The advanced scanner provides confidence levels:

- **🚨 High Confidence (70%+)** - Strong evidence of vulnerability
- **⚠️ Medium Confidence (40-69%)** - Probable vulnerability
- **ℹ️ Low Confidence (<40%)** - Possible vulnerability

## 🔍 Detection Techniques

### Error-Based Detection
- Database error message patterns
- Syntax error indicators
- Exception handling responses

### Time-Based Detection
- Response delay analysis
- Sleep/wait function detection
- Benchmark timing attacks

### Union-Based Detection
- Column number enumeration
- Data extraction verification
- Query result manipulation

### Boolean-Based Detection
- True/false response analysis
- Content length variations
- Conditional logic testing

## ⚡ Performance Optimization

### Concurrency Settings

Adjust thread count based on target capacity:
- **Small sites:** 10-20 threads
- **Medium sites:** 20-50 threads  
- **Large sites:** 50-100 threads

### Rate Limiting

Control request frequency to avoid detection:
- **Stealth mode:** 0.5-1.0s delay
- **Normal mode:** 0.1-0.2s delay
- **Aggressive mode:** 0.05-0.1s delay

### Resource Management

The scanner automatically manages:
- Connection pooling
- Memory usage optimization
- Timeout handling
- Session cleanup

## 🛡️ Ethical Usage

This tool is designed for:
- ✅ Authorized penetration testing
- ✅ Security research on owned systems
- ✅ Bug bounty hunting with proper authorization
- ✅ Educational purposes in controlled environments

**Important:** Only use this tool on systems you own or have explicit permission to test. Unauthorized testing may violate laws and regulations.

## 🤝 Contributing

Contributions are welcome! Please consider:

1. **Payload improvements** - Add new injection techniques
2. **Database support** - Extend fingerprinting capabilities
3. **WAF evasion** - Implement new bypass methods
4. **Performance optimization** - Enhance scanning efficiency
5. **Reporting features** - Improve output formatting

## 📝 License

This project is provided for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations.

## 🔗 Related Tools

- **SQLMap** - Advanced SQL injection exploitation tool
- **GAU** - GetAllURLs for URL discovery
- **Katana** - Web crawling framework
- **URLFinder** - JavaScript URL extraction
- **Waybackurls** - Wayback Machine URL extraction

## 📞 Support

For questions, issues, or feature requests:
- Review the documentation thoroughly
- Check existing issues and discussions
- Provide detailed information when reporting bugs
- Include sample URLs and configurations when possible

---

**Disclaimer:** This tool is for authorized security testing only. Always obtain proper permission before testing any systems you do not own.
