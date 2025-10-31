#!/usr/bin/env python3
"""
Advanced Web Security Scanner
A comprehensive web vulnerability scanner with multiple detection modules
"""

import argparse
import asyncio
import aiohttp
import re
import socket
import ssl
import urllib.parse
from datetime import datetime
from typing import List, Dict, Set, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json

# Banner
BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗███████╗
║    ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝██╔════╝
║    ███████║██║  ██║██║   ██║███████║██╔██╗ ██║██║     █████╗
║    ██╔══██║██║  ██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║     ██╔══╝
║    ██║  ██║██████╔╝ ╚████╔╝ ██║  ██║██║ ╚████║╚██████╗███████╗
║    ╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝
║                                                               ║
║           ADVANCED WEB SECURITY SCANNER v2.0                  ║
║              Professional Penetration Testing Tool            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""

@dataclass
class ScanResult:
    """Container for scan results"""
    url: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    timestamp: str

class AdvancedWebScanner:
    """Advanced web vulnerability scanner with multiple detection modules"""

    def __init__(self, target_url: str, threads: int = 10, timeout: int = 10):
        self.target_url = target_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.results: List[ScanResult] = []
        self.visited_urls: Set[str] = set()
        self.session = None

        # Payloads for various attacks
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
        ]

        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",
        ]

        self.lfi_payloads = [
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "C:\\Windows\\win.ini",
        ]

        self.command_injection_payloads = [
            "; ls -la",
            "| ls -la",
            "&& ls -la",
            "|| ls -la",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "`whoami`",
            "$(whoami)",
            "; ping -c 4 127.0.0.1",
        ]

        self.sensitive_files = [
            "/robots.txt",
            "/.git/config",
            "/.env",
            "/config.php",
            "/wp-config.php",
            "/.htaccess",
            "/admin",
            "/phpmyadmin",
            "/backup.sql",
            "/database.sql",
            "/.git/HEAD",
            "/composer.json",
            "/package.json",
            "/.gitignore",
            "/debug.log",
            "/error.log",
            "/access.log",
        ]

    async def create_session(self):
        """Create aiohttp session with custom settings"""
        connector = aiohttp.TCPConnector(ssl=False, limit=self.threads)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )

    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()

    def add_result(self, url: str, vuln_type: str, severity: str, description: str, evidence: str):
        """Add a vulnerability finding to results"""
        result = ScanResult(
            url=url,
            vulnerability_type=vuln_type,
            severity=severity,
            description=description,
            evidence=evidence,
            timestamp=datetime.now().isoformat()
        )
        self.results.append(result)
        self.print_finding(result)

    def print_finding(self, result: ScanResult):
        """Print a vulnerability finding with color coding"""
        severity_colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[91m',      # Red
            'MEDIUM': '\033[93m',    # Yellow
            'LOW': '\033[92m',       # Green
            'INFO': '\033[94m'       # Blue
        }
        reset = '\033[0m'
        color = severity_colors.get(result.severity, reset)

        print(f"\n{color}[{result.severity}] {result.vulnerability_type}{reset}")
        print(f"URL: {result.url}")
        print(f"Description: {result.description}")
        print(f"Evidence: {result.evidence[:200]}")

    async def fetch(self, url: str, method: str = 'GET', data: Dict = None) -> Optional[Dict]:
        """Fetch URL with error handling"""
        try:
            if method == 'GET':
                async with self.session.get(url) as response:
                    text = await response.text()
                    return {
                        'status': response.status,
                        'text': text,
                        'headers': dict(response.headers),
                        'url': str(response.url)
                    }
            elif method == 'POST':
                async with self.session.post(url, data=data) as response:
                    text = await response.text()
                    return {
                        'status': response.status,
                        'text': text,
                        'headers': dict(response.headers),
                        'url': str(response.url)
                    }
        except Exception as e:
            return None

    async def scan_xss(self):
        """Scan for Cross-Site Scripting vulnerabilities"""
        print("\n[*] Scanning for XSS vulnerabilities...")

        # First, crawl to find forms and parameters
        response = await self.fetch(self.target_url)
        if not response:
            return

        # Test URL parameters
        parsed = urllib.parse.urlparse(self.target_url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                for payload in self.xss_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                    result = await self.fetch(test_url)
                    if result and payload in result['text']:
                        self.add_result(
                            test_url,
                            "Cross-Site Scripting (XSS)",
                            "HIGH",
                            f"Reflected XSS found in parameter '{param}'",
                            f"Payload: {payload}"
                        )

    async def scan_sqli(self):
        """Scan for SQL Injection vulnerabilities"""
        print("\n[*] Scanning for SQL Injection vulnerabilities...")

        parsed = urllib.parse.urlparse(self.target_url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                for payload in self.sqli_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                    result = await self.fetch(test_url)
                    if result:
                        # Check for SQL error messages
                        sql_errors = [
                            "sql syntax",
                            "mysql_fetch",
                            "mysql error",
                            "postgresql error",
                            "ora-[0-9]",
                            "sqlite error",
                            "microsoft sql",
                            "odbc sql",
                            "warning: mysql",
                            "pg_query",
                            "sqlite3",
                        ]

                        for error in sql_errors:
                            if re.search(error, result['text'], re.IGNORECASE):
                                self.add_result(
                                    test_url,
                                    "SQL Injection",
                                    "CRITICAL",
                                    f"SQL Injection vulnerability found in parameter '{param}'",
                                    f"Payload: {payload}, Error: {error}"
                                )
                                break

    async def scan_lfi(self):
        """Scan for Local File Inclusion vulnerabilities"""
        print("\n[*] Scanning for LFI vulnerabilities...")

        parsed = urllib.parse.urlparse(self.target_url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                for payload in self.lfi_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                    result = await self.fetch(test_url)
                    if result:
                        # Check for file content indicators
                        lfi_indicators = [
                            "root:x:",
                            "[extensions]",
                            "; for 16-bit app support",
                            "bin/bash",
                            "daemon:",
                        ]

                        for indicator in lfi_indicators:
                            if indicator in result['text']:
                                self.add_result(
                                    test_url,
                                    "Local File Inclusion (LFI)",
                                    "CRITICAL",
                                    f"LFI vulnerability found in parameter '{param}'",
                                    f"Payload: {payload}, Indicator: {indicator}"
                                )
                                break

    async def scan_command_injection(self):
        """Scan for Command Injection vulnerabilities"""
        print("\n[*] Scanning for Command Injection vulnerabilities...")

        parsed = urllib.parse.urlparse(self.target_url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            for param in params:
                for payload in self.command_injection_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                    result = await self.fetch(test_url)
                    if result:
                        # Check for command output indicators
                        cmd_indicators = [
                            "uid=", "gid=", "groups=",
                            "drwx", "-rwx",
                            "root:", "bin:",
                            "total ",
                            "PING",
                        ]

                        for indicator in cmd_indicators:
                            if indicator in result['text']:
                                self.add_result(
                                    test_url,
                                    "Command Injection",
                                    "CRITICAL",
                                    f"Command Injection vulnerability found in parameter '{param}'",
                                    f"Payload: {payload}"
                                )
                                break

    async def scan_sensitive_files(self):
        """Scan for exposed sensitive files"""
        print("\n[*] Scanning for sensitive files...")

        tasks = []
        for file_path in self.sensitive_files:
            test_url = f"{self.target_url}{file_path}"
            tasks.append(self.check_sensitive_file(test_url, file_path))

        await asyncio.gather(*tasks)

    async def check_sensitive_file(self, url: str, file_path: str):
        """Check if sensitive file exists"""
        result = await self.fetch(url)
        if result and result['status'] == 200:
            self.add_result(
                url,
                "Sensitive File Exposure",
                "MEDIUM",
                f"Sensitive file '{file_path}' is publicly accessible",
                f"Status: {result['status']}, Size: {len(result['text'])} bytes"
            )

    async def scan_security_headers(self):
        """Check for missing security headers"""
        print("\n[*] Checking security headers...")

        result = await self.fetch(self.target_url)
        if not result:
            return

        headers = result['headers']

        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'XSS and injection protection',
            'X-XSS-Protection': 'XSS filter',
            'Referrer-Policy': 'Referrer information control',
            'Permissions-Policy': 'Feature policy control',
        }

        for header, purpose in security_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                self.add_result(
                    self.target_url,
                    "Missing Security Header",
                    "LOW",
                    f"Missing '{header}' header ({purpose})",
                    f"Header not found in response"
                )

    async def scan_ssl_tls(self):
        """Check SSL/TLS configuration"""
        print("\n[*] Checking SSL/TLS configuration...")

        parsed = urllib.parse.urlparse(self.target_url)
        if parsed.scheme != 'https':
            self.add_result(
                self.target_url,
                "No HTTPS",
                "HIGH",
                "Website is not using HTTPS encryption",
                "HTTP protocol detected"
            )
            return

        try:
            hostname = parsed.netloc.split(':')[0]
            context = ssl.create_default_context()

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    # Check cipher strength
                    if cipher[2] < 128:
                        self.add_result(
                            self.target_url,
                            "Weak SSL/TLS Cipher",
                            "MEDIUM",
                            f"Weak cipher suite detected: {cipher[0]}",
                            f"Cipher strength: {cipher[2]} bits"
                        )
        except Exception as e:
            pass

    async def scan_cors(self):
        """Check CORS configuration"""
        print("\n[*] Checking CORS configuration...")

        test_origin = "https://evil.com"
        headers = {'Origin': test_origin}

        try:
            async with self.session.get(self.target_url, headers=headers) as response:
                cors_header = response.headers.get('Access-Control-Allow-Origin', '')

                if cors_header == '*':
                    self.add_result(
                        self.target_url,
                        "Misconfigured CORS",
                        "MEDIUM",
                        "CORS policy allows requests from any origin",
                        f"Access-Control-Allow-Origin: {cors_header}"
                    )
                elif cors_header == test_origin:
                    self.add_result(
                        self.target_url,
                        "Misconfigured CORS",
                        "HIGH",
                        "CORS policy reflects arbitrary origins",
                        f"Origin {test_origin} is allowed"
                    )
        except Exception as e:
            pass

    async def port_scan(self):
        """Scan common ports"""
        print("\n[*] Scanning common ports...")

        parsed = urllib.parse.urlparse(self.target_url)
        hostname = parsed.netloc.split(':')[0]

        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443]

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                sock.close()

                if result == 0:
                    self.add_result(
                        f"{hostname}:{port}",
                        "Open Port",
                        "INFO",
                        f"Port {port} is open",
                        f"Service may be running on port {port}"
                    )
            except Exception:
                pass

    async def run_full_scan(self):
        """Execute all scanning modules"""
        print(BANNER)
        print(f"\n[*] Starting scan on: {self.target_url}")
        print(f"[*] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Threads: {self.threads}")
        print("=" * 70)

        await self.create_session()

        try:
            # Run all scan modules
            await self.scan_security_headers()
            await self.scan_sensitive_files()
            await self.scan_ssl_tls()
            await self.scan_cors()
            await self.scan_xss()
            await self.scan_sqli()
            await self.scan_lfi()
            await self.scan_command_injection()
            await self.port_scan()

        finally:
            await self.close_session()

        # Print summary
        self.print_summary()

    def print_summary(self):
        """Print scan summary"""
        print("\n" + "=" * 70)
        print("\n[*] SCAN SUMMARY")
        print("=" * 70)

        if not self.results:
            print("\n✓ No vulnerabilities found!")
            return

        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }

        for result in self.results:
            severity_counts[result.severity] += 1

        print(f"\nTotal Findings: {len(self.results)}")
        print(f"  CRITICAL: {severity_counts['CRITICAL']}")
        print(f"  HIGH: {severity_counts['HIGH']}")
        print(f"  MEDIUM: {severity_counts['MEDIUM']}")
        print(f"  LOW: {severity_counts['LOW']}")
        print(f"  INFO: {severity_counts['INFO']}")

        # Save to JSON
        self.save_report()

    def save_report(self):
        """Save scan results to JSON file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scan_report_{timestamp}.json"

        report = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(self.results),
            'findings': [
                {
                    'url': r.url,
                    'type': r.vulnerability_type,
                    'severity': r.severity,
                    'description': r.description,
                    'evidence': r.evidence,
                    'timestamp': r.timestamp
                }
                for r in self.results
            ]
        }

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[*] Report saved to: {filename}")


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Web Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -u https://example.com?id=1 -t 20
  %(prog)s -u https://example.com --timeout 15
        """
    )

    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')

    args = parser.parse_args()

    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("[!] Error: URL must start with http:// or https://")
        return

    # Run scanner
    scanner = AdvancedWebScanner(args.url, args.threads, args.timeout)
    asyncio.run(scanner.run_full_scan())


if __name__ == '__main__':
    main()
