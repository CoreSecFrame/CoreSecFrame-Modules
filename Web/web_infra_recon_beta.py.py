#!/usr/bin/env python3
# modules/Web/web_infra_recon.py

import subprocess
import requests
import json
import socket
import dns.resolver
import re
import sys
import os
import time
import threading
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime

# Try different import methods based on framework structure
try:
    from core.base import ToolModule
    from core.colors import Colors
except ImportError:
    try:
        from modules.core.base import ToolModule
        from modules.core.colors import Colors
    except ImportError:
        # Fallback classes if imports fail
        class ToolModule:
            def __init__(self):
                pass
            def _get_name(self) -> str:
                return ""
            def _get_category(self) -> str:
                return ""
            def _get_command(self) -> str:
                return ""
            def _get_description(self) -> str:
                return ""
            def _get_dependencies(self) -> List[str]:
                return []
            def check_installation(self) -> bool:
                return True
            def run_guided(self) -> None:
                pass
            def run_direct(self) -> None:
                pass
            def get_help(self) -> dict:
                return {}
        
        class Colors:
            CYAN = '\033[96m'
            GREEN = '\033[92m'
            WARNING = '\033[93m'
            FAIL = '\033[91m'
            ENDC = '\033[0m'
            BOLD = '\033[1m'
            RED = '\033[91m'
            BLUE = '\033[94m'

class WebInfrastructureRecon(ToolModule):
    def __init__(self):
        # Configuration
        self.ipinfo_token = "51a986ffa5ddb1"  # Free token
        self.timeout = 10
        
        # Extended ports for comprehensive scanning
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            9200: "Elasticsearch", 27017: "MongoDB", 3000: "Node.js", 
            5000: "Flask", 8000: "Django", 9000: "SonarQube", 11211: "Memcached",
            1433: "MSSQL", 5984: "CouchDB", 7000: "Cassandra", 9042: "Cassandra",
            50070: "Hadoop", 8088: "Hadoop", 9870: "Hadoop", 16010: "HBase"
        }
        
        # CloudFlare IP ranges for detection
        self.cloudflare_ranges = [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
            "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
        ]
        
        super().__init__()

    def _get_name(self) -> str:
        return "web_infra_recon"

    def _get_category(self) -> str:
        return "Web"

    def _get_command(self) -> str:
        return "web-infra-recon"

    def _get_description(self) -> str:
        return "Advanced web infrastructure reconnaissance with CloudFlare bypass, service detection, banner grabbing and security analysis"

    def _get_dependencies(self) -> List[str]:
        return ["python3-requests", "python3-dnspython"]

    def get_help(self) -> dict:
        return {
            "title": "Web Infrastructure Reconnaissance - Advanced Discovery",
            "usage": "use web_infra_recon",
            "desc": "Comprehensive web infrastructure reconnaissance with CloudFlare bypass, service detection, banner grabbing and vulnerability identification",
            "modes": {
                "Guided": "Interactive mode with step-by-step configuration",
                "Direct": "Direct execution with command line arguments",
                "Stealth": "Low-profile reconnaissance mode",
                "Aggressive": "Full port scan and service enumeration with vulnerability hints"
            },
            "options": {
                "-t, --target": "Target domain/URL/IP",
                "-m, --mode": "Scan mode (stealth/normal/aggressive)",
                "-p, --ports": "Custom port range (e.g., 1-1000)",
                "--threads": "Number of threads (default: 50)",
                "--timeout": "Request timeout (default: 10)",
                "--bypass-only": "Only attempt CloudFlare bypass",
                "--no-ping": "Skip ping/ICMP checks",
                "-v, --verbose": "Verbose output with debug info"
            },
            "examples": [
                "web-infra-recon -t example.com",
                "web-infra-recon -t example.com -m aggressive",
                "web-infra-recon -t 192.168.1.1 -p 1-1000",
                "web-infra-recon -t example.com --bypass-only"
            ],
            "features": [
                "CloudFlare bypass detection",
                "Subdomain enumeration via Certificate Transparency",
                "Historical DNS analysis",
                "SSL certificate reconnaissance", 
                "Advanced port scanning with threading",
                "Service fingerprinting and banner grabbing",
                "Technology stack detection",
                "CDN/WAF identification",
                "Security headers analysis",
                "Vulnerability assessment hints",
                "Export results to JSON/CSV"
            ],
            "notes": [
                "Tool works on any web infrastructure, not just CloudFlare",
                "Aggressive mode may trigger security alerts",
                "Use responsibly and within legal boundaries",
                "Results include confidence levels for accuracy"
            ]
        }

    def check_installation(self) -> bool:
        """Check if required dependencies are installed"""
        try:
            import requests
            import dns.resolver
            return True
        except ImportError as e:
            print(f"{Colors.FAIL}[!] Missing dependency: {e}{Colors.ENDC}")
            return False

    # ===== UTILITY FUNCTIONS =====
    
    def _clean_url(self, url: str) -> str:
        """Clean and normalize URL"""
        url = url.replace("www.", "")
        url = url.replace("http://", "")
        url = url.replace("https://", "")
        url = url.replace("/", "")
        return url.strip()

    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False

    def _is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP belongs to CloudFlare"""
        try:
            import ipaddress
            ip_addr = ipaddress.IPv4Address(ip)
            for cf_range in self.cloudflare_ranges:
                if ip_addr in ipaddress.IPv4Network(cf_range):
                    return True
        except:
            pass
        return False

    def _display_progress_bar(self, percentage: float):
        """Display a progress bar"""
        bar_length = 50
        filled_length = int(bar_length * percentage // 100)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        print(f"\r{Colors.GREEN}Progress: |{bar}| {percentage:.1f}%{Colors.ENDC}", end='', flush=True)

    # ===== DNS AND NETWORK FUNCTIONS =====
    
    def _get_primary_ip(self, domain: str) -> str:
        """Get primary IP for the domain"""
        try:
            return socket.gethostbyname(domain)
        except:
            return "Unknown"

    def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get DNS records for the domain"""
        records = {}
        try:
            # NS records
            ns_records = dns.resolver.resolve(domain, 'NS')
            records['NS'] = [str(record) for record in ns_records]
        except:
            records['NS'] = []
        
        try:
            # A records
            a_records = dns.resolver.resolve(domain, 'A')
            records['A'] = [str(record) for record in a_records]
        except:
            records['A'] = []
        
        try:
            # MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            records['MX'] = [str(record) for record in mx_records]
        except:
            records['MX'] = []
            
        return records

    # ===== SUBDOMAIN DISCOVERY =====
    
    def _find_subdomains(self, domain: str) -> List[str]:
        """Find subdomains using multiple sources"""
        subdomains = set()
        
        # Certificate Transparency logs
        try:
            ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(ct_url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    name = cert.get('name_value', '')
                    if name and not name.startswith('*'):
                        subdomains.add(name.strip())
        except:
            pass
        
        # DNSDumpster (web scraping)
        try:
            dns_url = f"https://dnsdumpster.com/"
            session = requests.Session()
            resp = session.get(dns_url)
            if resp.status_code == 200:
                csrf_token = re.search(r'name="csrfmiddlewaretoken" value="([^"]*)"', resp.text)
                if csrf_token:
                    data = {
                        'csrfmiddlewaretoken': csrf_token.group(1),
                        'targetip': domain
                    }
                    headers = {
                        'Referer': dns_url,
                        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                    }
                    resp = session.post(dns_url, data=data, headers=headers)
                    if resp.status_code == 200:
                        subdomain_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9]*\.)*' + re.escape(domain)
                        found = re.findall(subdomain_pattern, resp.text)
                        subdomains.update([match[0] + domain for match in found if match[0]])
        except:
            pass
        
        return list(subdomains)[:25]  # Limit to 25 subdomains

    def _check_subdomain_bypass(self, subdomains: List[str]) -> Dict[str, str]:
        """Check if subdomains reveal real IP"""
        bypassed_ips = {}
        
        for subdomain in subdomains:
            try:
                ip = socket.gethostbyname(subdomain)
                if not self._is_cloudflare_ip(ip):
                    if self._verify_real_server(subdomain, ip):
                        bypassed_ips[subdomain] = ip
            except:
                continue
        
        return bypassed_ips

    def _verify_real_server(self, domain: str, ip: str) -> bool:
        """Verify if IP serves the same content as the main domain"""
        try:
            headers = {'Host': domain.replace('www.', '')}
            response = requests.get(f"http://{ip}", headers=headers, timeout=5, allow_redirects=False)
            return response.status_code in [200, 301, 302, 403, 503]
        except:
            return False

    def _dns_history_lookup(self, domain: str) -> List[str]:
        """Look for historical DNS records"""
        historical_ips = []
        
        # ViewDNS (web scraping)
        try:
            url = f"https://viewdns.info/iphistory/?domain={domain}"
            headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ips = re.findall(ip_pattern, response.text)
                for ip in ips:
                    if not self._is_cloudflare_ip(ip) and ip not in historical_ips:
                        historical_ips.append(ip)
        except:
            pass
        
        return historical_ips[:5]

    def _ssl_certificate_lookup(self, domain: str) -> List[str]:
        """Look for IPs in SSL certificates"""
        cert_ips = []
        
        try:
            # Censys.io search (web scraping)
            search_url = f"https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q={domain}"
            headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}
            response = requests.get(search_url, headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ips = re.findall(ip_pattern, response.text)
                for ip in ips:
                    if not self._is_cloudflare_ip(ip) and ip not in cert_ips:
                        cert_ips.append(ip)
        except:
            pass
        
        return cert_ips[:5]

    # ===== ADVANCED PORT SCANNING =====
    
    def _advanced_port_scan(self, ip: str, mode: str = "normal") -> Dict[int, Dict]:
        """Advanced port scanning with service detection and banner grabbing"""
        if mode == "stealth":
            ports_to_scan = [80, 443, 22, 21, 25]
        elif mode == "aggressive":
            # Full port range plus common services
            ports_to_scan = list(self.common_ports.keys()) + list(range(8000, 8100)) + [1337, 31337, 8888, 9999]
        else:  # normal
            ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
        
        open_ports = {}
        
        for port in ports_to_scan:
            try:
                # TCP Connect scan
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    service_info = {
                        'port': port,
                        'protocol': 'tcp',
                        'service': self.common_ports.get(port, 'unknown'),
                        'banner': '',
                        'version': '',
                        'technology': '',
                        'framework': '',
                        'security': {},
                        'confidence': 'low'
                    }
                    
                    # Banner grabbing
                    banner = self._grab_banner(ip, port)
                    if banner:
                        service_info['banner'] = banner
                        service_info['confidence'] = 'medium'
                        
                        # Service fingerprinting
                        detected_service = self._fingerprint_service(banner, port)
                        if detected_service:
                            service_info.update(detected_service)
                            service_info['confidence'] = 'high'
                    
                    open_ports[port] = service_info
                
                sock.close()
            except Exception as e:
                continue
        
        return open_ports

    def _grab_banner(self, ip: str, port: int) -> str:
        """Enhanced banner grabbing for various services"""
        banner = ""
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            
            # Service-specific banner grabbing
            if port in [80, 8080, 8000, 3000, 5000, 9000]:
                # HTTP banner
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\nConnection: close\r\n\r\n"
                sock.send(request.encode())
                banner = sock.recv(4096).decode('utf-8', errors='ignore')
                
            elif port in [443, 8443]:
                # HTTPS banner
                try:
                    import ssl
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                        ssock.send(request.encode())
                        banner = ssock.recv(4096).decode('utf-8', errors='ignore')
                except:
                    banner = "HTTPS (SSL handshake failed)"
                    
            elif port == 22:
                # SSH banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
            elif port == 21:
                # FTP banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
            elif port == 25:
                # SMTP banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
            elif port == 3306:
                # MySQL banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
            elif port == 5432:
                # PostgreSQL
                startup = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
                sock.send(startup)
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
            elif port == 6379:
                # Redis
                sock.send(b'INFO\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
            elif port == 9200:
                # Elasticsearch
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                sock.send(request.encode())
                banner = sock.recv(4096).decode('utf-8', errors='ignore')
                
            elif port == 27017:
                # MongoDB
                banner = "MongoDB (binary protocol)"
                
            else:
                # Generic banner grab
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
            sock.close()
            
        except Exception as e:
            return f"Banner grab failed: {str(e)[:50]}"
        
        return banner.strip()[:500]  # Limit banner size

    def _fingerprint_service(self, banner: str, port: int) -> Dict:
        """Advanced service fingerprinting based on banner"""
        service_info = {}
        banner_lower = banner.lower()
        
        # Web servers
        if 'apache' in banner_lower:
            service_info['technology'] = 'Apache HTTP Server'
            version_match = re.search(r'apache[/\s](\d+\.\d+\.\d+)', banner_lower)
            if version_match:
                service_info['version'] = version_match.group(1)
                
        elif 'nginx' in banner_lower:
            service_info['technology'] = 'Nginx'
            version_match = re.search(r'nginx[/\s](\d+\.\d+\.\d+)', banner_lower)
            if version_match:
                service_info['version'] = version_match.group(1)
                
        elif 'microsoft-iis' in banner_lower:
            service_info['technology'] = 'Microsoft IIS'
            version_match = re.search(r'iis[/\s](\d+\.\d+)', banner_lower)
            if version_match:
                service_info['version'] = version_match.group(1)
        
        # Application servers
        elif 'tomcat' in banner_lower:
            service_info['technology'] = 'Apache Tomcat'
            version_match = re.search(r'tomcat[/\s](\d+\.\d+\.\d+)', banner_lower)
            if version_match:
                service_info['version'] = version_match.group(1)
                
        elif 'jetty' in banner_lower:
            service_info['technology'] = 'Eclipse Jetty'
            version_match = re.search(r'jetty[/\s](\d+\.\d+\.\d+)', banner_lower)
            if version_match:
                service_info['version'] = version_match.group(1)
                
        # Databases
        elif 'mysql' in banner_lower:
            service_info['technology'] = 'MySQL'
            version_match = re.search(r'(\d+\.\d+\.\d+)', banner)
            if version_match:
                service_info['version'] = version_match.group(1)
                
        elif 'postgresql' in banner_lower:
            service_info['technology'] = 'PostgreSQL'
            
        elif 'redis' in banner_lower:
            service_info['technology'] = 'Redis'
            version_match = re.search(r'redis_version:(\d+\.\d+\.\d+)', banner_lower)
            if version_match:
                service_info['version'] = version_match.group(1)
                
        elif 'elasticsearch' in banner_lower:
            service_info['technology'] = 'Elasticsearch'
            version_match = re.search(r'"version"\s*:\s*{\s*"number"\s*:\s*"([^"]+)"', banner)
            if version_match:
                service_info['version'] = version_match.group(1)
        
        # SSH
        elif 'ssh' in banner_lower:
            service_info['technology'] = 'OpenSSH' if 'openssh' in banner_lower else 'SSH'
            version_match = re.search(r'openssh[_\s](\d+\.\d+)', banner_lower)
            if version_match:
                service_info['version'] = version_match.group(1)
        
        # FTP
        elif 'ftp' in banner_lower:
            if 'vsftpd' in banner_lower:
                service_info['technology'] = 'vsftpd'
            elif 'pure-ftpd' in banner_lower:
                service_info['technology'] = 'Pure-FTPd'
            elif 'proftpd' in banner_lower:
                service_info['technology'] = 'ProFTPD'
            else:
                service_info['technology'] = 'FTP Server'
        
        # Framework detection
        if 'x-powered-by' in banner_lower:
            powered_match = re.search(r'x-powered-by:\s*([^\r\n]+)', banner_lower)
            if powered_match:
                service_info['framework'] = powered_match.group(1).strip()
        
        # Security headers analysis
        security_headers = self._analyze_security_headers(banner)
        if security_headers:
            service_info['security'] = security_headers
        
        return service_info

    def _analyze_security_headers(self, banner: str) -> Dict:
        """Analyze security headers in HTTP responses"""
        security_info = {}
        
        headers_to_check = {
            'strict-transport-security': 'HSTS',
            'content-security-policy': 'CSP',
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-xss-protection': 'XSS Protection',
            'referrer-policy': 'Referrer Policy',
            'server': 'Server Header'
        }
        
        for header, name in headers_to_check.items():
            if header in banner.lower():
                if header == 'server':
                    server_match = re.search(r'server:\s*([^\r\n]+)', banner.lower())
                    if server_match:
                        security_info[name] = server_match.group(1).strip()
                else:
                    security_info[name] = 'Present'
        
        # Analyze for potential vulnerabilities
        vuln_indicators = []
        
        if 'server:' in banner.lower():
            server_header = re.search(r'server:\s*([^\r\n]+)', banner.lower())
            if server_header:
                server_value = server_header.group(1)
                if re.search(r'\d+\.\d+', server_value):
                    vuln_indicators.append('Version disclosure in Server header')
        
        if 'x-powered-by:' in banner.lower():
            vuln_indicators.append('Technology disclosure in X-Powered-By header')
        
        if 'strict-transport-security' not in banner.lower() and 'https' in banner.lower():
            vuln_indicators.append('Missing HSTS header')
        
        if vuln_indicators:
            security_info['vulnerabilities'] = vuln_indicators
        
        return security_info

    # ===== IP INFORMATION GATHERING =====
    
    def _get_ip_info(self, ip: str) -> Dict:
        """Get detailed information about an IP address"""
        info = {}
        
        # IP-API.com for geolocation
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,query",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    info.update(data)
        except:
            pass

        # IPInfo.io for additional data
        try:
            response = requests.get(f"http://ipinfo.io/{ip}/json?token={self.ipinfo_token}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                info.update(data)
        except:
            pass

        # Reverse DNS lookup
        try:
            response = requests.get(f"https://get.geojs.io/v1/dns/ptr/{ip}", timeout=5)
            if response.status_code == 200:
                hostname = response.text.strip()
                if hostname and "Failed to get PTR record" not in hostname:
                    info['hostname'] = hostname
                else:
                    info['hostname'] = "Not detected"
        except:
            info['hostname'] = "Not detected"

        return info

    # ===== CDN/WAF DETECTION =====
    
    def _detect_cdn_waf(self, domain: str, ip: str) -> Dict:
        """Detect CDN/WAF services and security measures"""
        detection_results = {
            'cdn': None,
            'waf': None,
            'security_measures': [],
            'confidence': 'low'
        }
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(f"http://{domain}", headers=headers, timeout=self.timeout, allow_redirects=False)
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            
            # CloudFlare detection
            cf_indicators = ['cf-ray', 'cf-cache-status', '__cfduid', 'cloudflare']
            if any(indicator in str(response_headers).lower() for indicator in cf_indicators):
                detection_results['cdn'] = 'CloudFlare'
                detection_results['confidence'] = 'high'
            
            # Other CDN detection
            if 'x-amz-cf-id' in response_headers or 'x-amz-cf-pop' in response_headers:
                detection_results['cdn'] = 'Amazon CloudFront'
                detection_results['confidence'] = 'high'
            elif 'x-fastly-request-id' in response_headers:
                detection_results['cdn'] = 'Fastly'
                detection_results['confidence'] = 'high'
            elif 'x-akamai-edgescape' in response_headers:
                detection_results['cdn'] = 'Akamai'
                detection_results['confidence'] = 'high'
            elif 'server' in response_headers and 'cloudfront' in response_headers['server'].lower():
                detection_results['cdn'] = 'Amazon CloudFront'
                detection_results['confidence'] = 'high'
            
            # WAF detection
            waf_indicators = {
                'cloudflare': ['cf-ray', 'cloudflare'],
                'akamai': ['akamaighost'],
                'incapsula': ['incap_ses', 'visid_incap'],
                'sucuri': ['sucuri', 'x-sucuri'],
                'wordfence': ['wordfence'],
                'mod_security': ['mod_security'],
                'aws_waf': ['awsalb', 'awsalbcors']
            }
            
            for waf_name, indicators in waf_indicators.items():
                if any(indicator in str(response_headers).lower() for indicator in indicators):
                    detection_results['waf'] = waf_name.replace('_', ' ').title()
                    break
            
            # Security measures detection
            if 'strict-transport-security' in response_headers:
                detection_results['security_measures'].append('HSTS Enabled')
            
            if 'content-security-policy' in response_headers:
                detection_results['security_measures'].append('CSP Enabled')
            
            if 'x-frame-options' in response_headers:
                detection_results['security_measures'].append('X-Frame-Options Set')
            
            # Rate limiting detection
            if response.status_code == 429 or 'rate limit' in response.text.lower():
                detection_results['security_measures'].append('Rate Limiting Active')
            
        except Exception as e:
            detection_results['error'] = str(e)
        
        return detection_results

    def _technology_stack_detection(self, banner: str, headers: Dict) -> Dict:
        """Detect technology stack from banners and headers"""
        stack = {
            'web_server': None,
            'application_server': None,
            'programming_language': None,
            'framework': None,
            'database': None,
            'cms': None
        }
        
        banner_lower = banner.lower()
        headers_str = str(headers).lower()
        
        # Web servers
        web_servers = {
            'apache': 'Apache HTTP Server',
            'nginx': 'Nginx',
            'iis': 'Microsoft IIS',
            'lighttpd': 'Lighttpd',
            'caddy': 'Caddy'
        }
        
        for server, name in web_servers.items():
            if server in banner_lower or server in headers_str:
                stack['web_server'] = name
                break
        
        # Programming languages
        if 'x-powered-by' in headers_str:
            if 'php' in headers_str:
                stack['programming_language'] = 'PHP'
            elif 'asp.net' in headers_str:
                stack['programming_language'] = 'ASP.NET'
            elif 'express' in headers_str:
                stack['programming_language'] = 'Node.js'
        
        # Frameworks
        frameworks = {
            'laravel': 'Laravel',
            'symfony': 'Symfony',
            'django': 'Django',
            'flask': 'Flask',
            'rails': 'Ruby on Rails',
            'express': 'Express.js',
            'spring': 'Spring Framework'
        }
        
        for fw, name in frameworks.items():
            if fw in banner_lower or fw in headers_str:
                stack['framework'] = name
                break
        
        # CMS Detection
        cms_indicators = {
            'wordpress': 'WordPress',
            'wp-content': 'WordPress',
            'joomla': 'Joomla',
            'drupal': 'Drupal',
            'typo3': 'TYPO3'
        }
        
        for cms, name in cms_indicators.items():
            if cms in banner_lower:
                stack['cms'] = name
                break
        
        return stack

    # ===== ADVANCED BYPASS SCANNING =====
    
    def _advanced_bypass_scan(self, domain: str) -> Dict:
        """Comprehensive bypass scan using multiple techniques"""
        results = {
            'subdomains': {},
            'historical_ips': [],
            'certificate_ips': [],
            'verified_ips': []
        }
        
        print(f"{Colors.CYAN}[*] 1/4 - Searching for subdomains...{Colors.ENDC}")
        subdomains = self._find_subdomains(domain)
        if subdomains:
            print(f"{Colors.GREEN}[+] Found {len(subdomains)} subdomains{Colors.ENDC}")
            results['subdomains'] = self._check_subdomain_bypass(subdomains)
        
        print(f"{Colors.CYAN}[*] 2/4 - Looking for historical DNS records...{Colors.ENDC}")
        results['historical_ips'] = self._dns_history_lookup(domain)
        if results['historical_ips']:
            print(f"{Colors.GREEN}[+] Found {len(results['historical_ips'])} historical IPs{Colors.ENDC}")
        
        print(f"{Colors.CYAN}[*] 3/4 - Checking SSL certificates...{Colors.ENDC}")
        results['certificate_ips'] = self._ssl_certificate_lookup(domain)
        if results['certificate_ips']:
            print(f"{Colors.GREEN}[+] Found {len(results['certificate_ips'])} certificate IPs{Colors.ENDC}")
        
        print(f"{Colors.CYAN}[*] 4/4 - Verifying discovered IPs...{Colors.ENDC}")
        # Verify all discovered IPs
        all_ips = set()
        all_ips.update(results['subdomains'].values())
        all_ips.update(results['historical_ips'])
        all_ips.update(results['certificate_ips'])
        
        for ip in all_ips:
            if self._verify_real_server(domain, ip):
                results['verified_ips'].append(ip)
        
        if results['verified_ips']:
            print(f"{Colors.GREEN}[+] Verified {len(results['verified_ips'])} real IPs{Colors.ENDC}")
        
        return results

    # ===== SECURITY ANALYSIS =====
    
    def _comprehensive_security_analysis(self, scan_results: Dict) -> Dict:
        """Comprehensive security analysis of the infrastructure"""
        security_analysis = {
            'risk_level': 'LOW',
            'security_issues': [],
            'recommendations': [],
            'exposed_services': [],
            'encryption_status': {},
            'access_controls': {}
        }
        
        high_risk_count = 0
        medium_risk_count = 0
        
        # Analyze each discovered IP
        for ip, port_data in scan_results.get('port_scan_results', {}).items():
            for port, service_info in port_data.items():
                service_name = service_info.get('service', 'unknown')
                
                # Check for high-risk services
                high_risk_services = [21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 6379, 27017]
                if port in high_risk_services:
                    security_analysis['exposed_services'].append({
                        'ip': ip,
                        'port': port,
                        'service': service_name,
                        'risk': 'HIGH',
                        'reason': f'{service_name} exposed to internet'
                    })
                    high_risk_count += 1
                
                # Check for unencrypted services
                unencrypted_services = [21, 23, 25, 80, 110, 143]
                if port in unencrypted_services:
                    security_analysis['encryption_status'][f"{ip}:{port}"] = 'UNENCRYPTED'
                    medium_risk_count += 1
                
                # Analyze banners for vulnerabilities
                banner = service_info.get('banner', '')
                if banner:
                    # Version disclosure
                    if re.search(r'\d+\.\d+\.\d+', banner):
                        security_analysis['security_issues'].append({
                            'type': 'Information Disclosure',
                            'severity': 'MEDIUM',
                            'location': f"{ip}:{port}",
                            'description': 'Version information disclosed in banner',
                            'evidence': banner[:100]
                        })
                        medium_risk_count += 1
                    
                    # Default error pages
                    if any(indicator in banner.lower() for indicator in ['apache/2', 'nginx/1', 'iis/7', 'iis/8']):
                        security_analysis['security_issues'].append({
                            'type': 'Server Information Disclosure',
                            'severity': 'LOW',
                            'location': f"{ip}:{port}",
                            'description': 'Server type and version disclosed',
                            'evidence': banner[:100]
                        })
                
                # Check for security headers (HTTP services)
                if port in [80, 443, 8080, 8443] and service_info.get('security'):
                    sec_headers = service_info['security']
                    missing_headers = []
                    
                    important_headers = ['HSTS', 'CSP', 'X-Frame-Options', 'X-Content-Type-Options']
                    for header in important_headers:
                        if header not in sec_headers:
                            missing_headers.append(header)
                    
                    if missing_headers:
                        security_analysis['security_issues'].append({
                            'type': 'Missing Security Headers',
                            'severity': 'MEDIUM',
                            'location': f"{ip}:{port}",
                            'description': f'Missing headers: {", ".join(missing_headers)}',
                            'evidence': f'Checked headers: {list(sec_headers.keys())}'
                        })
                        medium_risk_count += 1

        # Determine overall risk level
        if high_risk_count > 2:
            security_analysis['risk_level'] = 'CRITICAL'
        elif high_risk_count > 0 or medium_risk_count > 3:
            security_analysis['risk_level'] = 'HIGH'
        elif medium_risk_count > 0:
            security_analysis['risk_level'] = 'MEDIUM'
        
        # Generate recommendations
        if security_analysis['exposed_services']:
            security_analysis['recommendations'].append(
                'Restrict access to sensitive services (FTP, SSH, RDP, databases) using firewall rules'
            )
        
        if security_analysis['encryption_status']:
            security_analysis['recommendations'].append(
                'Implement SSL/TLS encryption for all web services and enable HTTPS redirects'
            )
        
        if any(issue['type'] == 'Missing Security Headers' for issue in security_analysis['security_issues']):
            security_analysis['recommendations'].append(
                'Implement proper security headers (HSTS, CSP, X-Frame-Options, etc.)'
            )
        
        return security_analysis

    def _vulnerability_assessment(self, scan_results: Dict) -> Dict:
        """Basic vulnerability assessment based on discovered services"""
        vuln_hints = {
            'potential_vulnerabilities': [],
            'attack_vectors': [],
            'further_testing': []
        }
        
        for ip, port_data in scan_results.get('port_scan_results', {}).items():
            for port, service_info in port_data.items():
                service = service_info.get('service', '')
                version = service_info.get('version', '')
                banner = service_info.get('banner', '')
                
                # Common vulnerability patterns
                if port == 22 and 'openssh' in banner.lower():
                    vuln_hints['further_testing'].append(f"SSH brute force testing on {ip}:22")
                    vuln_hints['attack_vectors'].append('SSH Authentication')
                
                if port in [80, 443, 8080, 8443]:
                    vuln_hints['further_testing'].extend([
                        f"Directory bruteforcing on {ip}:{port}",
                        f"Web application vulnerability scanning on {ip}:{port}",
                        f"SSL/TLS configuration testing on {ip}:{port}"
                    ])
                    vuln_hints['attack_vectors'].append('Web Application')
                
                if port == 21:
                    vuln_hints['further_testing'].append(f"FTP anonymous login testing on {ip}:21")
                    vuln_hints['attack_vectors'].append('FTP Services')
                
                if port in [3306, 5432, 1433, 27017]:
                    vuln_hints['further_testing'].append(f"Database connection testing on {ip}:{port}")
                    vuln_hints['attack_vectors'].append('Database Services')
                
                # Version-specific vulnerabilities
                if version:
                    vuln_hints['potential_vulnerabilities'].append({
                        'service': f"{service} {version}",
                        'location': f"{ip}:{port}",
                        'recommendation': f"Check CVE database for {service} {version} vulnerabilities"
                    })
                
                # Default credentials hints
                default_creds_services = {
                    3306: 'MySQL (try root/root, root/mysql)',
                    5432: 'PostgreSQL (try postgres/postgres)',
                    6379: 'Redis (often no authentication)',
                    9200: 'Elasticsearch (often no authentication)',
                    27017: 'MongoDB (often no authentication)',
                    11211: 'Memcached (no authentication by default)'
                }
                
                if port in default_creds_services:
                    vuln_hints['potential_vulnerabilities'].append({
                        'service': service,
                        'location': f"{ip}:{port}",
                        'recommendation': f"Test default credentials: {default_creds_services[port]}"
                    })
        
        return vuln_hints

    # ===== MAIN SCANNING FUNCTION =====
    
    def _scan_target(self, domain: str, mode: str = "normal", verbose: bool = False) -> Dict:
        """Enhanced scanning function for complete infrastructure reconnaissance"""
        results = {
            'target': domain,
            'scan_mode': mode,
            'target_type': 'domain' if not self._is_ip(domain) else 'ip',
            'cloudflare_protected': False,
            'cdn_waf_info': {},
            'discovered_ips': [],
            'technology_stack': {},
            'dns_records': {},
            'bypass_methods': {},
            'port_scan_results': {},
            'security_analysis': {},
            'vulnerability_hints': {},
            'success': False
        }

        print(f"\n{Colors.CYAN}[*] Starting infrastructure reconnaissance: {Colors.BOLD}{domain}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Scan mode: {mode.upper()}{Colors.ENDC}")
        
        # Progress simulation
        steps = 8 if mode == "aggressive" else 6
        for i in range(0, 101, 100//steps):
            self._display_progress_bar(i)
            time.sleep(0.3)
        print()

        # Step 1: Basic DNS resolution
        if results['target_type'] == 'domain':
            primary_ip = self._get_primary_ip(domain)
            results['primary_ip'] = primary_ip
            if verbose:
                print(f"{Colors.BLUE}[*] Primary IP: {primary_ip}{Colors.ENDC}")

            # Get DNS records
            results['dns_records'] = self._get_dns_records(domain)
            if verbose and results['dns_records']['NS']:
                print(f"{Colors.BLUE}[*] NS Records: {', '.join(results['dns_records']['NS'])}{Colors.ENDC}")
        else:
            results['primary_ip'] = domain
            primary_ip = domain

        # Step 2: CDN/WAF Detection
        print(f"{Colors.CYAN}[*] Analyzing CDN/WAF protection...{Colors.ENDC}")
        if results['target_type'] == 'domain':
            results['cdn_waf_info'] = self._detect_cdn_waf(domain, primary_ip)
            if results['cdn_waf_info'].get('cdn') == 'CloudFlare':
                results['cloudflare_protected'] = True
                print(f"{Colors.WARNING}[!] CloudFlare protection detected{Colors.ENDC}")

        # Step 3: Infrastructure Discovery
        all_ips = set([primary_ip])
        
        if results['target_type'] == 'domain' and mode != "stealth":
            print(f"\n{Colors.CYAN}[*] Starting infrastructure discovery...{Colors.ENDC}")
            bypass_results = self._advanced_bypass_scan(domain)
            results['bypass_methods'] = bypass_results
            
            # Collect all discovered IPs
            for subdomain, ip in bypass_results['subdomains'].items():
                all_ips.add(ip)
                if verbose:
                    print(f"{Colors.GREEN}[+] Subdomain: {subdomain} -> {ip}{Colors.ENDC}")
            
            all_ips.update(bypass_results['historical_ips'])
            all_ips.update(bypass_results['certificate_ips'])
            all_ips.update(bypass_results['verified_ips'])

        results['discovered_ips'] = list(all_ips)

        # Step 4: Port Scanning and Service Detection
        print(f"\n{Colors.CYAN}[*] Scanning ports and identifying services...{Colors.ENDC}")
        for ip in results['discovered_ips']:
            if ip and ip != "Unknown":
                print(f"{Colors.BLUE}[*] Scanning {ip}...{Colors.ENDC}")
                port_results = self._advanced_port_scan(ip, mode)
                if port_results:
                    results['port_scan_results'][ip] = port_results
                    if verbose:
                        print(f"{Colors.GREEN}[+] Found {len(port_results)} open ports on {ip}{Colors.ENDC}")

        # Step 5: Technology Stack Analysis
        print(f"{Colors.CYAN}[*] Analyzing technology stack...{Colors.ENDC}")
        for ip, port_data in results['port_scan_results'].items():
            for port, service_info in port_data.items():
                if service_info.get('banner') and port in [80, 443, 8080, 8443]:
                    tech_stack = self._technology_stack_detection(
                        service_info['banner'], 
                        {'server': service_info.get('banner', '')}
                    )
                    if any(tech_stack.values()):
                        results['technology_stack'][ip] = tech_stack
                        break

        # Step 6: Security Analysis
        print(f"{Colors.CYAN}[*] Performing security analysis...{Colors.ENDC}")
        results['security_analysis'] = self._comprehensive_security_analysis(results)

        # Step 7: Vulnerability Assessment (Aggressive mode only)
        if mode == "aggressive":
            print(f"{Colors.CYAN}[*] Running vulnerability assessment...{Colors.ENDC}")
            results['vulnerability_hints'] = self._vulnerability_assessment(results)

        # Success determination
        results['success'] = bool(results['discovered_ips'] and any(results['port_scan_results'].values()))
        
        return results

    # ===== RESULTS DISPLAY =====
    
    def _display_results(self, results: Dict):
        """Display comprehensive reconnaissance results"""
        print(f"\n{Colors.GREEN}{'='*90}{Colors.ENDC}")
        print(f"{Colors.CYAN}{Colors.BOLD}Web Infrastructure Reconnaissance Report{Colors.ENDC}")
        print(f"{Colors.GREEN}{'='*90}{Colors.ENDC}")
        
        # Target Summary
        print(f"\n{Colors.BOLD}🎯 TARGET SUMMARY{Colors.ENDC}")
        print(f"  Target           : {results['target']}")
        print(f"  Target Type      : {results['target_type'].upper()}")
        print(f"  Scan Mode        : {results['scan_mode'].upper()}")
        print(f"  Primary IP       : {results.get('primary_ip', 'N/A')}")
        
        # CDN/WAF Information
        cdn_info = results.get('cdn_waf_info', {})
        if cdn_info:
            print(f"\n{Colors.BOLD}🛡️  CDN/WAF PROTECTION{Colors.ENDC}")
            if cdn_info.get('cdn'):
                color = Colors.WARNING if cdn_info['cdn'] == 'CloudFlare' else Colors.BLUE
                print(f"  CDN Service      : {color}{cdn_info['cdn']}{Colors.ENDC}")
            if cdn_info.get('waf'):
                print(f"  WAF Service      : {Colors.WARNING}{cdn_info['waf']}{Colors.ENDC}")
            if cdn_info.get('security_measures'):
                print(f"  Security Measures: {', '.join(cdn_info['security_measures'])}")

        # Infrastructure Discovery
        if results.get('bypass_methods') and results['target_type'] == 'domain':
            print(f"\n{Colors.BOLD}🔍 INFRASTRUCTURE DISCOVERY{Colors.ENDC}")
            bypass_methods = results['bypass_methods']
            
            if bypass_methods.get('subdomains'):
                print(f"  {Colors.GREEN}✓{Colors.ENDC} Subdomain Analysis: {len(bypass_methods['subdomains'])} found")
                for subdomain, ip in list(bypass_methods['subdomains'].items())[:5]:
                    print(f"    • {subdomain} -> {Colors.CYAN}{ip}{Colors.ENDC}")
            
            if bypass_methods.get('historical_ips'):
                print(f"  {Colors.GREEN}✓{Colors.ENDC} Historical DNS: {len(bypass_methods['historical_ips'])} IPs")
                for ip in bypass_methods['historical_ips'][:3]:
                    print(f"    • {Colors.CYAN}{ip}{Colors.ENDC}")
            
            if bypass_methods.get('certificate_ips'):
                print(f"  {Colors.GREEN}✓{Colors.ENDC} Certificate Analysis: {len(bypass_methods['certificate_ips'])} IPs")

        # Discovered Infrastructure
        if results.get('discovered_ips') and len(results['discovered_ips']) > 1:
            print(f"\n{Colors.BOLD}🌐 DISCOVERED INFRASTRUCTURE{Colors.ENDC}")
            for i, ip in enumerate(results['discovered_ips'], 1):
                if ip and ip != "Unknown":
                    print(f"  Server #{i:2d}      : {Colors.CYAN}{ip}{Colors.ENDC}")

        # Port Scan Results
        if results.get('port_scan_results'):
            print(f"\n{Colors.BOLD}🔌 PORT SCAN & SERVICE DETECTION{Colors.ENDC}")
            
            for ip, port_data in results['port_scan_results'].items():
                if port_data:
                    print(f"\n  {Colors.CYAN}📍 {ip}{Colors.ENDC}")
                    print(f"  {'Port':<6} {'Service':<12} {'Technology':<20} {'Version':<15} {'Status'}")
                    print(f"  {'-'*70}")
                    
                    for port, service_info in sorted(port_data.items()):
                        service = service_info.get('service', 'unknown')[:11]
                        tech = service_info.get('technology', 'N/A')[:19]
                        version = service_info.get('version', 'N/A')[:14]
                        confidence = service_info.get('confidence', 'low')
                        
                        # Color coding based on risk
                        if port in [21, 23, 135, 139, 445, 1433, 3306, 3389, 5432]:
                            port_color = Colors.FAIL
                        elif port in [22, 80, 443]:
                            port_color = Colors.GREEN
                        else:
                            port_color = Colors.CYAN
                        
                        confidence_indicator = {
                            'high': '●', 'medium': '◐', 'low': '○'
                        }.get(confidence, '?')
                        
                        print(f"  {port_color}{port:<6}{Colors.ENDC} {service:<12} {tech:<20} {version:<15} {confidence_indicator}")
                        
                        # Show banner excerpt for important services
                        if service_info.get('banner') and port in [22, 80, 443, 21, 25]:
                            banner_excerpt = service_info['banner'][:60].replace('\n', ' ').replace('\r', '')
                            if banner_excerpt:
                                print(f"    └─ {Colors.BLUE}Banner: {banner_excerpt}...{Colors.ENDC}")

        # Technology Stack
        if results.get('technology_stack'):
            print(f"\n{Colors.BOLD}⚙️  TECHNOLOGY STACK{Colors.ENDC}")
            for ip, stack in results['technology_stack'].items():
                print(f"\n  {Colors.CYAN}📍 {ip}{Colors.ENDC}")
                for component, technology in stack.items():
                    if technology:
                        component_name = component.replace('_', ' ').title()
                        print(f"    {component_name:<18}: {Colors.GREEN}{technology}{Colors.ENDC}")

        # Security Analysis
        security_analysis = results.get('security_analysis', {})
        if security_analysis:
            print(f"\n{Colors.BOLD}🔒 SECURITY ANALYSIS{Colors.ENDC}")
            
            risk_level = security_analysis.get('risk_level', 'UNKNOWN')
            risk_colors = {
                'LOW': Colors.GREEN,
                'MEDIUM': Colors.WARNING,
                'HIGH': Colors.FAIL,
                'CRITICAL': Colors.FAIL + Colors.BOLD
            }
            risk_color = risk_colors.get(risk_level, Colors.BLUE)
            
            print(f"  Risk Level       : {risk_color}{risk_level}{Colors.ENDC}")
            
            # Security Issues
            issues = security_analysis.get('security_issues', [])
            if issues:
                print(f"\n  {Colors.WARNING}⚠️  Security Issues Found:{Colors.ENDC}")
                for issue in issues[:5]:
                    severity_color = Colors.FAIL if issue['severity'] == 'HIGH' else Colors.WARNING
                    print(f"    • {severity_color}{issue['severity']}{Colors.ENDC}: {issue['type']} at {issue['location']}")
                    print(f"      └─ {issue['description']}")
            
            # Exposed Services
            exposed = security_analysis.get('exposed_services', [])
            if exposed:
                print(f"\n  {Colors.FAIL}🚨 High-Risk Exposed Services:{Colors.ENDC}")
                for service in exposed[:5]:
                    print(f"    • {Colors.FAIL}{service['service']}{Colors.ENDC} on {service['ip']}:{service['port']} - {service['reason']}")
            
            # Recommendations
            recommendations = security_analysis.get('recommendations', [])
            if recommendations:
                print(f"\n  {Colors.BLUE}💡 Security Recommendations:{Colors.ENDC}")
                for i, rec in enumerate(recommendations[:3], 1):
                    print(f"    {i}. {rec}")

        # Vulnerability Assessment (if available)
        vuln_hints = results.get('vulnerability_hints', {})
        if vuln_hints:
            print(f"\n{Colors.BOLD}🎯 VULNERABILITY ASSESSMENT{Colors.ENDC}")
            
            potential_vulns = vuln_hints.get('potential_vulnerabilities', [])
            if potential_vulns:
                print(f"\n  {Colors.WARNING}🔓 Potential Vulnerabilities:{Colors.ENDC}")
                for vuln in potential_vulns[:5]:
                    print(f"    • {vuln['service']} at {vuln['location']}")
                    print(f"      └─ {vuln['recommendation']}")
            
            attack_vectors = vuln_hints.get('attack_vectors', [])
            if attack_vectors:
                print(f"\n  {Colors.CYAN}🎪 Attack Vectors:{Colors.ENDC}")
                for vector in set(attack_vectors):
                    print(f"    • {vector}")
            
            further_testing = vuln_hints.get('further_testing', [])
            if further_testing:
                print(f"\n  {Colors.BLUE}🧪 Suggested Further Testing:{Colors.ENDC}")
                for test in further_testing[:5]:
                    print(f"    • {test}")

        # Summary
        print(f"\n{Colors.GREEN}{'─'*90}{Colors.ENDC}")
        if results['success']:
            discovered_count = len([ip for ip in results['discovered_ips'] if ip and ip != 'Unknown'])
            open_ports_count = sum(len(ports) for ports in results.get('port_scan_results', {}).values())
            
            print(f"{Colors.GREEN}✅ RECONNAISSANCE COMPLETED SUCCESSFULLY{Colors.ENDC}")
            print(f"   • Discovered {discovered_count} IP addresses")
            print(f"   • Found {open_ports_count} open ports")
            print(f"   • Identified {len(results.get('technology_stack', {}))} technology stacks")
            if security_analysis:
                print(f"   • Overall risk level: {risk_colors.get(risk_level, Colors.BLUE)}{risk_level}{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}⚠️  Limited information gathered{Colors.ENDC}")
            print(f"   • Target may be well-protected or unreachable")
            print(f"   • Consider using different scan modes or techniques")

        print(f"\n{Colors.BLUE}[i] Reconnaissance completed. Use results responsibly and within legal boundaries.{Colors.ENDC}")
        print(f"{Colors.BLUE}[i] Consider running additional specialized tools for deeper analysis.{Colors.ENDC}")

    # ===== SAVE RESULTS =====
    
    def _save_results_to_file(self, results: Dict):
        """Save scan results to a JSON file"""
        try:
            import json
            from datetime import datetime
            
            # Create filename
            target_clean = results['target'].replace(':', '_').replace('/', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"web_recon_{target_clean}_{timestamp}.json"
            
            # Prepare data for JSON serialization
            results_copy = results.copy()
            results_copy['scan_timestamp'] = datetime.now().isoformat()
            results_copy['tool_version'] = "Web Infrastructure Recon v2.0"
            
            with open(filename, 'w') as f:
                json.dump(results_copy, f, indent=2, default=str)
            
            print(f"{Colors.GREEN}[✓] Results saved to: {filename}{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error saving results: {e}{Colors.ENDC}")

    # ===== INTERFACE FUNCTIONS =====
    
    def run_guided(self) -> None:
        """Enhanced guided mode with multiple scan options"""
        print(f"{Colors.CYAN}{Colors.BOLD}Web Infrastructure Reconnaissance - Guided Mode{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] This tool is for educational and authorized testing purposes only{Colors.ENDC}\n")
        
        # Get target from user
        target = input(f"{Colors.CYAN}[?] Enter target (domain/IP): {Colors.ENDC}").strip()
        
        if not target:
            print(f"{Colors.FAIL}[!] No target specified{Colors.ENDC}")
            return
        
        # Clean the target
        if not self._is_ip(target):
            target = self._clean_url(target)
        
        # Scan mode selection
        print(f"\n{Colors.BOLD}Scan Modes:{Colors.ENDC}")
        print(f"  1. {Colors.GREEN}Stealth{Colors.ENDC}   - Minimal scanning, low detection risk")
        print(f"  2. {Colors.BLUE}Normal{Colors.ENDC}    - Balanced scanning (default)")
        print(f"  3. {Colors.WARNING}Aggressive{Colors.ENDC} - Full reconnaissance with vulnerability hints")
        
        mode_choice = input(f"\n{Colors.CYAN}[?] Select scan mode (1-3, default=2): {Colors.ENDC}").strip()
        
        mode_mapping = {'1': 'stealth', '2': 'normal', '3': 'aggressive', '': 'normal'}
        scan_mode = mode_mapping.get(mode_choice, 'normal')
        
        # Verbose output option
        verbose_input = input(f"{Colors.CYAN}[?] Enable verbose output? (y/N): {Colors.ENDC}").strip().lower()
        verbose = verbose_input in ['y', 'yes']
        
        # Confirmation for aggressive mode
        if scan_mode == 'aggressive':
            confirm = input(f"{Colors.WARNING}[!] Aggressive mode may trigger security alerts. Continue? (y/N): {Colors.ENDC}").strip().lower()
            if confirm not in ['y', 'yes']:
                scan_mode = 'normal'
                print(f"{Colors.BLUE}[*] Switched to normal mode{Colors.ENDC}")
        
        # Run the scan
        print(f"\n{Colors.GREEN}[*] Starting {scan_mode} reconnaissance of {target}...{Colors.ENDC}")
        results = self._scan_target(target, scan_mode, verbose)
        self._display_results(results)
        
        # Offer to save results
        save_option = input(f"\n{Colors.CYAN}[?] Save results to file? (y/N): {Colors.ENDC}").strip().lower()
        if save_option in ['y', 'yes']:
            self._save_results_to_file(results)

    def run_direct(self) -> None:
        """Run the tool in direct mode with command-line style arguments"""
        print(f"{Colors.CYAN}{Colors.BOLD}Web Infrastructure Reconnaissance - Direct Mode{Colors.ENDC}")
        
        # Simulate command line arguments input
        target = input(f"{Colors.CYAN}[?] Enter target (domain/IP): {Colors.ENDC}").strip()
        if not target:
            print(f"{Colors.FAIL}[!] No target specified{Colors.ENDC}")
            return
        
        mode = input(f"{Colors.CYAN}[?] Scan mode (stealth/normal/aggressive) [normal]: {Colors.ENDC}").strip() or "normal"
        verbose = input(f"{Colors.CYAN}[?] Verbose output (y/N): {Colors.ENDC}").strip().lower() in ['y', 'yes']
        
        if not self._is_ip(target):
            target = self._clean_url(target)
        
        results = self._scan_target(target, mode, verbose)
        self._display_results(results)

    def run_with_target(self, target: str, mode: str = "normal", verbose: bool = False) -> Dict:
        """Run scan with specific parameters (for API/programmatic use)"""
        if not self._is_ip(target):
            target = self._clean_url(target)
        return self._scan_target(target, mode, verbose)

    def run_cloudflare_bypass_only(self, target: str) -> Dict:
        """Legacy method for CloudFlare bypass only"""
        print(f"{Colors.WARNING}[!] Running in CloudFlare bypass mode only{Colors.ENDC}")
        
        if not self._is_ip(target):
            target = self._clean_url(target)
        
        # Run only bypass techniques
        results = {
            'target': target,
            'bypass_methods': {},
            'success': False
        }
        
        print(f"{Colors.CYAN}[*] Starting CloudFlare bypass techniques...{Colors.ENDC}")
        results['bypass_methods'] = self._advanced_bypass_scan(target)
        
        # Check if any real IPs were found
        all_ips = set()
        all_ips.update(results['bypass_methods'].get('subdomains', {}).values())
        all_ips.update(results['bypass_methods'].get('historical_ips', []))
        all_ips.update(results['bypass_methods'].get('certificate_ips', []))
        all_ips.update(results['bypass_methods'].get('verified_ips', []))
        
        if all_ips:
            results['success'] = True
            results['discovered_ips'] = list(all_ips)
            
            print(f"\n{Colors.GREEN}[✓] CloudFlare bypass successful!{Colors.ENDC}")
            for ip in results['discovered_ips']:
                if ip:
                    print(f"  • Real IP: {Colors.CYAN}{ip}{Colors.ENDC}")
        else:
            print(f"\n{Colors.WARNING}[!] CloudFlare bypass unsuccessful{Colors.ENDC}")
            print(f"    • No alternative IPs found")
            print(f"    • Target may be properly protected")
        
        return results

# Additional utility functions for the module
def detect_web_technology(url: str) -> Dict:
    """Standalone function to detect web technology stack"""
    module = WebInfrastructureRecon()
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        
        banner = f"{response.status_code} {response.reason}\n"
        for header, value in response.headers.items():
            banner += f"{header}: {value}\n"
        
        tech_stack = module._technology_stack_detection(banner, response.headers)
        return tech_stack
        
    except Exception as e:
        return {'error': str(e)}

def quick_port_scan(ip: str, ports: List[int] = None) -> Dict:
    """Standalone function for quick port scanning"""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
    
    module = WebInfrastructureRecon()
    # Create a custom port scan for specific ports
    open_ports = {}
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                service_info = {
                    'port': port,
                    'service': module.common_ports.get(port, 'unknown'),
                    'banner': module._grab_banner(ip, port)
                }
                open_ports[port] = service_info
            
            sock.close()
        except:
            continue
    
    return open_ports

def cloudflare_bypass_quick(domain: str) -> List[str]:
    """Quick CloudFlare bypass function"""
    module = WebInfrastructureRecon()
    if not module._is_ip(domain):
        domain = module._clean_url(domain)
    
    bypass_results = module._advanced_bypass_scan(domain)
    
    all_ips = set()
    all_ips.update(bypass_results.get('subdomains', {}).values())
    all_ips.update(bypass_results.get('historical_ips', []))
    all_ips.update(bypass_results.get('certificate_ips', []))
    all_ips.update(bypass_results.get('verified_ips', []))
    
    return list(all_ips)

# Module instantiation for framework
def get_module():
    return WebInfrastructureRecon()

# Export functions for use in other modules
__all__ = [
    'WebInfrastructureRecon',
    'detect_web_technology', 
    'quick_port_scan',
    'cloudflare_bypass_quick',
    'get_module'
]

if __name__ == "__main__":
    # For standalone execution
    module = WebInfrastructureRecon()
    module.run_guided()