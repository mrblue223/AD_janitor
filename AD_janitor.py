#!/usr/bin/env python3
"""
Enhanced AD Janitor - Active Directory Enumeration & Vulnerability Assessment Tool
Now with AS-REP Roasting, BloodHound export, GPP password scanning, and more!
"""

import subprocess
import json
import sys
import os
import re
import argparse
import tempfile
import csv
import base64
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set, Any
from collections import defaultdict
import hashlib
import time
import random
from pathlib import Path

class EnhancedADJanitor:
    def __init__(self, ldap_server: str, username: str, password: str, base_dn: str, 
                 output_dir: str = "ad_enum_results", stealth_mode: bool = False):
        """
        Initialize Enhanced AD Janitor with connection parameters
        
        Args:
            ldap_server: LDAP server URL (e.g., ldap://10.200.71.101)
            username: Username for authentication
            password: Password for authentication
            base_dn: Base Distinguished Name (e.g., DC=za,DC=tryhackme,DC=com)
            output_dir: Directory to store results
            stealth_mode: Enable stealthy enumeration with random delays
        """
        self.ldap_server = ldap_server
        self.username = username
        self.password = password
        self.base_dn = base_dn
        self.output_dir = output_dir
        self.stealth_mode = stealth_mode
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Extract domain from base DN for file naming
        self.domain = self.extract_domain_from_dn(base_dn)
        
        # Setup logging
        self.log_file = os.path.join(output_dir, f"ad_janitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        self.log("Enhanced AD Janitor initialized")
        
        # Data storage
        self.users_data = []
        self.groups_data = []
        self.computers_data = []
        self.ous_data = []
        self.trusts_data = []
        self.gpp_data = []
        self.group_membership = defaultdict(list)  # group -> list of members
        self.user_groups = defaultdict(list)       # user -> list of groups
        self.computer_admin_users = defaultdict(list)  # computer -> list of admin users
        
        # Vulnerability storage
        self.vulnerable_users = {
            "password_never_expires": [],
            "password_not_required": [],
            "reversible_encryption": [],
            "admin_count_set": [],
            "service_accounts": [],
            "inactive_accounts": [],
            "plaintext_passwords": [],
            "kerberoastable": [],
            "asrep_roastable": [],  # NEW: AS-REP roastable accounts
            "unconstrained_delegation": [],  # NEW: Unconstrained delegation
            "constrained_delegation": [],  # NEW: Constrained delegation
            "resource_based_delegation": []  # NEW: Resource-based constrained delegation
        }
        
        # Common AD vulnerabilities
        self.VULNERABILITY_FLAGS = {
            "PASSWD_NOTREQD": 0x00000020,      # Password not required
            "PASSWD_CANT_CHANGE": 0x00000040,   # User cannot change password
            "PASSWD_NEVER_EXPIRES": 0x00010000, # Password never expires
            "ENCRYPTED_TEXT_PWD_ALLOWED": 0x00000080, # Reversible encryption
            "ACCOUNTDISABLE": 0x00000002,       # Account disabled
            "NORMAL_ACCOUNT": 0x00000200,       # Normal user account
            "WORKSTATION_TRUST_ACCOUNT": 0x00001000, # Computer account
            "SERVER_TRUST_ACCOUNT": 0x00002000, # Domain controller account
            "DONT_EXPIRE_PASSWORD": 0x00010000, # Password doesn't expire
            "SMARTCARD_REQUIRED": 0x00040000,   # Smart card required
            "PASSWORD_EXPIRED": 0x00800000,     # Password expired
            "TRUSTED_FOR_DELEGATION": 0x00080000, # Trusted for delegation (unconstrained)
            "NOT_DELEGATED": 0x00100000,        # Not delegated
            "USE_DES_KEY_ONLY": 0x00200000,     # Use DES encryption only
            "DONT_REQ_PREAUTH": 0x00400000,     # Don't require pre-auth (AS-REP roastable)
            "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x01000000, # Trusted to auth for delegation
            "PASSWORD_NOT_REQUIRED": 0x0020,    # Password not required (short form)
            "PASSWORD_EXPIRED": 0x00800000      # Password expired
        }
        
        # High-privilege groups to monitor
        self.PRIVILEGED_GROUPS = [
            "Domain Admins",
            "Enterprise Admins", 
            "Schema Admins",
            "Administrators",
            "Backup Operators",
            "Account Operators",
            "Print Operators",
            "Server Operators",
            "Domain Controllers",
            "Read-only Domain Controllers",
            "Group Policy Creator Owners",
            "Cryptographic Operators",
            "Distributed COM Users",
            "Event Log Readers",
            "Certificate Service DCOM Access",
            "RDS Endpoint Servers",
            "RDS Management Servers",
            "Remote Desktop Users",
            "Network Configuration Operators",
            "Incoming Forest Trust Builders",
            "Windows Authorization Access Group",
            "Terminal Server License Servers",
            "Allowed RODC Password Replication Group",
            "Denied RODC Password Replication Group",
            "Protected Users",
            "Key Admins",
            "Enterprise Key Admins",
            "DnsAdmins",
            "DnsUpdateProxy"
        ]
        
        # Password spray common passwords
        self.COMMON_PASSWORDS = [
            "Password1", "Password123", "Summer2023", "Winter2023",
            "Welcome1", "Welcome123", "P@ssw0rd", "P@ssw0rd123",
            "Qwerty123", "Qwerty123!", "Admin123", "Admin123!",
            "Passw0rd", "Passw0rd123", "Spring2023", "Fall2023",
            "Company123", "Company2023", "Changeme123", "Changeme1"
        ]
        
    def log(self, message: str, level: str = "INFO"):
        """Log messages to file and console"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        print(log_entry)
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')
    
    def stealth_delay(self):
        """Add random delay for stealth mode"""
        if self.stealth_mode:
            delay = random.uniform(0.5, 3.0)
            time.sleep(delay)
    
    def extract_domain_from_dn(self, dn: str) -> str:
        """Extract domain name from Distinguished Name"""
        parts = re.findall(r'DC=([^,]+)', dn, re.IGNORECASE)
        return '.'.join(parts) if parts else "unknown_domain"
    
    def run_ldapsearch(self, search_filter: str, attributes: List[str] = None, 
                      scope: str = "sub", simple_output: bool = False,
                      page_size: int = 1000) -> Tuple[bool, str]:
        """Execute ldapsearch command with pagination support"""
        # Build base command
        cmd = [
            'ldapsearch',
            '-LLL',  # Use LDIF output format
            '-H', self.ldap_server,
            '-x',  # Use simple authentication
            '-D', self.username,
            '-w', self.password,
            '-b', self.base_dn,
            '-s', scope,
            '-E', f'pr={page_size}/noprompt',  # Enable pagination
            search_filter
        ]
        
        if attributes:
            cmd.extend(attributes)
        
        try:
            self.log(f"Running ldapsearch with filter: {search_filter[:50]}... (pagination: {page_size})")
            
            # Stealth delay
            self.stealth_delay()
            
            # Run command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # Increased timeout for pagination
            )
            
            # Debug output
            if result.stderr:
                stderr_lines = result.stderr.strip().split('\n')
                for line in stderr_lines:
                    if line and 'Size limit exceeded' not in line:  # Filter out size limit warnings
                        self.log(f"ldapsearch stderr: {line}", "DEBUG")
            
            if result.returncode == 0:
                output = result.stdout
                
                if not output.strip():
                    self.log("ldapsearch returned empty output", "WARNING")
                    return False, "Empty output from ldapsearch"
                
                if simple_output:
                    return self.simplify_ldap_output(output)
                
                return True, output
            else:
                error_msg = f"ldapsearch failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr[:200]}"
                self.log(error_msg, "ERROR")
                
                # Try without pagination if pagination fails
                if 'paged' in error_msg.lower() or 'pr=' in error_msg.lower():
                    self.log("Pagination failed, trying without pagination...", "WARNING")
                    return self.run_ldapsearch_without_pagination(search_filter, attributes, scope, simple_output)
                
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            error_msg = "ldapsearch command timed out"
            self.log(error_msg, "ERROR")
            return False, error_msg
        except Exception as e:
            error_msg = f"Error running ldapsearch: {str(e)}"
            self.log(error_msg, "ERROR")
            return False, error_msg
    
    def run_ldapsearch_without_pagination(self, search_filter: str, attributes: List[str] = None, 
                                         scope: str = "sub", simple_output: bool = False) -> Tuple[bool, str]:
        """Execute ldapsearch command without pagination"""
        # Build base command without pagination
        cmd = [
            'ldapsearch',
            '-LLL',  # Use LDIF output format
            '-H', self.ldap_server,
            '-x',  # Use simple authentication
            '-D', self.username,
            '-w', self.password,
            '-b', self.base_dn,
            '-s', scope,
            search_filter
        ]
        
        if attributes:
            cmd.extend(attributes)
        
        try:
            self.log(f"Running ldapsearch without pagination: {search_filter[:50]}...")
            
            # Stealth delay
            self.stealth_delay()
            
            # Run command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                if not output.strip():
                    self.log("ldapsearch returned empty output", "WARNING")
                    return False, "Empty output from ldapsearch"
                
                if simple_output:
                    return self.simplify_ldap_output(output)
                
                return True, output
            else:
                error_msg = f"ldapsearch failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr[:200]}"
                self.log(error_msg, "ERROR")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            error_msg = "ldapsearch command timed out"
            self.log(error_msg, "ERROR")
            return False, error_msg
        except Exception as e:
            error_msg = f"Error running ldapsearch: {str(e)}"
            self.log(error_msg, "ERROR")
            return False, error_msg
    
    def run_ldapsearch_simple(self, search_filter: str, attributes: List[str] = None, 
                             limit: int = 50) -> Tuple[bool, str]:
        """Execute ldapsearch with a result limit"""
        # Build base command with size limit
        cmd = [
            'ldapsearch',
            '-LLL',  # Use LDIF output format
            '-H', self.ldap_server,
            '-x',  # Use simple authentication
            '-D', self.username,
            '-w', self.password,
            '-b', self.base_dn,
            '-z', str(limit),  # Size limit
            search_filter
        ]
        
        if attributes:
            cmd.extend(attributes)
        
        try:
            self.log(f"Running ldapsearch with limit {limit}: {search_filter[:50]}...")
            
            # Stealth delay
            self.stealth_delay()
            
            # Run command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                if not output.strip():
                    self.log("ldapsearch returned empty output", "WARNING")
                    return False, "Empty output from ldapsearch"
                
                return self.simplify_ldap_output(output)
            else:
                error_msg = f"ldapsearch failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr[:200]}"
                self.log(error_msg, "ERROR")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            error_msg = "ldapsearch command timed out"
            self.log(error_msg, "ERROR")
            return False, error_msg
        except Exception as e:
            error_msg = f"Error running ldapsearch: {str(e)}"
            self.log(error_msg, "ERROR")
            return False, error_msg
    
    def test_connection(self) -> bool:
        """Test LDAP connection with a simple query"""
        self.log("Testing LDAP connection...")
        
        # Simple query to test connectivity
        test_filter = "(objectClass=*)"
        success, output = self.run_ldapsearch(test_filter, scope="base", simple_output=False)
        
        if success:
            self.log("LDAP connection test successful!")
            return True
        else:
            self.log(f"LDAP connection test failed: {output}", "ERROR")
            return False
    
    def simplify_ldap_output(self, output: str) -> Tuple[bool, str]:
        """Parse and simplify LDAP output into structured JSON"""
        entries = []
        current_entry = {}
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            if not line:
                if current_entry:
                    entries.append(current_entry)
                    current_entry = {}
                continue
            
            if line.startswith('#'):
                continue
                
            if ': ' in line:
                key, value = line.split(': ', 1)
                
                # Handle multi-valued attributes
                if key in current_entry:
                    if isinstance(current_entry[key], list):
                        current_entry[key].append(value)
                    else:
                        current_entry[key] = [current_entry[key], value]
                else:
                    current_entry[key] = value
        
        if current_entry:
            entries.append(current_entry)
        
        return True, json.dumps(entries, indent=2)
    
    # ==================== NEW FEATURES ====================
    
    def find_asrep_roastable(self):
        """Find AS-REP roastable accounts (DONT_REQ_PREAUTH flag)"""
        self.log("Searching for AS-REP roastable accounts...")
        
        # Accounts that don't require Kerberos pre-authentication
        search_filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        attributes = ["samAccountName", "userPrincipalName", "userAccountControl", "description"]
        
        success, output = self.run_ldapsearch(search_filter, attributes, simple_output=True)
        
        if success:
            try:
                accounts = json.loads(output)
                for account in accounts:
                    sam_account = account.get('samAccountName', [''])[0]
                    upn = account.get('userPrincipalName', [''])[0]
                    description = account.get('description', [''])[0]
                    
                    self.vulnerable_users["asrep_roastable"].append({
                        "username": sam_account,
                        "userPrincipalName": upn,
                        "description": description,
                        "risk": "🔴 CRITICAL",
                        "explanation": "Account doesn't require Kerberos pre-authentication. Can be AS-REP roasted."
                    })
                    
                self.log(f"Found {len(accounts)} AS-REP roastable accounts")
            except:
                self.log("Failed to parse AS-REP roastable accounts", "ERROR")
    
    def find_unconstrained_delegation(self):
        """Find accounts/computers with unconstrained delegation"""
        self.log("Searching for unconstrained delegation...")
        
        # TRUSTED_FOR_DELEGATION flag without NOT_DELEGATED
        search_filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        attributes = ["samAccountName", "servicePrincipalName", "userAccountControl"]
        
        success, output = self.run_ldapsearch(search_filter, attributes, simple_output=True)
        
        if success:
            try:
                accounts = json.loads(output)
                for account in accounts:
                    sam_account = account.get('samAccountName', [''])[0]
                    spns = account.get('servicePrincipalName', [])
                    
                    self.vulnerable_users["unconstrained_delegation"].append({
                        "username": sam_account,
                        "spns": spns,
                        "risk": "🔴 CRITICAL",
                        "explanation": "Account has unconstrained delegation. Can impersonate any user to any service."
                    })
                    
                self.log(f"Found {len(accounts)} accounts with unconstrained delegation")
            except:
                self.log("Failed to parse unconstrained delegation accounts", "ERROR")
        
        # Also check computers
        search_filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        success, output = self.run_ldapsearch(search_filter, ["dNSHostName", "userAccountControl"], simple_output=True)
        
        if success:
            try:
                computers = json.loads(output)
                for computer in computers:
                    hostname = computer.get('dNSHostName', [''])[0]
                    self.vulnerable_users["unconstrained_delegation"].append({
                        "hostname": hostname,
                        "type": "computer",
                        "risk": "🔴 CRITICAL",
                        "explanation": "Computer has unconstrained delegation. Can be used for delegation attacks."
                    })
                self.log(f"Found {len(computers)} computers with unconstrained delegation")
            except:
                pass
    
    def find_constrained_delegation(self):
        """Find accounts with constrained delegation"""
        self.log("Searching for constrained delegation...")
        
        # msDS-AllowedToDelegateTo attribute
        search_filter = "(msDS-AllowedToDelegateTo=*)"
        attributes = ["samAccountName", "msDS-AllowedToDelegateTo", "userAccountControl"]
        
        success, output = self.run_ldapsearch(search_filter, attributes, simple_output=True)
        
        if success:
            try:
                accounts = json.loads(output)
                for account in accounts:
                    sam_account = account.get('samAccountName', [''])[0]
                    allowed_to_delegate = account.get('msDS-AllowedToDelegateTo', [])
                    
                    self.vulnerable_users["constrained_delegation"].append({
                        "username": sam_account,
                        "allowed_services": allowed_to_delegate,
                        "risk": "🟠 HIGH",
                        "explanation": "Account has constrained delegation. Can delegate to specific services."
                    })
                    
                self.log(f"Found {len(accounts)} accounts with constrained delegation")
            except:
                self.log("Failed to parse constrained delegation accounts", "ERROR")
    
    def find_resource_based_delegation(self):
        """Find Resource-Based Constrained Delegation"""
        self.log("Searching for Resource-Based Constrained Delegation...")
        
        # msDS-AllowedToActOnBehalfOfOtherIdentity
        search_filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
        attributes = ["samAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"]
        
        success, output = self.run_ldapsearch(search_filter, attributes, simple_output=True)
        
        if success:
            try:
                accounts = json.loads(output)
                for account in accounts:
                    sam_account = account.get('samAccountName', [''])[0]
                    
                    self.vulnerable_users["resource_based_delegation"].append({
                        "username": sam_account,
                        "risk": "🟠 HIGH",
                        "explanation": "Account has Resource-Based Constrained Delegation configured."
                    })
                    
                self.log(f"Found {len(accounts)} accounts with RBCD")
            except:
                self.log("Failed to parse RBCD accounts", "ERROR")
    
    def scan_gpp_passwords(self):
        """Scan for Group Policy Preferences passwords"""
        self.log("Scanning for Group Policy Preferences passwords...")
        
        # This would typically require access to SYSVOL share
        # For now, we'll search for GPP-related attributes in LDAP
        search_filter = "(objectClass=groupPolicyContainer)"
        attributes = ["displayName", "gPCFileSysPath", "versionNumber"]
        
        success, output = self.run_ldapsearch(search_filter, attributes, simple_output=True)
        
        if success:
            try:
                gpos = json.loads(output)
                self.gpp_data = gpos
                
                self.log(f"Found {len(gpos)} Group Policy Objects")
                self.log("Note: GPP password extraction requires SYSVOL access")
                self.log("Use tools like Get-GPPPassword on Windows or gpp-decrypt on Linux")
                
            except:
                self.log("Failed to parse GPO data", "ERROR")
    
    def test_password_spray(self, usernames: List[str] = None, passwords: List[str] = None):
        """Test password spray against accounts"""
        self.log("Testing password spray (simulation mode)...")
        
        if not usernames:
            # Get some user accounts to test
            search_filter = "(objectClass=user)"
            success, output = self.run_ldapsearch_simple(search_filter, ["samAccountName"], limit=10)
            if success:
                try:
                    users = json.loads(output)
                    usernames = [u.get('samAccountName', [''])[0] for u in users]
                except:
                    usernames = []
        
        if not passwords:
            passwords = self.COMMON_PASSWORDS
        
        if not usernames:
            self.log("No usernames available for password spray test", "WARNING")
            return
        
        self.log(f"Password spray simulation against {len(usernames)} users with {len(passwords)} common passwords")
        self.log("WARNING: Actual password spraying can lock out accounts!")
        self.log("This is a simulation showing vulnerable accounts based on common weak passwords")
        
        # Simulate finding accounts with common weak password indicators
        for user in self.users_data:
            sam_account = user.get('samAccountName', [''])[0]
            description = user.get('description', [''])[0].lower()
            
            # Check if description contains password hints
            password_hints = []
            for pwd in passwords[:5]:  # Check first 5 common passwords
                if pwd.lower() in description:
                    password_hints.append(pwd)
            
            if password_hints:
                self.log(f"User {sam_account} has password hints in description: {', '.join(password_hints)}", "WARNING")
    
    def enumerate_trusts(self):
        """Enumerate domain trusts"""
        self.log("Enumerating domain trusts...")
        
        search_filter = "(objectClass=trustedDomain)"
        attributes = ["trustPartner", "trustDirection", "trustType", "trustAttributes"]
        
        success, output = self.run_ldapsearch(search_filter, attributes, simple_output=True)
        
        if success:
            try:
                self.trusts_data = json.loads(output)
                
                for trust in self.trusts_data:
                    partner = trust.get('trustPartner', [''])[0]
                    direction = trust.get('trustDirection', ['0'])[0]
                    
                    # Convert direction to readable format
                    direction_map = {
                        "0": "Disabled",
                        "1": "Inbound",
                        "2": "Outbound",
                        "3": "Bidirectional"
                    }
                    
                    self.log(f"Trust found: {partner} ({direction_map.get(direction, direction)})")
                    
            except:
                self.log("Failed to parse trust data", "ERROR")
    
    def generate_bloodhound_data(self):
        """Generate BloodHound-compatible JSON data"""
        self.log("Generating BloodHound-compatible data...")
        
        bloodhound_data = {
            "meta": {
                "count": len(self.users_data) + len(self.groups_data) + len(self.computers_data),
                "type": "ADJanitorExport",
                "version": 4
            },
            "data": []
        }
        
        # Add users
        for user in self.users_data:
            sam_account = user.get('samAccountName', [''])[0]
            if sam_account.endswith('$'):
                continue  # Skip computer accounts
                
            user_entry = {
                "Properties": {
                    "samaccountname": sam_account,
                    "domain": self.domain,
                    "enabled": not (int(user.get('userAccountControl', ['0'])[0]) & 0x2),
                    "pwdneverexpires": bool(int(user.get('userAccountControl', ['0'])[0]) & 0x10000),
                    "passwordnotrequired": bool(int(user.get('userAccountControl', ['0'])[0]) & 0x20),
                    "admincount": user.get('adminCount', ['0'])[0] == '1'
                },
                "ObjectIdentifier": f"{self.domain.upper()}\\{sam_account.upper()}",
                "ObjectType": "User",
                "Aces": []
            }
            bloodhound_data["data"].append(user_entry)
        
        # Add groups
        for group in self.groups_data:
            group_name = group.get('samAccountName', [''])[0]
            group_entry = {
                "Properties": {
                    "samaccountname": group_name,
                    "domain": self.domain
                },
                "ObjectIdentifier": f"{self.domain.upper()}\\{group_name.upper()}",
                "ObjectType": "Group",
                "Members": self.group_membership.get(group_name, []),
                "Aces": []
            }
            bloodhound_data["data"].append(group_entry)
        
        # Save BloodHound data
        filename = os.path.join(self.output_dir, f"bloodhound_{self.domain}.json")
        with open(filename, 'w') as f:
            json.dump(bloodhound_data, f, indent=2)
        
        self.log(f"BloodHound data saved to: {filename}")
        self.log("Import this file into BloodHound for visualization")
        
        return filename
    
    def analyze_laps(self):
        """Check LAPS (Local Administrator Password Solution) implementation"""
        self.log("Analyzing LAPS implementation...")
        
        # Check for ms-Mcs-AdmPwd attribute on computers
        search_filter = "(ms-Mcs-AdmPwd=*)"
        attributes = ["dNSHostName", "ms-Mcs-AdmPwdExpirationTime"]
        
        success, output = self.run_ldapsearch(search_filter, attributes, simple_output=True)
        
        laps_computers = []
        if success:
            try:
                computers = json.loads(output)
                laps_computers = computers
                self.log(f"Found {len(computers)} computers with LAPS passwords")
            except:
                pass
        
        # Check which groups can read LAPS passwords
        # This is a simplified check - real implementation would require ACL analysis
        self.log("LAPS Analysis:")
        self.log(f"  - Computers with LAPS: {len(laps_computers)}")
        
        if laps_computers:
            self.log("  ✓ LAPS appears to be implemented")
        else:
            self.log("  ✗ LAPS may not be implemented or no computers have passwords set")
    
    def find_privilege_escalation_paths(self):
        """Identify potential privilege escalation paths"""
        self.log("Analyzing privilege escalation paths...")
        
        escalation_paths = []
        
        # Check for users in privileged groups
        for username, groups in self.user_groups.items():
            privileged_groups_in = [g for g in groups if g in self.PRIVILEGED_GROUPS]
            if privileged_groups_in:
                escalation_paths.append({
                    "user": username,
                    "path": f"Already in privileged groups: {', '.join(privileged_groups_in)}",
                    "risk": "🔴 CRITICAL"
                })
        
        # Check for nested group memberships that could lead to privilege escalation
        # This is a simplified version - real analysis would need full group nesting analysis
        
        # Save escalation paths
        if escalation_paths:
            filename = os.path.join(self.output_dir, f"privilege_escalation_{self.domain}.txt")
            with open(filename, 'w') as f:
                f.write("PRIVILEGE ESCALATION PATHS ANALYSIS\n")
                f.write("=" * 60 + "\n\n")
                
                for path in escalation_paths:
                    f.write(f"User: {path['user']}\n")
                    f.write(f"Risk: {path['risk']}\n")
                    f.write(f"Path: {path['path']}\n")
                    f.write("-" * 40 + "\n\n")
            
            self.log(f"Privilege escalation analysis saved to: {filename}")
        
        return escalation_paths
    
    def generate_risk_score(self):
        """Calculate overall domain risk score"""
        self.log("Calculating domain risk score...")
        
        risk_weights = {
            "asrep_roastable": 10,
            "unconstrained_delegation": 9,
            "reversible_encryption": 8,
            "plaintext_passwords": 8,
            "kerberoastable": 7,
            "password_not_required": 6,
            "constrained_delegation": 5,
            "password_never_expires": 4,
            "admin_count_set": 3,
            "inactive_accounts": 2
        }
        
        total_score = 0
        max_possible_score = sum(risk_weights.values()) * 10  # Assuming max 10 findings per category
        
        for category, weight in risk_weights.items():
            count = len(self.vulnerable_users.get(category, []))
            category_score = min(count, 10) * weight  # Cap at 10 findings per category
            total_score += category_score
        
        # Normalize to 0-100 scale
        risk_score = (total_score / max_possible_score) * 100 if max_possible_score > 0 else 0
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "🔴 CRITICAL"
        elif risk_score >= 40:
            risk_level = "🟠 HIGH"
        elif risk_score >= 20:
            risk_level = "🟡 MEDIUM"
        else:
            risk_level = "🟢 LOW"
        
        risk_assessment = {
            "score": round(risk_score, 1),
            "level": risk_level,
            "total_findings": sum(len(v) for v in self.vulnerable_users.values())
        }
        
        return risk_assessment
    
    # ==================== END NEW FEATURES ====================
    
    def enumerate_users(self, detailed: bool = True, limit: int = None) -> Dict:
        """Enumerate all users with detailed analysis"""
        self.log("Starting comprehensive user enumeration")
        
        # Test connection first
        if not self.test_connection():
            return {"error": "LDAP connection failed", "users": []}
        
        # Comprehensive list of user attributes
        attributes = [
            "samAccountName", "displayName", "mail", "memberOf", 
            "userAccountControl", "lastLogon", "lastLogonTimestamp",
            "pwdLastSet", "description", "whenCreated", "whenChanged",
            "userPrincipalName", "primaryGroupID", "accountExpires",
            "logonCount", "badPwdCount", "badPasswordTime",
            "lastLogoff", "homeDirectory", "scriptPath",
            "profilePath", "userWorkstations", "department",
            "title", "company", "manager", "telephoneNumber",
            "homePhone", "mobile", "facsimileTelephoneNumber",
            "streetAddress", "postOfficeBox", "city", "state",
            "postalCode", "country", "wWWHomePage", "adminCount",
            "servicePrincipalName", "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity"
        ]
        
        search_filter = "(&(objectClass=user)(objectCategory=person))"
        
        # Try different approaches
        approaches = [
            ("pagination", lambda: self.run_ldapsearch(search_filter, attributes, simple_output=True, page_size=500)),
            ("no_pagination", lambda: self.run_ldapsearch_without_pagination(search_filter, attributes, simple_output=True)),
            ("limited", lambda: self.run_ldapsearch_simple(search_filter, attributes, limit=limit or 1000))
        ]
        
        success = False
        output = ""
        
        for approach_name, approach_func in approaches:
            self.log(f"Trying user enumeration with {approach_name}...")
            success, output = approach_func()
            if success:
                self.log(f"User enumeration successful with {approach_name}")
                break
        
        if success:
            try:
                self.users_data = json.loads(output)
                
                # Analyze each user for vulnerabilities
                self.analyze_user_vulnerabilities()
                
                # Build user-group relationships
                self.build_group_memberships()
                
                # Run new vulnerability checks
                self.find_asrep_roastable()
                self.find_unconstrained_delegation()
                self.find_constrained_delegation()
                self.find_resource_based_delegation()
                
                # Save detailed user data
                filename = os.path.join(self.output_dir, f"users_detailed_{self.domain}.json")
                with open(filename, 'w') as f:
                    json.dump(self.users_data, f, indent=2)
                
                # Generate CSV report
                csv_filename = os.path.join(self.output_dir, f"users_summary_{self.domain}.csv")
                self.generate_user_csv(csv_filename)
                
                self.log(f"User enumeration completed. Found {len(self.users_data)} users")
                self.log(f"Detailed JSON: {filename}")
                self.log(f"Summary CSV: {csv_filename}")
                
                return {
                    "total": len(self.users_data),
                    "vulnerable_count": self.count_vulnerable_users(),
                    "files": {
                        "detailed": filename,
                        "csv": csv_filename
                    }
                }
                
            except json.JSONDecodeError as e:
                self.log(f"Failed to parse user data: {e}", "ERROR")
                # Try to save raw output for debugging
                debug_file = os.path.join(self.output_dir, f"users_raw_{self.domain}.txt")
                with open(debug_file, 'w') as f:
                    f.write(output)
                self.log(f"Raw output saved to: {debug_file}")
                return {"error": "Failed to parse user data", "raw_file": debug_file}
        
        return {"error": "Failed to enumerate users", "users": []}
    
    def analyze_user_vulnerabilities(self):
        """Analyze users for common AD vulnerabilities"""
        if not self.users_data:
            self.log("No user data to analyze", "WARNING")
            return
        
        self.log("Analyzing users for vulnerabilities")
        
        for user in self.users_data:
            sam_account = user.get('samAccountName', [''])[0]
            dn = user.get('dn', '')
            
            # Skip computer accounts
            if sam_account.endswith('$'):
                continue
            
            # Get userAccountControl value
            uac_str = user.get('userAccountControl', ['0'])[0]
            try:
                uac = int(uac_str)
            except ValueError:
                uac = 0
            
            # Check for common vulnerabilities
            
            # Password never expires
            if uac & self.VULNERABILITY_FLAGS["PASSWD_NEVER_EXPIRES"]:
                self.vulnerable_users["password_never_expires"].append({
                    "username": sam_account,
                    "dn": dn,
                    "uac_value": uac
                })
            
            # Password not required
            if uac & self.VULNERABILITY_FLAGS["PASSWD_NOTREQD"]:
                self.vulnerable_users["password_not_required"].append({
                    "username": sam_account,
                    "dn": dn,
                    "uac_value": uac
                })
            
            # Reversible encryption enabled
            if uac & self.VULNERABILITY_FLAGS["ENCRYPTED_TEXT_PWD_ALLOWED"]:
                self.vulnerable_users["reversible_encryption"].append({
                    "username": sam_account,
                    "dn": dn,
                    "uac_value": uac
                })
            
            # Admin count set
            if user.get('adminCount', ['0'])[0] == '1':
                self.vulnerable_users["admin_count_set"].append({
                    "username": sam_account,
                    "dn": dn
                })
            
            # Check for Service Principal Names (Kerberoastable)
            spn = user.get('servicePrincipalName', [])
            if spn and len(spn) > 0:
                self.vulnerable_users["kerberoastable"].append({
                    "username": sam_account,
                    "dn": dn,
                    "spns": spn
                })
            
            # Check for description containing password (common misconfiguration)
            description = user.get('description', [''])[0].lower()
            password_indicators = ['password', 'pwd', 'pass', 'welcome', 'changeme']
            if any(indicator in description for indicator in password_indicators):
                self.vulnerable_users["plaintext_passwords"].append({
                    "username": sam_account,
                    "dn": dn,
                    "description": user.get('description', [''])[0]
                })
            
            # Check for inactive accounts (no login in 90 days)
            last_logon = user.get('lastLogonTimestamp', ['0'])[0]
            if last_logon != '0':
                try:
                    # Convert Windows NT time to datetime
                    last_logon_dt = self.convert_windows_time(int(last_logon))
                    if (datetime.now() - last_logon_dt).days > 90:
                        self.vulnerable_users["inactive_accounts"].append({
                            "username": sam_account,
                            "dn": dn,
                            "last_logon": last_logon_dt.strftime('%Y-%m-%d'),
                            "days_inactive": (datetime.now() - last_logon_dt).days
                        })
                except:
                    pass
            
            # Check for service accounts (common naming patterns)
            service_patterns = ['svc_', '_svc', 'service', 'app_', 'sql', 'iis', 'websvc']
            if any(pattern in sam_account.lower() for pattern in service_patterns):
                self.vulnerable_users["service_accounts"].append({
                    "username": sam_account,
                    "dn": dn,
                    "description": user.get('description', [''])[0]
                })
    
    def convert_windows_time(self, windows_time: int) -> datetime:
        """Convert Windows NT time (100-nanosecond intervals since 1601) to datetime"""
        if windows_time == 0:
            return datetime.min
        
        # Windows NT time is in 100-nanosecond intervals since 1601-01-01
        # Convert to seconds since 1601
        seconds_since_1601 = windows_time / 10000000
        
        # Seconds between 1601-01-01 and 1970-01-01
        seconds_1601_to_1970 = 11644473600
        
        # Convert to Unix timestamp
        unix_timestamp = seconds_since_1601 - seconds_1601_to_1970
        
        return datetime.fromtimestamp(unix_timestamp)
    
    def count_vulnerable_users(self) -> int:
        """Count total number of vulnerable users across all categories"""
        if not self.users_data:
            return 0
            
        total = 0
        for category, users in self.vulnerable_users.items():
            total += len(users)
        return total
    
    def enumerate_groups(self, limit: int = None) -> Dict:
        """Enumerate all groups with detailed membership"""
        self.log("Starting group enumeration with membership analysis")
        
        attributes = [
            "samAccountName", "name", "description", "member", 
            "memberOf", "groupType", "whenCreated", "whenChanged",
            "managedBy", "info", "mail", "adminCount"
        ]
        
        search_filter = "(objectClass=group)"
        
        # Try different approaches
        approaches = [
            ("pagination", lambda: self.run_ldapsearch(search_filter, attributes, simple_output=True, page_size=500)),
            ("no_pagination", lambda: self.run_ldapsearch_without_pagination(search_filter, attributes, simple_output=True)),
            ("limited", lambda: self.run_ldapsearch_simple(search_filter, attributes, limit=limit or 1000))
        ]
        
        success = False
        output = ""
        
        for approach_name, approach_func in approaches:
            self.log(f"Trying group enumeration with {approach_name}...")
            success, output = approach_func()
            if success:
                self.log(f"Group enumeration successful with {approach_name}")
                break
        
        if success:
            try:
                self.groups_data = json.loads(output)
                
                # Process group membership
                self.process_group_membership()
                
                filename = os.path.join(self.output_dir, f"groups_detailed_{self.domain}.json")
                with open(filename, 'w') as f:
                    json.dump(self.groups_data, f, indent=2)
                
                # Generate group membership matrix if we have users
                if self.users_data:
                    matrix_file = os.path.join(self.output_dir, f"group_membership_matrix_{self.domain}.csv")
                    self.generate_membership_matrix(matrix_file)
                    
                    # Generate privileged group report
                    priv_file = os.path.join(self.output_dir, f"privileged_groups_{self.domain}.txt")
                    self.generate_privileged_group_report(priv_file)
                
                self.log(f"Group enumeration completed. Found {len(self.groups_data)} groups")
                
                return {
                    "total": len(self.groups_data),
                    "privileged_count": len(self.identify_privileged_groups()),
                    "files": {
                        "detailed": filename,
                        "matrix": matrix_file if self.users_data else None,
                        "privileged": priv_file if self.users_data else None
                    }
                }
                
            except json.JSONDecodeError as e:
                self.log(f"Failed to parse group data: {e}", "ERROR")
                return {"error": "Failed to parse group data", "groups": []}
        
        return {"error": "Failed to enumerate groups", "groups": []}
    
    def process_group_membership(self):
        """Process group membership from group data"""
        if not self.groups_data:
            return
            
        for group in self.groups_data:
            group_name = group.get('samAccountName', [''])[0]
            members = group.get('member', [])
            
            if isinstance(members, str):
                members = [members]
            
            for member_dn in members:
                # Extract username from DN
                username = self.extract_username_from_dn(member_dn)
                if username:
                    self.group_membership[group_name].append(username)
                    self.user_groups[username].append(group_name)
    
    def extract_username_from_dn(self, dn: str) -> str:
        """Extract username from Distinguished Name"""
        # Look for CN=username in DN
        match = re.search(r'CN=([^,]+)', dn, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Look for samAccountName in DN
        match = re.search(r'sAMAccountName=([^,]+)', dn, re.IGNORECASE)
        if match:
            return match.group(1)
        
        return ""
    
    def build_group_memberships(self):
        """Build user-group relationships from user data"""
        if not self.users_data:
            return
            
        for user in self.users_data:
            username = user.get('samAccountName', [''])[0]
            member_of = user.get('memberOf', [])
            
            if isinstance(member_of, str):
                member_of = [member_of]
            
            for group_dn in member_of:
                group_name = self.extract_groupname_from_dn(group_dn)
                if group_name:
                    self.user_groups[username].append(group_name)
                    self.group_membership[group_name].append(username)
    
    def extract_groupname_from_dn(self, dn: str) -> str:
        """Extract group name from Distinguished Name"""
        match = re.search(r'CN=([^,]+)', dn, re.IGNORECASE)
        if match:
            return match.group(1)
        return ""
    
    def identify_privileged_groups(self) -> List[Dict]:
        """Identify and analyze privileged groups"""
        if not self.groups_data:
            return []
            
        privileged_groups = []
        
        for group in self.groups_data:
            group_name = group.get('samAccountName', [''])[0]
            
            # Check if group is in privileged list
            if group_name in self.PRIVILEGED_GROUPS:
                members = self.group_membership.get(group_name, [])
                privileged_groups.append({
                    "name": group_name,
                    "description": group.get('description', [''])[0],
                    "member_count": len(members),
                    "members": members[:10],  # First 10 members for report
                    "total_members": len(members),
                    "managed_by": group.get('managedBy', [''])[0]
                })
        
        return privileged_groups
    
    def generate_user_csv(self, filename: str):
        """Generate CSV report for users"""
        if not self.users_data:
            self.log("No user data to generate CSV", "WARNING")
            return
            
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = [
                'Username', 'Display Name', 'Email', 'Description',
                'Account Disabled', 'Password Never Expires', 
                'Password Not Required', 'Reversible Encryption',
                'Admin Count', 'Last Logon', 'Member Of', 'SPNs',
                'Groups Count', 'Group Names', 'AS-REP Roastable',
                'Unconstrained Delegation', 'Constrained Delegation'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for user in self.users_data:
                username = user.get('samAccountName', [''])[0]
                
                # Skip computer accounts
                if username.endswith('$'):
                    continue
                
                # Get userAccountControl flags
                uac_str = user.get('userAccountControl', ['0'])[0]
                try:
                    uac = int(uac_str)
                except:
                    uac = 0
                
                # Get groups for this user
                user_groups = self.user_groups.get(username, [])
                
                # Check for new vulnerability flags
                asrep_roastable = 'Yes' if uac & self.VULNERABILITY_FLAGS["DONT_REQ_PREAUTH"] else 'No'
                unconstrained_delegation = 'Yes' if uac & self.VULNERABILITY_FLAGS["TRUSTED_FOR_DELEGATION"] else 'No'
                constrained_delegation = 'Yes' if user.get('msDS-AllowedToDelegateTo', []) else 'No'
                
                writer.writerow({
                    'Username': username,
                    'Display Name': user.get('displayName', [''])[0],
                    'Email': user.get('mail', [''])[0],
                    'Description': user.get('description', [''])[0],
                    'Account Disabled': 'Yes' if uac & self.VULNERABILITY_FLAGS["ACCOUNTDISABLE"] else 'No',
                    'Password Never Expires': 'Yes' if uac & self.VULNERABILITY_FLAGS["PASSWD_NEVER_EXPIRES"] else 'No',
                    'Password Not Required': 'Yes' if uac & self.VULNERABILITY_FLAGS["PASSWD_NOTREQD"] else 'No',
                    'Reversible Encryption': 'Yes' if uac & self.VULNERABILITY_FLAGS["ENCRYPTED_TEXT_PWD_ALLOWED"] else 'No',
                    'Admin Count': user.get('adminCount', ['0'])[0],
                    'Last Logon': user.get('lastLogonTimestamp', [''])[0],
                    'Member Of': '; '.join(user.get('memberOf', [])),
                    'SPNs': '; '.join(user.get('servicePrincipalName', [])),
                    'Groups Count': len(user_groups),
                    'Group Names': '; '.join(user_groups[:10]),  # First 10 groups
                    'AS-REP Roastable': asrep_roastable,
                    'Unconstrained Delegation': unconstrained_delegation,
                    'Constrained Delegation': constrained_delegation
                })
    
    def generate_membership_matrix(self, filename: str):
        """Generate group membership matrix (users x groups)"""
        if not self.user_groups or not self.group_membership:
            self.log("No group membership data for matrix", "WARNING")
            return
            
        # Get all users and groups
        all_users = list(self.user_groups.keys())
        all_groups = list(self.group_membership.keys())
        
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            header = ['Username'] + all_groups
            writer.writerow(header)
            
            # Write rows
            for user in all_users:
                row = [user]
                for group in all_groups:
                    if user in self.group_membership.get(group, []):
                        row.append('X')
                    else:
                        row.append('')
                writer.writerow(row)
    
    def generate_privileged_group_report(self, filename: str):
        """Generate detailed report for privileged groups"""
        privileged_groups = self.identify_privileged_groups()
        
        if not privileged_groups:
            self.log("No privileged groups found", "INFO")
            return
            
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("PRIVILEGED GROUP ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Domain: {self.domain}\n")
            f.write(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Privileged Groups Found: {len(privileged_groups)}\n\n")
            
            for i, group in enumerate(privileged_groups, 1):
                f.write(f"{i}. {group['name']}\n")
                f.write(f"   Description: {group['description']}\n")
                f.write(f"   Managed By: {group['managed_by']}\n")
                f.write(f"   Total Members: {group['total_members']}\n")
                
                if group['members']:
                    f.write(f"   Members (first 10):\n")
                    for member in group['members']:
                        f.write(f"     - {member}\n")
                else:
                    f.write(f"   Members: None\n")
                
                f.write("\n")
            
            # Summary statistics
            f.write("=" * 80 + "\n")
            f.write("SUMMARY STATISTICS\n")
            f.write("=" * 80 + "\n\n")
            
            # Count members in each privileged group
            member_counts = {}
            for group in privileged_groups:
                member_counts[group['name']] = group['total_members']
            
            # Sort by member count
            sorted_counts = sorted(member_counts.items(), key=lambda x: x[1], reverse=True)
            
            f.write("Privileged Groups by Member Count:\n")
            for group_name, count in sorted_counts:
                f.write(f"  {group_name}: {count} members\n")
    
    def generate_vulnerability_report(self) -> Dict:
        """Generate comprehensive vulnerability report"""
        if not self.users_data:
            self.log("No user data for vulnerability report", "WARNING")
            return {
                "report_file": None,
                "csv_file": None,
                "total_vulnerabilities": 0,
                "unique_vulnerable_users": 0
            }
            
        self.log("Generating vulnerability assessment report")
        
        report_file = os.path.join(self.output_dir, f"vulnerability_report_{self.domain}.txt")
        csv_file = os.path.join(self.output_dir, f"vulnerability_summary_{self.domain}.csv")
        
        with open(report_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("ACTIVE DIRECTORY VULNERABILITY ASSESSMENT REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Domain: {self.domain}\n")
            f.write(f"Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Users Analyzed: {len(self.users_data)}\n\n")
            
            f.write("-" * 80 + "\n")
            f.write("VULNERABILITY CATEGORIES AND COUNTS\n")
            f.write("-" * 80 + "\n\n")
            
            total_vulnerabilities = 0
            
            # Define risk levels for each category
            risk_levels = {
                'asrep_roastable': '🔴 CRITICAL',
                'unconstrained_delegation': '🔴 CRITICAL',
                'reversible_encryption': '🔴 CRITICAL',
                'plaintext_passwords': '🔴 CRITICAL',
                'kerberoastable': '🟠 HIGH',
                'password_not_required': '🟠 HIGH',
                'constrained_delegation': '🟠 HIGH',
                'resource_based_delegation': '🟠 HIGH',
                'password_never_expires': '🟡 MEDIUM',
                'admin_count_set': '🟡 MEDIUM',
                'service_accounts': '🟡 MEDIUM',
                'inactive_accounts': '🔵 LOW'
            }
            
            for category, users in self.vulnerable_users.items():
                count = len(users)
                total_vulnerabilities += count
                
                risk = risk_levels.get(category, '⚪ UNKNOWN')
                
                f.write(f"{category.upper().replace('_', ' ')}:\n")
                f.write(f"  Risk Level: {risk}\n")
                f.write(f"  Count: {count}\n")
                if self.users_data:
                    f.write(f"  Percentage of Users: {count/len(self.users_data)*100:.1f}%\n")
                else:
                    f.write(f"  Percentage of Users: N/A\n")
                
                if users:
                    f.write(f"  Affected Accounts (first 5):\n")
                    for user in users[:5]:
                        username = user.get('username', user.get('hostname', 'Unknown'))
                        f.write(f"    - {username}\n")
                        if 'explanation' in user:
                            f.write(f"      Reason: {user['explanation']}\n")
                    if count > 5:
                        f.write(f"    ... and {count-5} more\n")
                f.write("\n")
            
            f.write("-" * 80 + "\n")
            f.write(f"TOTAL VULNERABILITIES IDENTIFIED: {total_vulnerabilities}\n")
            f.write(f"USERS WITH AT LEAST ONE VULNERABILITY: {self.count_unique_vulnerable_users()}\n")
            f.write("-" * 80 + "\n\n")
            
            # Detailed vulnerability breakdown
            f.write("DETAILED VULNERABILITY ANALYSIS\n")
            f.write("-" * 80 + "\n\n")
            
            for category, users in self.vulnerable_users.items():
                if users:
                    f.write(f"\n{category.upper().replace('_', ' ')}:\n")
                    f.write("-" * 40 + "\n")
                    
                    for user in users:
                        username = user.get('username', user.get('hostname', 'Unknown'))
                        dn = user.get('dn', '')
                        
                        f.write(f"  Account: {username}\n")
                        if dn:
                            f.write(f"  DN: {dn}\n")
                        
                        if 'uac_value' in user:
                            f.write(f"  UAC Value: {user['uac_value']}\n")
                        
                        if 'spns' in user:
                            f.write(f"  SPNs: {', '.join(user['spns'][:3])}")
                            if len(user['spns']) > 3:
                                f.write(f" ... and {len(user['spns'])-3} more")
                            f.write("\n")
                        
                        if 'description' in user:
                            f.write(f"  Description: {user['description'][:100]}...\n")
                        
                        if 'last_logon' in user:
                            f.write(f"  Last Logon: {user['last_logon']} ({user['days_inactive']} days ago)\n")
                        
                        if 'explanation' in user:
                            f.write(f"  Explanation: {user['explanation']}\n")
                        
                        if 'allowed_services' in user:
                            f.write(f"  Allowed Services: {', '.join(user['allowed_services'][:3])}")
                            if len(user['allowed_services']) > 3:
                                f.write(f" ... and {len(user['allowed_services'])-3} more")
                            f.write("\n")
                        
                        f.write("\n")
        
        # Generate CSV summary
        with open(csv_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Vulnerability Category', 'Count', 'Percentage', 'Risk Level', 'Description'])
            
            category_descriptions = {
                'password_never_expires': 'Accounts with non-expiring passwords',
                'password_not_required': 'Accounts that dont require passwords',
                'reversible_encryption': 'Accounts with reversible encryption enabled',
                'admin_count_set': 'Accounts with adminCount=1 attribute',
                'kerberoastable': 'Service accounts with SPNs (Kerberoastable)',
                'plaintext_passwords': 'Passwords found in description fields',
                'inactive_accounts': 'Accounts inactive for 90+ days',
                'service_accounts': 'Potential service accounts',
                'asrep_roastable': 'Accounts that dont require Kerberos pre-auth',
                'unconstrained_delegation': 'Accounts with unconstrained delegation',
                'constrained_delegation': 'Accounts with constrained delegation',
                'resource_based_delegation': 'Resource-Based Constrained Delegation'
            }
            
            for category, users in self.vulnerable_users.items():
                count = len(users)
                percentage = (count / len(self.users_data)) * 100 if self.users_data else 0
                risk = risk_levels.get(category, 'Unknown')
                description = category_descriptions.get(category, '')
                
                writer.writerow([
                    category.replace('_', ' ').title(),
                    count,
                    f"{percentage:.1f}%",
                    risk,
                    description
                ])
        
        self.log(f"Vulnerability report generated: {report_file}")
        self.log(f"CSV summary: {csv_file}")
        
        return {
            "report_file": report_file,
            "csv_file": csv_file,
            "total_vulnerabilities": total_vulnerabilities,
            "unique_vulnerable_users": self.count_unique_vulnerable_users()
        }
    
    def count_unique_vulnerable_users(self) -> int:
        """Count unique users with at least one vulnerability"""
        vulnerable_users = set()
        
        for category, users in self.vulnerable_users.items():
            for user in users:
                username = user.get('username', '')
                if username:
                    vulnerable_users.add(username)
        
        return len(vulnerable_users)
    
    def generate_group_membership_report(self) -> Dict:
        """Generate detailed group membership report"""
        if not self.user_groups:
            self.log("No group membership data for report", "WARNING")
            return {
                "report_file": None,
                "total_groups": 0,
                "total_users_with_groups": 0
            }
            
        self.log("Generating group membership analysis report")
        
        report_file = os.path.join(self.output_dir, f"group_analysis_{self.domain}.txt")
        
        with open(report_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("GROUP MEMBERSHIP ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Domain: {self.domain}\n")
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Groups: {len(self.group_membership)}\n")
            f.write(f"Total Users with Group Memberships: {len(self.user_groups)}\n\n")
            
            f.write("-" * 80 + "\n")
            f.write("TOP 20 GROUPS BY MEMBER COUNT\n")
            f.write("-" * 80 + "\n\n")
            
            # Sort groups by member count
            sorted_groups = sorted(
                self.group_membership.items(),
                key=lambda x: len(x[1]),
                reverse=True
            )
            
            for i, (group_name, members) in enumerate(sorted_groups[:20], 1):
                f.write(f"{i:2}. {group_name}: {len(members)} members\n")
                
                # Show first 5 members if any
                if members:
                    f.write(f"    Members (first 5): {', '.join(members[:5])}")
                    if len(members) > 5:
                        f.write(f" ... and {len(members)-5} more")
                    f.write("\n")
                f.write("\n")
            
            f.write("-" * 80 + "\n")
            f.write("USERS IN MULTIPLE PRIVILEGED GROUPS\n")
            f.write("-" * 80 + "\n\n")
            
            # Find users in multiple privileged groups
            users_in_privileged = {}
            
            for username, groups in self.user_groups.items():
                privileged_count = sum(1 for g in groups if g in self.PRIVILEGED_GROUPS)
                if privileged_count >= 2:  # Users in 2 or more privileged groups
                    users_in_privileged[username] = {
                        'count': privileged_count,
                        'groups': [g for g in groups if g in self.PRIVILEGED_GROUPS]
                    }
            
            if users_in_privileged:
                sorted_users = sorted(
                    users_in_privileged.items(),
                    key=lambda x: x[1]['count'],
                    reverse=True
                )
                
                for username, data in sorted_users:
                    f.write(f"User: {username}\n")
                    f.write(f"  Privileged Groups: {data['count']}\n")
                    f.write(f"  Groups: {', '.join(data['groups'])}\n\n")
            else:
                f.write("No users found in multiple privileged groups.\n\n")
            
            f.write("-" * 80 + "\n")
            f.write("GROUP NESTING ANALYSIS\n")
            f.write("-" * 80 + "\n\n")
            
            # Check for group nesting (groups that are members of other groups)
            nested_groups = []
            for group in self.groups_data:
                group_name = group.get('samAccountName', [''])[0]
                member_of = group.get('memberOf', [])
                
                if member_of:
                    if isinstance(member_of, str):
                        member_of = [member_of]
                    
                    parent_groups = [self.extract_groupname_from_dn(dn) for dn in member_of]
                    nested_groups.append({
                        'group': group_name,
                        'parent_groups': parent_groups
                    })
            
            if nested_groups:
                f.write(f"Found {len(nested_groups)} nested groups:\n\n")
                for nesting in nested_groups[:10]:  # Show first 10
                    f.write(f"  {nesting['group']} is a member of:\n")
                    for parent in nesting['parent_groups']:
                        f.write(f"    - {parent}\n")
                    f.write("\n")
                
                if len(nested_groups) > 10:
                    f.write(f"  ... and {len(nested_groups)-10} more nested groups\n\n")
            else:
                f.write("No group nesting detected.\n\n")
        
        self.log(f"Group membership report generated: {report_file}")
        
        return {
            "report_file": report_file,
            "total_groups": len(self.group_membership),
            "total_users_with_groups": len(self.user_groups)
        }
    
    def run_comprehensive_analysis(self):
        """Run comprehensive AD analysis with vulnerability assessment"""
        self.log("=" * 80)
        self.log("STARTING COMPREHENSIVE AD ANALYSIS WITH ADVANCED FEATURES")
        self.log("=" * 80)
        
        results = {}
        
        # Step 1: Enumerate users with vulnerability analysis
        self.log("\n[PHASE 1] User Enumeration & Vulnerability Analysis")
        user_results = self.enumerate_users(detailed=True)
        results['users'] = user_results
        
        if 'error' in user_results:
            self.log(f"User enumeration failed: {user_results.get('error')}", "ERROR")
            # Try with limit
            self.log("Trying user enumeration with limit...")
            user_results = self.enumerate_users(detailed=True, limit=100)
            results['users'] = user_results
        
        # Step 2: Enumerate groups with membership analysis
        self.log("\n[PHASE 2] Group Enumeration & Membership Analysis")
        group_results = self.enumerate_groups()
        results['groups'] = group_results
        
        if 'error' in group_results:
            self.log(f"Group enumeration failed: {group_results.get('error')}", "ERROR")
            # Try with limit
            self.log("Trying group enumeration with limit...")
            group_results = self.enumerate_groups(limit=100)
            results['groups'] = group_results
        
        # Step 3: Run new advanced scans
        self.log("\n[PHASE 3] Advanced Vulnerability Scans")
        
        # AS-REP Roasting detection
        self.find_asrep_roastable()
        
        # Delegation attacks
        self.find_unconstrained_delegation()
        self.find_constrained_delegation()
        self.find_resource_based_delegation()
        
        # Domain trusts
        self.enumerate_trusts()
        
        # GPP scanning (informational)
        self.scan_gpp_passwords()
        
        # LAPS analysis
        self.analyze_laps()
        
        # Password spray simulation
        self.test_password_spray()
        
        # Step 4: Generate BloodHound data
        self.log("\n[PHASE 4] BloodHound Data Generation")
        bloodhound_file = self.generate_bloodhound_data()
        results['bloodhound'] = bloodhound_file
        
        # Step 5: Privilege escalation analysis
        self.log("\n[PHASE 5] Privilege Escalation Analysis")
        escalation_paths = self.find_privilege_escalation_paths()
        results['escalation_paths'] = escalation_paths
        
        # Step 6: Risk scoring
        self.log("\n[PHASE 6] Risk Assessment")
        risk_assessment = self.generate_risk_score()
        results['risk_assessment'] = risk_assessment
        
        # Step 7: Generate vulnerability report if we have data
        if self.users_data:
            self.log("\n[PHASE 7] Vulnerability Assessment")
            vuln_results = self.generate_vulnerability_report()
            results['vulnerabilities'] = vuln_results
            
            # Step 8: Generate group membership report if we have data
            if self.user_groups:
                self.log("\n[PHASE 8] Group Membership Analysis")
                membership_results = self.generate_group_membership_report()
                results['membership'] = membership_results
            else:
                results['membership'] = {"error": "No group membership data"}
        else:
            results['vulnerabilities'] = {"error": "No user data for vulnerability analysis"}
            results['membership'] = {"error": "No user data for membership analysis"}
        
        # Step 9: Generate executive summary
        self.log("\n[PHASE 9] Executive Summary Generation")
        summary_file = self.generate_executive_summary(results)
        results['summary'] = summary_file
        
        self.log("\n" + "=" * 80)
        self.log("ADVANCED ANALYSIS COMPLETE")
        self.log("=" * 80)
        
        return results
    
    def generate_executive_summary(self, results: Dict) -> str:
        """Generate executive summary report"""
        summary_file = os.path.join(self.output_dir, f"executive_summary_{self.domain}.txt")
        
        with open(summary_file, 'w') as f:
            f.write("╔══════════════════════════════════════════════════════════════════════════════╗\n")
            f.write("║               AD JANITOR - ADVANCED EXECUTIVE SUMMARY REPORT               ║\n")
            f.write("╚══════════════════════════════════════════════════════════════════════════════╝\n\n")
            
            f.write(f"DOMAIN: {self.domain}\n")
            f.write(f"REPORT DATE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"LDAP SERVER: {self.ldap_server}\n")
            f.write(f"STEALTH MODE: {'Enabled' if self.stealth_mode else 'Disabled'}\n\n")
            
            f.write("─" * 80 + "\n")
            f.write("KEY FINDINGS\n")
            f.write("─" * 80 + "\n\n")
            
            # User statistics
            total_users = len(self.users_data)
            
            if total_users > 0:
                vulnerable_count = self.count_vulnerable_users()
                
                f.write(f"📊 USER ANALYSIS\n")
                f.write(f"   • Total Users: {total_users}\n")
                f.write(f"   • Vulnerable Users: {vulnerable_count} ({vulnerable_count/total_users*100:.1f}%)\n")
                f.write(f"   • Unique Vulnerable Users: {self.count_unique_vulnerable_users()}\n\n")
                
                # Group statistics
                total_groups = len(self.groups_data)
                privileged_count = len(self.identify_privileged_groups())
                
                f.write(f"👥 GROUP ANALYSIS\n")
                f.write(f"   • Total Groups: {total_groups}\n")
                f.write(f"   • Privileged Groups: {privileged_count}\n")
                f.write(f"   • Users with Group Memberships: {len(self.user_groups)}\n\n")
                
                # Risk assessment
                risk = results.get('risk_assessment', {})
                if risk:
                    f.write(f"⚠️  RISK ASSESSMENT\n")
                    f.write(f"   • Overall Risk Score: {risk.get('score', 0)}/100\n")
                    f.write(f"   • Risk Level: {risk.get('level', 'Unknown')}\n")
                    f.write(f"   • Total Findings: {risk.get('total_findings', 0)}\n\n")
                
                # Critical findings
                f.write(f"🔴 CRITICAL FINDINGS\n")
                critical_findings = []
                for category in ['asrep_roastable', 'unconstrained_delegation', 'reversible_encryption', 'plaintext_passwords']:
                    count = len(self.vulnerable_users.get(category, []))
                    if count > 0:
                        readable_name = category.replace('_', ' ').title()
                        critical_findings.append(f"{readable_name}: {count}")
                
                if critical_findings:
                    for finding in critical_findings:
                        f.write(f"   • {finding}\n")
                else:
                    f.write(f"   • No critical findings detected\n")
                f.write("\n")
                
                # High risk findings
                f.write(f"🟠 HIGH RISK FINDINGS\n")
                high_findings = []
                for category in ['kerberoastable', 'password_not_required', 'constrained_delegation', 'resource_based_delegation']:
                    count = len(self.vulnerable_users.get(category, []))
                    if count > 0:
                        readable_name = category.replace('_', ' ').title()
                        high_findings.append(f"{readable_name}: {count}")
                
                if high_findings:
                    for finding in high_findings:
                        f.write(f"   • {finding}\n")
                else:
                    f.write(f"   • No high risk findings detected\n")
                f.write("\n")
                
                # Advanced attack vectors
                f.write(f"🎯 ADVANCED ATTACK VECTORS DETECTED\n")
                
                # AS-REP Roasting
                asrep_count = len(self.vulnerable_users.get('asrep_roastable', []))
                if asrep_count > 0:
                    f.write(f"   • AS-REP Roasting: {asrep_count} vulnerable accounts\n")
                    examples = [u['username'] for u in self.vulnerable_users['asrep_roastable'][:3]]
                    f.write(f"     Examples: {', '.join(examples)}\n")
                
                # Unconstrained delegation
                ud_count = len(self.vulnerable_users.get('unconstrained_delegation', []))
                if ud_count > 0:
                    f.write(f"   • Unconstrained Delegation: {ud_count} vulnerable objects\n")
                
                # Constrained delegation
                cd_count = len(self.vulnerable_users.get('constrained_delegation', []))
                if cd_count > 0:
                    f.write(f"   • Constrained Delegation: {cd_count} vulnerable accounts\n")
                
                if asrep_count == 0 and ud_count == 0 and cd_count == 0:
                    f.write(f"   • No advanced Kerberos attack vectors detected\n")
                f.write("\n")
                
                # BloodHound integration
                f.write(f"🗺️  BLOODHOUND INTEGRATION\n")
                f.write(f"   • Data exported for BloodHound visualization\n")
                f.write(f"   • Import file: bloodhound_{self.domain}.json\n")
                f.write("\n")
                
                # Privilege escalation paths
                escalation_paths = results.get('escalation_paths', [])
                if escalation_paths:
                    f.write(f"📈 PRIVILEGE ESCALATION PATHS\n")
                    f.write(f"   • Found {len(escalation_paths)} potential escalation paths\n")
                    for i, path in enumerate(escalation_paths[:3], 1):
                        f.write(f"   {i}. {path['user']}: {path['path'][:50]}...\n")
                    if len(escalation_paths) > 3:
                        f.write(f"   ... and {len(escalation_paths)-3} more\n")
                f.write("\n")
                
                # Domain trusts
                if self.trusts_data:
                    f.write(f"🔗 DOMAIN TRUSTS\n")
                    f.write(f"   • Found {len(self.trusts_data)} domain trusts\n")
                    for trust in self.trusts_data[:3]:
                        partner = trust.get('trustPartner', [''])[0]
                        f.write(f"   • Trust with: {partner}\n")
                f.write("\n")
                
                # GPP information
                if self.gpp_data:
                    f.write(f"🔐 GROUP POLICY PREFERENCES\n")
                    f.write(f"   • Found {len(self.gpp_data)} Group Policy Objects\n")
                    f.write(f"   ⚠️  Check SYSVOL for GPP passwords using tools like Get-GPPPassword\n")
                f.write("\n")
                
                # Recommendations
                f.write("─" * 80 + "\n")
                f.write("PRIORITIZED RECOMMENDATIONS\n")
                f.write("─" * 80 + "\n\n")
                
                recommendations = []
                
                # Critical recommendations
                if len(self.vulnerable_users.get('asrep_roastable', [])) > 0:
                    recommendations.append(("🔴 IMMEDIATE ACTION REQUIRED", [
                        "Enable Kerberos pre-authentication for all user accounts",
                        "Change passwords for AS-REP roastable accounts",
                        "Monitor for Kerberos AS-REQ requests"
                    ]))
                
                if len(self.vulnerable_users.get('unconstrained_delegation', [])) > 0:
                    recommendations.append(("🔴 IMMEDIATE ACTION REQUIRED", [
                        "Remove unconstrained delegation from all accounts and computers",
                        "Implement constrained delegation where necessary",
                        "Monitor for suspicious delegation tickets"
                    ]))
                
                if len(self.vulnerable_users.get('reversible_encryption', [])) > 0:
                    recommendations.append(("🔴 IMMEDIATE ACTION REQUIRED", [
                        "Disable reversible encryption immediately",
                        "Force password changes for affected accounts"
                    ]))
                
                # High priority recommendations
                if len(self.vulnerable_users.get('kerberoastable', [])) > 0:
                    recommendations.append(("🟠 HIGH PRIORITY", [
                        "Use Managed Service Accounts (MSAs) or Group Managed Service Accounts (gMSAs)",
                        "Implement strong, complex passwords for service accounts",
                        "Monitor for Kerberoasting attempts"
                    ]))
                
                if len(self.vulnerable_users.get('password_not_required', [])) > 0:
                    recommendations.append(("🟠 HIGH PRIORITY", [
                        "Enable password requirements for all accounts",
                        "Implement password policy enforcement",
                        "Review and secure password-less accounts"
                    ]))
                
                # Medium priority recommendations
                recommendations.append(("🟡 MEDIUM PRIORITY", [
                    "Implement password expiration policy",
                    "Review accounts with adminCount=1",
                    "Clean up inactive accounts (90+ days)"
                ]))
                
                # General improvements
                recommendations.append(("🔵 GENERAL IMPROVEMENTS", [
                    "Implement LAPS for local administrator passwords",
                    "Regularly review privileged group memberships",
                    "Implement least privilege principle",
                    "Enable auditing for sensitive activities"
                ]))
                
                for priority, items in recommendations:
                    f.write(f"{priority}:\n")
                    for item in items:
                        f.write(f"  • {item}\n")
                    f.write("\n")
            else:
                f.write("❌ NO DATA RETRIEVED\n")
                f.write("   Unable to retrieve data from the LDAP server.\n")
                f.write("   The server may have size limits or pagination restrictions.\n\n")
                
                f.write("Troubleshooting steps:\n")
                f.write("1. Try manual query with pagination:\n")
                f.write(f"   ldapsearch -H {self.ldap_server} -x -D '{self.username}' -w '{self.password}' -b '{self.base_dn}' -E 'pr=500/noprompt' '(objectClass=user)' samAccountName\n")
                f.write("\n2. Try with size limit:\n")
                f.write(f"   ldapsearch -H {self.ldap_server} -x -D '{self.username}' -w '{self.password}' -b '{self.base_dn}' -z 100 '(objectClass=user)' samAccountName\n")
                f.write("\n3. Check if anonymous bind is allowed:\n")
                f.write(f"   ldapsearch -H {self.ldap_server} -x -b '{self.base_dn}' -z 1 '(objectClass=*)'\n")
                f.write("\n")
            
            # Generated files
            f.write("─" * 80 + "\n")
            f.write("GENERATED REPORTS & ARTIFACTS\n")
            f.write("─" * 80 + "\n\n")
            
            files = [
                ("Executive Summary", summary_file),
                ("Vulnerability Report", results.get('vulnerabilities', {}).get('report_file', '')),
                ("Group Analysis", results.get('membership', {}).get('report_file', '')),
                ("BloodHound Data", results.get('bloodhound', '')),
                ("User Details", results.get('users', {}).get('files', {}).get('detailed', '')),
                ("Group Details", results.get('groups', {}).get('files', {}).get('detailed', '')),
                ("Privilege Escalation", "privilege_escalation_{self.domain}.txt"),
                ("Execution Log", self.log_file)
            ]
            
            for name, path in files:
                if path and os.path.exists(path):
                    f.write(f"• {name}: {os.path.basename(path)}\n")
            
            f.write(f"\nAll artifacts are available in: {os.path.abspath(self.output_dir)}\n\n")
            
            f.write("╔══════════════════════════════════════════════════════════════════════════════╗\n")
            f.write("║                          END OF ADVANCED REPORT                            ║\n")
            f.write("╚══════════════════════════════════════════════════════════════════════════════╝\n")
        
        self.log(f"Executive summary generated: {summary_file}")
        return summary_file
    
    def query_user_groups(self, username: str) -> List[str]:
        """Query all groups a specific user belongs to"""
        if not self.user_groups:
            # Try to get data first
            self.enumerate_users()
            self.enumerate_groups()
        
        return self.user_groups.get(username, [])
    
    def query_group_members(self, group_name: str) -> List[str]:
        """Query all members of a specific group"""
        if not self.group_membership:
            # Try to get data first
            self.enumerate_users()
            self.enumerate_groups()
        
        return self.group_membership.get(group_name, [])
    
    def find_users_by_vulnerability(self, vulnerability_type: str) -> List[Dict]:
        """Find all users with a specific vulnerability"""
        if not self.vulnerable_users:
            # Try to get data first
            self.enumerate_users()
        
        return self.vulnerable_users.get(vulnerability_type, [])


def main():
    """Main function for CLI usage"""
    parser = argparse.ArgumentParser(
        description='Enhanced AD Janitor - Advanced AD Enumeration & Vulnerability Assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -s ldap://10.200.71.101 -u leslie.young@za.tryhackme.com -p 'password' -b 'DC=za,DC=tryhackme,DC=com'
  
  # Advanced scan with stealth mode
  %(prog)s -s ldap://dc.example.com -u admin@example.com -p 'Passw0rd!' -b 'DC=example,DC=com' --stealth
  
  # Quick scan with limit
  %(prog)s -s ldap://dc.example.com -u admin@example.com -p 'Passw0rd!' -b 'DC=example,DC=com' --quick --limit 100
  
  # Test specific vulnerabilities
  %(prog)s -s ldap://dc.example.com -u admin@example.com -p 'Passw0rd!' -b 'DC=example,DC=com' --find-asrep
  
  # Manual test commands
  %(prog)s --manual-test
        '''
    )
    
    parser.add_argument('-s', '--server', help='LDAP server URL')
    parser.add_argument('-u', '--username', help='Username for LDAP bind')
    parser.add_argument('-p', '--password', help='Password for LDAP bind')
    parser.add_argument('-b', '--base-dn', help='Base Distinguished Name')
    parser.add_argument('-o', '--output-dir', default='ad_enum_results', help='Output directory')
    parser.add_argument('-l', '--limit', type=int, default=1000, help='Result limit for queries')
    
    # New features
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode with random delays')
    parser.add_argument('--find-asrep', action='store_true', help='Find AS-REP roastable accounts only')
    parser.add_argument('--find-delegation', action='store_true', help='Find delegation vulnerabilities only')
    parser.add_argument('--bloodhound', action='store_true', help='Generate BloodHound data only')
    parser.add_argument('--password-spray', action='store_true', help='Test password spray (simulation)')
    
    # Query options
    parser.add_argument('--query-user', help='Get all groups for a specific user')
    parser.add_argument('--query-group', help='Get all members of a specific group')
    parser.add_argument('--find-vulnerable', choices=[
        'password_never_expires', 'password_not_required', 
        'reversible_encryption', 'admin_count_set', 'kerberoastable',
        'plaintext_passwords', 'inactive_accounts', 'service_accounts',
        'asrep_roastable', 'unconstrained_delegation', 'constrained_delegation'
    ], help='Find users with specific vulnerability')
    
    # Analysis options
    parser.add_argument('--test-only', action='store_true', help='Test LDAP connection only')
    parser.add_argument('--quick', action='store_true', help='Quick scan (users and groups only)')
    parser.add_argument('--full', action='store_true', help='Full comprehensive analysis (default)')
    parser.add_argument('--manual-test', action='store_true', help='Show manual test command')
    
    args = parser.parse_args()
    
    # Show manual test command
    if args.manual_test:
        print("Manual LDAP test commands:")
        print("\n1. Test AS-REP roastable accounts:")
        print(f"   ldapsearch -H ldap://10.200.71.101 -x -D 'leslie.young@za.tryhackme.com' -w 'password' -b 'DC=za,DC=tryhackme,DC=com' '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' samAccountName")
        print("\n2. Test unconstrained delegation:")
        print(f"   ldapsearch -H ldap://10.200.71.101 -x -D 'leslie.young@za.tryhackme.com' -w 'password' -b 'DC=za,DC=tryhackme,DC=com' '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))' samAccountName")
        print("\n3. Test constrained delegation:")
        print(f"   ldapsearch -H ldap://10.200.71.101 -x -D 'leslie.young@za.tryhackme.com' -w 'password' -b 'DC=za,DC=tryhackme,DC=com' '(msDS-AllowedToDelegateTo=*)' samAccountName")
        print("\n4. Test with pagination:")
        print(f"   ldapsearch -H ldap://10.200.71.101 -x -D 'leslie.young@za.tryhackme.com' -w 'password' -b 'DC=za,DC=tryhackme,DC=com' -E 'pr=500/noprompt' '(objectClass=user)' samAccountName")
        return
    
    # Check if required arguments are provided for non-test modes
    if not args.test_only and not args.manual_test:
        if not all([args.server, args.username, args.password, args.base_dn]):
            parser.error("--server, --username, --password, and --base-dn are required for analysis")
    
    # Create Enhanced AD Janitor instance
    janitor = EnhancedADJanitor(
        ldap_server=args.server,
        username=args.username,
        password=args.password,
        base_dn=args.base_dn,
        output_dir=args.output_dir,
        stealth_mode=args.stealth
    )
    
    # Check ldapsearch availability
    try:
        subprocess.run(['ldapsearch', '--help'], capture_output=True, check=False)
    except FileNotFoundError:
        print("Error: 'ldapsearch' not found. Install with:")
        print("  Debian/Ubuntu: sudo apt install ldap-utils")
        print("  RHEL/CentOS: sudo yum install openldap-clients")
        sys.exit(1)
    
    # Test connection only
    if args.test_only:
        if janitor.test_connection():
            print("✅ LDAP connection successful!")
        else:
            print("❌ LDAP connection failed")
            print("\nTroubleshooting steps:")
            print("1. Check if the LDAP server is reachable:")
            print(f"   ping -c 1 {args.server.replace('ldap://', '')}")
            print("\n2. Test with a manual ldapsearch command:")
            print(f"   ldapsearch -H {args.server} -x -D '{args.username}' -w '{args.password}' -b '{args.base_dn}' -z 1 '(objectClass=*)'")
        return
    
    # Specialized scans
    if args.find_asrep:
        print("Searching for AS-REP roastable accounts...")
        janitor.test_connection()
        janitor.find_asrep_roastable()
        
        asrep_accounts = janitor.vulnerable_users.get('asrep_roastable', [])
        if asrep_accounts:
            print(f"\nFound {len(asrep_accounts)} AS-REP roastable accounts:")
            for account in asrep_accounts:
                print(f"  - {account['username']} ({account.get('userPrincipalName', '')})")
                print(f"    {account['explanation']}")
        else:
            print("\nNo AS-REP roastable accounts found.")
        return
    
    if args.find_delegation:
        print("Searching for delegation vulnerabilities...")
        janitor.test_connection()
        janitor.find_unconstrained_delegation()
        janitor.find_constrained_delegation()
        janitor.find_resource_based_delegation()
        
        print("\nDelegation vulnerabilities found:")
        
        ud_accounts = janitor.vulnerable_users.get('unconstrained_delegation', [])
        if ud_accounts:
            print(f"\nUnconstrained Delegation ({len(ud_accounts)}):")
            for account in ud_accounts[:5]:
                if 'username' in account:
                    print(f"  - User: {account['username']}")
                elif 'hostname' in account:
                    print(f"  - Computer: {account['hostname']}")
        
        cd_accounts = janitor.vulnerable_users.get('constrained_delegation', [])
        if cd_accounts:
            print(f"\nConstrained Delegation ({len(cd_accounts)}):")
            for account in cd_accounts[:5]:
                print(f"  - {account['username']}")
        
        if not ud_accounts and not cd_accounts:
            print("\nNo delegation vulnerabilities found.")
        return
    
    if args.bloodhound:
        print("Generating BloodHound data...")
        janitor.test_connection()
        janitor.enumerate_users(limit=args.limit)
        janitor.enumerate_groups(limit=args.limit)
        bloodhound_file = janitor.generate_bloodhound_data()
        print(f"\nBloodHound data saved to: {bloodhound_file}")
        print("Import this file into BloodHound for visualization")
        return
    
    if args.password_spray:
        print("Password spray simulation (no actual authentication attempts)...")
        janitor.test_connection()
        janitor.enumerate_users(limit=50)
        janitor.test_password_spray()
        return
    
    # Run based on arguments
    if args.query_user:
        groups = janitor.query_user_groups(args.query_user)
        print(f"\nGroups for user '{args.query_user}':")
        for group in groups:
            print(f"  - {group}")
        if not groups:
            print("  No groups found or user not found")
        
    elif args.query_group:
        members = janitor.query_group_members(args.query_group)
        print(f"\nMembers of group '{args.query_group}':")
        for member in members:
            print(f"  - {member}")
        if not members:
            print("  No members found or group not found")
    
    elif args.find_vulnerable:
        vulnerable = janitor.find_users_by_vulnerability(args.find_vulnerable)
        vuln_name = args.find_vulnerable.replace('_', ' ').title()
        
        print(f"\nUsers with {vuln_name} vulnerability:")
        for user in vulnerable:
            print(f"  - {user['username']}")
            if 'description' in user:
                print(f"    Description: {user['description'][:50]}...")
        if not vulnerable:
            print("  No users found with this vulnerability")
    
    elif args.quick:
        print("Running quick scan...")
        janitor.enumerate_users(limit=args.limit)
        janitor.enumerate_groups(limit=args.limit)
        
        # Quick summary
        print(f"\nQuick Scan Results:")
        print(f"  Users: {len(janitor.users_data)}")
        print(f"  Groups: {len(janitor.groups_data)}")
        print(f"  Vulnerable users: {janitor.count_vulnerable_users()}")
        
        if len(janitor.users_data) == 0:
            print("\n⚠️  No user data retrieved. Server may have size limits.")
            print("\nTry with --limit 100 to get a sample:")
            print(f"  {sys.argv[0]} -s {args.server} -u '{args.username}' -p '{args.password}' -b '{args.base_dn}' --quick --limit 100")
        
    else:  # Full comprehensive analysis (default)
        results = janitor.run_comprehensive_analysis()
        
        # Print key findings
        print(f"\n{'='*60}")
        print("ADVANCED ANALYSIS COMPLETE - KEY FINDINGS")
        print(f"{'='*60}")
        
        if len(janitor.users_data) > 0:
            print(f"✓ Users analyzed: {len(janitor.users_data)}")
            print(f"✓ Groups analyzed: {len(janitor.groups_data)}")
            print(f"✓ Total vulnerabilities found: {janitor.count_vulnerable_users()}")
            print(f"✓ Unique vulnerable users: {janitor.count_unique_vulnerable_users()}")
            
            # Show critical findings
            asrep_count = len(janitor.vulnerable_users.get('asrep_roastable', []))
            ud_count = len(janitor.vulnerable_users.get('unconstrained_delegation', []))
            
            if asrep_count > 0:
                print(f"🔴 AS-REP Roastable accounts: {asrep_count}")
            if ud_count > 0:
                print(f"🔴 Unconstrained Delegation: {ud_count}")
            
            # Risk assessment
            risk = results.get('risk_assessment', {})
            if risk:
                print(f"⚠️  Overall Risk Score: {risk.get('score', 0)}/100 ({risk.get('level', 'Unknown')})")
            
            print(f"🗺️  BloodHound data generated")
        else:
            print("⚠️  LIMITED DATA RETRIEVED")
            print(f"   Groups found: {len(janitor.groups_data)}")
            print("   Check the executive summary for troubleshooting steps")
        
        print(f"📁 Reports generated in: {os.path.abspath(args.output_dir)}")
        print(f"{'='*60}")


if __name__ == "__main__":
    main()