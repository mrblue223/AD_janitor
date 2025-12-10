# ==============================================
# AD JANITOR - COMPREHENSIVE USAGE EXAMPLES
# ==============================================

# BASIC USAGE
# -----------
# Full comprehensive analysis (default)
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com'

# Quick scan with limit
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --quick --limit 100

# Test connection only
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --test-only

# Show manual test commands
sudo python3 AD_janitor.py --manual-test


# ADVANCED FEATURES
# -----------------
# Find AS-REP roastable accounts only
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --find-asrep

# Find delegation vulnerabilities only
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --find-delegation

# Generate BloodHound data only
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --bloodhound --limit 500

# Password spray simulation
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --password-spray

# Advanced scan with stealth mode
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --stealth --full


# QUERY SPECIFIC INFORMATION
# --------------------------
# Query specific user's groups
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --query-user 'john.doe'

# Query specific group members
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --query-group 'Domain Admins'

# Find users with specific vulnerability
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --find-vulnerable kerberoastable

# Find AS-REP roastable accounts (alternative)
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --find-vulnerable asrep_roastable


# OUTPUT MANAGEMENT
# -----------------
# Specify custom output directory
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  -o '/tmp/ad_scan_results' \
  --full

# With different limit
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --limit 500 \
  --quick


# REAL-WORLD SCENARIOS
# --------------------
# 1. Initial reconnaissance (stealthy)
sudo python3 AD_janitor.py -s ldap://dc.corp.local \
  -u 'pentester@corp.local' \
  -p 'P@ssw0rd123!' \
  -b 'DC=corp,DC=local' \
  --stealth --limit 200 --quick

# 2. Full security assessment
sudo python3 AD_janitor.py -s ldap://dc.corp.local \
  -u 'security.admin@corp.local' \
  -p 'S3cur3P@ss!' \
  -b 'DC=corp,DC=local' \
  --full -o '/reports/ad_assessment_2024'

# 3. Hunt for critical vulnerabilities
sudo python3 AD_janitor.py -s ldap://dc.corp.local \
  -u 'auditor@corp.local' \
  -p 'Audit2024!' \
  -b 'DC=corp,DC=local' \
  --find-asrep --find-delegation

# 4. Prepare for BloodHound visualization
sudo python3 AD_janitor.py -s ldap://dc.corp.local \
  -u 'analyst@corp.local' \
  -p 'Analyst123!' \
  -b 'DC=corp,DC=local' \
  --bloodhound --limit 1000

# 5. Check password policy weaknesses
sudo python3 AD_janitor.py -s ldap://dc.corp.local \
  -u 'admin@corp.local' \
  -p 'AdminPass!' \
  -b 'DC=corp,DC=local' \
  --find-vulnerable password_never_expires \
  --find-vulnerable password_not_required \
  --find-vulnerable reversible_encryption


# TROUBLESHOOTING COMMANDS
# ------------------------
# Test with minimal output
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --test-only

# Manual LDAP test commands
sudo python3 AD_janitor.py --manual-test

# If getting "Size limit exceeded" errors
sudo python3 AD_janitor.py -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com' \
  --quick --limit 50


# COMPREHENSIVE EXAMPLES WITH ALL OPTIONS
# ---------------------------------------
# Complete assessment with all features
sudo python3 AD_janitor.py \
  --server ldap://dc.example.com \
  --username 'administrator@example.com' \
  --password 'P@ssw0rd123!' \
  --base-dn 'DC=example,DC=com' \
  --output-dir '/opt/assessment/results' \
  --limit 2000 \
  --stealth \
  --full

# Quick check for common issues
sudo python3 AD_janitor.py \
  -s ldaps://dc.secure.corp:636 \
  -u 'svc_scanner@secure.corp' \
  -p 'Scanner2024!' \
  -b 'DC=secure,DC=corp' \
  --find-asrep \
  --find-delegation \
  --find-vulnerable kerberoastable \
  --find-vulnerable plaintext_passwords

# Generate reports for management
sudo python3 AD_janitor.py \
  -s ldap://dc.company.com \
  -u 'report.user@company.com' \
  -p 'ReportPass123' \
  -b 'DC=company,DC=com' \
  -o '/shared/reports/AD_Security_Review' \
  --full

# Red team engagement (stealthy recon)
sudo python3 AD_janitor.py \
  -s ldap://dc.target.org \
  -u 'normal.user@target.org' \
  -p 'UserPassword123' \
  -b 'DC=target,DC=org' \
  --stealth \
  --limit 100 \
  --quick \
  -o '/tmp/redteam_recon'

# Blue team monitoring (check for new vulns)
sudo python3 AD_janitor.py \
  -s ldap://dc.company.local \
  -u 'security@company.local' \
  -p 'SecMonitor2024!' \
  -b 'DC=company,DC=local' \
  --find-asrep \
  --find-delegation \
  --bloodhound \
  -o '/monitoring/daily_check'


# VULNERABILITY SPECIFIC SCANS
# ----------------------------
# Scan for Kerberos-related vulnerabilities
sudo python3 AD_janitor.py -s ldap://dc.example.com \
  -u 'kerb.scan@example.com' \
  -p 'ScanPass!' \
  -b 'DC=example,DC=com' \
  --find-vulnerable asrep_roastable \
  --find-vulnerable kerberoastable \
  --find-vulnerable unconstrained_delegation \
  --find-vulnerable constrained_delegation

# Scan for password policy issues
sudo python3 AD_janitor.py -s ldap://dc.example.com \
  -u 'policy.scan@example.com' \
  -p 'PolicyScan!' \
  -b 'DC=example,DC=com' \
  --find-vulnerable password_never_expires \
  --find-vulnerable password_not_required \
  --find-vulnerable reversible_encryption \
  --find-vulnerable plaintext_passwords

# Scan for account management issues
sudo python3 AD_janitor.py -s ldap://dc.example.com \
  -u 'account.scan@example.com' \
  -p 'AccountScan!' \
  -b 'DC=example,DC=com' \
  --find-vulnerable admin_count_set \
  --find-vulnerable inactive_accounts \
  --find-vulnerable service_accounts


# COMBINATION SCANS
# -----------------
# Quick security health check
sudo python3 AD_janitor.py -s ldap://dc.example.com \
  -u 'health.check@example.com' \
  -p 'HealthCheck123' \
  -b 'DC=example,DC=com' \
  --find-asrep \
  --find-delegation \
  --password-spray \
  --limit 100

# Complete attack surface analysis
sudo python3 AD_janitor.py -s ldap://dc.example.com \
  -u 'attack.surface@example.com' \
  -p 'SurfaceAnalysis!' \
  -b 'DC=example,DC=com' \
  --stealth \
  --full \
  -o '/reports/attack_surface_analysis'


# SHORT-FORM COMMANDS
# -------------------
# Using short options
sudo python3 AD_janitor.py \
  -s ldap://dc.short.com \
  -u short@short.com \
  -p shortpass \
  -b 'DC=short,DC=com' \
  -o /tmp/short \
  -l 500 \
  --quick

# Minimal command (if defaults work)
sudo python3 AD_janitor.py \
  -s ldap://10.200.71.101 \
  -u 'leslie.young@za.tryhackme.com' \
  -p '1CZY15ztC' \
  -b 'DC=za,DC=tryhackme,DC=com'

# ==============================================
# COMMON VULNERABILITY TYPES FOR --find-vulnerable
# ==============================================
# asrep_roastable        - AS-REP roastable accounts
# unconstrained_delegation - Unconstrained delegation
# constrained_delegation  - Constrained delegation
# kerberoastable         - Service accounts with SPNs
# password_never_expires - Non-expiring passwords
# password_not_required  - No password required
# reversible_encryption  - Reversible encryption enabled
# plaintext_passwords    - Passwords in descriptions
# admin_count_set        - adminCount=1
# inactive_accounts      - Inactive >90 days
# service_accounts       - Potential service accounts

# ==============================================
# TIPS FOR DIFFERENT ENVIRONMENTS
# ==============================================

# 1. For TryHackMe/HTB labs:
#    -- Use quick scans with limits
#    -- Test connection first
#    -- Use --manual-test for debugging

# 2. For corporate assessments:
#    -- Use --stealth for production
#    -- Start with --quick then --full
#    -- Use custom output directories

# 3. For compliance audits:
#    -- Run --full for complete reports
#    -- Check all vulnerability types
#    -- Generate BloodHound data for visualization

# 4. For red team engagements:
#    -- Start with --stealth --quick
#    -- Focus on --find-asrep and --find-delegation
#    -- Use --password-spray simulation

# 5. For blue team monitoring:
#    -- Schedule regular --quick scans
#    -- Monitor for new AS-REP/delegation issues
#    -- Generate BloodHound data periodically