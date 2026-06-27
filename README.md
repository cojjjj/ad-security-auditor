AD Security Auditor
AD Security Auditor is a safe, offline-first blue-team audit tool for reviewing Active Directory posture from a JSON export. It does not connect to a domain controller, perform authentication attempts, or make changes to any environment.
Checks
Total users
Disabled users
Inactive users
Password never expires
Users with no recent logon
Domain Admin group members
Service accounts
Stale computer accounts
Basic password policy
Security score with plain-English deductions
Quick Start
python auditor.py sample-data/sample_ad_export.json
The tool prints a console summary and writes an HTML report to:
reports/report.html
You can choose a different report path:
python auditor.py sample-data/sample_ad_export.json --output reports/my-audit.html
You can also change the inactivity threshold. The default is 90 days:
python auditor.py sample-data/sample_ad_export.json --inactive-days 120
Sample Output
AD Security Audit Report

Users: 15
Disabled Users: 2
Password Never Expires: 5
Inactive Users: 6
Users With No Recent Logon: 8
Domain Admins: 4
Service Accounts: 3
Stale Computers: 3

Security Score: 70/100
Report written to: reports/report.html
Input Format
The input file should be a JSON object with these top-level keys:
users
groups
computers
password_policy
The included sample-data/sample_ad_export.json shows the expected shape.
Project Structure
ad-security-auditor/
|-- auditor.py
|-- collectors/
|   |-- users.py
|   |-- groups.py
|   `-- computers.py
|-- reports/
|   `-- report.html
|-- sample-data/
|   `-- sample_ad_export.json
|-- README.md
`-- requirements.txt
Future Enhancements
LDAP read-only collection mode
PowerShell export helper
CSV report output
Severity levels per finding
Trend comparison between two audit exports
