DomainEnum - Advanced VAPT Reconnaissance Tool

DomainEnum is a comprehensive, modular vulnerability assessment and reconnaissance tool designed for security professionals. It automates the passive and active gathering of information, vulnerability scanning, and reporting.

Generated reports are executive-grade, featuring professional charts, risk scores, and detailed findings.

🚀 Features

🛡️ WAF Detection: Identifies Web Application Firewalls using wafw00f.

🌐 Port Scanning: Intelligent scanning modes (basic, version, vuln) using nmap.

📜 JavaScript Analysis: Crawls, downloads, and statically analyzes JS files for secrets (AWS keys, API tokens).

🕸️ GraphQL Enumeration: Detects exposed GraphQL endpoints.

💉 Injection Checks: Tests for Host Header Injection and other misconfigurations.

🔒 Security Headers: Analyzes missing security headers.

📄 Executive PDF Report: Generates a polished PDF with:

Risk Overview Charts (Pie/Bar)

KPI Cards

Detailed Vulnerability Breakdown

"GV Hacks" Professional Branding

📦 Installation

Clone the repository:

git clone [https://github.com/gokulvinesh6010/domainenum.git](https://github.com/gokulvinesh6010/domainenum.git)
cd domainenum



Install Python dependencies:

pip install -r requirements.txt



System Dependencies:
Ensure you have Nmap installed and added to your system PATH.

Windows: Download Nmap

Linux: sudo apt install nmap

MacOS: brew install nmap

Ensure wafw00f is in your path (installed via pip requirements).

🛠️ Usage

Basic Scan

python domainenum.py -d example.com -o report.pdf



Full Vulnerability Scan

Performs aggressive Nmap scripts and deeper analysis.

python domainenum.py -d example.com -o report.pdf --scan-type vuln



Fast Scan

Skips broken link checking and heavy port scans.

python domainenum.py -d example.com -o report.pdf --fast



📂 Output

PDF Report: Saved to reports/ (or specified path).

JavaScript Files: Downloaded to collected_js/<domain>/ for manual review.

⚖️ Legal Disclaimer

This tool is created for EDUCATIONAL PURPOSES and AUTHORIZED SECURITY AUDITS only.
The author is not responsible for any misuse of this tool. Scanning targets without prior mutual consent is illegal. Always obtain permission before scanning a network you do not own.

Author: GVhacks
