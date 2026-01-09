#!/usr/bin/env python3
import argparse
import sys
import os
import logging
from datetime import datetime

# --- IMPORT BLOCK ---
# We rely on Python to find the modules. If folders are missing, ImportError is raised.
try:
    from core.dns_enum import resolve_domain
    from core.port_scan import scan_ports
    from core.js_enum import extract_and_save_js
    from core.robots_check import check_robots_txt
    from core.waf_detect import detect_waf
    from core.server_detect import detect_server_info, check_methods, check_ip_accessibility
    from core.ssl_analysis import analyze_ssl
    from core.headers_check import check_security_headers, check_host_header_injection
    from core.cms_detect import detect_cms
    from core.broken_links import check_broken_links
    from core.email_extract import extract_emails
    from core.secrets_scan import scan_for_secrets
    from core.graphql_check import check_graphql
    
    from report.pdf_report import generate_pdf_report

except ImportError as e:
    print(f"\n[!] Critical Import Error: {e}")
    print("[!] Ensure the 'core' and 'report' folders exist and contain __init__.py")
    sys.exit(1)

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("domainenum")

# ANSI Colors
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner(target):
    print(f"""{Colors.CYAN}
    .......................................................
    :   {Colors.YELLOW}DOMAIN ENUMERATION & VAPT TOOL{Colors.CYAN}                    :
    :   {Colors.MAGENTA}Author: GVhacks{Colors.CYAN}                                   :
    :.....................................................:
    :                                                     :
    :   {Colors.GREEN}Target  :{Colors.END} {target:<35} {Colors.CYAN}:
    :   {Colors.GREEN}Time    :{Colors.END} {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<35} {Colors.CYAN}:
    :.....................................................:
    {Colors.END}""")

def main():
    parser = argparse.ArgumentParser(description="GVhacks Domain Enumeration & VAPT Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target Domain (e.g., example.com)")
    parser.add_argument("-o", "--output", required=True, help="Output PDF filename (e.g., report.pdf)")
    parser.add_argument("--scan-type", choices=['basic', 'version', 'vuln'], default='basic', 
                        help="Nmap Scan Type: basic (Fast), version (Service Info), vuln (Vulnerability Scripts)")
    parser.add_argument("--fast", action="store_true", help="Skip time-consuming checks like Broken Links")
    
    args = parser.parse_args()
    target_domain = args.domain
    
    # --- OUTPUT FOLDER LOGIC ---
    # Determine where to save the report
    reports_dir = os.path.join(os.getcwd(), "reports")
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        
    if os.path.sep in args.output or '/' in args.output:
        output_file = args.output
        custom_dir = os.path.dirname(os.path.abspath(output_file))
        if not os.path.exists(custom_dir):
            os.makedirs(custom_dir)
    else:
        output_file = os.path.join(reports_dir, args.output)

    print_banner(target_domain)

    results = {}

    try:
        # 1. DNS Resolution
        logger.info(f"{Colors.BLUE}[*] Resolving Domain...{Colors.END}")
        results['dns'] = resolve_domain(target_domain)
        if not results['dns']['ip']:
            logger.error(f"{Colors.RED}[-] Could not resolve domain. Exiting.{Colors.END}")
            sys.exit(1)
        
        target_ip = results['dns']['ip']
        logger.info(f"{Colors.GREEN}[+] Target IP: {target_ip}{Colors.END}")

        # 2. Server Availability
        logger.info(f"{Colors.BLUE}[*] Checking Server Availability & Methods...{Colors.END}")
        results['server_info'] = detect_server_info(target_domain)
        results['ip_accessible'] = check_ip_accessibility(target_ip, target_domain)
        results['http_methods'] = check_methods(target_domain)

        # 3. WAF Detection
        logger.info(f"{Colors.BLUE}[*] Detecting WAF...{Colors.END}")
        results['waf'] = detect_waf(target_domain)
        logger.info(f"{Colors.GREEN}[+] WAF: {results['waf']}{Colors.END}")

        # 4. Port Scanning
        logger.info(f"{Colors.BLUE}[*] Performing Nmap Scan (Type: {args.scan_type.upper()})...{Colors.END}")
        results['ports'] = scan_ports(target_ip, args.scan_type)
        count = len(results['ports'].get('open_ports', []))
        logger.info(f"{Colors.GREEN}[+] Open Ports Found: {count}{Colors.END}")

        # 5. SSL Analysis
        logger.info(f"{Colors.BLUE}[*] Analyzing SSL/TLS...{Colors.END}")
        results['ssl'] = analyze_ssl(target_domain)

        # 6. Security Headers
        logger.info(f"{Colors.BLUE}[*] Checking Security Headers & Host Injection...{Colors.END}")
        results['headers'] = check_security_headers(target_domain)
        results['host_injection'] = check_host_header_injection(target_domain)

        # 7. GraphQL
        logger.info(f"{Colors.BLUE}[*] Checking for GraphQL...{Colors.END}")
        results['graphql'] = check_graphql(target_domain)

        # 8. CMS
        logger.info(f"{Colors.BLUE}[*] Detecting CMS...{Colors.END}")
        results['cms'] = detect_cms(target_domain)

        # 9. JS Extraction
        logger.info(f"{Colors.BLUE}[*] Extracting & Saving JS Files...{Colors.END}")
        base_url = f"https://{target_domain}" if results['ssl']['valid'] else f"http://{target_domain}"
        js_data = extract_and_save_js(base_url, target_domain)
        results['js_files'] = js_data['files']
        results['js_save_path'] = js_data['save_path']
        
        emails = extract_emails(base_url)
        results['emails'] = list(emails)

        # 10. Secrets Scanning
        logger.info(f"{Colors.BLUE}[*] Performing In-Depth Secrets & Source Analysis on Saved JS...{Colors.END}")
        results['secrets'] = scan_for_secrets(base_url, results['js_files'], js_save_dir=results['js_save_path'])

        # 11. Broken Links
        if not args.fast:
            logger.info(f"{Colors.BLUE}[*] Checking for Broken Links...{Colors.END}")
            results['broken_links'] = check_broken_links(base_url)
        else:
            results['broken_links'] = []
            
        # 12. Robots.txt
        results['robots'] = check_robots_txt(target_domain)

        # Generate Report
        logger.info(f"{Colors.MAGENTA}[*] Generating PDF Report: {output_file}{Colors.END}")
        generate_pdf_report(target_domain, results, output_file)
        
        print(f"\n{Colors.GREEN}[+] Scan Completed Successfully.{Colors.END}")
        print(f"{Colors.GREEN}[+] JS Files saved in: {results['js_save_path']}{Colors.END}")
        print(f"{Colors.GREEN}[+] Report saved to: {output_file}{Colors.END}")

    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[-] Scan interrupted by user.{Colors.END}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"{Colors.RED}Critical Error: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()