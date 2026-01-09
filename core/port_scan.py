import nmap
import logging

def scan_ports(ip_address, scan_type='basic'):
    """
    Scans ports using python-nmap based on the selected type.
    Types: basic (-F), version (-sV -p-), vuln (-p- --script vuln)
    """
    logger = logging.getLogger("domainenum")
    results = {'open_ports': [], 'scan_type': scan_type}
    
    if not ip_address:
        return results

    nm = nmap.PortScanner()
    try:
        args = ""
        if scan_type == 'basic':
            # Fast scan (Top 100 ports)
            args = '-F -T4'
        elif scan_type == 'version':
            # Full port scan with version detection
            args = '-p- -sV -T4'
        elif scan_type == 'vuln':
            # Full port scan with vuln scripts (Aggressive)
            args = '-p- -sV --script vuln -T4'
            
        logger.info(f"Running Nmap with args: {args}")
        nm.scan(ip_address, arguments=args)
        
        if ip_address in nm.all_hosts():
            for proto in nm[ip_address].all_protocols():
                ports = nm[ip_address][proto].keys()
                for port in ports:
                    port_info = nm[ip_address][proto][port]
                    state = port_info['state']
                    service = port_info['name']
                    product = port_info.get('product', '')
                    version = port_info.get('version', '')
                    
                    # Capture script output for vuln scan
                    script_output = ""
                    if 'script' in port_info:
                        for script_name, output in port_info['script'].items():
                            script_output += f"\n[{script_name}]: {output.strip()}"

                    if state == 'open':
                        results['open_ports'].append({
                            'port': port,
                            'protocol': proto,
                            'service': service,
                            'version': f"{product} {version}".strip(),
                            'vuln_info': script_output
                        })
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")
        results['error'] = str(e)
        
    return results