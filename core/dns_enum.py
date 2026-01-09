import socket
import logging

def resolve_domain(domain):
    """
    Resolves domain to IP address.
    """
    logger = logging.getLogger("domainenum")
    results = {'ip': None, 'error': None}
    
    try:
        ip_address = socket.gethostbyname(domain)
        results['ip'] = ip_address
    except socket.gaierror:
        results['error'] = "Could not resolve hostname."
        logger.error(f"DNS Resolution failed for {domain}")
    except Exception as e:
        results['error'] = str(e)
    
    return results