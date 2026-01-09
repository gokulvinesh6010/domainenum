import ssl
import socket
import logging
from datetime import datetime

def analyze_ssl(domain):
    """
    Retrieves SSL certificate details.
    """
    logger = logging.getLogger("domainenum")
    result = {'valid': False, 'issuer': None, 'expiry': None, 'version': None}
    
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result['valid'] = True
                result['version'] = ssock.version()
                
                # Extract Issuer
                issuer = dict(x[0] for x in cert['issuer'])
                result['issuer'] = issuer.get('organizationName', 'Unknown')
                
                # Extract Expiry
                not_after = cert['notAfter']
                # Convert standard ssl date format to simpler string
                # Format usually: May 24 12:00:00 2024 GMT
                result['expiry'] = not_after
                
    except Exception as e:
        logger.warning(f"SSL handshake failed: {e}")
        
    return result