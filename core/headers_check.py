import requests
import logging

def check_security_headers(domain):
    """
    Checks for presence of recommended security headers.
    """
    required_headers = [
        'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options',
        'Content-Security-Policy', 'X-XSS-Protection', 'Referrer-Policy'
    ]
    results = {'missing': [], 'present': {}}
    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=5)
        for header in required_headers:
            if header in response.headers:
                results['present'][header] = response.headers[header]
            else:
                results['missing'].append(header)
    except:
        pass
    return results

def check_host_header_injection(domain):
    """
    Checks for Host Header Injection vulnerabilities.
    """
    result = {'vulnerable': False, 'details': 'No injection detected'}
    url = f"http://{domain}"
    evil_host = "evil.com"
    
    try:
        # 1. Standard Host Header Injection
        headers = {'Host': evil_host}
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
        
        # Check if evil_host is reflected in location header (Redirection)
        if response.status_code in [301, 302] and evil_host in response.headers.get('Location', ''):
            result['vulnerable'] = True
            result['details'] = f"Vulnerable: Host header reflected in Location redirect to {evil_host}"
            return result
            
        # Check if X-Forwarded-Host is reflected
        headers = {'X-Forwarded-Host': evil_host}
        response = requests.get(url, headers=headers, timeout=5)
        if evil_host in response.text:
             result['vulnerable'] = True
             result['details'] = "Vulnerable: X-Forwarded-Host reflected in response body"
             return result

    except Exception as e:
        result['details'] = f"Check failed: {e}"
        
    return result