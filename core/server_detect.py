import requests
import logging

def detect_server_info(domain):
    """
    Detects Server header and X-Powered-By.
    """
    info = {'status': 'Down', 'server_header': 'Not found', 'x_powered_by': 'Not found'}
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=5)
        info['status'] = 'Up'
        info['server_header'] = response.headers.get('Server', 'Hidden')
        info['x_powered_by'] = response.headers.get('X-Powered-By', 'Hidden')
    except:
        pass
    return info

def check_ip_accessibility(ip, domain):
    """
    Checks if the application is accessible directly via IP address.
    """
    result = {'accessible': False, 'message': 'Not accessible by IP'}
    if not ip:
        return result
        
    try:
        url = f"http://{ip}"
        # Disable certificate warnings for IP access
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
        
        if response.status_code < 400:
            result['accessible'] = True
            result['message'] = f"Accessible (Status: {response.status_code})"
        elif response.status_code in [301, 302]:
            result['accessible'] = True
            result['message'] = f"Redirects (Status: {response.status_code})"
    except Exception as e:
        result['message'] = str(e)
        
    return result

def check_methods(domain):
    """
    Checks for available HTTP methods using OPTIONS.
    """
    allowed_methods = "Unknown"
    try:
        url = f"http://{domain}"
        response = requests.options(url, timeout=5)
        allowed_methods = response.headers.get('Allow', 'Header not present')
    except:
        pass
    return allowed_methods