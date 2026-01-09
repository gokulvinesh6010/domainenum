import requests
import logging

def check_robots_txt(domain):
    """
    Checks for the existence and content of robots.txt.
    """
    logger = logging.getLogger("domainenum")
    url = f"http://{domain}/robots.txt"
    results = {'exists': False, 'entries': []}
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            results['exists'] = True
            lines = response.text.split('\n')
            # Extract Disallow/Allow entries for report
            for line in lines:
                if line.strip() and not line.startswith('#'):
                    if 'Disallow' in line or 'Allow' in line:
                        results['entries'].append(line.strip())
    except Exception as e:
        logger.error(f"Robots.txt check failed: {e}")
        
    return results