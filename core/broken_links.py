import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging

def check_broken_links(base_url):
    """
    Finds internal links and checks if they are broken (404/500).
    Limits to first 20 links to prevent long execution.
    """
    logger = logging.getLogger("domainenum")
    broken_links = []
    
    try:
        response = requests.get(base_url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')
        
        domain = urlparse(base_url).netloc
        
        count = 0
        limit = 20 # Limit to prevent aggressive crawling
        
        for link in links:
            if count >= limit:
                break
                
            href = link.get('href')
            if href and not href.startswith('#') and not href.startswith('javascript:'):
                full_url = urljoin(base_url, href)
                
                # Only check internal links
                if domain in full_url:
                    try:
                        res = requests.head(full_url, timeout=5)
                        if res.status_code >= 400:
                            broken_links.append({
                                'url': full_url,
                                'status': res.status_code
                            })
                        count += 1
                    except:
                        pass
                        
    except Exception as e:
        logger.error(f"Broken link check failed: {e}")
        
    return broken_links