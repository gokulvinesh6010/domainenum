import requests
from bs4 import BeautifulSoup
import logging

def detect_cms(domain):
    """
    Basic CMS detection based on meta tags and common paths.
    """
    logger = logging.getLogger("domainenum")
    cms = "Unknown"
    
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check Generator Meta Tag
        meta_gen = soup.find("meta", attrs={"name": "generator"})
        if meta_gen:
            content = meta_gen.get("content", "")
            if "WordPress" in content:
                cms = "WordPress"
            elif "Joomla" in content:
                cms = "Joomla"
            elif "Drupal" in content:
                cms = "Drupal"
            else:
                cms = content
                
        # Simple fingerprinting if meta not found
        if cms == "Unknown":
            if "/wp-content/" in response.text:
                cms = "WordPress"
            elif "/sites/default/files" in response.text:
                cms = "Drupal"
                
    except Exception as e:
        logger.error(f"CMS detection error: {e}")
        
    return cms