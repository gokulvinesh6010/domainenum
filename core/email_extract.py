import requests
import re
import logging

def extract_emails(url):
    """
    Extracts emails from the page source using Regex.
    """
    logger = logging.getLogger("domainenum")
    emails = set()
    
    # Generic Email Regex
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    
    try:
        response = requests.get(url, timeout=10)
        found = re.findall(email_pattern, response.text)
        for email in found:
            # Filter out common false positives like image filenames
            if not email.endswith(('.png', '.jpg', '.jpeg', '.gif')):
                emails.add(email)
                
    except Exception as e:
        logger.error(f"Email extraction failed: {e}")
        
    return emails