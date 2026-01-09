import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
import os
import re

def extract_and_save_js(base_url, domain):
    """
    Extracts JS files, handles relative paths, and SAVES them locally.
    """
    logger = logging.getLogger("domainenum")
    js_files = []
    
    # Create directory for saving JS
    save_dir = os.path.join("collected_js", domain)
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
        
    try:
        response = requests.get(base_url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. Find script tags with src
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src')
            if src:
                full_url = urljoin(base_url, src)
                if full_url not in js_files:
                    js_files.append(full_url)
                    
        # 2. Regex fallback for scripts inside HTML text (e.g. dynamic loading)
        # Matches "something.js" or 'something.js'
        regex_js = re.findall(r'["\'](.*\.js)["\']', response.text)
        for js_match in regex_js:
            # Basic validation to avoid junk
            if not js_match.startswith('http') and not js_match.startswith('//'):
                full_url = urljoin(base_url, js_match)
            else:
                 full_url = js_match if js_match.startswith('http') else "https:" + js_match
            
            if full_url not in js_files:
                js_files.append(full_url)

        # 3. Download Files
        logger.info(f"Downloading {len(js_files)} JS files to {save_dir}...")
        for js_url in js_files:
            try:
                filename = os.path.basename(urlparse(js_url).path)
                if not filename or not filename.endswith('.js'):
                    filename = f"script_{js_files.index(js_url)}.js"
                
                # Sanitize filename
                filename = "".join([c for c in filename if c.isalpha() or c.isdigit() or c in (' ','.','_','-')]).strip()
                
                file_path = os.path.join(save_dir, filename)
                
                # Fetch and save
                js_content = requests.get(js_url, timeout=5).text
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(js_content)
                    
            except Exception as e:
                # logger.warning(f"Failed to download {js_url}: {e}")
                pass

    except Exception as e:
        logger.error(f"JS extraction failed: {e}")
        
    return {'files': js_files, 'save_path': save_dir}