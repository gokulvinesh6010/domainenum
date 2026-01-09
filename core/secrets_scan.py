import requests
import re
import os

# NOTE: This file must NOT import 'domainenum' or 'logging' configurations 
# from the main script to avoid circular import errors.

def scan_for_secrets(base_url, js_urls, js_save_dir=None):
    """
    Scans HTML and discovered JS files for API keys, secrets, 
    Encryption keys, and sensitive tokens. 
    """
    findings = []
    
    # --- REGEX PATTERNS ---
    patterns = {
        'AWS Access Key': r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
        'Generic API Key': r'(?i)((api|secret|token|access)_?key|auth_token)\s*[:=]\s*[\"\'][a-zA-Z0-9_\-]{16,64}[\"\']',
        'Private Key': r'-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----',
        'CryptoJS Encrypt': r'CryptoJS\.(AES|DES|Rabbit|RC4)\.encrypt',
        'CryptoJS Decrypt': r'CryptoJS\.(AES|DES|Rabbit|RC4)\.decrypt',
    }

    def analyze(content, src):
        if not content: return
        for name, pat in patterns.items():
            for m in re.finditer(pat, content):
                snip = m.group(0)
                if len(snip) > 100: snip = snip[:100] + "..."
                
                # Deduplicate findings
                if not any(f['snippet'] == snip and f['type'] == name for f in findings):
                    findings.append({
                        'source': src, 
                        'type': name, 
                        'snippet': snip
                    })

    # 1. SCAN LOCAL FILES (IN-DEPTH)
    if js_save_dir and os.path.exists(js_save_dir):
        for root, dirs, files in os.walk(js_save_dir):
            for file in files:
                if file.endswith(('.js', '.json', '.map', '.txt')):
                    try:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            analyze(f.read(), f"Local File: {file}")
                    except Exception:
                        pass 

    # 2. SCAN MAIN HTML
    try:
        response = requests.get(base_url, timeout=5)
        analyze(response.text, "Main HTML Page")
    except Exception:
        pass

    return findings