import shutil
import subprocess
import logging

def detect_waf(domain):
    """
    Detects WAF using the installed 'wafw00f' command line tool.
    Returns a string identifying the WAF or 'None detected'.
    """
    logger = logging.getLogger("domainenum")
    
    waf_result = "Detection Failed / Not Installed"
    
    # Check if wafw00f is installed
    if not shutil.which('wafw00f'):
        return "wafw00f not found in PATH"

    try:
        # Run wafw00f in verbose mode to capture output
        cmd = ['wafw00f', domain]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        output = result.stdout
        
        # Parse output for simple detection
        if "No WAF detected" in output:
            waf_result = "No WAF detected"
        else:
            # Try to find the line saying "is behind"
            for line in output.split('\n'):
                if "is behind" in line:
                    waf_result = line.strip()
                    break
            if waf_result == "Detection Failed / Not Installed":
                 # Fallback if specific line not found but not negative
                 if "The site" in output: 
                     waf_result = "Potential WAF detected (See logs)"
                     
    except Exception as e:
        logger.error(f"WAF detection error: {e}")
        waf_result = f"Error: {str(e)}"

    return waf_result