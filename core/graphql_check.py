import requests
import logging

def check_graphql(domain):
    """
    Checks for common GraphQL endpoints.
    """
    endpoints = [
        '/graphql',
        '/api/graphql',
        '/v1/graphql',
        '/gql',
        '/query'
    ]
    found = []
    
    base_url = f"http://{domain}"
    
    # Simple introspection query
    query = {"query": "{__schema{types{name}}}"}
    
    for endp in endpoints:
        url = base_url + endp
        try:
            # Try GET first
            res = requests.get(url, timeout=3)
            if res.status_code == 200 and ('errors' in res.text or 'data' in res.text):
                found.append(url)
                continue
                
            # Try POST
            res = requests.post(url, json=query, timeout=3)
            if res.status_code == 200 and ('data' in res.text or 'schema' in res.text):
                found.append(url)
                
        except:
            pass
            
    return found