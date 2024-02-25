import requests
import time
import random
import argparse
import pandas as pd

def get_ssl_scan_results(domain, use_cache=False, max_age=24):
    """Fetch SSL scan results from SSL Labs API."""
    # Construct API URL with parameters
    api_url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}&all=done"
    if use_cache:
        api_url += f"&fromCache=on&maxAge={max_age}"
    else:
        api_url += "&startNew=on"

    print(f"Fetching SSL scan results from: {api_url}")
    try:
        # Handle HTTP errors and retry logic
        response = requests.get(api_url)
        if response.status_code in [400, 429, 500, 503, 529]:
            print(f"Error: {response.status_code}")
            handle_error(response.status_code)
            return None

        data = response.json()
        while data['status'] != 'READY' and data['status'] != 'ERROR':
            print(f"Status: {data['status']}")
            time.sleep(30)  # Polling interval
            response = requests.get(api_url + "&fromCache=on")
            data = response.json()

        return data
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

def handle_error(status_code):
    """Handle errors based on status code."""
    if status_code == 429:
        print("Rate limit exceeded, slowing down...")
    elif status_code in [503, 529]:
        # Delay for service availability
        delay = 15 if status_code == 503 else 30
        print(f"Service unavailable or overloaded, retrying in {delay} minutes...")
        time.sleep(delay * 60 + random.randint(1, 300))
    elif status_code == 500:
        print("Internal server error, proceeding with caution...")

def print_scan_results(data, email_format=False):
    """Print formatted SSL scan results."""
    certs_data = []
    endpoints_data = []

    if not data or 'endpoints' not in data:
        print("No data available for this domain.")
        return

    for endpoint in data['endpoints']:
        if 'details' in endpoint:
            details = endpoint['details']
            endpoints_data.append({
                "IP": endpoint.get('ipAddress'),
                "Grade": endpoint.get('grade'),
                "Warnings": endpoint.get('hasWarnings'),
                "OpenSslCcs": details.get('openSslCcs'),
                "OpenSSLLuckyMinus20": details.get('openSSLLuckyMinus20'),
                "PoodleTls": details.get('poodleTls'),
                "StatusCode": details.get('httpStatusCode')
            })

    if 'certs' in data:
        for cert in data['certs']:
            expiration_date = time.strftime('%Y-%m-%d', time.gmtime(cert.get('notAfter') / 1000))
            certs_data.append({
                "Subject": cert.get('subject'),
                "Expiration": expiration_date,
                "Sig Algo": cert.get('sigAlg'),
                "Issues": cert.get('issues')
            })

    if email_format:
        # Format output for email
        print("SSL Scan Results (Email Format):")
        print(pd.DataFrame(certs_data).to_string(index=False))
        print(pd.DataFrame(endpoints_data).to_string(index=False))
    else:
        # Standard output
        print("SSL Scan Results:")
        print(pd.DataFrame(certs_data))
        print(pd.DataFrame(endpoints_data))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get SSL scan results from SSL Labs API.')
    parser.add_argument('domain', type=str, help='Domain to scan')
    parser.add_argument('--use_cache', action='store_true', help='Use cached results if available')
    parser.add_argument('--email_format', action='store_true', help='Format output for email')
    args = parser.parse_args()

    results = get_ssl_scan_results(args.domain, use_cache=args.use_cache)
    print_scan_results(results, email_format=args.email_format)
