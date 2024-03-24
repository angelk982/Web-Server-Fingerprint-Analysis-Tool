import argparse
import hashlib
import json
import nmap
import requests
import builtwith
from urllib.parse import urlparse

def generate_hash(info):
    """
    Generate a SHA-256 hash of the server information.

    This function takes a dictionary containing various pieces of information about a web server,
    serializes it into a JSON string ensuring the keys are sorted to maintain consistency,
    and then generates a SHA-256 hash of this string. SHA-256 is chosen for its balance between
    speed and security, making it a good choice for generating a unique fingerprint of server information.
    """
    hash_obj = hashlib.sha256()
    hash_obj.update(json.dumps(info, sort_keys=True).encode())
    return hash_obj.hexdigest()

def get_web_info(url):
    """
    Get basic information from the web server.

    This function attempts to perform an HTTP GET request to the provided URL and collects basic
    information from the response, including the status code, server type, content type, and cookies.
    It gracefully handles exceptions, ensuring the program can continue execution even if this step fails.
    """
    try:
        response = requests.get(url)
        return {
            'status_code': response.status_code,
            'server': response.headers.get('Server', 'Unknown'),
            'content_type': response.headers.get('Content-Type', 'Unknown'),
            'cookies': list(response.cookies),
        }
    except Exception as e:
        print(f"Error retrieving web server information: {e}")
        return {}

def gather_builtwith_info(url):
    """
    Use the builtwith library to identify technologies used by the web server.

    This function leverages the builtwith library to analyze the given URL and determine the
    technologies used by the web server. It returns a dictionary of identified technologies,
    providing insights into the server's software stack.
    """
    return builtwith.builtwith(url)

def scan_ports(domain):
    """
    Scan for open ports using Nmap.

    This function utilizes the Nmap PortScanner to perform a scan on the specified domain,
    looking for open ports and the services running on those ports. The '-sS' and '-sV'
    arguments are used to perform a SYN scan and service/version detection, respectively,
    offering a balance between speed and detail in the scan results.
    """
    scanner = nmap.PortScanner()
    scanner.scan(domain, arguments='-sS -sV')
    return {host: scanner[host] for host in scanner.all_hosts()}

def main():
    """
    Main function to parse arguments and gather information based on user input.

    This function sets up command line argument parsing and calls other functions to gather
    information about the web server specified by the URL argument. It supports filtering the
    type of information to retrieve and selecting the output format (hash or JSON).
    """
    parser = argparse.ArgumentParser(description="Web Server Information and Hash Generation")
    parser.add_argument('url', help="URL of the web server to analyze.")
    parser.add_argument('--info', choices=['all', 'web', 'ports', 'tech'], default='all', help="Type of information to retrieve.")
    parser.add_argument('--output', choices=['hash', 'json'], default='hash', help="Output format.")
    args = parser.parse_args()

    domain = urlparse(args.url).netloc
    info = {}

    # Gathering specified information based on user input
    if args.info in ['all', 'web']:
        info['web_info'] = get_web_info(args.url)
    if args.info in ['all', 'ports']:
        info['ports_scan'] = scan_ports(domain)
    if args.info in ['all', 'tech']:
        info['tech_scan'] = gather_builtwith_info(args.url)

    # Outputting the information in the specified format
    if args.output == 'json':
        print(json.dumps(info, indent=4))
    else:
        print(generate_hash(info))

if __name__ == "__main__":
    main()
