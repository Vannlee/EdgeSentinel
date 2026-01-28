import argparse
from argparse import RawTextHelpFormatter
import os
import sys
import re
import requests
from bs4 import BeautifulSoup
import json
from datetime import datetime
import time
from urllib.parse import urljoin, urlparse

# Global session object for maintaining authentication state
session = requests.Session()

def login_to_website(login_url, username, password, username_field='username', password_field='password'):
    """
    Authenticates to a website using provided credentials.
    
    Args:
        login_url (str): URL of the login page/endpoint
        username (str): Username for authentication
        password (str): Password for authentication
        username_field (str): Name of the username form field (default: 'username')
        password_field (str): Name of the password form field (default: 'password')
    
    Returns:
        bool: True if login successful, False otherwise
    """
    try:
        print(f"\n[*] Attempting to login to {login_url}")
        print(f"[*] Username: {username}")
        
        # First, get the login page to retrieve any CSRF tokens or session cookies
        response = session.get(login_url, timeout=10)
        
        # Parse the login form to find additional fields (like CSRF tokens)
        soup = BeautifulSoup(response.text, 'html.parser')
        login_form = soup.find('form')
        
        # Prepare login data
        login_data = {
            username_field: username,
            password_field: password
        }
        
        # Check for hidden fields (like CSRF tokens) and add them
        if login_form:
            hidden_inputs = login_form.find_all('input', type='hidden')
            for hidden in hidden_inputs:
                field_name = hidden.get('name')
                field_value = hidden.get('value', '')
                if field_name:
                    login_data[field_name] = field_value
                    print(f"[+] Found hidden field: {field_name}")
        
        # Determine the form action (login endpoint)
        if login_form and login_form.get('action'):
            form_action = login_form.get('action')
            if form_action:
                login_url = urljoin(login_url, form_action)
        
        # Perform the login POST request
        print(f"[*] Submitting credentials to {login_url}")
        login_response = session.post(login_url, data=login_data, timeout=10, allow_redirects=True)
        
        # Check if login was successful
        # Common indicators: redirect to dashboard, absence of login form, presence of logout button
        response_text = login_response.text.lower()
        
        # Check for success indicators
        success_indicators = ['logout', 'dashboard', 'welcome', 'profile', 'signed in', 'logged in']
        failure_indicators = ['login failed', 'invalid credentials', 'incorrect password', 'username or password', 'authentication failed']
        
        has_success = any(indicator in response_text for indicator in success_indicators)
        has_failure = any(indicator in response_text for indicator in failure_indicators)
        
        if has_failure:
            print("[!] Login failed: Invalid credentials or login error detected")
            return False
        elif has_success or login_response.status_code == 200:
            print("[+] Login successful! Session established.")
            print(f"[+] Cookies: {len(session.cookies)} cookie(s) stored")
            return True
        else:
            print(f"[!] Login status unclear (Status: {login_response.status_code})")
            print("[*] Proceeding with caution...")
            return True
            
    except requests.exceptions.ConnectionError:
        print(f"[!] Error: Could not connect to {login_url}")
        return False
    except requests.exceptions.Timeout:
        print(f"[!] Error: Request to {login_url} timed out")
        return False
    except Exception as e:
        print(f"[!] Login error: {e}")
        return False


def quick_scan(url, html_form=None, session_obj=None):
    """Function will scan for first 12 CWEs of A10"""
    try:
        print(f"\n[*] EdgeSentinel - Quick Scan Mode")
        print(f"[*] Target: {url}")
        print(f"[*] Testing first 12 CWEs of OWASP A10\n")
        
        # Use provided session or global session
        if session_obj is None:
            session_obj = session
        
        # Fetch webpage if no HTML form provided
        if html_form:
            print(f"[+] Using provided HTML form...")
            html_content = html_form
        else:
            print(f"[+] Fetching webpage...")
            response = fetch_webpage(url, session_obj=session_obj)
            if not response:
                print("[!] Failed to fetch webpage. Exiting.")
                return
            html_content = response['html']
            print(f"[+] Webpage fetched successfully (Status: {response['status_code']})")
        
        # Identify input parameters
        print(f"[+] Analyzing HTML forms...")
        parameters = identify_input_parameters(html_content, url)
        
        if not parameters:
            print("[!] No input parameters found in the HTML.")
            return
        
        print(f"[+] Found {len(parameters)} input parameter(s)\n")
        
        # Generate payloads
        payloads = generate_edge_case_payloads()
        
        # Test each parameter
        all_results = []
        for param in parameters:
            print(f"[*] Testing parameter: {param['param_name']} (type: {param['param_type']})")
            print(f"    Form action: {param['form_action']}")
            print(f"    Method: {param['method']}")
            
            # Get original response for this endpoint
            original_response = fetch_webpage(param['form_action'], session_obj=session_obj)
            
            # Execute tests
            results = execute_test_suite(param, payloads, original_response, session_obj=session_obj)
            all_results.extend(results)
        
        # Display results summary
        print(f"\n[+] Scan complete!")
        print(f"[+] Total tests executed: {len(all_results)}")
        
        # Analyze and display findings
        print(f"\n[*] Analyzing results...\n")
        findings = analyze_test_results(all_results)
        
        display_findings(findings)
        
    except Exception as e:
        print(f"[!] Error during quick scan: {e}")
        print("Use '-h' for more information on the usage of EdgeSentinel")


# fetch_webpage() - Retrieves HTML and response metadata
# identify_input_parameters() - Extracts all testable parameters from forms, URLs, and AJAX endpoints
# generate_edge_case_payloads() - Creates 7 categories of test payloads targeting specific CWEs
# execute_test_suite() - Runs all tests and captures detailed responses
# analyze_responses() - Detects 10 types of vulnerabilities with severity scoring
# generate_recommendations() - Provides CWE-specific remediation guidance with code examples
# generate_report() - Creates downloadable HTML and JSON reports
# edge_case_scanner() - Main orchestrator function

def fetch_webpage(url, session_obj=None):
    """
    Fetches the HTML content of the target URL and extracts metadata.
    
    Args:
        url (str): Target URL to fetch
        session_obj (requests.Session): Session object for maintaining authentication
    
    Returns:
        dict: Contains 'html', 'status_code', 'headers', 'response_time'
    """
    try:
        # Use session if provided, otherwise use requests directly
        if session_obj is None:
            session_obj = requests
        
        start_time = time.time()
        response = session_obj.get(url, timeout=10, allow_redirects=True)
        response_time = time.time() - start_time
        
        return {
            'html': response.text,
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'response_time': response_time,
            'url': response.url
        }
    except requests.exceptions.ConnectionError:
        print(f"[!] Error: Could not connect to {url}")
        return None
    except requests.exceptions.Timeout:
        print(f"[!] Error: Request to {url} timed out")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[!] HTTP Error: {e}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return None


def identify_input_parameters(html_content, url):
    """
    Parses HTML to identify all input parameters for testing.
    
    Args:
        html_content (str): HTML content from target page or provided HTML form
        url (str): Base URL for resolving relative form actions
    
    Returns:
        list: List of dicts containing form/input metadata
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    parameters = []
    
    # Find all forms
    forms = soup.find_all('form')
    
    for idx, form in enumerate(forms):
        form_action = form.get('action', '')
        # Resolve relative URLs
        if form_action:
            form_action = urljoin(url, form_action)
        else:
            form_action = url
            
        form_method = form.get('method', 'GET').upper()
        
        # Find all input fields in this form
        inputs = form.find_all(['input', 'textarea', 'select'])
        
        for inp in inputs:
            param_name = inp.get('name')
            if not param_name:
                continue
                
            param_type = inp.get('type', 'text')
            param_value = inp.get('value', '')
            placeholder = inp.get('placeholder', '')
            disabled = inp.has_attr('disabled')
            
            parameters.append({
                'param_name': param_name,
                'param_type': param_type,
                'form_action': form_action,
                'method': form_method,
                'context': f'form_{idx}',
                'default_value': param_value,
                'placeholder': placeholder,
                'disabled': disabled
            })
    
    return parameters


def generate_edge_case_payloads():
    """
    Generates comprehensive test payloads for edge case testing.
    Focuses on the first 12 CWEs for quick scan mode.
    
    Returns:
        dict: Categorized payloads for different vulnerability types
    """
    return {
        'error_disclosure': [  # CWE-209, CWE-550
            "' OR '1'='1",
            "1'; DROP TABLE users--",
            "<>\"'`;&|",
            "\x00",
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%s%s%s%s",
            "${7*7}",
            "<script>alert('XSS')</script>",
            "{{7*7}}",
            "1/0",
            "SELECT * FROM users"
        ],
        'missing_param': [  # CWE-234
            "",
            "   ",
            "\t\n",
            None
        ],
        'extra_param': [  # CWE-235
            "admin=true",
            "role=administrator",
            "debug=1"
        ],
        'type_confusion': [  # CWE-248, CWE-369
            "abc",
            "99999999999999999999",
            "0",
            "-1",
            "-999",
            "1.1e308",
            "NaN",
            "Infinity"
        ],
        'special_values': [  # CWE-476, CWE-390
            "null",
            "NULL",
            "nil",
            "true",
            "false",
            "True",
            "False",
            "[]",
            "{}",
            "A" * 10000
        ],
        'status_code_tests': [  # CWE-394
            "/../admin",
            "/../../etc/passwd",
            "//example.com"
        ]
    }


def execute_test_suite(parameter_info, payloads, original_response, session_obj=None):
    """
    Executes all test cases and captures responses for analysis.
    
    Args:
        parameter_info (dict): Parameter metadata from identify_input_parameters()
        payloads (dict): Test payloads from generate_edge_case_payloads()
        original_response (dict): Baseline response from fetch_webpage()
        session_obj (requests.Session): Session object for maintaining authentication
    
    Returns:
        list: Test results with findings
    """
    # Use session if provided, otherwise use requests directly
    if session_obj is None:
        session_obj = requests
    
    results = []
    
    for category, payload_list in payloads.items():
        print(f"[*] Testing {category} payloads...")
        
        for payload in payload_list:
            if payload is None:
                # Test missing parameter - skip sending it
                continue
                
            try:
                start_time = time.time()
                
                # Build request based on method
                if parameter_info['method'] == 'POST':
                    data = {parameter_info['param_name']: payload}
                    response = requests.post(
                        parameter_info['form_action'],
                        data=data,
                        timeout=10,
                        allow_redirects=True
                    )
                else:  # GET
                    params = {parameter_info['param_name']: payload}
                    response = requests.get(
                        parameter_info['form_action'],
                        params=params,
                        timeout=10,
                        allow_redirects=True
                    )
                
                response_time = time.time() - start_time
                
                result = {
                    'payload': str(payload),
                    'category': category,
                    'param_name': parameter_info['param_name'],
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'response_body': response.text,
                    'headers': dict(response.headers),
                    'exception': None,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                results.append(result)
                
                # Add delay to avoid overwhelming the server
                time.sleep(0.3)
                
            except requests.exceptions.Timeout:
                results.append({
                    'payload': str(payload),
                    'category': category,
                    'param_name': parameter_info['param_name'],
                    'exception': 'Timeout',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
            except Exception as e:
                results.append({
                    'payload': str(payload),
                    'category': category,
                    'param_name': parameter_info['param_name'],
                    'exception': str(e),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
    
    return results


# def analyze_responses(test_results, original_response):
#     """
#     Analyzes test results to identify vulnerabilities and anomalies.
#     
#     Args:
#         test_results (list): Results from execute_test_suite()
#         original_response (dict): Baseline response for comparison
#     
#     Returns:
#         list: Detected vulnerabilities with severity and recommendations
#     
#     Detection Logic:
#     
#     1. ERROR MESSAGE DISCLOSURE (CWE-209, CWE-550):
#        - Check for stack traces: "Traceback", "Exception in thread"
#        - Database errors: "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL"
#        - Framework errors: "Django", "Laravel", "Spring", "ASP.NET"
#        - File paths: "C:\\", "/var/www/", "/usr/local/"
#        - Server info: "Apache/2.4", "nginx/1.18", "IIS/10.0"
#        Severity: HIGH if sensitive info exposed
#     
#     2. MISSING PARAMETER HANDLING (CWE-234):
#        - Compare response when param omitted vs. present
#        - Check if error is gracefully handled or crashes
#        - Look for 400 Bad Request vs 500 Internal Server Error
#        Severity: MEDIUM if poor error handling
#     
#     3. EXTRA PARAMETER HANDLING (CWE-235):
#        - Send unexpected parameters
#        - Check if they're ignored or cause errors
#        - Test parameter pollution attacks
#        Severity: MEDIUM if parameters not validated
#     
#     4. UNCAUGHT EXCEPTIONS (CWE-248, CWE-396):
#        - 500 status codes indicate uncaught exceptions
#        - Generic error pages vs. detailed error messages
#        - Check for "Internal Server Error" without details
#        Severity: HIGH if exceptions not caught
#     
#     5. DIVIDE BY ZERO (CWE-369):
#        - Test with "0" in numeric fields
#        - Look for "division by zero" errors
#        Severity: MEDIUM
#     
#     6. RESPONSE TIME ANOMALIES:
#        - Baseline response time vs. test response time
#        - Significant delays might indicate:
#          * Compute-intensive error handling
#          * Timing-based attacks working
#          * Resource exhaustion
#        Severity: Variable based on context
#     
#     7. STATUS CODE ANOMALIES (CWE-394):
#        - Unexpected 3xx redirects
#        - 403 Forbidden (insufficient privileges - CWE-274, CWE-280)
#        - 500-series errors
#        - Inconsistent status codes for similar inputs
#        Severity: Based on context
#     
#     8. CONTENT DIFFERENCES:
#        - Use difflib to compare response bodies
#        - Significant differences indicate:
#          * Different code paths executed
#          * Error conditions triggered
#          * Potential injection success
#        - Calculate similarity ratio
#        Severity: Variable
#     
#     9. HEADER ANOMALIES:
#        - X-Debug headers appearing
#        - Changed Content-Type (might indicate error page)
#        - Security headers missing on error pages
#        Severity: LOW to MEDIUM
#     
#     10. RESPONSE SIZE ANOMALIES:
#         - Unusually large responses (verbose errors)
#         - Unusually small responses (crashed)
#         - Deviation from baseline size
#         Severity: LOW
#     
#     Implementation:
#         1. Create finding structure:
#            {
#                'cwe_id': 'CWE-209',
#                'cwe_name': 'Generation of Error Message Containing Sensitive Information',
#                'severity': 'HIGH',
#                'description': 'Stack trace exposed in error response',
#                'evidence': {
#                    'payload': '<test_payload>',
#                    'response_snippet': '...',
#                    'status_code': 500
#                },
#                'affected_parameter': 'search',
#                'recommendation': 'Implement generic error pages...',
#                'remediation_code': '...'
#            }
#         
#         2. For each test result:
#            - Run all detection checks
#            - Score severity based on multiple factors
#            - Deduplicate similar findings
#            - Prioritize by severity
#         
#         3. Return sorted list of findings
#     """
#     pass


# def generate_recommendations(vulnerability):
#     """
#     Generates specific remediation advice for each vulnerability type.
#     
#     Args:
#         vulnerability (dict): Vulnerability details from analyze_responses()
#     
#     Returns:
#         dict: Detailed recommendations with code examples
#     
#     Recommendations by CWE:
#     
#     CWE-209 (Error Message Disclosure):
#         - Use generic error pages for production
#         - Log detailed errors server-side only
#         - Never expose stack traces to users
#         - Example code for custom error handlers
#     
#     CWE-234 (Missing Parameter):
#         - Validate all required parameters
#         - Return 400 Bad Request with clear message
#         - Provide default values where appropriate
#         - Example validation code
#     
#     CWE-235 (Extra Parameters):
#         - Whitelist expected parameters
#         - Reject or ignore unexpected parameters
#         - Log suspicious extra parameters
#         - Example parameter filtering code
#     
#     CWE-248 (Uncaught Exception):
#         - Implement global exception handlers
#         - Catch specific exceptions first
#         - Always have a catch-all for unexpected errors
#         - Example try/catch structures
#     
#     CWE-369 (Divide By Zero):
#         - Validate numeric inputs before operations
#         - Check for zero before division
#         - Handle edge cases explicitly
#         - Example validation code
#     
#     CWE-476 (NULL Pointer):
#         - Check for null/None before using values
#         - Use optional chaining where available
#         - Provide default values
#         - Example null checking code
#     
#     CWE-550 (Server Error Disclosure):
#         - Configure web server to hide version info
#         - Use custom error pages
#         - Disable debug mode in production
#         - Server configuration examples
#     
#     General Security Headers:
#         - Add X-Content-Type-Options: nosniff
#         - Add X-Frame-Options: DENY
#         - Add Content-Security-Policy
#         - Example header configuration
#     
#     Implementation:
#         Return dict with:
#         {
#             'summary': 'Brief recommendation',
#             'detailed_steps': ['Step 1...', 'Step 2...'],
#             'code_example': 'Code snippet...',
#             'references': ['OWASP link', 'CWE link']
#         }
#     """
#     pass


# def generate_report(url, findings, test_summary):
#     """
#     Generates comprehensive HTML and JSON reports of findings.
#     
#     Args:
#         url (str): Target URL tested
#         findings (list): Vulnerabilities from analyze_responses()
#         test_summary (dict): Statistics about tests performed
#     
#     Returns:
#         tuple: (html_report_path, json_report_path)
#     
#     Report Structure:
#     
#     1. EXECUTIVE SUMMARY:
#        - Target URL and test timestamp
#        - Total tests performed
#        - Vulnerabilities found (by severity)
#        - Overall security score (0-100)
#        - High-level risk assessment
#     
#     2. VULNERABILITY DETAILS:
#        For each finding:
#        - CWE ID and name
#        - Severity (Critical/High/Medium/Low)
#        - Description of issue
#        - Affected parameter/endpoint
#        - Proof of concept (payload used)
#        - Response evidence (status, headers, body snippet)
#        - Impact assessment
#        - Remediation steps
#        - Code examples for fixing
#     
#     3. TEST COVERAGE:
#        - Parameters tested
#        - Payload categories used
#        - Total requests sent
#        - Success/failure rates
#        - Time taken for scan
#     
#     4. DETAILED TEST LOG:
#        - Table of all tests performed
#        - Request/response pairs
#        - Anomalies detected
#        - Filter by severity/category
#     
#     5. RECOMMENDATIONS SUMMARY:
#        - Prioritized action items
#        - Quick wins (easy fixes)
#        - Long-term improvements
#        - Best practices checklist
#     
#     6. APPENDIX:
#        - Methodology explanation
#        - CWE reference guide
#        - OWASP A10 overview
#        - Tool version and configuration
#     
#     HTML Report Implementation:
#         - Use template with CSS for styling
#         - Color-coded severity levels
#         - Collapsible sections for details
#         - Syntax highlighting for code examples
#         - Charts showing vulnerability distribution
#         - Downloadable as single HTML file
#     
#     JSON Report Implementation:
#         - Structured data for programmatic access
#         - Include all raw test results
#         - Machine-readable format
#         - Can be imported into other tools
#     
#     File Naming:
#         - HTML: "edgesentinel_report_{url}_{timestamp}.html"
#         - JSON: "edgesentinel_report_{url}_{timestamp}.json"
#         - Save to current directory or specified output path
#     
#     Example HTML Template Structure:
#         <!DOCTYPE html>
#         <html>
#         <head>
#             <title>EdgeSentinel Security Report</title>
#             <style>
#                 .critical { color: red; }
#                 .high { color: orange; }
#                 .medium { color: yellow; }
#                 .low { color: blue; }
#             </style>
#         </head>
#         <body>
#             <h1>Security Scan Report for {url}</h1>
#             <section id="summary">...</section>
#             <section id="findings">...</section>
#             ...
#         </body>
#         </html>
#     """
#     pass


# def edge_case_scanner(url, target_parameter=None, output_format='both'):
#     """
#     Main orchestration function for edge case testing.
#     
#     Args:
#         url (str): Target URL to test
#         target_parameter (str, optional): Specific parameter to test
#                                          If None, tests all parameters
#         output_format (str): 'html', 'json', or 'both'
#     
#     Returns:
#         dict: Scan results and report paths
#     
#     Workflow:
#         1. Validate URL format and accessibility
#         2. Fetch target webpage
#         3. Identify all input parameters
#         4. If target_parameter specified, filter to that parameter
#         5. Generate edge case payloads
#         6. Execute test suite for each parameter
#         7. Analyze all responses for vulnerabilities
#         8. Generate remediation recommendations
#         9. Create and save reports
#         10. Display summary to console
#         11. Return results
#     
#     Error Handling:
#         - Invalid URL format
#         - Unreachable target
#         - No parameters found
#         - Network errors during testing
#         - Report generation failures
#     
#     Progress Reporting:
#         - Print status updates during scan
#         - Show progress bar for test execution
#         - Indicate when vulnerabilities are found
#         - Final summary with report location
#     
#     Example Usage:
#         results = edge_case_scanner(
#             url='https://example.com/search',
#             target_parameter='q',
#             output_format='both'
#         )
#         print(f"Report saved to: {results['html_report']}")
#     
#     Console Output Example:
#         [*] EdgeSentinel - Edge Case Vulnerability Scanner
#         [*] Target: https://example.com/search
#         [+] Fetching webpage...
#         [+] Found 3 input parameters
#         [*] Testing parameter: q (text input)
#         [*] Running 147 test cases...
#         [!] Found CWE-209: Error message disclosure (HIGH)
#         [!] Found CWE-234: Missing parameter handling (MEDIUM)
#         [+] Scan complete!
#         [+] Total vulnerabilities: 2 (1 HIGH, 1 MEDIUM)
#         [+] Report saved to: edgesentinel_report_example.com_20260127_103045.html
#         [+] JSON data saved to: edgesentinel_report_example.com_20260127_103045.json
#     """
#     pass


# ============================================================================
# INTEGRATION WITH EXISTING SCANNER
# ============================================================================
# To integrate this edge case scanner with the existing CWE scanner:
#
# 1. Add command-line argument for edge case scanning:
#    parser.add_argument("-e", "--edge-case", 
#                        help="Run edge case scanner on target parameter",
#                        metavar="PARAM_NAME")
#
# 2. In main() function, add condition:
#    elif (arguments.edge_case):
#        edge_case_scanner(url, target_parameter=arguments.edge_case)
#
# 3. Can also combine with existing scans:
#    - Run static CWE analysis first
#    - Then run dynamic edge case testing
#    - Combine results into unified report
#
# 4. Example usage:
#    python edgesentinel.py https://example.com/search -e q
#    (Tests the 'q' parameter with edge cases)
#
#    python edgesentinel.py https://example.com/search -e
#    (Automatically detects and tests all parameters)
# ============================================================================


def analyze_test_results(results):
    """Analyze test results and identify vulnerabilities"""
    findings = []
    
    for result in results:
        if 'exception' in result and result.get('exception'):
            # Skip results with exceptions for now
            continue
            
        if 'status_code' not in result:
            continue
            
        status = result['status_code']
        body = result.get('response_body', '')
        category = result.get('category', '')
        payload = result.get('payload', '')
        
        # CWE-209: Error message disclosure
        if status == 500 or 'error' in body.lower() or 'exception' in body.lower():
            if any(keyword in body.lower() for keyword in ['traceback', 'stack trace', 'sql', 'mysql', 'postgresql', 'oracle']):
                findings.append({
                    'cwe': 'CWE-209',
                    'name': 'Generation of Error Message Containing Sensitive Information',
                    'severity': 'HIGH',
                    'payload': payload,
                    'evidence': f"Status: {status}, Response contains error details",
                    'param': result.get('param_name', 'unknown')
                })
        
        # CWE-234: Missing parameter handling
        if category == 'missing_param' and status == 500:
            findings.append({
                'cwe': 'CWE-234',
                'name': 'Failure to Handle Missing Parameter',
                'severity': 'MEDIUM',
                'payload': payload,
                'evidence': f"Status: {status} when parameter missing/empty",
                'param': result.get('param_name', 'unknown')
            })
        
        # CWE-369: Divide by zero
        if category == 'type_confusion' and payload == '0' and status == 500:
            findings.append({
                'cwe': 'CWE-369',
                'name': 'Divide By Zero',
                'severity': 'MEDIUM',
                'payload': payload,
                'evidence': f"Status: {status} when zero value provided",
                'param': result.get('param_name', 'unknown')
            })
        
        # CWE-394: Unexpected status code
        if status not in [200, 201, 204, 301, 302, 400, 401, 403, 404]:
            findings.append({
                'cwe': 'CWE-394',
                'name': 'Unexpected Status Code or Return Value',
                'severity': 'LOW',
                'payload': payload,
                'evidence': f"Unusual status code: {status}",
                'param': result.get('param_name', 'unknown')
            })
    
    return findings


def display_findings(findings):
    """Display findings in a formatted way"""
    if not findings:
        print("[+] No vulnerabilities detected!")
        return
    
    print(f"[!] Found {len(findings)} potential vulnerability/vulnerabilities:\n")
    
    severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    for finding in findings:
        severity = finding['severity']
        severity_counts[severity] += 1
        
        print(f"[{severity}] {finding['cwe']}: {finding['name']}")
        print(f"    Parameter: {finding['param']}")
        print(f"    Payload: {finding['payload'][:100]}..." if len(finding['payload']) > 100 else f"    Payload: {finding['payload']}")
        print(f"    Evidence: {finding['evidence']}")
        print()
    
    print(f"\n[*] Summary:")
    print(f"    HIGH severity: {severity_counts['HIGH']}")
    print(f"    MEDIUM severity: {severity_counts['MEDIUM']}")
    print(f"    LOW severity: {severity_counts['LOW']}")


def specify_scan(url, scan_cwe):
    "function will scan for specified CWEs"
    try:
        cwes = {1 : "CWE-209 Generation of Error Message Containing "
                "Sensitive Information", 2 : "CWE-215 Insertion of Sensitive "
                "Information Into Debugging Code", 3 : "CWE-234 Failure to "
                "Handle Missing Parameter", 4 : "CWE-235 Improper Handling of "
                "Extra Parameters", 5 : "CWE-248 Uncaught Exception", 
                6 : "CWE-252 Unchecked Return Value", 7 : "CWE-274 Improper "
                "Handling of Insufficient Privileges", 8 : "CWE-280 Improper "
                "Handling of Insufficient Permissions or Privileges", 
                9 : "CWE-369 Divide By Zero", 10 : "CWE-390 Detection of "
                "Error Condition Without Action", 11 : "CWE-391 Unchecked "
                "Error Condition", 12 : "CWE-394 Unexpected Status Code or "
                "Return Value", 13 : "CWE-396 Declaration of Catch for "
                "Generic Exception", 14 : "CWE-397 Declaration of Throws for "
                "Generic Exception", 15 : "CWE-460 Improper Cleanup on Thrown "
                "Exception", 16 : "CWE-476 NULL Pointer Dereference", 
                17 : "CWE-478 Missing Default Case in Multiple Condition "
                "Expression", 18 : "CWE-484 Omitted Break Statement in Switch",
                19 : "CWE-550 Server-generated Error Message Containing "
                "Sensitive Information", 20 : "CWE-636 Not Failing Securely "
                "('Failing Open')", 21 : "CWE-703 Improper Check or Handling "
                "of Exceptional Conditions", 22 : "CWE-754 Improper Check for "
                "Unusual or Exceptional Conditions", 23 : "CWE-755 Improper "
                "Handling of Exceptional Conditions", 24 : "CWE-756 Missing "
                "Custom Error Page"}
        scan_cwe = [int(number) for number in scan_cwe]

        print("Conducting scanning for the chosen CWES:\n")
        for number in scan_cwe:
            print(f"{number}. {cwes[number]}")

    except ValueError:
        print("CWEs specified can only be integers from 1-24")


def default_scan(url):
    "function will scan for all 24 CWEs under A10"
    try:
        print(f"Conducting scanning for all 24 CWEs for {url}")

    except:
        print("Use '-h' for more information on the usage of EdgeSentinel")



def main():
    parser = argparse.ArgumentParser(description="EdgeSentinel is a command "
                                     "line focused detection tool that helps "
                                     "testers and developers identify OWASP "
                                     "A10 relevant weaknesses from a target "
                                     "URL", formatter_class=RawTextHelpFormatter)
    parser.add_argument("url", help="Target URL to be analysed for all 24 "
                        "CWEs under A10 by default unless the '-q' or '-s' "
                        "flag is specified")
    parser_args = parser.add_mutually_exclusive_group(required=False) 
    parser_args.add_argument("-q", "--quick_scan", action="store_true", 
                             help="Used to specify a quick analysis, "
                                "checking for the first 12 CWEs under A10 "
                                "instead of doing a complete analysis for all "
                                "24 CWEs")
    parser.add_argument("-a", "--html_form",
                        help="HTML form to run the script on. "
                            "Example: -a='<input>$test$</input>'",
                        metavar="HTML")
    parser.add_argument("-u", "--username",
                        help="Username for authentication (use with -p/--password and -l/--login-url)",
                        metavar="USERNAME")
    parser.add_argument("-p", "--password",
                        help="Password for authentication (use with -u/--username and -l/--login-url)",
                        metavar="PASSWORD")
    parser.add_argument("-l", "--login-url",
                        help="Login page URL for authentication (use with -u/--username and -p/--password)",
                        metavar="LOGIN_URL")
    parser.add_argument("--username-field",
                        help="Name of the username form field (default: 'username')",
                        default="username",
                        metavar="FIELD")
    parser.add_argument("--password-field",
                        help="Name of the password form field (default: 'password')",
                        default="password",
                        metavar="FIELD")
    parser_args.add_argument("-s", "--specify",
                             help="Used to specify the CWEs to be tested "
                                "for, using numbers separated by commas."
                                "\nThe list of CWEs are as follows:\n1. "
                                "CWE-209 Generation of Error Message "
                                "Containing Sensitive Information\n2. CWE-215 "
                                "Insertion of Sensitive Information Into "
                                "Debugging Code\n3. CWE-234 Failure to Handle "
                                "Missing Parameter\n4. CWE-235 Improper "
                                "Handling of Extra Parameters\n5. CWE-248 "
                                "Uncaught Exception\n6. CWE-252 Unchecked "
                                "Return Value\n7. CWE-274 Improper Handling "
                                "of Insufficient Privileges\n8. CWE-280 "
                                "Improper Handling of Insufficient "
                                "Permissions or Privileges\n9. CWE-369 Divide "
                                "By Zero\n10. CWE-390 Detection of Error "
                                "Condition Without Action\n11. CWE-391 "
                                "Unchecked Error Condition\n12. CWE-394 "
                                "Unexpected Status Code or Return Value\n13. "
                                "CWE-396 Declaration of Catch for Generic "
                                "Exception\n14. CWE-397 Declaration of Throws "
                                "for Generic Exception\n15. CWE-460 Improper "
                                "Cleanup on Thrown Exception\n16. CWE-476 "
                                "NULL Pointer Dereference\n17. CWE-478 "
                                "Missing Default Case in Multiple Condition "
                                "Expression\n18. CWE-484 Omitted Break "
                                "Statement in Switch\n19. CWE-550 "
                                "Server-generated Error Message Containing "
                                "Sensitive Information\n20. CWE-636 Not "
                                "Failing Securely ('Failing Open')\n21. "
                                "CWE-703 Improper Check or Handling of "
                                "Exceptional Conditions\n22. CWE-754 Improper "
                                "Check for Unusual or Exceptional Conditions\n"
                                "23. CWE-755 Improper Handling of Exceptional "
                                "Conditions\n24. CWE-756 Missing Custom "
                                "Error Page")
            
    arguments = parser.parse_args()
    url = arguments.url
    html_form = arguments.html_form if hasattr(arguments, 'html_form') else None
    
    # Handle authentication if credentials provided
    if arguments.username and arguments.password and arguments.login_url:
        login_success = login_to_website(
            login_url=arguments.login_url,
            username=arguments.username,
            password=arguments.password,
            username_field=arguments.username_field,
            password_field=arguments.password_field
        )
        
        if not login_success:
            print("[!] Failed to authenticate. Exiting...")
            print("[*] Tip: Check your credentials and login URL")
            return
    elif any([arguments.username, arguments.password, arguments.login_url]):
        print("[!] Error: Authentication requires all three: --username, --password, and --login-url")
        print("    Use '-h' for more information")
        return

    if (arguments.quick_scan):
        quick_scan(url, html_form, session_obj=session)
    elif (arguments.specify):
        scan_cwe = (arguments.specify).split(",")
        specify_scan(url, scan_cwe)
    else:
        default_scan(url)


if __name__=='__main__':
    main()
