#!/usr/bin/env python3
"""
EdgeSentinel (CLI only)
- Bounded crawl (depth/page limits)
- Finds endpoints (links + forms)
- Runs A10 edge-case requests (missing/extra params, type confusion, encoding, etc.)
- Analyzes responses (error disclosure, 5xx, unexpected status changes, timing anomalies)
- Writes JSON + HTML report
"""

# Normal (all CWEs 1-24)
#python edgesentinel.py https://example.com

# Quick scan (CWEs 1-12)
#python edgesentinel.py https://example.com -q

# Specific CWEs (by your numbering)
#python edgesentinel.py https://example.com -s 1,3,4,5,12

# Bounded crawl controls
#python edgesentinel.py https://example.com --depth 2 --max-pages 15

# Scan only the given URL (no crawling)
#python edgesentinel.py https://example.com --no-crawl

# Only test one parameter name
#python edgesentinel.py https://example.com --param q

from __future__ import annotations
import argparse
from argparse import RawTextHelpFormatter
from dataclasses import dataclass, asdict
from datetime import datetime
from html import escape
import json
import re
import time
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import requests
from bs4 import BeautifulSoup

# CWE mapping
CWE_LIST = {
    1: ("CWE-209", "Generation of Error Message Containing Sensitive Information"),
    2: ("CWE-215", "Insertion of Sensitive Information Into Debugging Code"),
    3: ("CWE-234", "Failure to Handle Missing Parameter"),
    4: ("CWE-235", "Improper Handling of Extra Parameters"),
    5: ("CWE-248", "Uncaught Exception"),
    6: ("CWE-252", "Unchecked Return Value"),
    7: ("CWE-274", "Improper Handling of Insufficient Privileges"),
    8: ("CWE-280", "Improper Handling of Insufficient Permissions or Privileges"),
    9: ("CWE-369", "Divide By Zero"),
    10: ("CWE-390", "Detection of Error Condition Without Action"),
    11: ("CWE-391", "Unchecked Error Condition"),
    12: ("CWE-394", "Unexpected Status Code or Return Value"),
    13: ("CWE-396", "Declaration of Catch for Generic Exception"),
    14: ("CWE-397", "Declaration of Throws for Generic Exception"),
    15: ("CWE-460", "Improper Cleanup on Thrown Exception"),
    16: ("CWE-476", "NULL Pointer Dereference"),
    17: ("CWE-478", "Missing Default Case in Multiple Condition Expression"),
    18: ("CWE-484", "Omitted Break Statement in Switch"),
    19: ("CWE-550", "Server-generated Error Message Containing Sensitive Information"),
    20: ("CWE-636", "Not Failing Securely ('Failing Open')"),
    21: ("CWE-703", "Improper Check or Handling of Exceptional Conditions"),
    22: ("CWE-754", "Improper Check for Unusual or Exceptional Conditions"),
    23: ("CWE-755", "Improper Handling of Exceptional Conditions"),
    24: ("CWE-756", "Missing Custom Error Page"),
}

# Quick scan = first 12
QUICK_SCAN_SET = set(range(1, 13))

# -----------------------------
# CWE-specific recommendations + code examples
# Keyed by CWE ID string (e.g. "CWE-209")
# -----------------------------
CWE_RECOMMENDATIONS = {
    "CWE-209": {
        "summary": "Return generic error messages to users. Log full details server-side only.",
        "bad": """\
# BAD: Leaks internal detail to the client
except Exception as e:
    return jsonify({"error": str(e)}), 500  # exposes stack trace / DB message""",
        "good": """\
# GOOD: Generic message to client, full detail in server log
import logging
except Exception as e:
    logging.exception("Unhandled error in /api/endpoint")
    return jsonify({"error": "An unexpected error occurred. Please try again."}), 500""",
    },
    "CWE-215": {
        "summary": "Disable debug endpoints and verbose logging in production. Remove phpinfo(), .env, and debug routes.",
        "bad": """\
# BAD: Debug info accessible in production
@app.route('/phpinfo')
def phpinfo():
    return subprocess.check_output(['php', '-i'])  # exposes server config""",
        "good": """\
# GOOD: Guard debug routes with environment checks
import os
@app.route('/debug')
def debug_info():
    if os.environ.get('FLASK_ENV') != 'development':
        abort(404)  # Completely hide in production
    return jsonify({"status": "dev mode"})""",
    },
    "CWE-234": {
        "summary": "Validate all required parameters and return 400 Bad Request with a safe message when missing.",
        "bad": """\
# BAD: No check for missing parameter — crashes or behaves unexpectedly
@app.route('/search')
def search():
    query = request.args.get('q')
    results = db.execute(f"SELECT * FROM items WHERE name='{query}'")  # query may be None""",
        "good": """\
# GOOD: Validate presence before use
@app.route('/search')
def search():
    query = request.args.get('q')
    if not query:
        return jsonify({"error": "Parameter 'q' is required."}), 400
    results = db.search(query)
    return jsonify(results)""",
    },
    "CWE-235": {
        "summary": "Whitelist expected parameters. Ignore or reject any unexpected extras.",
        "bad": """\
# BAD: Extra params like ?admin=true silently change behavior
@app.route('/data')
def data():
    if request.args.get('admin'):   # attacker-supplied extra param
        return admin_data()
    return user_data()""",
        "good": """\
# GOOD: Only read the exact parameters you expect
ALLOWED_PARAMS = {'page', 'limit', 'sort'}
@app.route('/data')
def data():
    unexpected = set(request.args.keys()) - ALLOWED_PARAMS
    if unexpected:
        return jsonify({"error": "Unexpected parameters"}), 400
    page = int(request.args.get('page', 1))
    return user_data(page)""",
    },
    "CWE-248": {
        "summary": "Catch all exceptions at the application boundary. Never let uncaught exceptions reach the client.",
        "bad": """\
# BAD: Uncaught exception returns Werkzeug/Django debug page
@app.route('/process')
def process():
    value = int(request.args['value'])   # raises ValueError if not a number
    return jsonify({"result": 100 / value})  # raises ZeroDivisionError if 0""",
        "good": """\
# GOOD: Explicit exception handling at every risky operation
@app.route('/process')
def process():
    try:
        value = int(request.args.get('value', ''))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid value; must be a non-zero integer."}), 400
    if value == 0:
        return jsonify({"error": "Value must not be zero."}), 400
    return jsonify({"result": 100 / value})""",
    },
    "CWE-252": {
        "summary": "Always check return values. Propagate errors explicitly; do not silently continue.",
        "bad": """\
# BAD: Return value ignored — execution continues on failure
def save_user(data):
    db.insert(data)   # may return False / raise — never checked
    return "Saved"    # always reports success""",
        "good": """\
# GOOD: Check the return value and propagate failure
def save_user(data):
    success = db.insert(data)
    if not success:
        raise RuntimeError("Database insert failed for user data")
    return "Saved" """,
    },
    "CWE-274": {
        "summary": "Fail closed on missing or unexpected privilege values. Default to deny, not allow.",
        "bad": """\
# BAD: Missing role defaults to granting access
@app.route('/admin')
def admin():
    role = request.args.get('role')
    if role == 'admin':
        return admin_panel()
    # No else — falls through and returns admin_panel() anyway""",
        "good": """\
# GOOD: Explicit deny-by-default
@app.route('/admin')
def admin():
    role = session.get('role')          # Read from trusted server-side session
    if role != 'admin':                 # Anything other than 'admin' is denied
        return jsonify({"error": "Forbidden"}), 403
    return admin_panel()""",
    },
    "CWE-280": {
        "summary": "Enforce permission checks server-side using trusted session data, not client-supplied parameters.",
        "bad": """\
# BAD: Permission determined by user-supplied parameter
@app.route('/file')
def get_file():
    if request.args.get('perm') == 'read':
        return send_file('secret.txt')  # attacker passes ?perm=read""",
        "good": """\
# GOOD: Check permission from server-side session/ACL
@app.route('/file')
def get_file():
    user_id = session.get('user_id')
    if not acl.can_read(user_id, 'secret.txt'):
        return jsonify({"error": "Forbidden"}), 403
    return send_file('secret.txt')""",
    },
    "CWE-369": {
        "summary": "Guard every division operation with an explicit zero check before dividing.",
        "bad": """\
# BAD: No check — crashes with ZeroDivisionError when divisor=0
result = numerator / int(request.args.get('divisor'))""",
        "good": """\
# GOOD: Validate before dividing
divisor = int(request.args.get('divisor', '1'))
if divisor == 0:
    return jsonify({"error": "Divisor must not be zero."}), 400
result = numerator / divisor""",
    },
    "CWE-390": {
        "summary": "Always take corrective action when an error is detected. Do not silently absorb exceptions.",
        "bad": """\
# BAD: Exception caught but nothing is done — processing continues
try:
    result = risky_operation()
except Exception:
    pass    # error detected, zero action taken
return result  # result may be undefined / stale""",
        "good": """\
# GOOD: Log the error and return a safe response
try:
    result = risky_operation()
except Exception as e:
    logging.error("risky_operation failed: %s", e)
    return jsonify({"error": "Operation failed. Please try again."}), 500""",
    },
    "CWE-391": {
        "summary": "Check every error condition. Do not allow execution to continue when an operation has failed.",
        "bad": """\
# BAD: Error condition ignored — execution proceeds with invalid state
data = fetch_from_db(user_id)   # returns None on failure
name = data['name']             # KeyError / TypeError if data is None""",
        "good": """\
# GOOD: Halt and return safe response when an error condition is found
data = fetch_from_db(user_id)
if data is None:
    return jsonify({"error": "User not found."}), 404
name = data['name']""",
    },
    "CWE-394": {
        "summary": "Validate status codes from all calls. Treat unexpected codes as errors, not successes.",
        "bad": """\
# BAD: Non-200 status codes silently ignored
resp = requests.get(upstream_url)
return jsonify(resp.json())   # may forward 500/403 responses as success""",
        "good": """\
# GOOD: Explicitly check status before using response
resp = requests.get(upstream_url, timeout=5)
if resp.status_code != 200:
    logging.warning("Upstream returned %d", resp.status_code)
    return jsonify({"error": "Upstream service error."}), 502
return jsonify(resp.json())""",
    },
    "CWE-396": {
        "summary": "Catch specific exceptions, not the base Exception class. Handle each error type appropriately.",
        "bad": """\
# BAD: Catches everything — masks programming errors and hides specific failures
try:
    process(data)
except Exception:   # too broad — catches ValueError, TypeError, IOError alike
    return "Error" """,
        "good": """\
# GOOD: Specific exception types with tailored handling
try:
    process(data)
except ValueError as e:
    return jsonify({"error": f"Invalid input: {e}"}), 400
except IOError as e:
    logging.error("IO failure: %s", e)
    return jsonify({"error": "Service temporarily unavailable."}), 503""",
    },
    "CWE-397": {
        "summary": "Declare specific checked exceptions in method signatures rather than throwing generic Exception.",
        "bad": """\
// BAD (Java): Declares throws Exception — callers cannot distinguish error types
public void processOrder(Order o) throws Exception {
    if (o == null) throw new Exception("Null order");
}""",
        "good": """\
// GOOD (Java): Specific exception type communicates intent
public void processOrder(Order o) throws IllegalArgumentException, OrderProcessingException {
    if (o == null) throw new IllegalArgumentException("Order must not be null");
    // ...
}""",
    },
    "CWE-460": {
        "summary": "Release resources (files, connections, locks) in finally blocks or use try-with-resources.",
        "bad": """\
# BAD: File never closed if exception occurs between open and close
f = open('data.txt', 'r')
data = f.read()
process(data)   # if this throws, f.close() is never reached
f.close()""",
        "good": """\
# GOOD: Context manager guarantees cleanup on exit or exception
with open('data.txt', 'r') as f:
    data = f.read()
    process(data)  # file is closed even if this raises""",
    },
    "CWE-476": {
        "summary": "Always check for null/None before dereferencing objects. Use safe defaults or early returns.",
        "bad": """\
# BAD: Direct property access without null check — crashes if user is None
user = db.find_user(user_id)
return jsonify({"name": user["name"]})   # TypeError if user is None""",
        "good": """\
# GOOD: Explicit None check before access
user = db.find_user(user_id)
if user is None:
    return jsonify({"error": "User not found."}), 404
return jsonify({"name": user["name"]})""",
    },
    "CWE-478": {
        "summary": "Always include a default case in switch/match statements to handle unexpected values safely.",
        "bad": """\
// BAD (Java): No default — unexpected values silently do nothing
switch (status) {
    case "active":   enable();  break;
    case "inactive": disable(); break;
    // missing default — "pending", null, etc. are silently ignored
}""",
        "good": """\
// GOOD (Java): Default case handles unexpected values explicitly
switch (status) {
    case "active":   enable();  break;
    case "inactive": disable(); break;
    default:
        logger.warn("Unknown status: " + status);
        throw new IllegalArgumentException("Unrecognized status: " + status);
}""",
    },
    "CWE-484": {
        "summary": "Include break statements in every switch case. Use fall-through only when explicitly intended and documented.",
        "bad": """\
// BAD (Java): Missing break causes unintended fall-through
switch (level) {
    case 1: grantBasicAccess();   // falls through to case 2!
    case 2: grantAdminAccess();   // unintentionally executed for level=1
    case 3: grantSuperAccess(); break;
}""",
        "good": """\
// GOOD (Java): Every case has an explicit break
switch (level) {
    case 1: grantBasicAccess(); break;
    case 2: grantAdminAccess(); break;
    case 3: grantSuperAccess(); break;
    default: throw new IllegalArgumentException("Unknown level: " + level);
}""",
    },
    "CWE-550": {
        "summary": "Configure the server to suppress technical error details. Use custom error handlers that return safe messages.",
        "bad": """\
# BAD (PHP): display_errors = On in production
# php.ini: display_errors = On
# Results in: Fatal error: Uncaught PDOException: SQLSTATE[42000]:
#   Syntax error ... in /var/www/html/db.php on line 47""",
        "good": """\
# GOOD (PHP): Suppress display, log to file instead
# php.ini:
#   display_errors = Off
#   log_errors = On
#   error_log = /var/log/php_errors.log

# GOOD (Flask): Register a generic error handler
@app.errorhandler(500)
def server_error(e):
    app.logger.exception("Internal error: %s", e)
    return jsonify({"error": "Internal server error."}), 500""",
    },
    "CWE-636": {
        "summary": "Default to deny. Ensure all code paths — including edge cases and empty values — require positive authorization.",
        "bad": """\
# BAD: Only checks the 'admin' case — all other inputs fall through to access
def authorize(role):
    if role == 'admin':
        return True
    # No explicit deny — returns None (falsy but not False)
    # Caller doing `if authorize(role):` may treat None as False, but
    # the function itself never enforces denial""",
        "good": """\
# GOOD: Explicit allowlist — everything else is denied, including None/empty
ALLOWED_ROLES = {'admin'}
def authorize(role):
    if not role or role.strip() not in ALLOWED_ROLES:
        return False    # deny-by-default
    return True""",
    },
    "CWE-703": {
        "summary": "Implement consistent error handling for all exceptional conditions. Log anomalies and return safe, uniform responses.",
        "bad": """\
# BAD: Some paths handle errors, others crash silently
@app.route('/data')
def data():
    try:
        return fetch_data()
    except DatabaseError:
        return "DB Error", 500
    # ValueError, TypeError, etc. are unhandled — crash with 500 + stack trace""",
        "good": """\
# GOOD: Catch-all handler with specific types handled first
@app.route('/data')
def data():
    try:
        return fetch_data()
    except ValueError as e:
        return jsonify({"error": "Invalid input."}), 400
    except DatabaseError as e:
        logging.error("DB error: %s", e)
        return jsonify({"error": "Service unavailable."}), 503
    except Exception as e:
        logging.exception("Unexpected error in /data")
        return jsonify({"error": "Unexpected error."}), 500""",
    },
    "CWE-754": {
        "summary": "Validate inputs for unusual/boundary values (empty, NaN, Infinity, oversized) before processing.",
        "bad": """\
# BAD: No boundary checks — special values cause crashes
@app.route('/calc')
def calc():
    x = float(request.args.get('x'))  # 'NaN', 'Infinity', '' all accepted
    return jsonify({"result": 100 / x})""",
        "good": """\
# GOOD: Validate for unusual conditions before use
import math
@app.route('/calc')
def calc():
    try:
        x = float(request.args.get('x', ''))
    except (ValueError, TypeError):
        return jsonify({"error": "x must be a valid number."}), 400
    if math.isnan(x) or math.isinf(x):
        return jsonify({"error": "x must be a finite number."}), 400
    if x == 0:
        return jsonify({"error": "x must not be zero."}), 400
    return jsonify({"result": 100 / x})""",
    },
    "CWE-755": {
        "summary": "Handle all exceptional conditions (overflow, encoding errors, resource limits) explicitly. Do not let them propagate as unhandled exceptions.",
        "bad": """\
# BAD: Special input types crash the server
@app.route('/process')
def process():
    value = request.args.get('value', '')
    if int(value) > 2147483647:   # ValueError if value isn't numeric
        raise OverflowError("Too large")  # Unhandled — 500 with stack trace""",
        "good": """\
# GOOD: Validate and handle all edge cases gracefully
@app.route('/process')
def process():
    value = request.args.get('value', '')
    try:
        num = int(value)
    except (ValueError, TypeError):
        return jsonify({"error": "value must be an integer."}), 400
    if not (-2147483648 <= num <= 2147483647):
        return jsonify({"error": "value is out of the supported range."}), 400
    return jsonify({"result": num * 2})""",
    },
    "CWE-756": {
        "summary": "Define custom error pages for all HTTP error codes (400, 403, 404, 500). Never expose default server error pages.",
        "bad": """\
# BAD: No custom error handlers — Flask/Werkzeug default pages shown
# These expose server name, version, and stack traces""",
        "good": """\
# GOOD (Flask): Register custom handlers for all common error codes
@app.errorhandler(400)
def bad_request(e):
    return render_template('errors/400.html'), 400

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    app.logger.exception("Server error: %s", e)
    return render_template('errors/500.html'), 500

# Apache .htaccess equivalent:
# ErrorDocument 400 /errors/400.html
# ErrorDocument 404 /errors/404.html
# ErrorDocument 500 /errors/500.html""",
    },
}


# Data models
@dataclass
class Endpoint:
    kind: str                 # "link" | "form"
    url: str                  # absolute URL
    method: str               # GET/POST (forms), GET for links
    params: List[str]         # parameters we can test
    context: str              # short description (where it came from)


@dataclass
class Baseline:
    status_code: int
    elapsed_ms: int
    headers: Dict[str, str]
    body_snippet: str
    content_len: int


@dataclass
class TestResult:
    endpoint_url: str
    method: str
    parameter: str
    category: str
    payload: Optional[str]          # None for omitted param
    sent_params: Dict[str, str]
    status_code: Optional[int]
    elapsed_ms: Optional[int]
    content_len: Optional[int]
    body_snippet: str
    full_body: str                  # Store full response for error detection
    error: Optional[str]


@dataclass
class Finding:
    cwe_num: int
    cwe_id: str
    cwe_name: str
    severity: str                  # LOW/MEDIUM/HIGH
    title: str
    description: str
    evidence: Dict[str, object]
    recommendation: str
    confidence: str               # LOW/MEDIUM/HIGH


# Safety & config
DEFAULT_UA = "EdgeSentinel/0.1 (CLI; educational; authorized testing only)"

# Generic error patterns (optional - used as additional signal)
ERROR_KEYWORDS = [
    # stack traces / exceptions
    "traceback", "exception", "stack trace", "fatal error",
    # common DB errors (generic patterns)  
    "sql syntax", "syntax error", "query failed", "database error",
    "you have an error", "mysql", "postgresql", "sqlite", "sqlstate",
    "mysqli", "pdo", "odbc",  # Database drivers
    # DVWA-specific MySQL errors
    "check the manual that corresponds to your mysql",
    "near", "line", "unexpected",  # Common in SQL syntax errors
    # file paths (disclosure)
    "/var/www", "/usr/local", "c:\\", "d:\\", "/home/",
    # generic error indicators
    "warning:", "fatal:", "error:", "undefined", "null reference",
    "division by zero", "cannot be null", "out of bounds",
    # PHP errors (common in DVWA)
    "notice:", "parse error", "call to",
    # Debug information exposure (CWE-215)
    "phpinfo", "php version", "xdebug", "display_errors", "error_reporting",
    "debug mode", "development mode", "var_dump", "print_r", "debug_backtrace",
]

# SQLish payloads for detection - DESTRUCTIVE PAYLOAD COMMENTED OUT
SQLISH_PAYLOADS = [
    "' OR '1'='1",  # Basic SQL injection test
    "1'--",  # SQL comment injection
    "\" OR \"1\"=\"1",  # Double-quote SQL injection
    # "1; DROP TABLE t--",  # DESTRUCTIVE - commented out for safety
    "1' OR '1'='1",  # Non-destructive alternative
]

# Special characters - DESTRUCTIVE PATH TRAVERSAL COMMENTED OUT
SPECIAL_CHARS = [
    "<>\"'`;&|",  # Special shell/script characters
    "\x00",  # Null byte
    # "../" * 3 + "etc/passwd",  # DESTRUCTIVE - path traversal (Linux)
    # "..\\..\\windows\\system32",  # DESTRUCTIVE - path traversal (Windows)
    "../test",  # Non-destructive path traversal test
    "..\\test",  # Non-destructive Windows path test
]
FORMAT_STRINGS = ["%s%s%s%s", "${7*7}", "{7*7}"]
XSSISH = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

# Enhanced type confusion to trigger more error types
TYPE_CONFUSION = [
    "abc",                      # String where number expected
    "99999999999999999999",     # Integer overflow
    "-1",                       # Negative number (array index, etc.)
    "0",                        # Zero (divide-by-zero tests)
    "1.1e308",                  # Float overflow
    "NaN",                      # Not a Number
    "Infinity",                 # Infinity value
    "-Infinity",                # Negative infinity
    "0.0",                      # Float zero
    "00",                       # Leading zeros
    "0x0",                      # Hex notation
    "2147483648",               # INT_MAX + 1 (32-bit overflow)
    "-2147483649",              # INT_MIN - 1
]

# Enhanced special values to trigger NULL pointer, uninitialized, etc.
SPECIAL_VALUES = [
    "",                               # Empty string (actual null/missing value)
    " ",                              # Whitespace only
    "null", "NULL", "nil", "None",  # String null representations
    "undefined", "#undef",           # Undefined values
    "true", "false", "True", "False",  # Booleans
    "[]", "{}", "()",                # Empty structures
    "0",                              # Zero (invalid ID for NULL pointer tests)
    "-1",                             # Negative (invalid ID)
    "999999999",                      # Non-existent ID (triggers NULL when object not found)
    "A" * 5000,                       # Large input (buffer)
    "A" * 10000,                      # Very large input
    "\n\r\t",                        # Control characters
    "�",                             # Unicode replacement char
]

ENCODING = ["%3Cscript%3E", "%253Cscript%253E", "SeLeCt", "SELECT"]
TIMING = ["sleep(2)", "WAITFOR DELAY '00:00:02'"]  # only used as "timing probe" (no exploit claims)

# Additional numeric edge cases specifically for divide-by-zero and numeric errors
NUMERIC_EDGE_CASES = [
    "0",           # Zero
    "0.0",         # Float zero
    "-0",          # Negative zero
    "00",          # Zero with leading zero
    "0x0",         # Hex zero
    "1/0",         # Division expression
    "0/0",         # Undefined division
]


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def is_http_url(u: str) -> bool:
    try:
        p = urlparse(u)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def same_host(a: str, b: str) -> bool:
    return urlparse(a).netloc.lower() == urlparse(b).netloc.lower()


def clip(text: str, max_len: int = 800) -> str:
    """Clip text for display. Increased from 350 to 800 to capture more error content."""
    text = text or ""
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_len] + ("..." if len(text) > max_len else "")


# -----------------------------
# HTTP helpers
# -----------------------------
def make_session(user_agent: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent})
    return s


def safe_request(
    session: requests.Session,
    method: str,
    url: str,
    params: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, str]] = None,
    timeout: int = 10,
    allow_redirects: bool = True,
) -> Tuple[Optional[requests.Response], Optional[str], int]:
    """
    Returns (response, error, elapsed_ms)
    """
    start = time.time()
    try:
        resp = session.request(
            method=method.upper(),
            url=url,
            params=params if method.upper() == "GET" else None,
            data=data if method.upper() == "POST" else None,
            timeout=timeout,
            allow_redirects=allow_redirects,
        )
        elapsed_ms = int((time.time() - start) * 1000)
        return resp, None, elapsed_ms
    except Exception as e:
        elapsed_ms = int((time.time() - start) * 1000)
        return None, str(e), elapsed_ms


def perform_login(
    session: requests.Session,
    login_url: str,
    username: str,
    password: str,
    username_field: str = "username",
    password_field: str = "password",
    timeout: int = 10,
) -> Tuple[bool, str]:
    """
    Performs form-based login with CSRF token support.
    Returns (success: bool, message: str)
    """
    print(f"[+] Attempting login to: {login_url}")
    print(f"[+] Username field: {username_field}, Password field: {password_field}")
    
    # Step 1: Fetch the login page to extract CSRF tokens
    print("[+] Fetching login page to extract CSRF tokens...")
    resp, err, elapsed = safe_request(
        session=session,
        method="GET",
        url=login_url,
        timeout=timeout,
        allow_redirects=True,
    )
    
    if err or resp is None:
        return False, f"Failed to fetch login page: {err}"
    
    # Step 2: Parse the login form and extract CSRF tokens and hidden fields
    login_data = {
        username_field: username,
        password_field: password,
    }
    
    try:
        soup = BeautifulSoup(resp.text, "html.parser")
        
        # Find all forms on the page
        forms = soup.find_all("form")
        
        if forms:
            # Use the first form (or find login form by action/id if multiple exist)
            login_form = forms[0]
            
            # Extract all hidden input fields (including CSRF tokens)
            hidden_inputs = login_form.find_all("input", type="hidden")
            for hidden in hidden_inputs:
                name = hidden.get("name")
                value = hidden.get("value", "")
                if name:
                    login_data[name] = value
                    print(f"[+] Found hidden field: {name} = {value[:50]}{'...' if len(value) > 50 else ''}")
            
            # Also check for common CSRF token fields in visible inputs
            csrf_fields = ["csrf_token", "user_token", "_token", "token", "authenticity_token", "csrf"]
            for csrf_name in csrf_fields:
                csrf_input = login_form.find("input", attrs={"name": csrf_name})
                if csrf_input and csrf_name not in login_data:
                    value = csrf_input.get("value", "")
                    login_data[csrf_name] = value
                    print(f"[+] Found CSRF token field: {csrf_name} = {value[:50]}{'...' if len(value) > 50 else ''}")
            
            # Extract submit button value if it has a name (some forms require this)
            submit_btn = login_form.find("input", type="submit")
            if submit_btn:
                btn_name = submit_btn.get("name")
                btn_value = submit_btn.get("value", "")
                if btn_name:
                    login_data[btn_name] = btn_value
                    print(f"[+] Found submit button: {btn_name} = {btn_value}")
        else:
            print("[!] Warning: No forms found on login page")
    
    except Exception as e:
        print(f"[!] Warning: Error parsing login form: {e}")
    
    # Step 3: Attempt login with all collected data
    print(f"[+] Submitting login with {len(login_data)} fields...")
    resp, err, elapsed = safe_request(
        session=session,
        method="POST",
        url=login_url,
        data=login_data,
        timeout=timeout,
        allow_redirects=True,
    )
    
    if err or resp is None:
        return False, f"Login request failed: {err}"
    
    # Check for common success indicators
    # Note: This is heuristic - adjust based on your target application
    success_indicators = [
        resp.status_code == 200,
        "logout" in resp.text.lower(),
        "welcome" in resp.text.lower(),
        "dashboard" in resp.text.lower(),
    ]
    
    # Check for common failure indicators
    failure_indicators = [
        "invalid" in resp.text.lower() and ("username" in resp.text.lower() or "password" in resp.text.lower()),
        "incorrect" in resp.text.lower(),
        "failed" in resp.text.lower() and "login" in resp.text.lower(),
    ]
    
    if any(failure_indicators):
        return False, "Login appears to have failed (invalid credentials or error message detected)"
    
    if any(success_indicators):
        print(f"[+] Login successful! Session cookies: {len(session.cookies)} cookie(s) set")
        return True, "Login successful"
    
    # If unclear, check if cookies were set (common for session-based auth)
    if len(session.cookies) > 0:
        print(f"[+] Login completed. Session cookies: {len(session.cookies)} cookie(s) set")
        return True, "Login completed (cookies set)"
    
    return False, "Login status unclear - no clear success or failure indicators found"


# -----------------------------
# Crawl & endpoint discovery
# -----------------------------
def crawl(
    session: requests.Session,
    start_url: str,
    max_depth: int,
    max_pages: int,
    delay_s: float,
    timeout: int,
    same_host_only: bool = True,
    stay_in_path: bool = True,
) -> List[str]:
    """
    Simple BFS crawl over <a href> links.
    
    Args:
        stay_in_path: If True, only crawl URLs within the same base path as start_url.
                     E.g., if start_url is http://example.com/dvwa/page.php,
                     only crawl URLs starting with http://example.com/dvwa/
    """
    seen: Set[str] = set()
    queue: List[Tuple[str, int]] = [(start_url, 0)]
    out: List[str] = []
    
    # Extract base path from start URL for path filtering
    start_parsed = urlparse(start_url)
    base_path = '/'.join(start_parsed.path.rstrip('/').split('/')[:-1]) + '/' if '/' in start_parsed.path else '/'
    # For /dvwa/vulnerabilities/sqli/ -> /dvwa/
    # Extract the top-level application path
    path_parts = [p for p in start_parsed.path.split('/') if p]
    if path_parts:
        base_path = '/' + path_parts[0] + '/'
    else:
        base_path = '/'

    while queue and len(out) < max_pages:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)

        if same_host_only and not same_host(start_url, url):
            continue
        
        # Check if URL is within the same base path (e.g., stay in /dvwa/)
        if stay_in_path:
            url_parsed = urlparse(url)
            if not url_parsed.path.startswith(base_path):
                continue

        resp, err, _ = safe_request(session, "GET", url, timeout=timeout)
        time.sleep(delay_s)

        if err or resp is None:
            continue

        # only parse HTML pages for crawling
        ctype = resp.headers.get("Content-Type", "")
        if "text/html" not in ctype:
            continue

        out.append(url)

        if depth >= max_depth:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            nxt = urljoin(url, href)
            if not is_http_url(nxt):
                continue
            if same_host_only and not same_host(start_url, nxt):
                continue
            
            # Check if link stays within base path
            if stay_in_path:
                nxt_parsed = urlparse(nxt)
                if not nxt_parsed.path.startswith(base_path):
                    continue
            
            if nxt not in seen:
                queue.append((nxt, depth + 1))

    return out


def extract_endpoints_from_page(page_url: str, html: str) -> List[Endpoint]:
    soup = BeautifulSoup(html, "html.parser")
    endpoints: List[Endpoint] = []

    # Links with query parameters are immediately testable
    for a in soup.find_all("a", href=True):
        href = a.get("href")
        abs_url = urljoin(page_url, href)
        if not is_http_url(abs_url):
            continue
        qs = parse_qs(urlparse(abs_url).query)
        if qs:
            endpoints.append(
                Endpoint(
                    kind="link",
                    url=abs_url,
                    method="GET",
                    params=sorted(qs.keys()),
                    context=f"link: {clip(a.get_text() or href, 60)}",
                )
            )
    
    # Detect common API paths (as per proposal: "links, forms and common API paths")
    # Look for common API endpoint patterns in links
    api_patterns = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql', '/json', '/xml']
    for a in soup.find_all("a", href=True):
        href = a.get("href")
        abs_url = urljoin(page_url, href)
        if not is_http_url(abs_url):
            continue
        # Check if URL contains API patterns and doesn't already have query params
        if any(pattern in abs_url.lower() for pattern in api_patterns):
            # Treat path segments as potential parameters for testing
            parsed = urlparse(abs_url)
            path_parts = [p for p in parsed.path.split('/') if p and not any(pat.strip('/') in p for pat in api_patterns)]
            if path_parts:
                endpoints.append(
                    Endpoint(
                        kind="api",
                        url=abs_url,
                        method="GET",
                        params=[],  # API paths tested differently (will trigger missing param tests)
                        context=f"api: {clip(abs_url, 60)}",
                    )
                )

    # Forms
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = (form.get("method") or "GET").upper()
        abs_action = urljoin(page_url, action)

        # collect input names
        names: List[str] = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                names.append(name)

        names = sorted(set(names))
        if names:
            endpoints.append(
                Endpoint(
                    kind="form",
                    url=abs_action,
                    method="POST" if method == "POST" else "GET",
                    params=names,
                    context="form",
                )
            )

    # de-dup by (method,url,params)
    uniq = {}
    for ep in endpoints:
        k = (ep.method, ep.url, tuple(ep.params))
        uniq[k] = ep
    return list(uniq.values())


def discover_endpoints(
    session: requests.Session,
    pages: List[str],
    delay_s: float,
    timeout: int,
) -> List[Endpoint]:
    endpoints: List[Endpoint] = []
    for u in pages:
        resp, err, _ = safe_request(session, "GET", u, timeout=timeout)
        time.sleep(delay_s)
        if err or resp is None:
            continue
        ctype = resp.headers.get("Content-Type", "")
        if "text/html" not in ctype:
            continue
        endpoints.extend(extract_endpoints_from_page(u, resp.text))

    # de-dup by (method,url)
    uniq = {}
    for ep in endpoints:
        k = (ep.method, ep.url, tuple(ep.params))
        uniq[k] = ep
    return list(uniq.values())


# -----------------------------
# Debug endpoint detection (CWE-215)
# -----------------------------
def check_debug_endpoints(
    session: requests.Session,
    base_url: str,
    timeout: int,
    delay_s: float,
) -> List[Finding]:
    """
    Probe for common debug/info endpoints that expose sensitive information.
    Returns findings for CWE-215 (Debug Information Insertion).
    """
    findings: List[Finding] = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    # Extract base path (e.g., /dvwa/ from /dvwa/vulnerabilities/)
    path_parts = [p for p in parsed.path.split('/') if p]
    if path_parts:
        app_base = '/' + path_parts[0] + '/'
    else:
        app_base = '/'
    
    # Common debug endpoints
    DEBUG_PATHS = [
        '/phpinfo.php',
        '/info.php',
        '/test.php',
        '/debug.php',
        '/debug',
        '/test',
        '/.env',
        '/config.php',
        '/configuration.php',
    ]
    
    # Also check in app base path
    paths_to_check = DEBUG_PATHS.copy()
    if app_base != '/':
        paths_to_check.extend([app_base + p.lstrip('/') for p in DEBUG_PATHS])
    
    for path in paths_to_check:
        url = base + path
        resp, err, _ = safe_request(session, "GET", url, timeout=timeout)
        time.sleep(delay_s)
        
        if err or resp is None:
            continue
        
        if resp.status_code == 200:
            body = resp.text or ""
            
            # Check for phpinfo signature
            if 'phpinfo()' in body or 'PHP Version' in body or 'PHP Credits' in body:
                findings.append(
                    Finding(
                        cwe_num=2,
                        cwe_id="CWE-215",
                        cwe_name="Insertion of Sensitive Information Into Debugging Code",
                        severity="HIGH",
                        title=f"phpinfo() endpoint exposed: {path}",
                        description=f"The endpoint {path} exposes phpinfo() output, revealing detailed PHP configuration, "
                                  f"loaded modules, environment variables, and system paths.",
                        evidence={
                            "url": url,
                            "status_code": resp.status_code,
                            "snippet": clip(body, 400),
                        },
                        recommendation=CWE_RECOMMENDATIONS.get("CWE-215", {}).get("summary") or "Remove phpinfo() and other debug endpoints from production. If needed for diagnostics, protect with authentication and IP whitelisting.",
                        confidence="HIGH",
                    )
                )
            
            # Check for debug mode indicators
            debug_indicators = ['debug mode', 'development mode', 'error_reporting', 'display_errors']
            if any(indicator in body.lower() for indicator in debug_indicators):
                findings.append(
                    Finding(
                        cwe_num=2,
                        cwe_id="CWE-215",
                        cwe_name="Insertion of Sensitive Information Into Debugging Code",
                        severity="MEDIUM",
                        title=f"Debug endpoint accessible: {path}",
                        description=f"The endpoint {path} is accessible and contains debug information.",
                        evidence={
                            "url": url,
                            "status_code": resp.status_code,
                            "snippet": clip(body, 400),
                        },
                        recommendation=CWE_RECOMMENDATIONS.get("CWE-215", {}).get("summary") or "Remove debug endpoints or protect them with proper access controls.",
                        confidence="MEDIUM",
                    )
                )
            
            # Check for .env file exposure
            if '.env' in path and ('DB_PASSWORD' in body or 'API_KEY' in body or 'SECRET' in body):
                findings.append(
                    Finding(
                        cwe_num=2,
                        cwe_id="CWE-215",
                        cwe_name="Insertion of Sensitive Information Into Debugging Code",
                        severity="CRITICAL",
                        title=f"Environment file exposed: {path}",
                        description=f"The .env file is publicly accessible, exposing credentials and secrets.",
                        evidence={
                            "url": url,
                            "status_code": resp.status_code,
                            "snippet": clip(body, 400),
                        },
                        recommendation=CWE_RECOMMENDATIONS.get("CWE-215", {}).get("summary") or "Immediately remove .env file from web-accessible directories. Store environment variables securely outside document root.",
                        confidence="HIGH",
                    )
                )
    
    return findings


# -----------------------------
# Payload generation
# -----------------------------
def generate_payloads() -> Dict[str, List[Optional[str]]]:
    """
    Returns category -> payload list.
    payload None means "omit parameter" for missing-param tests.
    """
    return {
        "error_disclosure": SQLISH_PAYLOADS + SPECIAL_CHARS + FORMAT_STRINGS + XSSISH,
        "missing_param": [None, "", "   ", "\x00"],  # Enhanced: include null byte
        "extra_param": ["admin=true", "debug=true", "role=admin", "priv=1"],  # Privilege-related
        "type_confusion": TYPE_CONFUSION,
        "special_values": SPECIAL_VALUES,
        "encoding": ENCODING,
        "timing": TIMING,
        "numeric_edge": NUMERIC_EDGE_CASES,  # New category for numeric errors
    }


# -----------------------------
# Baseline & test execution
# -----------------------------
def build_default_params(param_names: List[str]) -> Dict[str, str]:
    # safe, non-destructive defaults
    return {p: "test" for p in param_names}


def baseline_request(
    session: requests.Session,
    ep: Endpoint,
    timeout: int,
) -> Baseline:
    params = build_default_params(ep.params)

    resp, err, elapsed = safe_request(
        session,
        ep.method,
        ep.url,
        params=params if ep.method == "GET" else None,
        data=params if ep.method == "POST" else None,
        timeout=timeout,
    )
    if err or resp is None:
        return Baseline(
            status_code=0,
            elapsed_ms=elapsed,
            headers={},
            body_snippet=f"Baseline error: {err}",
            content_len=0,
        )

    return Baseline(
        status_code=resp.status_code,
        elapsed_ms=elapsed,
        headers={k: v for k, v in resp.headers.items()},
        body_snippet=clip(resp.text),
        content_len=len(resp.content or b""),
    )


def execute_tests_for_endpoint(
    session: requests.Session,
    ep: Endpoint,
    payloads: Dict[str, List[Optional[str]]],
    timeout: int,
    delay_s: float,
    target_param: Optional[str] = None,
) -> List[TestResult]:
    results: List[TestResult] = []
    base_params = build_default_params(ep.params)

    for p in ep.params:
        if target_param and p != target_param:
            continue

        for category, plist in payloads.items():
            for payload in plist:
                sent = dict(base_params)

                # category-specific mutation logic
                if category == "missing_param":
                    if payload is None:
                        sent.pop(p, None)  # omit
                    else:
                        sent[p] = payload
                elif category == "extra_param":
                    # add an extra param while also fuzzing current param slightly
                    sent[p] = "test"
                    key, val = payload.split("=", 1)
                    sent[key] = val
                else:
                    sent[p] = payload if payload is not None else ""

                resp, err, elapsed = safe_request(
                    session,
                    ep.method,
                    ep.url,
                    params=sent if ep.method == "GET" else None,
                    data=sent if ep.method == "POST" else None,
                    timeout=timeout,
                )
                time.sleep(delay_s)

                if err or resp is None:
                    results.append(
                        TestResult(
                            endpoint_url=ep.url,
                            method=ep.method,
                            parameter=p,
                            category=category,
                            payload=payload,
                            sent_params=sent,
                            status_code=None,
                            elapsed_ms=elapsed,
                            content_len=None,
                            body_snippet="",
                            full_body="",
                            error=err,
                        )
                    )
                    continue

                results.append(
                    TestResult(
                        endpoint_url=ep.url,
                        method=ep.method,
                        parameter=p,
                        category=category,
                        payload=payload,
                        sent_params=sent,
                        status_code=resp.status_code,
                        elapsed_ms=elapsed,
                        content_len=len(resp.content or b""),
                        body_snippet=clip(resp.text),
                        full_body=resp.text or "",  # Store full response
                        error=None,
                    )
                )

    return results


# -----------------------------
# Analysis → Findings
# -----------------------------
def looks_like_error_disclosure(text: str) -> bool:
    t = (text or "").lower()
    return any(k in t for k in ERROR_KEYWORDS)


def significant_content_change(baseline_len: int, test_len: int, threshold: float = 0.15) -> bool:
    """
    Detects if response size changed significantly (±15% by default, lowered from 30%).
    Indicates different code path or error handling.
    Lower threshold catches more subtle anomalies.
    """
    if baseline_len == 0:
        return test_len > 50  # any substantial response when baseline was empty (lowered from 100)
    
    ratio = abs(test_len - baseline_len) / baseline_len
    return ratio > threshold


def significant_timing_change(baseline_ms: int, test_ms: int, threshold_ms: int = 800) -> bool:
    """
    Detects significant slowdown suggesting expensive error handling or resource issues.
    Lowered from 1500ms to 800ms to catch more anomalies.
    """
    return test_ms > baseline_ms + threshold_ms


def content_type_changed(baseline_headers: Dict[str, str], test_headers: Dict[str, str]) -> bool:
    """
    Detects if content type changed (e.g., HTML -> JSON, suggesting error response).
    """
    baseline_ct = baseline_headers.get("Content-Type", "").split(";")[0].strip().lower()
    test_ct = test_headers.get("Content-Type", "").split(";")[0].strip().lower()
    
    if baseline_ct and test_ct:
        return baseline_ct != test_ct
    return False


def severity_from_signal(high: bool, medium: bool) -> str:
    if high:
        return "HIGH"
    if medium:
        return "MEDIUM"
    return "LOW"


def analyze(
    ep: Endpoint,
    baseline: Baseline,
    tests: List[TestResult],
    enabled_cwe_nums: Set[int],
) -> List[Finding]:
    findings: List[Finding] = []

    # Helper to add finding with correct CWE info
    def add(cwe_num: int, title: str, desc: str, sev: str, evidence: Dict[str, object], rec: str, conf: str):
        if cwe_num not in enabled_cwe_nums:
            return
        cwe_id, cwe_name = CWE_LIST[cwe_num]
        # Use CWE_RECOMMENDATIONS summary as single source of truth so JSON and HTML stay in sync
        rec_synced = CWE_RECOMMENDATIONS.get(cwe_id, {}).get("summary") or rec
        findings.append(
            Finding(
                cwe_num=cwe_num,
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                severity=sev,
                title=title,
                description=desc,
                evidence=evidence,
                recommendation=rec_synced,
                confidence=conf,
            )
        )

    for tr in tests:
        # Skip if request outright failed (still useful, but keep it lower signal)
        body = tr.body_snippet or ""
        full_body = tr.full_body or ""  # Use full body for error detection
        sc = tr.status_code or 0
        test_len = tr.content_len or 0
        test_time = tr.elapsed_ms or 0

        # BEHAVIORAL DETECTION (generic, works across all apps)
        
        # 1. Status code 5xx = server error (CWE-248: Uncaught Exception)
        if sc >= 500:
            add(
                5,  # Maps to CWE-248 in CWE_LIST
                "Uncaught exception (5xx response)",
                "Server returned a 5xx error to edge-case input, indicating unhandled exception or server error.",
                "HIGH",
                {
                    "endpoint": tr.endpoint_url,
                    "method": tr.method,
                    "parameter": tr.parameter,
                    "category": tr.category,
                    "payload": tr.payload,
                    "status_code": tr.status_code,
                    "snippet": body,
                },
                "Implement centralized exception handling and return generic error responses to clients while logging details server-side.",
                "HIGH",
            )

        # 2. Significant response size change (generic behavioral indicator)
        # Only flag if BOTH responses are successful (200) but different sizes
        # Don't flag size changes when status code changes to error (expected behavior)
        if significant_content_change(baseline.content_len, test_len):
            # Skip if status changed from 2xx to 4xx/5xx (error pages are naturally smaller)
            baseline_success = baseline.status_code and 200 <= baseline.status_code < 300
            test_success = sc and 200 <= sc < 300
            
            # Only flag if both successful or both errors with size change
            if baseline_success == test_success:
                # Different code path or error handling
                sev = "HIGH" if sc >= 500 or sc == 0 else "MEDIUM"
                add(
                    21,
                    "Significant response size anomaly",
                    f"Response size changed significantly from baseline ({baseline.content_len}B -> {test_len}B). "
                    f"This indicates different code execution path or error handling for edge-case input.",
                    sev,
                    {
                        "endpoint": tr.endpoint_url,
                        "parameter": tr.parameter,
                        "baseline_size": baseline.content_len,
                        "test_size": test_len,
                        "category": tr.category,
                        "payload": tr.payload,
                        "status_code": tr.status_code,
                    },
                    "Ensure consistent error handling across all input validation paths. Review why this input triggers different behavior.",
                    "MEDIUM",
                )

        # 3. Timing anomaly (generic)
        if significant_timing_change(baseline.elapsed_ms, test_time):
            add(
                22,
                "Response time anomaly detected",
                f"Response took significantly longer ({test_time}ms vs baseline {baseline.elapsed_ms}ms). "
                f"This can indicate expensive error paths, resource strain, or algorithmic complexity issues.",
                "MEDIUM",
                {
                    "endpoint": tr.endpoint_url,
                    "baseline_ms": baseline.elapsed_ms,
                    "test_ms": test_time,
                    "category": tr.category,
                    "payload": tr.payload,
                },
                "Add input validation, throttling, and ensure exceptional-condition handling is efficient and bounded.",
                "LOW",
            )

        # 4. Status code changes (generic behavioral)
        if baseline.status_code and sc and sc != baseline.status_code:
            # Meaningful changes: baseline 2xx but test 4xx/5xx, or vice versa
            # Exclude correct HTTP protocol responses (413, 414, 431)
            meaningful = (baseline.status_code < 400 <= sc) or (baseline.status_code >= 400 > sc)
            correct_http_errors = sc in [413, 414, 431]  # Correct responses to oversized inputs
            
            if meaningful and not correct_http_errors:
                sev = "HIGH" if sc >= 500 else "MEDIUM"
                add(
                    12,
                    "Unexpected status code behavior",
                    f"Status code changed from {baseline.status_code} to {sc} for edge-case input. "
                    f"This indicates inconsistent error handling or different execution paths.",
                    sev,
                    {
                        "endpoint": tr.endpoint_url,
                        "baseline_status": baseline.status_code,
                        "test_status": sc,
                        "category": tr.category,
                        "payload": tr.payload,
                        "snippet": body,
                    },
                    "Ensure consistent, safe error handling across code paths. Review why this input changes control flow.",
                    "MEDIUM",
                )

        # 5. Missing parameter handling (generic)
        if tr.category == "missing_param" and tr.payload is None:
            # Behavioral: any error response (5xx, 4xx, or significant size change)
            if sc >= 500 or significant_content_change(baseline.content_len, test_len):
                add(
                    3,
                    "Missing parameter triggers error condition",
                    f"Omitting parameter '{tr.parameter}' caused an error response or significant behavior change. "
                    f"Required parameters should be validated gracefully.",
                    "MEDIUM" if sc >= 500 else "LOW",
                    {
                        "endpoint": tr.endpoint_url,
                        "parameter": tr.parameter,
                        "status_code": sc,
                        "baseline_size": baseline.content_len,
                        "test_size": test_len,
                    },
                    "Validate required parameters and return 400 Bad Request with a safe message instead of crashing or exposing errors.",
                    "HIGH",
                )

        # 6. Extra parameters (generic behavioral)
        if tr.category == "extra_param":
            if sc >= 500 or significant_content_change(baseline.content_len, test_len):
                add(
                    4,
                    "Extra parameter triggers error condition",
                    f"Adding unexpected parameter caused error response or behavior change. "
                    f"Applications should safely ignore or reject unexpected inputs.",
                    "MEDIUM" if sc >= 500 else "LOW",
                    {
                        "endpoint": tr.endpoint_url,
                        "sent_params": tr.sent_params,
                        "status_code": sc,
                    },
                    "Whitelist expected parameters and reject/ignore extras; log suspicious requests for monitoring.",
                    "MEDIUM",
                )

        # 7. Divide by zero detection (enhanced - check multiple zero representations)
        zero_variants = ["0", "0.0", "-0", "00", "0x0"]
        if tr.payload in zero_variants or (tr.category == "numeric_edge" and tr.payload in NUMERIC_EDGE_CASES):
            # Search full body for division errors
            if sc >= 500 or "division by zero" in full_body.lower() or "divide by zero" in full_body.lower() or significant_content_change(baseline.content_len, test_len):
                add(
                    9,
                    "Potential divide-by-zero vulnerability",
                    f"Zero input triggered error condition consistent with divide-by-zero or unsafe numeric handling.",
                    "MEDIUM",
                    {
                        "endpoint": tr.endpoint_url,
                        "parameter": tr.parameter,
                        "status_code": sc,
                    },
                    "Validate numeric inputs; explicitly guard division operations with zero checks and safe fallbacks.",
                    "MEDIUM",
                )

        # 8. Failing open detection (generic)
        if baseline.status_code in (401, 403) and sc == 200:
            add(
                20,
                "Potential failing-open behavior",
                f"Baseline indicates access denied ({baseline.status_code}) but edge-case request returned 200. "
                f"This suggests inconsistent authorization checks.",
                "HIGH",
                {
                    "endpoint": tr.endpoint_url,
                    "baseline_status": baseline.status_code,
                    "test_status": sc,
                    "category": tr.category,
                    "sent_params": tr.sent_params,
                },
                "Review authorization logic to ensure it fails closed on all exceptional conditions; test for parameter pollution.",
                "LOW",
            )

        # Additional CWE detections for better A10 coverage
        
        # CWE-476: NULL Pointer Dereference detection
        # Check for empty values, invalid IDs, and null-like inputs
        null_indicators = ["", "null", "NULL", "nil", "None", "undefined", "0", "-1", "999999999"]
        if tr.payload in null_indicators or (isinstance(tr.payload, str) and tr.payload.strip() == ""):
            # Enhanced NULL error patterns for better detection
            null_errors = [
                "null pointer", "nullpointer", "null reference", 
                "object reference not set", "cannot be null",
                "undefined index", "undefined offset", "undefined variable",
                "trying to get property", "trying to access array offset",  # PHP 7.4+
                "undefined array key",  # PHP 8.0+
                "does not exist", "not found in database",
                "null value in column", "violates not-null constraint",  # Database
                "cannot read property", "cannot read properties of null",  # JavaScript
                "nonetype", "nonetype object",  # Python
                "attempt to invoke", "on a null object reference",  # Java
            ]
            # Search full body, not just snippet
            if sc >= 500 or any(err in full_body.lower() for err in null_errors) or significant_content_change(baseline.content_len, test_len):
                add(
                    16,
                    "Null pointer dereference indication",
                    f"Null-like input '{tr.payload}' triggered error behavior suggesting improper null handling.",
                    "HIGH" if sc >= 500 else "MEDIUM",
                    {
                        "endpoint": tr.endpoint_url,
                        "parameter": tr.parameter,
                        "payload": tr.payload,
                        "status_code": sc,
                        "snippet": body if any(err in body.lower() for err in null_errors) else None,
                    },
                    "Add null checks before dereferencing objects; use safe navigation operators or default values.",
                    "HIGH" if any(err in body.lower() for err in null_errors) else "MEDIUM",
                )
        
        # CWE-252: Unchecked Return Value (detect when errors aren't properly propagated)
        if baseline.status_code == 200 and sc == 200 and significant_content_change(baseline.content_len, test_len, threshold=0.1):
            # Subtle changes with same status suggest silent failures
            add(
                6,
                "Potential unchecked return value",
                f"Edge-case input caused subtle response changes without status code change, suggesting error condition not properly checked/propagated.",
                "LOW",
                {
                    "endpoint": tr.endpoint_url,
                    "parameter": tr.parameter,
                    "baseline_status": baseline.status_code,
                    "test_status": sc,
                    "baseline_size": baseline.content_len,
                    "test_size": test_len,
                    "category": tr.category,
                },
                "Check return values from all operations; propagate errors appropriately rather than silently failing.",
                "LOW",
            )
        
        # CWE-754: Improper Check for Unusual or Exceptional Conditions
        # Only flag actual application errors, not correct HTTP protocol responses
        # Note: 413/414/431 are CORRECT responses for oversized inputs, not vulnerabilities
        unusual_conditions = [
            (sc == 400 and tr.category == "type_confusion", "Type confusion"),
            (sc == 400 and tr.category == "encoding", "Encoding issue"),
            # APPLICATION errors that should have been validated before reaching the server
            (sc == 500 and tr.category in ["type_confusion", "encoding", "special_values"], "Unhandled input condition"),
        ]
        
        for condition, desc in unusual_conditions:
            if condition:
                add(
                    22,  # CWE-754
                    f"Improper check for unusual condition: {desc}",
                    f"Application failed to properly handle unusual input condition ({desc}), "
                    f"returning error status {sc} instead of graceful validation.",
                    "MEDIUM",
                    {
                        "endpoint": tr.endpoint_url,
                        "parameter": tr.parameter,
                        "category": tr.category,
                        "payload": str(tr.payload)[:100] if tr.payload else None,
                        "status_code": sc,
                        "condition_type": desc,
                    },
                    "Implement proper input validation for boundary conditions, size limits, and unusual inputs. "
                    "Return 400 Bad Request with safe error messages instead of allowing server errors.",
                    "MEDIUM",
                )
                break  # Only report once per test
        
        # CWE-755: Improper Handling of Exceptional Conditions (catch-all for unusual responses)
        if tr.category in ["type_confusion", "special_values"] and sc not in [200, 400, 404, 413, 414, 431]:
            # Unusual status codes for type/value confusion suggest poor exception handling
            add(
                23,
                "Improper handling of exceptional input conditions",
                f"Type confusion or special value input resulted in unusual status code {sc}, indicating inadequate exception handling.",
                "MEDIUM",
                {
                    "endpoint": tr.endpoint_url,
                    "parameter": tr.parameter,
                    "category": tr.category,
                    "payload": tr.payload,
                    "status_code": sc,
                },
                "Implement comprehensive input validation and exception handling for all data types and edge cases.",
                "MEDIUM",
            )
        
        # CWE-274/280: Privilege/Permission handling issues (extra params with privilege keywords)
        priv_keywords = ["admin", "role", "priv", "permission", "auth", "user"]
        if tr.category == "extra_param" and any(kw in tr.sent_params.keys() for kw in priv_keywords):
            if sc == 200 and baseline.status_code in [401, 403]:
                add(
                    7,
                    "Insufficient privilege handling",
                    f"Adding privilege-related parameter bypassed authorization (baseline {baseline.status_code} -> {sc}).",
                    "HIGH",
                    {
                        "endpoint": tr.endpoint_url,
                        "sent_params": tr.sent_params,
                        "baseline_status": baseline.status_code,
                        "test_status": sc,
                    },
                    "Implement proper authorization checks; whitelist parameters and reject unexpected privilege escalation attempts.",
                    "MEDIUM",
                )
            elif significant_content_change(baseline.content_len, test_len):
                add(
                    8,
                    "Improper permission parameter handling",
                    f"Privilege-related extra parameter caused behavioral change, suggesting improper permission handling.",
                    "MEDIUM",
                    {
                        "endpoint": tr.endpoint_url,
                        "sent_params": tr.sent_params,
                        "baseline_size": baseline.content_len,
                        "test_size": test_len,
                    },
                    "Validate and sanitize all parameters; ignore unexpected permission/privilege parameters.",
                    "LOW",
                )
        
        # CWE-756: Missing Custom Error Page (detect default error pages)
        # Only flag APPLICATION errors (5xx), not standard HTTP protocol errors (413, 414, 431)
        default_error_indicators = [
            "apache", "nginx", "iis", "tomcat",  # Server names
            "500 internal server error", "502 bad gateway", "503 service unavailable",
            "<hr>", "<address>",  # Default HTML error page elements
        ]
        # Exclude correct HTTP protocol responses: 413, 414, 431
        is_application_error = sc >= 500 or (sc >= 400 and sc not in [413, 414, 431])
        
        if is_application_error and any(indicator in body.lower() for indicator in default_error_indicators):
            add(
                24,
                "Default/generic error page detected",
                f"Server returned default error page with technical details (status {sc}), rather than custom user-friendly page.",
                "LOW",
                {
                    "endpoint": tr.endpoint_url,
                    "status_code": sc,
                    "snippet": body,
                },
                "Implement custom error pages for all error conditions; suppress technical details from default server pages.",
                "MEDIUM" if sc >= 500 else "LOW",
            )
        
        # CWE-390/391: Error Detection Without Action / Unchecked Error Condition
        # Look for error keywords in 200 responses (errors being displayed but not handled)
        error_in_success = [
            "error:", "warning:", "exception", "failed", "could not", "unable to",
            "not found" if sc == 200 else None,  # "not found" in 200 response suggests unhandled error
        ]
        error_in_success = [e for e in error_in_success if e]  # Remove None
        
        if sc == 200 and any(err in body.lower() for err in error_in_success):
            add(
                10,
                "Error condition without proper action",
                f"Error message appears in successful response (200), suggesting error detected but not properly handled.",
                "MEDIUM",
                {
                    "endpoint": tr.endpoint_url,
                    "status_code": sc,
                    "parameter": tr.parameter,
                    "snippet": body,
                },
                "Return appropriate error status codes; handle errors properly instead of embedding error messages in successful responses.",
                "MEDIUM",
            )
            
            # Also flag as CWE-391 (unchecked error condition)
            add(
                11,
                "Unchecked error condition",
                f"Error condition appears to be unchecked (error text in 200 response), allowing execution to continue despite failure.",
                "MEDIUM",
                {
                    "endpoint": tr.endpoint_url,
                    "status_code": sc,
                    "parameter": tr.parameter,
                    "snippet": body,
                },
                "Check all error conditions; halt execution or use safe fallbacks rather than continuing with error state.",
                "LOW",
            )
        
        # CWE-550: Server-generated error with sensitive info (more specific than CWE-209)
        # Use more specific patterns to avoid false positives on normal HTML
        server_sensitive = [
            "sql syntax error", "mysql error", "mysqli_", "postgresql error", "pg_query",
            "stack trace:", "traceback (most recent", "call stack:",
            "/var/www/", "/usr/local/", "c:\\\\windows\\\\", "c:\\\\inetpub\\\\",  # Actual path disclosures
            " on line ", "error in ", "exception in ",  # Error location patterns
            "fatal error:", "uncaught exception"
        ]
        # Search full body, and accept any status code (not just 5xx) since DVWA returns 200
        if any(sensitive in full_body.lower() for sensitive in server_sensitive):
            add(
                19,
                "Server error message containing sensitive information",
                f"Response contains technical implementation details (SQL queries, database errors, paths, stack traces).",
                "HIGH" if sc >= 500 else "HIGH",  # HIGH regardless of status for sensitive data disclosure
                {
                    "endpoint": tr.endpoint_url,
                    "status_code": sc,
                    "parameter": tr.parameter,
                    "payload": tr.payload,
                    "snippet": body,
                },
                "Configure server to suppress technical details in error responses; use custom error handlers.",
                "HIGH",
            )
        
        # CWE-209 - Specific error disclosure (extra signal, not required)
        # Search FULL body, not just snippet - this is critical for catching errors
        if looks_like_error_disclosure(full_body):
            # This catches specific error messages as bonus detection
            confidence = "HIGH" if sc >= 500 else "MEDIUM"
            add(
                1,
                "Error message contains sensitive information",
                "Response contains technical error details (stack traces, database errors, file paths, etc.) "
                "that may aid attackers in reconnaissance.",
                "HIGH",
                {
                    "endpoint": tr.endpoint_url,
                    "method": tr.method,
                    "parameter": tr.parameter,
                    "category": tr.category,
                    "payload": tr.payload,
                    "status_code": sc,
                    "snippet": body,
                },
                "Disable debug mode in production. Use generic error pages for clients and log detailed errors server-side only.",
                confidence,
            )
        
        # CWE-215: Debug information exposure detection
        debug_indicators = ["phpinfo", "php version", "xdebug", "display_errors", "error_reporting",
                           "debug mode", "development mode", "var_dump", "print_r"]
        if any(indicator in full_body.lower() for indicator in debug_indicators):
            add(
                2,
                "Debug information exposure detected",
                "Response contains debug information (phpinfo, error_reporting settings, debug mode indicators) "
                "that reveals internal application details.",
                "MEDIUM",
                {
                    "endpoint": tr.endpoint_url,
                    "parameter": tr.parameter,
                    "payload": tr.payload,
                    "status_code": sc,
                    "snippet": body,
                },
                "Disable debug mode and verbose error reporting in production environments. Remove phpinfo() and debug endpoints.",
                "HIGH",
            )
        
        # 9. Rate limiting / throttling detection (as per proposal)
        # Status 429 (Too Many Requests) indicates rate limiting is present
        if sc == 429:
            add(
                21,
                "Rate limiting detected (positive security control)",
                "Endpoint implements rate limiting (HTTP 429), which helps prevent resource exhaustion and DoS. "
                "This is a positive finding indicating proper exceptional condition prevention.",
                "LOW",  # This is actually good security practice
                {
                    "endpoint": tr.endpoint_url,
                    "status_code": sc,
                    "category": tr.category,
                    "payload": tr.payload,
                },
                "Ensure rate limiting is consistently applied across all endpoints and returns appropriate retry-after headers.",
                "HIGH",
            )
        
        # Missing rate limiting on resource-intensive operations
        # If timing is excessively high but no rate limiting detected, flag it
        if test_time > 5000 and sc == 200:  # >5 seconds but still processing
            # Check if we've seen 429s for this endpoint before (would indicate rate limiting exists)
            has_rate_limit = any(
                t.endpoint_url == tr.endpoint_url and t.status_code == 429 
                for t in tests
            )
            if not has_rate_limit:
                add(
                    22,
                    "Potential resource exhaustion risk (no rate limiting detected)",
                    f"Endpoint took {test_time}ms to respond to edge-case input without returning rate limit errors. "
                    f"This may indicate missing throttling controls, allowing resource exhaustion attacks.",
                    "MEDIUM",
                    {
                        "endpoint": tr.endpoint_url,
                        "test_ms": test_time,
                        "payload": tr.payload,
                        "category": tr.category,
                    },
                    "Implement rate limiting, request throttling and timeout controls to prevent resource exhaustion under exceptional conditions.",
                    "MEDIUM",
                )

    # de-duplicate loosely (same CWE + endpoint + title)
    uniq = {}
    for f in findings:
        key = (f.cwe_num, f.evidence.get("endpoint"), f.title)
        uniq[key] = f
    findings = list(uniq.values())

    # sort by severity (CRITICAL > HIGH > MEDIUM > LOW)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: order.get(x.severity, 9))
    return findings


# -----------------------------
# Report generation
# -----------------------------
def write_json_report(out_path: str, payload: dict) -> None:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def write_html_report(out_path: str, payload: dict) -> None:
    meta = payload["meta"]
    findings = payload["findings"]

    def sev_class(s: str) -> str:
        return s.lower()

    rows = []
    for f in findings:
        ev = f["evidence"]
        cwe_id = f["cwe_id"]

        # ── Evidence column ──────────────────────────────────────────────
        evidence_html = ""
        if ev.get("snippet"):
            evidence_html = f'<pre>{escape(str(ev.get("snippet",""))[:400])}</pre>'
        else:
            evidence_parts = []
            if "baseline_size" in ev and "test_size" in ev:
                evidence_parts.append(f"<b>Size change:</b> {ev['baseline_size']}B → {ev['test_size']}B")
            if "baseline_ms" in ev and "test_ms" in ev:
                evidence_parts.append(f"<b>Time change:</b> {ev['baseline_ms']}ms → {ev['test_ms']}ms")
            if "baseline_status" in ev and "test_status" in ev:
                evidence_parts.append(f"<b>Status change:</b> {ev['baseline_status']} → {ev['test_status']}")
            if "status_code" in ev:
                evidence_parts.append(f"<b>Status:</b> {ev['status_code']}")
            if "parameter" in ev:
                evidence_parts.append(f"<b>Parameter:</b> {escape(str(ev['parameter']))}")
            if "payload" in ev and ev["payload"]:
                payload_str = str(ev["payload"])[:50]
                evidence_parts.append(f"<b>Payload:</b> <code>{escape(payload_str)}</code>")
            if "category" in ev:
                evidence_parts.append(f"<b>Category:</b> {escape(str(ev['category']))}")
            evidence_html = "<br>".join(evidence_parts) if evidence_parts else "<em>Behavioral anomaly detected</em>"

        # ── Recommendation column ────────────────────────────────────────
        rec_data = CWE_RECOMMENDATIONS.get(cwe_id)
        if rec_data:
            summary   = escape(rec_data["summary"])
            bad_code  = escape(rec_data.get("bad", ""))
            good_code = escape(rec_data.get("good", ""))
            code_block = ""
            if bad_code or good_code:
                code_block = f"""
                <details>
                  <summary style="cursor:pointer;color:#0066cc;margin-top:6px;">Code Example</summary>
                  <div style="margin-top:6px;">
                    {"<p><b>Vulnerable pattern:</b></p><pre class='code-bad'>" + bad_code + "</pre>" if bad_code else ""}
                    {"<p><b>Secure practice:</b></p><pre class='code-good'>" + good_code + "</pre>" if good_code else ""}
                  </div>
                </details>"""
            rec_html = f"<span>{summary}</span>{code_block}"
        else:
            rec_html = f"<span>{escape(f.get('recommendation', ''))}</span>"

        rows.append(
            f"""
            <tr>
              <td class="{sev_class(f['severity'])}">{escape(f["severity"])}</td>
              <td><b>{escape(cwe_id)}</b><br><small>{escape(f["cwe_name"])}</small></td>
              <td>{escape(f["title"])}</td>
              <td><code>{escape(str(ev.get("endpoint","")))}</code></td>
              <td>{evidence_html}</td>
              <td>{rec_html}</td>
            </tr>
            """
        )

    # ── Untested (SAST-only) CWEs ───────────────────────────────────────────
    # These are hardcoded — they appear in every report regardless of scan results.
    SAST_ONLY_CWES = [
        {"cwe_id": "CWE-396", "cwe_name": "Declaration of Catch for Generic Exception"},
        {"cwe_id": "CWE-397", "cwe_name": "Declaration of Throws for Generic Exception"},
        {"cwe_id": "CWE-460", "cwe_name": "Improper Cleanup on Thrown Exception"},
        {"cwe_id": "CWE-478", "cwe_name": "Missing Default Case in Multiple Condition Expression"},
        {"cwe_id": "CWE-484", "cwe_name": "Omitted Break Statement in Switch"},
    ]

    untested_rows_list = []
    for sc in SAST_ONLY_CWES:
        rec_data = CWE_RECOMMENDATIONS.get(sc["cwe_id"])
        if rec_data:
            summary   = escape(rec_data["summary"])
            bad_code  = escape(rec_data.get("bad", ""))
            good_code = escape(rec_data.get("good", ""))
            code_block = ""
            if bad_code or good_code:
                code_block = f"""
                <details>
                  <summary style="cursor:pointer;color:#0066cc;margin-top:6px;">Code Example</summary>
                  <div style="margin-top:6px;">
                    {"<p><b>Vulnerable pattern:</b></p><pre class='code-bad'>" + bad_code + "</pre>" if bad_code else ""}
                    {"<p><b>Secure practice:</b></p><pre class='code-good'>" + good_code + "</pre>" if good_code else ""}
                  </div>
                </details>"""
            rec_html_u = f"<span>{summary}</span>{code_block}"
        else:
            rec_html_u = "<em>See CWE reference for guidance.</em>"

        untested_rows_list.append(f"""      <tr style="background:#fafafa;">
        <td><b>{escape(sc['cwe_id'])}</b></td>
        <td><small>{escape(sc['cwe_name'])}</small></td>
        <td>{rec_html_u}</td>
      </tr>""")

    untested_rows = "\n".join(untested_rows_list)

    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>EdgeSentinel Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background:#fafafa; }}
    h1   {{ color: #222; }}
    .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 14px; margin-bottom: 14px; background:#fff; }}
    table {{ border-collapse: collapse; width: 100%; background:#fff; }}
    th, td {{ border: 1px solid #ddd; padding: 8px 10px; vertical-align: top; }}
    th {{ background: #f0f0f0; text-align: left; font-size: 0.9em; }}
    td {{ font-size: 0.88em; }}
    .critical {{ color: #8b0000; font-weight: bold; background-color: #ffe0e0; }}
    .high    {{ color: #b00020; font-weight: bold; }}
    .medium  {{ color: #b26a00; font-weight: bold; }}
    .low     {{ color: #1b5e20; font-weight: bold; }}
    pre  {{ white-space: pre-wrap; word-break: break-word; margin: 4px 0; font-size: 0.82em; }}
    code {{ font-size: 0.85em; }}
    .code-bad  {{ background: #fff0f0; border-left: 3px solid #cc0000; padding: 6px 10px; border-radius: 4px; }}
    .code-good {{ background: #f0fff0; border-left: 3px solid #007700; padding: 6px 10px; border-radius: 4px; }}
    details summary:hover {{ text-decoration: underline; }}
    small {{ color: #555; }}
  </style>
</head>
<body>
  <h1>EdgeSentinel Report</h1>

  <div class="card">
    <h3>Scan Metadata</h3>
    <p><b>Target:</b> {escape(meta["target_url"])}</p>
    <p><b>Timestamp:</b> {escape(meta["timestamp"])}</p>
    <p><b>Mode:</b> {escape(meta["mode"])}</p>
    <p><b>Pages crawled:</b> {meta["pages_crawled"]} &nbsp;|&nbsp; <b>Endpoints found:</b> {meta["endpoints_found"]}</p>
    <p><b>Total tests:</b> {meta["total_tests"]} &nbsp;|&nbsp; <b>Findings:</b> {meta["finding_count"]}</p>
  </div>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th style="width:70px">Severity</th>
        <th style="width:130px">CWE</th>
        <th style="width:200px">Title</th>
        <th style="width:200px">Endpoint</th>
        <th style="width:220px">Evidence</th>
        <th>Recommendation &amp; Secure Coding</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows) if rows else '<tr><td colspan="6">No findings detected by current heuristics.</td></tr>'}
    </tbody>
  </table>

  <p style="margin-top:16px; color:#666;">
    Findings are heuristic and should be validated manually.
    Code examples show common vulnerable patterns and their secure equivalents.
  </p>

  <h2 style="margin-top:36px;">Untested CWEs</h2>
  <p style="color:#666;margin-bottom:12px;">
    The following CWEs cannot be detected by a black-box dynamic scanner (DAST) because they describe
    structural source-code patterns such as catch block declarations, switch statement structure, and
    exception propagation chains which are invisible at the HTTP level. A <b>Static Application Security
    Testing (SAST)</b> tool or manual code review is required to assess these.
  </p>
  <table>
    <thead>
      <tr>
        <th style="width:110px">CWE</th>
        <th style="width:220px">Name</th>
        <th>Recommendation &amp; Secure Coding</th>
      </tr>
    </thead>
    <tbody>
{untested_rows}
    </tbody>
  </table>

</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


# -----------------------------
# Orchestrator
# -----------------------------
def run_scan(
    url: str,
    mode: str,
    enabled_cwe_nums: Set[int],
    depth: int,
    max_pages: int,
    delay_s: float,
    timeout: int,
    outdir: str,
    out_format: str,
    user_agent: str,
    no_crawl: bool,
    allow_external_paths: bool,
    target_param: Optional[str],
    login_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    username_field: str = "username",
    password_field: str = "password",
) -> Tuple[str, Optional[str]]:
    if not is_http_url(url):
        raise ValueError("Invalid URL. Must start with http:// or https://")

    session = make_session(user_agent=user_agent)
    
    # Perform login if credentials are provided
    if login_url and username and password:
        success, message = perform_login(
            session=session,
            login_url=login_url,
            username=username,
            password=password,
            username_field=username_field,
            password_field=password_field,
            timeout=timeout,
        )
        if not success:
            print(f"[!] Error: {message}")
            print("[!] Authentication failed. Cannot proceed with scan.")
            print("[!] Please check your credentials and login URL.")
            raise ValueError(f"Login failed: {message}")
        else:
            print(f"[+] {message}")
            
            # Verify we can access the target URL after login
            print(f"[+] Verifying access to target URL...")
            test_resp, test_err, _ = safe_request(session, "GET", url, timeout=timeout)
            if test_resp:
                if "login" in test_resp.url.lower() and test_resp.url != url:
                    print(f"[!] Warning: Redirected to login page. Authentication may have failed.")
                    print(f"[!] Target URL: {url}")
                    print(f"[!] Redirected to: {test_resp.url}")
                    raise ValueError("Target URL redirected to login - authentication failed")
                else:
                    print(f"[+] Successfully accessed target URL (status: {test_resp.status_code})")
            else:
                print(f"[!] Warning: Could not verify target URL access: {test_err}")
    elif login_url or username or password:
        print("[!] Warning: Incomplete login credentials provided. Skipping login.")
        print("[!] All three are required: --login-url, --username, --password")

    print("[*] EdgeSentinel - Edge Case Vulnerability Scanner (CLI)")
    print(f"[*] Target: {url}")
    print(f"[*] Mode: {mode}")
    print(f"[*] Crawl: {'OFF' if no_crawl else f'depth={depth}, max_pages={max_pages}'}")
    if not no_crawl and not allow_external_paths:
        # Show user that path filtering is active
        start_parsed = urlparse(url)
        path_parts = [p for p in start_parsed.path.split('/') if p]
        if path_parts:
            base_path = '/' + path_parts[0] + '/'
            print(f"[*] Path filter: Only crawling URLs starting with {base_path}")
    print(f"[*] Delay: {delay_s}s | Timeout: {timeout}s")

    # Crawl pages
    if no_crawl:
        pages = [url]
    else:
        print("[+] Crawling...")
        pages = crawl(
            session=session,
            start_url=url,
            max_depth=depth,
            max_pages=max_pages,
            delay_s=delay_s,
            timeout=timeout,
            same_host_only=True,
            stay_in_path=not allow_external_paths,  # Stay in path by default (True), unless --allow-external-paths
        )
        if url not in pages:
            pages.insert(0, url)

    print(f"[+] Pages selected: {len(pages)}")

    # Discover endpoints
    print("[+] Discovering endpoints (links + forms)...")
    endpoints = discover_endpoints(session, pages, delay_s=delay_s, timeout=timeout)
    
    # If --no-crawl is used, filter to only test endpoints on the target page itself
    # (exclude navigation links to other pages)
    if no_crawl:
        target_parsed = urlparse(url)
        target_base = f"{target_parsed.scheme}://{target_parsed.netloc}{target_parsed.path}"
        
        filtered_endpoints = []
        for ep in endpoints:
            ep_parsed = urlparse(ep.url)
            ep_base = f"{ep_parsed.scheme}://{ep_parsed.netloc}{ep_parsed.path}"
            
            # Keep endpoints that match the target base URL (same path)
            if ep_base.rstrip('/') == target_base.rstrip('/'):
                filtered_endpoints.append(ep)
        
        print(f"[+] Endpoints found: {len(endpoints)} (filtered to {len(filtered_endpoints)} on target page)")
        endpoints = filtered_endpoints
    else:
        print(f"[+] Endpoints found: {len(endpoints)}")

    # Check for debug endpoints (CWE-215)
    print("[+] Checking for debug endpoints...")
    debug_findings = check_debug_endpoints(
        session=session,
        base_url=url,
        timeout=timeout,
        delay_s=delay_s,
    )
    
    # Display debug findings immediately
    for f in debug_findings:
        print(f"[!] {f.severity} - {f.cwe_id}: {f.title}")

    # Generate payloads & execute tests
    payloads = generate_payloads()
    all_test_results: List[TestResult] = []
    all_findings: List[Finding] = debug_findings  # Start with debug findings

    for idx, ep in enumerate(endpoints, 1):
        print(f"[*] ({idx}/{len(endpoints)}) Baseline: {ep.method} {ep.url} [{', '.join(ep.params[:6])}{'...' if len(ep.params)>6 else ''}]")
        base = baseline_request(session, ep, timeout=timeout)

        tests = execute_tests_for_endpoint(
            session=session,
            ep=ep,
            payloads=payloads,
            timeout=timeout,
            delay_s=delay_s,
            target_param=target_param,
        )
        all_test_results.extend(tests)

        findings = analyze(
            ep=ep,
            baseline=base,
            tests=tests,
            enabled_cwe_nums=enabled_cwe_nums,
        )
        all_findings.extend(findings)

        for f in findings:
            print(f"[!] {f.severity} - {f.cwe_id}: {f.title}")

    # Prepare report payload
    ts = now_stamp()
    parsed = urlparse(url)
    safe_host = re.sub(r"[^a-zA-Z0-9._-]+", "_", parsed.netloc)

    json_path = f"{outdir}/edgesentinel_report_{safe_host}_{ts}.json"
    html_path = f"{outdir}/edgesentinel_report_{safe_host}_{ts}.html"

    # Convert test results to dict but exclude full_body to reduce JSON size
    test_results_for_json = []
    for r in all_test_results:
        r_dict = asdict(r)
        r_dict.pop("full_body", None)  # Remove full_body from JSON export
        test_results_for_json.append(r_dict)
    
    # Build untested CWEs for JSON (same data as HTML section)
    _SAST_ONLY = [
        {"cwe_id": "CWE-396", "cwe_name": "Declaration of Catch for Generic Exception"},
        {"cwe_id": "CWE-397", "cwe_name": "Declaration of Throws for Generic Exception"},
        {"cwe_id": "CWE-460", "cwe_name": "Improper Cleanup on Thrown Exception"},
        {"cwe_id": "CWE-478", "cwe_name": "Missing Default Case in Multiple Condition Expression"},
        {"cwe_id": "CWE-484", "cwe_name": "Omitted Break Statement in Switch"},
    ]
    untested_cwes_for_json = [
        {
            "cwe_id": s["cwe_id"],
            "cwe_name": s["cwe_name"],
            "detection": "SAST only, not detectable by DAST",
            "recommendation": CWE_RECOMMENDATIONS.get(s["cwe_id"], {}).get("summary", ""),
        }
        for s in _SAST_ONLY
    ]

    report = {
        "meta": {
            "target_url": url,
            "timestamp": ts,
            "mode": mode,
            "pages_crawled": len(pages),
            "endpoints_found": len(endpoints),
            "total_tests": len(all_test_results),
            "finding_count": len(all_findings),
            "enabled_cwes": sorted(list(enabled_cwe_nums)),
            "notes": "For authorized testing only. Heuristic findings; validate manually.",
        },
        "endpoints": [asdict(e) for e in endpoints],
        "test_results": test_results_for_json,
        "findings": [asdict(f) for f in all_findings],
        "untested_cwes": untested_cwes_for_json,
    }

    # Write outputs
    import os
    os.makedirs(outdir, exist_ok=True)

    if out_format in ("json", "both"):
        write_json_report(json_path, report)
        print(f"[+] JSON report: {json_path}")

    if out_format in ("html", "both"):
        write_html_report(html_path, report)
        print(f"[+] HTML report: {html_path}")

    print("[+] Scan complete.")
    return (json_path if out_format in ("json", "both") else ""), (html_path if out_format in ("html", "both") else None)


# -----------------------------
# CLI (keeps your scan modes)
# -----------------------------
def parse_cwe_list(spec: str) -> Set[int]:
    nums: Set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        n = int(part)
        if n < 1 or n > 24:
            raise ValueError("CWEs specified must be integers from 1-24")
        nums.add(n)
    return nums


def main():
    parser = argparse.ArgumentParser(
        description="EdgeSentinel - OWASP A10:2025 Focused Detection Tool\n\n"
                    "A lightweight scanner that helps testers and developers "
                    "quickly surface A10: Mishandling of Exceptional "
                    "Conditions vulnerabilities from a target URL.\n\n"
                    "Performs bounded crawling, executes curated edge-case "
                    "test suites, and generates reports identifying "
                    "A10-relevant weaknesses mapped to specific CWEs.\n\n"
                    "Features:\n"
                    "  - Bounded crawling (configurable depth/page limits)\n"
                    "  - Endpoint discovery (links, forms, common API paths)\n"
                    "  - Edge-case testing (missing/extra params, type "
                    "confusion, etc.)\n"
                    "  - Behavioral analysis (status codes, response sizes, "
                    "timing)\n"
                    "  - CSRF-aware authentication support\n"
                    "  - Structured reporting with remediation guidance\n\n"
                    "Scan Modes:\n"
                    "  Normal:   All 24 CWEs (default)\n"
                    "  Quick:    First 12 CWEs only (-q)\n"
                    "  Specific: Selected CWEs only (-s 1,3,5)\n\n"
                    "For authorized testing only. Non-destructive payloads.",
        formatter_class=RawTextHelpFormatter,
    )

    parser.add_argument("url", help="Target URL to scan "
                        "(e.g. http://example.com)")

    # Scan mode arguments 
    mode_group = parser.add_mutually_exclusive_group(required=False)
    mode_group.add_argument(
        "-q", "--quick_scan",
        action="store_true",
        help="Quick analysis: first 12 CWEs only (1-12)."
    )
    mode_group.add_argument(
        "-s", "--specify",
        help="Specify CWEs by number separated by commas (e.g. 1,3,5)."
    )

    # Crawl boundary arguments
    parser.add_argument(
        "-n", "--no-crawl", 
        action="store_true",
        help="Disable crawling and scans only the given URL"
        )
    parser.add_argument(
        "-dl", "--depth-level", 
        type=int, 
        default=1,
        help="Set crawl depth (Default depth is 1)"
        )
    parser.add_argument(
        "-m", "--max-pages", 
        type=int, 
        default=10,
        help="Max pages to crawl for the website (Max pages is set to 10 "
        "by default)"
        )
    parser.add_argument(
        "-e", "--allow-external-paths", 
        action="store_true",
        help="Allow crawling outside the base path (e.g., allow /docs/ when "
        "starting from /dvwa/). By default, crawler stays within the same "
        "path prefix to avoid wandering to documentation or unrelated "
        "sections."
        )

    # Request control arguments
    parser.add_argument(
        "-d", "--delay", 
        type=float, 
        default=0.3,
        help="Sets timing delay between requests in seconds (Default delay "
        "is 0.3s)"
        )
    parser.add_argument(
        "-t", "--timeout", 
        type=int, 
        default=10,
        help="Sets timing to wait for request before timeout in seconds "
        "(Default timeout is 10s)"
        )
    parser.add_argument(
        "-a", "--user-agent", 
        default=DEFAULT_UA,
        help="Specifies User-Agent header to be used for the request"
        )

    # Targeting arguments
    parser.add_argument(
        "--param", 
        help="Specifies parameter name to be tested (optional)"
        )

    # Authentication arguments
    parser.add_argument(
        "-l", "--login-url", 
        help="Specifies URL of the login page/endpoint (optional)"
        )
    parser.add_argument(
        "-u", "--username", 
        help="Specifies username to be used for authentication with -l flag"
        )
    parser.add_argument(
        "-p", "--password", 
        help="Specifies password to be used for authentication with -l flag"
        )
    parser.add_argument(
        "-uf", "--username-field", 
        default="username", 
        help="Specifies name of username field in login form (Default is "
        "set to username)"
        )
    parser.add_argument(
        "-pf", "--password-field", 
        default="password", 
        help="Specifies name of password field in login form (Default is "
        "set to password)"
        )

    # Output file arguments
    parser.add_argument(
        "-o", "--outdir", 
        default="reports", 
        help="Specifies output directory for report generated"
        " (Default directort is reports)")
    parser.add_argument(
        "-f", "--format",
        choices=["json", "html", "both"],
        default="both",
        help="Specifies format of generated report (Default is both)"
        )

    args = parser.parse_args()

    url = args.url
    if args.quick_scan:
        enabled = set(QUICK_SCAN_SET)
        mode = "quick"
    elif args.specify:
        enabled = parse_cwe_list(args.specify)
        mode = "specific"
    else:
        enabled = set(range(1, 25))
        mode = "normal"

    if args.no_crawl:
        if (args.depth_level != 1 or args.max_pages != 10 
            or args.allow_external_paths):
            parser.error("--no-crawl flag cannot be used with --depth-level, "
                         "--max-pages, or --allow-external-paths flags. Use "
                         "-h for more information.")
            
    if args.login_url:
        if not (args.username and args.password):
            parser.error("--username and --password flags must be specified "
                         "when --login_url is set. Use -h for more "
                         "information")

    # Very important: authorized testing only
    print("[!] Reminder: Only scan systems you own or have explicit permission to test.\n")

    run_scan(
        url=url,
        mode=mode,
        enabled_cwe_nums=enabled,
        depth=max(0, args.depth_level),
        max_pages=max(1, args.max_pages),
        delay_s=max(0.0, args.delay),
        timeout=max(1, args.timeout),
        outdir=args.outdir,
        out_format=args.format,
        user_agent=args.user_agent,
        no_crawl=args.no_crawl,
        allow_external_paths=args.allow_external_paths,
        target_param=args.param,
        login_url=args.login_url,
        username=args.username,
        password=args.password,
        username_field=args.username_field,
        password_field=args.password_field,
    )


if __name__ == "__main__":
    main()
