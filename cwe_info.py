# Contains:
#   CWE_LIST          — internal number (1-19) → (CWE ID, name) mapping
#   QUICK_SCAN_SET    — CWE numbers included in quick-scan mode (-q)
#   SAST_ONLY_CWES    — CWEs that require static analysis; not detectable by DAST
#   CWE_RECOMMENDATIONS — per-CWE remediation summaries and secure/vulnerable
#                         code examples, keyed by CWE ID string (e.g. "CWE-209")

# CWE mapping
CWE_LIST = {
    1:  ("CWE-209", "Generation of Error Message Containing Sensitive Information"),
    2:  ("CWE-215", "Insertion of Sensitive Information Into Debugging Code"),
    3:  ("CWE-234", "Failure to Handle Missing Parameter"),
    4:  ("CWE-235", "Improper Handling of Extra Parameters"),
    5:  ("CWE-248", "Uncaught Exception"),
    6:  ("CWE-252", "Unchecked Return Value"),
    7:  ("CWE-274", "Improper Handling of Insufficient Privileges"),
    8:  ("CWE-280", "Improper Handling of Insufficient Permissions or Privileges"),
    9:  ("CWE-369", "Divide By Zero"),
    10: ("CWE-390", "Detection of Error Condition Without Action"),
    11: ("CWE-391", "Unchecked Error Condition"),
    12: ("CWE-394", "Unexpected Status Code or Return Value"),
    13: ("CWE-476", "NULL Pointer Dereference"),
    14: ("CWE-550", "Server-generated Error Message Containing Sensitive Information"),
    15: ("CWE-636", "Not Failing Securely ('Failing Open')"),
    16: ("CWE-703", "Improper Check or Handling of Exceptional Conditions"),
    17: ("CWE-754", "Improper Check for Unusual or Exceptional Conditions"),
    18: ("CWE-755", "Improper Handling of Exceptional Conditions"),
    19: ("CWE-756", "Missing Custom Error Page"),
}

# Quick scan (-q) first 10 CWEs only
QUICK_SCAN_SET = set(range(1, 11))

# CWEs that require static analysis (SAST) 
SAST_ONLY_CWES = [
    {"cwe_id": "CWE-396", "cwe_name": "Declaration of Catch for Generic Exception"},
    {"cwe_id": "CWE-397", "cwe_name": "Declaration of Throws for Generic Exception"},
    {"cwe_id": "CWE-460", "cwe_name": "Improper Cleanup on Thrown Exception"},
    {"cwe_id": "CWE-478", "cwe_name": "Missing Default Case in Multiple Condition Expression"},
    {"cwe_id": "CWE-484", "cwe_name": "Omitted Break Statement in Switch"},
]


# CWE recommendations
# Keyed by CWE ID string (e.g. "CWE-209"). Each entry contains:
#   "summary" — one-line remediation guidance shown in reports
#   "bad"     — example of a vulnerable code pattern (optional)
#   "good"    — example of the secure equivalent (optional)

CWE_RECOMMENDATIONS = {
    # Dynamically testable CWEs (CWE_LIST entries 1-19)

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

    # SAST-only CWEs (SAST_ONLY_CWES entries)

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
}
