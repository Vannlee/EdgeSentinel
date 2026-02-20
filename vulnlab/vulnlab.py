#!/usr/bin/env python3
"""
VulnLab - Deliberately Vulnerable Web Application
For testing EdgeSentinel scanner coverage of OWASP A10:2025 CWEs

WARNING: This application contains intentional vulnerabilities.
DO NOT deploy to production or expose to untrusted networks.
FOR EDUCATIONAL/TESTING PURPOSES ONLY.
"""

from flask import Flask, request, jsonify, render_template_string
import sys

app = Flask(__name__)

# Disable Flask's default error handling to expose raw errors (CWE-24)
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['TRAP_HTTP_EXCEPTIONS'] = False

# Simple in-memory "database"
users = {
    "1": {"id": "1", "name": "Alice", "role": "user"},
    "2": {"id": "2", "name": "Bob", "role": "admin"},
}

@app.route('/')
def index():
    # IMPORTANT: Using HTML forms (not plain links) so the scanner discovers
    # parameters cleanly and can replace them with test payloads without
    # duplicate-param issues. Forms produce clean base URLs (no embedded query strings).
    return """<!DOCTYPE html>
<html>
<head><title>VulnLab - CWE Test Application</title></head>
<body>
    <h1>VulnLab - CWE Test Application</h1>
    <p><strong>WARNING:</strong> Deliberately vulnerable endpoints for EdgeSentinel scanner testing.</p>

    <h2>CWE-9 (Divide By Zero) - /api/calc</h2>
    <form action="/api/calc" method="GET">
        Divisor: <input type="text" name="divisor" value="5">
        <button type="submit">Calculate</button>
    </form>

    <h2>CWE-16 (NULL Pointer) - /api/user</h2>
    <form action="/api/user" method="GET">
        User ID: <input type="text" name="id" value="1">
        <button type="submit">Lookup User</button>
    </form>

    <h2>CWE-4, CWE-12 (Extra Params, Status Changes) - /api/stats</h2>
    <form action="/api/stats" method="GET">
        Type: <input type="text" name="type" value="summary">
        <button type="submit">Get Stats</button>
    </form>

    <h2>CWE-7, CWE-8, CWE-20 (Auth Bypass / Fail Open) - /admin/config</h2>
    <form action="/admin/config" method="GET">
        Role: <input type="text" name="role" value="user">
        <button type="submit">Get Config</button>
    </form>

    <h2>CWE-5, CWE-22, CWE-23 (Uncaught Exception, Unusual Conditions) - /api/process</h2>
    <form action="/api/process" method="GET">
        Value: <input type="text" name="value" value="hello">
        <button type="submit">Process</button>
    </form>
</body>
</html>"""


# CWE-9 (369): Divide By Zero
@app.route('/api/calc')
def calculate():
    """Division calculator - vulnerable to divide-by-zero.
    Uses single 'divisor' param so scanner can replace it cleanly.
    Handles non-numeric gracefully (400) but NOT zero (ZeroDivisionError -> 500).
    """
    divisor = request.args.get('divisor', '5')

    try:
        d = float(divisor)
    except (ValueError, TypeError):
        return jsonify({"error": "'divisor' must be a number"}), 400

    # VULNERABILITY CWE-9: No zero check before division
    result = 100.0 / d  # ZeroDivisionError if divisor=0

    return jsonify({"numerator": 100, "divisor": d, "result": result})


# CWE-16 (476): NULL Pointer Dereference
@app.route('/api/user')
def get_user():
    """User lookup - vulnerable to NULL pointer dereference.
    Handles non-numeric IDs gracefully (400) so scanner baseline succeeds.
    Crashes when a numeric-looking ID has no matching user (None access -> 500).
    """
    user_id = request.args.get('id', '1')

    # Reject obviously non-numeric IDs gracefully (baseline with 'test' returns 400)
    if not str(user_id).lstrip('-').isdigit():
        return jsonify({"error": "'id' must be a numeric value"}), 400

    user = users.get(str(user_id))  # Returns None for valid-looking but missing IDs

    # VULNERABILITY CWE-16: No None check before accessing properties
    # id=0, id=-1, id=999 etc. all return None and crash here
    return jsonify({
        "id": user["id"],
        "name": user["name"],
        "role": user["role"]
    })


# CWE-4 (235): Improper Handling of Extra Parameters
# CWE-12 (394): Unexpected Status Code Changes
@app.route('/api/stats')
def statistics():
    """Statistics endpoint - changes behavior with extra params"""
    stat_type = request.args.get('type', 'summary')
    
    # VULNERABILITY: Extra 'admin' parameter changes behavior unexpectedly
    if 'admin' in request.args:
        # Changes from 200 to 403 when extra param present
        return jsonify({"error": "Admin parameter not allowed"}), 403
    
    # VULNERABILITY: Extra 'debug' parameter triggers different status
    if 'debug' in request.args:
        # Returns 500 with extra debug param
        raise Exception("Debug mode triggered error")
    
    # VULNERABILITY: Unknown type values cause status code changes
    if stat_type not in ['summary', 'detailed']:
        return jsonify({"error": "Invalid type"}), 400  # Status change from baseline
    
    return jsonify({
        "type": stat_type,
        "total_users": len(users),
        "timestamp": "2026-02-19"
    })


# CWE-7 (274): Improper Handling of Insufficient Privileges
# CWE-8 (280): Improper Handling of Insufficient Permissions
# CWE-20 (636): Not Failing Securely ('Failing Open')
@app.route('/admin/config')
def admin_config():
    """Admin endpoint - vulnerable to failing open on missing/empty role.
    Scanner baseline (role='test') returns 403 (forbidden).
    Missing or empty role parameter fails open and returns full config (200).
    """
    role = request.args.get('role')

    # VULNERABILITY CWE-20: Fails open when role is missing or empty string
    # Should return 403, but returns sensitive config instead
    if role is None or role.strip() == '':
        return jsonify({
            "config": {
                "db_password": "SuperSecret123!",
                "api_key": "sk-abc123xyz",
                "debug_mode": True
            }
        })

    # Admin is allowed
    if role == 'admin':
        return jsonify({
            "config": {
                "db_password": "SuperSecret123!",
                "api_key": "sk-abc123xyz",
                "debug_mode": True
            }
        })

    # All other roles (including scanner default 'test') are forbidden
    # This makes baseline = 403, so the fail-open above is detectable
    return jsonify({"error": "Forbidden: insufficient privileges"}), 403


# CWE-5 (248): Uncaught Exception
# CWE-22 (754): Improper Check for Unusual or Exceptional Conditions
# CWE-23 (755): Improper Handling of Exceptional Conditions
@app.route('/api/process')
def process_data():
    """Data processor - vulnerable to uncaught exceptions on edge cases.
    Normal strings (including scanner baseline 'hello') return 200.
    Special/unusual inputs crash with unhandled exceptions (500).
    """
    value = request.args.get('value', 'hello')

    # VULNERABILITY CWE-22/23: No validation for special float string values
    # NaN and Infinity are valid Python floats but cause arithmetic issues
    if value in ['NaN', 'Infinity', '-Infinity', 'nan', 'inf', '-inf']:
        raise ValueError(f"Unhandled special numeric value: {value}")

    # VULNERABILITY CWE-5/22: Integer overflow not caught
    if value.lstrip('-').isdigit() and abs(int(value)) > 2147483647:
        raise OverflowError(f"Integer overflow: {value}")

    # VULNERABILITY CWE-22/23: Large inputs not validated before processing
    if len(value) > 10000:
        raise MemoryError("Input exceeds processing capacity")

    # VULNERABILITY CWE-22: Unicode/encoding issues not handled
    if any(ord(c) > 127 for c in value):
        raise UnicodeError(f"Non-ASCII character in input: {repr(value)}")

    return jsonify({
        "processed": value,
        "length": len(value),
        "status": "success"
    })


# CWE-24 (756): Missing Custom Error Page
# Flask's default error handlers expose stack traces and technical details
# We explicitly disable custom error handling to expose this


@app.route('/api/crash')
def intentional_crash():
    """Endpoint that always crashes - tests error page handling"""
    # Triggers unhandled exception with default Flask error page
    raise RuntimeError("This endpoint intentionally crashes for testing")


# Additional test endpoints for comprehensive coverage

@app.route('/api/divide')
def divide_endpoint():
    """Alternative divide-by-zero test"""
    x = int(request.args.get('x', '100'))
    y = int(request.args.get('y', '10'))
    
    # No zero check
    return jsonify({"result": x / y})


@app.route('/api/lookup')
def lookup():
    """Database lookup - NULL pointer when record not found"""
    record_id = request.args.get('id')
    
    # Simulate database lookup that returns None
    record = None  # Database returned nothing
    
    # Direct access without None check
    return jsonify({
        "id": record["id"],
        "data": record["data"]
    })


if __name__ == '__main__':
    print("=" * 60)
    print("VulnLab - Deliberately Vulnerable Test Application")
    print("=" * 60)
    print("WARNING: Contains intentional security vulnerabilities!")
    print("FOR TESTING EDGESENTINEL SCANNER ONLY")
    print("=" * 60)
    print("\nStarting server on http://0.0.0.0:5000")
    print("Accessible from: http://127.0.0.1:5000 (local)")
    print("                 http://<VM-IP>:5000 (remote)")
    print("Press Ctrl+C to stop\n")
    
    # Run with debug mode OFF to expose raw errors (CWE-24)
    # But keep verbose error messages for testing
    # Bind to 0.0.0.0 to accept connections from any IP (needed for VM deployment)
    app.run(host='0.0.0.0', port=5000, debug=False)
