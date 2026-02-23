from typing import Dict, List, Optional, Set

# Generic error patterns used as additional detection signal
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

# SQLish payloads for detection
SQLISH_PAYLOADS = [
    "' OR '1'='1",           # Basic SQL injection test
    "1'--",                  # SQL comment injection
    "\" OR \"1\"=\"1",       # Double-quote SQL injection
    # "1; DROP TABLE t--",   # DESTRUCTIVE - commented out for safety
    "1' OR '1'='1",          # Non-destructive alternative
]

# Special characters
SPECIAL_CHARS = [
    "<>\"'`;&|",             # Special shell/script characters
    "\x00",                  # Null byte
    # "../" * 3 + "etc/passwd",      # DESTRUCTIVE - path traversal (Linux)
    # "..\\..\\windows\\system32",   # DESTRUCTIVE - path traversal (Windows)
    "../test",               # Non-destructive path traversal test
    "..\\test",              # Non-destructive Windows path test
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
    "null", "NULL", "nil", "None",   # String null representations
    "undefined", "#undef",           # Undefined values
    "true", "false", "True", "False", # Booleans
    "[]", "{}", "()",                 # Empty structures
    "0",                              # Zero (invalid ID for NULL pointer tests)
    "-1",                             # Negative (invalid ID)
    "999999999",                      # Non-existent ID (triggers NULL when object not found)
    "A" * 5000,                       # Large input (buffer)
    "A" * 10000,                      # Very large input
    "\n\r\t",                         # Control characters
    "â",                              # Unicode replacement char
]

ENCODING = ["%3Cscript%3E", "%253Cscript%253E", "SeLeCt", "SELECT"]

TIMING = ["sleep(2)", "WAITFOR DELAY '00:00:02'"]  # timing probe only, no exploit claims

# Additional numeric edge cases specifically for divide-by-zero and numeric errors
NUMERIC_EDGE_CASES = [
    "0",       # Zero
    "0.0",     # Float zero
    "-0",      # Negative zero
    "00",      # Zero with leading zero
    "0x0",     # Hex zero
    "1/0",     # Division expression
    "0/0",     # Undefined division
]


# Per-CWE payload functions
# Each function returns a dict of { category: [payloads] } relevant to that CWE.
# None in a payload list means "omit the parameter entirely" (missing-param test).

def payloads_cwe_209() -> Dict[str, List[Optional[str]]]:
    """CWE-209: Generation of Error Message Containing Sensitive Information.
    Needs payloads that provoke verbose error responses."""
    return {
        "error_disclosure": SQLISH_PAYLOADS + SPECIAL_CHARS + FORMAT_STRINGS + XSSISH,
    }


def payloads_cwe_215() -> Dict[str, List[Optional[str]]]:
    """CWE-215: Insertion of Sensitive Information Into Debugging Code.
    Needs payloads that surface debug output in responses."""
    return {
        "error_disclosure": SQLISH_PAYLOADS + SPECIAL_CHARS,
    }


def payloads_cwe_234() -> Dict[str, List[Optional[str]]]:
    """CWE-234: Failure to Handle Missing Parameter."""
    return {
        "missing_param": [None, "", "   ", "\x00"],
    }


def payloads_cwe_235() -> Dict[str, List[Optional[str]]]:
    """CWE-235: Improper Handling of Extra Parameters."""
    return {
        "extra_param": ["admin=true", "debug=true", "role=admin", "priv=1"],
    }


def payloads_cwe_248() -> Dict[str, List[Optional[str]]]:
    """CWE-248: Uncaught Exception.
    Needs a broad range of unexpected inputs to provoke 5xx responses."""
    return {
        "error_disclosure": SQLISH_PAYLOADS + SPECIAL_CHARS + FORMAT_STRINGS + XSSISH,
        "type_confusion":   TYPE_CONFUSION,
        "special_values":   SPECIAL_VALUES,
        "encoding":         ENCODING,
    }


def payloads_cwe_252() -> Dict[str, List[Optional[str]]]:
    """CWE-252: Unchecked Return Value.
    Looks for subtle 200-OK responses that hide errors — needs broad inputs."""
    return {
        "error_disclosure": SQLISH_PAYLOADS + SPECIAL_CHARS,
        "type_confusion":   TYPE_CONFUSION,
        "special_values":   SPECIAL_VALUES,
    }


def payloads_cwe_274() -> Dict[str, List[Optional[str]]]:
    """CWE-274: Improper Handling of Insufficient Privileges."""
    return {
        "extra_param": ["admin=true", "debug=true", "role=admin", "priv=1"],
    }


def payloads_cwe_280() -> Dict[str, List[Optional[str]]]:
    """CWE-280: Improper Handling of Insufficient Permissions or Privileges."""
    return {
        "extra_param": ["admin=true", "debug=true", "role=admin", "priv=1"],
    }


def payloads_cwe_369() -> Dict[str, List[Optional[str]]]:
    """CWE-369: Divide By Zero."""
    return {
        "numeric_edge": NUMERIC_EDGE_CASES,
    }


def payloads_cwe_390() -> Dict[str, List[Optional[str]]]:
    """CWE-390: Detection of Error Condition Without Action.
    Needs broad inputs to find errors swallowed inside 200 responses."""
    return {
        "error_disclosure": SQLISH_PAYLOADS + SPECIAL_CHARS + FORMAT_STRINGS,
        "type_confusion":   TYPE_CONFUSION,
        "special_values":   SPECIAL_VALUES,
    }


def payloads_cwe_391() -> Dict[str, List[Optional[str]]]:
    """CWE-391: Unchecked Error Condition (shares detection with CWE-390)."""
    return {
        "error_disclosure": SQLISH_PAYLOADS + SPECIAL_CHARS + FORMAT_STRINGS,
        "type_confusion":   TYPE_CONFUSION,
        "special_values":   SPECIAL_VALUES,
    }


def payloads_cwe_394() -> Dict[str, List[Optional[str]]]:
    """CWE-394: Unexpected Status Code or Return Value."""
    return {
        "error_disclosure": SQLISH_PAYLOADS + SPECIAL_CHARS + FORMAT_STRINGS + XSSISH,
        "missing_param":    [None, "", "   ", "\x00"],
        "type_confusion":   TYPE_CONFUSION,
        "special_values":   SPECIAL_VALUES,
        "encoding":         ENCODING,
    }


def payloads_cwe_476() -> Dict[str, List[Optional[str]]]:
    """CWE-476: NULL Pointer Dereference."""
    return {
        "special_values": SPECIAL_VALUES,
        "missing_param":  [None, "", "   ", "\x00"],
    }


def payloads_cwe_550() -> Dict[str, List[Optional[str]]]:
    """CWE-550: Server-generated Error Message Containing Sensitive Information."""
    return {
        "error_disclosure": SQLISH_PAYLOADS + SPECIAL_CHARS + FORMAT_STRINGS + XSSISH,
    }


def payloads_cwe_636() -> Dict[str, List[Optional[str]]]:
    """CWE-636: Not Failing Securely ('Failing Open').
    Needs inputs that bypass auth — extra privilege params plus edge-case values."""
    return {
        "extra_param":  ["admin=true", "debug=true", "role=admin", "priv=1"],
        "special_values": SPECIAL_VALUES,
    }


def payloads_cwe_703() -> Dict[str, List[Optional[str]]]:
    """CWE-703: Improper Check or Handling of Exceptional Conditions."""
    return {
        "error_disclosure": SQLISH_PAYLOADS + SPECIAL_CHARS + FORMAT_STRINGS + XSSISH,
        "type_confusion":   TYPE_CONFUSION,
        "special_values":   SPECIAL_VALUES,
        "encoding":         ENCODING,
        "missing_param":    [None, "", "   ", "\x00"],
        "extra_param":      ["admin=true", "debug=true", "role=admin", "priv=1"],
    }


def payloads_cwe_754() -> Dict[str, List[Optional[str]]]:
    """CWE-754: Improper Check for Unusual or Exceptional Conditions."""
    return {
        "type_confusion": TYPE_CONFUSION,
        "encoding":       ENCODING,
        "timing":         TIMING,
        "numeric_edge":   NUMERIC_EDGE_CASES,
        "special_values": SPECIAL_VALUES,
    }


def payloads_cwe_755() -> Dict[str, List[Optional[str]]]:
    """CWE-755: Improper Handling of Exceptional Conditions."""
    return {
        "type_confusion": TYPE_CONFUSION,
        "special_values": SPECIAL_VALUES,
    }


def payloads_cwe_756() -> Dict[str, List[Optional[str]]]:
    """CWE-756: Missing Custom Error Page.
    Any error-inducing payload is sufficient to trigger a 4xx/5xx for page detection."""
    return {
        "error_disclosure": SQLISH_PAYLOADS + SPECIAL_CHARS,
        "missing_param":    [None, "", "   ", "\x00"],
        "type_confusion":   TYPE_CONFUSION,
    }


# CWE to payload function mapping
_CWE_PAYLOAD_FUNCS = {
    1:  payloads_cwe_209,
    2:  payloads_cwe_215,
    3:  payloads_cwe_234,
    4:  payloads_cwe_235,
    5:  payloads_cwe_248,
    6:  payloads_cwe_252,
    7:  payloads_cwe_274,
    8:  payloads_cwe_280,
    9:  payloads_cwe_369,
    10: payloads_cwe_390,
    11: payloads_cwe_391,
    12: payloads_cwe_394,
    13: payloads_cwe_476,
    14: payloads_cwe_550,
    15: payloads_cwe_636,
    16: payloads_cwe_703,
    17: payloads_cwe_754,
    18: payloads_cwe_755,
    19: payloads_cwe_756,
}


def get_payloads_for_cwes(enabled_cwe_nums: Set[int]) -> Dict[str, List[Optional[str]]]:
    """
    Merge payload categories needed for the given set of enabled CWE numbers.
    Only categories required by at least one enabled CWE are included, and
    duplicate payloads within a category are de-duplicated while preserving order.

    Returns a dict of { category: [payloads] } ready for execute_tests_for_endpoint().
    """
    merged: Dict[str, List[Optional[str]]] = {}

    for cwe_num in sorted(enabled_cwe_nums):
        func = _CWE_PAYLOAD_FUNCS.get(cwe_num)
        if func is None:
            continue
        for category, payload_list in func().items():
            if category not in merged:
                merged[category] = []
            # De-duplicate while preserving insertion order
            seen_in_cat = set(
                str(p) if p is not None else "__NONE__"
                for p in merged[category]
            )
            for p in payload_list:
                key = str(p) if p is not None else "__NONE__"
                if key not in seen_in_cat:
                    merged[category].append(p)
                    seen_in_cat.add(key)

    return merged


def generate_payloads() -> Dict[str, List[Optional[str]]]:
    """
    Legacy helper: returns the full merged payload set for all 19 CWEs.
    Kept for backward compatibility. Prefer get_payloads_for_cwes() for
    targeted scans.
    """
    return get_payloads_for_cwes(set(range(1, 20)))
