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


# -----------------------------
# CWE mapping (your numbering)
# -----------------------------
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
# Data models
# -----------------------------
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


# -----------------------------
# Safety & config
# -----------------------------
DEFAULT_UA = "EdgeSentinel/0.1 (CLI; educational; authorized testing only)"

# Generic error patterns (optional - used as additional signal)
ERROR_KEYWORDS = [
    # stack traces / exceptions
    "traceback", "exception", "stack trace", "fatal error",
    # common DB errors (generic patterns)
    "sql syntax", "syntax error", "query failed", "database error",
    "you have an error", "mysql", "postgresql", "sqlite", "sqlstate",
    # file paths (disclosure)
    "/var/www", "/usr/local", "c:\\", "d:\\", "/home/",
    # generic error indicators
    "warning:", "fatal:", "error:", "undefined", "null reference",
    "division by zero", "cannot be null", "out of bounds",
]

SQLISH_PAYLOADS = ["' OR '1'='1", "1'--", "\" OR \"1\"=\"1", "1; DROP TABLE t--"]
SPECIAL_CHARS = ["<>\"'`;&|", "\x00", "../" * 3 + "etc/passwd", "..\\..\\windows\\system32"]
FORMAT_STRINGS = ["%s%s%s%s", "${7*7}", "{7*7}"]
XSSISH = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

TYPE_CONFUSION = ["abc", "99999999999999999999", "-1", "0", "1.1e308"]
SPECIAL_VALUES = ["null", "NULL", "nil", "true", "false", "[]", "{}", "A" * 5000]
ENCODING = ["%3Cscript%3E", "%253Cscript%253E", "SeLeCt", "SELECT"]
TIMING = ["sleep(2)", "WAITFOR DELAY '00:00:02'"]  # only used as "timing probe" (no exploit claims)


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


def clip(text: str, max_len: int = 350) -> str:
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
) -> List[str]:
    """
    Simple BFS crawl over <a href> links.
    """
    seen: Set[str] = set()
    queue: List[Tuple[str, int]] = [(start_url, 0)]
    out: List[str] = []

    while queue and len(out) < max_pages:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)

        if same_host_only and not same_host(start_url, url):
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
# Payload generation
# -----------------------------
def generate_payloads() -> Dict[str, List[Optional[str]]]:
    """
    Returns category -> payload list.
    payload None means "omit parameter" for missing-param tests.
    """
    return {
        "error_disclosure": SQLISH_PAYLOADS + SPECIAL_CHARS + FORMAT_STRINGS + XSSISH,
        "missing_param": [None, "", "   "],
        "extra_param": ["admin=true", "debug=true"],
        "type_confusion": TYPE_CONFUSION,
        "special_values": SPECIAL_VALUES,
        "encoding": ENCODING,
        "timing": TIMING,
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


def significant_content_change(baseline_len: int, test_len: int, threshold: float = 0.3) -> bool:
    """
    Detects if response size changed significantly (±30% by default).
    Indicates different code path or error handling.
    """
    if baseline_len == 0:
        return test_len > 100  # any substantial response when baseline was empty
    
    ratio = abs(test_len - baseline_len) / baseline_len
    return ratio > threshold


def significant_timing_change(baseline_ms: int, test_ms: int, threshold_ms: int = 1500) -> bool:
    """
    Detects significant slowdown suggesting expensive error handling or resource issues.
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
        findings.append(
            Finding(
                cwe_num=cwe_num,
                cwe_id=cwe_id,
                cwe_name=cwe_name,
                severity=sev,
                title=title,
                description=desc,
                evidence=evidence,
                recommendation=rec,
                confidence=conf,
            )
        )

    for tr in tests:
        # Skip if request outright failed (still useful, but keep it lower signal)
        body = tr.body_snippet or ""
        sc = tr.status_code or 0
        test_len = tr.content_len or 0
        test_time = tr.elapsed_ms or 0

        # BEHAVIORAL DETECTION (generic, works across all apps)
        
        # 1. Status code 5xx = server error (generic)
        if sc >= 500:
            add(
                5,
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
        if significant_content_change(baseline.content_len, test_len):
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
            meaningful = (baseline.status_code < 400 <= sc) or (baseline.status_code >= 400 > sc)
            if meaningful:
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

        # 7. Divide by zero detection (generic)
        if tr.payload == "0":
            if sc >= 500 or "division by zero" in body.lower() or significant_content_change(baseline.content_len, test_len):
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

        # BONUS: Specific error disclosure (extra signal, not required)
        if looks_like_error_disclosure(body):
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

    # de-duplicate loosely (same CWE + endpoint + title)
    uniq = {}
    for f in findings:
        key = (f.cwe_num, f.evidence.get("endpoint"), f.title)
        uniq[key] = f
    findings = list(uniq.values())

    # sort by severity
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
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
        
        # Build evidence display - show snippet OR other relevant fields
        evidence_html = ""
        
        if ev.get("snippet"):
            # Show error message snippet if available
            evidence_html = f'<pre>{escape(str(ev.get("snippet",""))[:400])}</pre>'
        else:
            # Show other evidence fields for behavioral detections
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
            
            if evidence_parts:
                evidence_html = "<br>".join(evidence_parts)
            else:
                evidence_html = "<em>Behavioral anomaly detected</em>"
        
        rows.append(
            f"""
            <tr>
              <td>{escape(f["severity"])}</td>
              <td>{escape(f["cwe_id"])}</td>
              <td>{escape(f["title"])}</td>
              <td><code>{escape(str(ev.get("endpoint","")))}</code></td>
              <td>{evidence_html}</td>
            </tr>
            """
        )

    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>EdgeSentinel Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 14px; margin-bottom: 14px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ background: #f6f6f6; text-align: left; }}
    .high {{ color: #b00020; font-weight: bold; }}
    .medium {{ color: #b26a00; font-weight: bold; }}
    .low {{ color: #1b5e20; font-weight: bold; }}
    pre {{ white-space: pre-wrap; word-break: break-word; }}
  </style>
</head>
<body>
  <h1>EdgeSentinel Report</h1>

  <div class="card">
    <h3>Scan Metadata</h3>
    <p><b>Target:</b> {escape(meta["target_url"])}</p>
    <p><b>Timestamp:</b> {escape(meta["timestamp"])}</p>
    <p><b>Mode:</b> {escape(meta["mode"])}</p>
    <p><b>Pages crawled:</b> {meta["pages_crawled"]} | <b>Endpoints found:</b> {meta["endpoints_found"]}</p>
    <p><b>Total tests:</b> {meta["total_tests"]} | <b>Findings:</b> {meta["finding_count"]}</p>
  </div>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>CWE</th>
        <th>Title</th>
        <th>Endpoint</th>
        <th>Evidence (snippet)</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows) if rows else '<tr><td colspan="5">No findings detected by current heuristics.</td></tr>'}
    </tbody>
  </table>

  <p style="margin-top:16px; color:#666;">
    Note: This is a lightweight edge-case scanner. Findings are heuristic and should be validated manually.
  </p>
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
        )
        if url not in pages:
            pages.insert(0, url)

    print(f"[+] Pages selected: {len(pages)}")

    # Discover endpoints
    print("[+] Discovering endpoints (links + forms)...")
    endpoints = discover_endpoints(session, pages, delay_s=delay_s, timeout=timeout)
    print(f"[+] Endpoints found: {len(endpoints)}")

    # Generate payloads & execute tests
    payloads = generate_payloads()
    all_test_results: List[TestResult] = []
    all_findings: List[Finding] = []

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
        "test_results": [asdict(r) for r in all_test_results],
        "findings": [asdict(f) for f in all_findings],
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
        description="EdgeSentinel is a command line focused detection tool that helps "
                    "testers and developers identify OWASP A10 relevant weaknesses from a target URL",
        formatter_class=RawTextHelpFormatter,
    )

    parser.add_argument("url", help="Target URL to scan")

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

    # Crawl bounds (baseline deliverable calls out bounded crawling)
    parser.add_argument("--depth", type=int, default=1, help="Crawl depth (default: 1)")
    parser.add_argument("--max-pages", type=int, default=10, help="Max pages to crawl (default: 10)")
    parser.add_argument("--no-crawl", action="store_true", help="Disable crawling; scan only the given URL")

    # Request controls (be gentle / avoid accidental DoS)
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--user-agent", default=DEFAULT_UA, help="User-Agent header")

    # Targeting
    parser.add_argument("--param", default=None, help="Only test a specific parameter name (optional)")

    # Authentication
    parser.add_argument("--login-url", default=None, help="URL of the login page/endpoint (optional)")
    parser.add_argument("--username", default=None, help="Username for authentication (optional)")
    parser.add_argument("--password", default=None, help="Password for authentication (optional)")
    parser.add_argument("--username-field", default="username", help="Name of username field in login form (default: username)")
    parser.add_argument("--password-field", default="password", help="Name of password field in login form (default: password)")

    # Output
    parser.add_argument("--outdir", default="reports", help="Output directory (default: reports)")
    parser.add_argument("--format", choices=["json", "html", "both"], default="both", help="Report format (default: both)")

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

    # Very important: authorized testing only
    print("[!] Reminder: Only scan systems you own or have explicit permission to test.\n")

    run_scan(
        url=url,
        mode=mode,
        enabled_cwe_nums=enabled,
        depth=max(0, args.depth),
        max_pages=max(1, args.max_pages),
        delay_s=max(0.0, args.delay),
        timeout=max(1, args.timeout),
        outdir=args.outdir,
        out_format=args.format,
        user_agent=args.user_agent,
        no_crawl=args.no_crawl,
        target_param=args.param,
        login_url=args.login_url,
        username=args.username,
        password=args.password,
        username_field=args.username_field,
        password_field=args.password_field,
    )


if __name__ == "__main__":
    main()
