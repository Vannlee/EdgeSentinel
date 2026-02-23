from __future__ import annotations
import json
import os
import re
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from html import escape
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
import requests
from bs4 import BeautifulSoup
from cwe_info import CWE_LIST, SAST_ONLY_CWES, CWE_RECOMMENDATIONS
from payloads import ERROR_KEYWORDS, NUMERIC_EDGE_CASES, get_payloads_for_cwes


DEFAULT_UA = "EdgeSentinel/0.1 (CLI; educational; authorized testing only)"


# Data models
@dataclass
class Endpoint:
    kind: str        # "link" | "form" | "api"
    url: str         # absolute URL
    method: str      # GET/POST
    params: List[str]
    context: str     # short description of where it came from


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
    full_body: str                  # Full response for error detection
    error: Optional[str]


@dataclass
class Finding:
    cwe_num: int
    cwe_id: str
    cwe_name: str
    severity: str                   # LOW/MEDIUM/HIGH/CRITICAL
    title: str
    description: str
    evidence: Dict[str, object]
    recommendation: str
    confidence: str                 # LOW/MEDIUM/HIGH


# General utilities
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
    """Clip text for display. 800 chars to capture enough error content."""
    text = text or ""
    import re as _re
    text = _re.sub(r"\s+", " ", text).strip()
    return text[:max_len] + ("..." if len(text) > max_len else "")


# HTTP helpers
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
    """Returns (response, error, elapsed_ms)."""
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
        forms = soup.find_all("form")

        if forms:
            login_form = forms[0]

            hidden_inputs = login_form.find_all("input", type="hidden")
            for hidden in hidden_inputs:
                name = hidden.get("name")
                value = hidden.get("value", "")
                if name:
                    login_data[name] = value
                    print(f"[+] Found hidden field: {name} = {value[:50]}{'...' if len(value) > 50 else ''}")

            csrf_fields = ["csrf_token", "user_token", "_token", "token", "authenticity_token", "csrf"]
            for csrf_name in csrf_fields:
                csrf_input = login_form.find("input", attrs={"name": csrf_name})
                if csrf_input and csrf_name not in login_data:
                    value = csrf_input.get("value", "")
                    login_data[csrf_name] = value
                    print(f"[+] Found CSRF token field: {csrf_name} = {value[:50]}{'...' if len(value) > 50 else ''}")

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

    # Step 3: Submit login
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

    success_indicators = [
        resp.status_code == 200,
        "logout" in resp.text.lower(),
        "welcome" in resp.text.lower(),
        "dashboard" in resp.text.lower(),
    ]
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

    if len(session.cookies) > 0:
        print(f"[+] Login completed. Session cookies: {len(session.cookies)} cookie(s) set")
        return True, "Login completed (cookies set)"

    return False, "Login status unclear - no clear success or failure indicators found"


# Crawl & endpoint discovery
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
                      E.g. if start_url is http://example.com/dvwa/page.php,
                      only crawl URLs starting with http://example.com/dvwa/
    """
    seen: Set[str] = set()
    queue: List[Tuple[str, int]] = [(start_url, 0)]
    out: List[str] = []

    start_parsed = urlparse(start_url)
    path_parts = [p for p in start_parsed.path.split('/') if p]
    base_path = '/' + path_parts[0] + '/' if path_parts else '/'

    while queue and len(out) < max_pages:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)

        if same_host_only and not same_host(start_url, url):
            continue

        if stay_in_path:
            url_parsed = urlparse(url)
            if not url_parsed.path.startswith(base_path):
                continue

        resp, err, _ = safe_request(session, "GET", url, timeout=timeout)
        time.sleep(delay_s)

        if err or resp is None:
            continue

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

    # Links with query parameters
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

    # Common API path patterns
    api_patterns = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql', '/json', '/xml']
    for a in soup.find_all("a", href=True):
        href = a.get("href")
        abs_url = urljoin(page_url, href)
        if not is_http_url(abs_url):
            continue
        if any(pattern in abs_url.lower() for pattern in api_patterns):
            parsed = urlparse(abs_url)
            path_parts = [p for p in parsed.path.split('/') if p and not any(pat.strip('/') in p for pat in api_patterns)]
            if path_parts:
                endpoints.append(
                    Endpoint(
                        kind="api",
                        url=abs_url,
                        method="GET",
                        params=[],
                        context=f"api: {clip(abs_url, 60)}",
                    )
                )

    # Forms
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = (form.get("method") or "GET").upper()
        abs_action = urljoin(page_url, action)

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

    # De-duplicate by (method, url, params)
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

    uniq = {}
    for ep in endpoints:
        k = (ep.method, ep.url, tuple(ep.params))
        uniq[k] = ep
    return list(uniq.values())


# Debug endpoint detection (CWE-215)
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

    path_parts = [p for p in parsed.path.split('/') if p]
    app_base = '/' + path_parts[0] + '/' if path_parts else '/'

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

            if 'phpinfo()' in body or 'PHP Version' in body or 'PHP Credits' in body:
                findings.append(
                    Finding(
                        cwe_num=2,
                        cwe_id="CWE-215",
                        cwe_name="Insertion of Sensitive Information Into Debugging Code",
                        severity="HIGH",
                        title=f"phpinfo() endpoint exposed: {path}",
                        description=(
                            f"The endpoint {path} exposes phpinfo() output, revealing detailed PHP configuration, "
                            f"loaded modules, environment variables, and system paths."
                        ),
                        evidence={"url": url, "status_code": resp.status_code, "snippet": clip(body, 400)},
                        recommendation=CWE_RECOMMENDATIONS.get("CWE-215", {}).get("summary") or
                            "Remove phpinfo() and other debug endpoints from production.",
                        confidence="HIGH",
                    )
                )

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
                        evidence={"url": url, "status_code": resp.status_code, "snippet": clip(body, 400)},
                        recommendation=CWE_RECOMMENDATIONS.get("CWE-215", {}).get("summary") or
                            "Remove debug endpoints or protect them with proper access controls.",
                        confidence="MEDIUM",
                    )
                )

            if '.env' in path and ('DB_PASSWORD' in body or 'API_KEY' in body or 'SECRET' in body):
                findings.append(
                    Finding(
                        cwe_num=2,
                        cwe_id="CWE-215",
                        cwe_name="Insertion of Sensitive Information Into Debugging Code",
                        severity="CRITICAL",
                        title=f"Environment file exposed: {path}",
                        description="The .env file is publicly accessible, exposing credentials and secrets.",
                        evidence={"url": url, "status_code": resp.status_code, "snippet": clip(body, 400)},
                        recommendation=CWE_RECOMMENDATIONS.get("CWE-215", {}).get("summary") or
                            "Immediately remove .env file from web-accessible directories.",
                        confidence="HIGH",
                    )
                )

    return findings


# Baseline & test execution
def build_default_params(param_names: List[str]) -> Dict[str, str]:
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

                if category == "missing_param":
                    if payload is None:
                        sent.pop(p, None)
                    else:
                        sent[p] = payload
                elif category == "extra_param":
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
                        full_body=resp.text or "",
                        error=None,
                    )
                )

    return results


# Analysis helpers
def looks_like_error_disclosure(text: str) -> bool:
    t = (text or "").lower()
    return any(k in t for k in ERROR_KEYWORDS)


def significant_content_change(baseline_len: int, test_len: int, threshold: float = 0.15) -> bool:
    """Detects if response size changed significantly (±15% by default)."""
    if baseline_len == 0:
        return test_len > 50
    return abs(test_len - baseline_len) / baseline_len > threshold


def significant_timing_change(baseline_ms: int, test_ms: int, threshold_ms: int = 800) -> bool:
    """Detects significant slowdown suggesting expensive error handling."""
    return test_ms > baseline_ms + threshold_ms


def content_type_changed(baseline_headers: Dict[str, str], test_headers: Dict[str, str]) -> bool:
    """Detects if content type changed (e.g., HTML -> JSON)."""
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


# Each function takes (tr, baseline, tests, add) and calls add() if its
# enabled_cwe_nums set and will silently no-op for disabled CWEs.
# Signature: _analyze_cwe_NNN(tr, baseline, tests, add) -> None

def _analyze_cwe_1(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-209: Generation of Error Message Containing Sensitive Information."""
    full_body = tr.full_body or ""
    body = tr.body_snippet or ""
    sc = tr.status_code or 0
    if looks_like_error_disclosure(full_body):
        confidence = "HIGH" if sc >= 500 else "MEDIUM"
        add(
            1, "Error message contains sensitive information",
            "Response contains technical error details (stack traces, database errors, file paths, etc.) "
            "that may aid attackers in reconnaissance.",
            "HIGH",
            {"endpoint": tr.endpoint_url, "method": tr.method, "parameter": tr.parameter,
             "category": tr.category, "payload": tr.payload, "status_code": sc, "snippet": body},
            "Disable debug mode in production. Use generic error pages for clients and log detailed errors server-side only.",
            confidence,
        )


def _analyze_cwe_2(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-215: Insertion of Sensitive Information Into Debugging Code."""
    full_body = tr.full_body or ""
    body = tr.body_snippet or ""
    sc = tr.status_code or 0
    debug_indicators = [
        "phpinfo", "php version", "xdebug", "display_errors", "error_reporting",
        "debug mode", "development mode", "var_dump", "print_r",
    ]
    if any(indicator in full_body.lower() for indicator in debug_indicators):
        add(
            2, "Debug information exposure detected",
            "Response contains debug information (phpinfo, error_reporting settings, debug mode indicators) "
            "that reveals internal application details.",
            "MEDIUM",
            {"endpoint": tr.endpoint_url, "parameter": tr.parameter, "payload": tr.payload,
             "status_code": sc, "snippet": body},
            "Disable debug mode and verbose error reporting in production environments. Remove phpinfo() and debug endpoints.",
            "HIGH",
        )


def _analyze_cwe_3(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-234: Failure to Handle Missing Parameter."""
    sc = tr.status_code or 0
    test_len = tr.content_len or 0
    if tr.category == "missing_param" and tr.payload is None:
        if sc >= 500 or significant_content_change(baseline.content_len, test_len):
            add(
                3, "Missing parameter triggers error condition",
                f"Omitting parameter '{tr.parameter}' caused an error response or significant behavior change.",
                "MEDIUM" if sc >= 500 else "LOW",
                {"endpoint": tr.endpoint_url, "parameter": tr.parameter, "status_code": sc,
                 "baseline_size": baseline.content_len, "test_size": test_len},
                "Validate required parameters and return 400 Bad Request with a safe message instead of crashing.",
                "HIGH",
            )


def _analyze_cwe_4(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-235: Improper Handling of Extra Parameters."""
    sc = tr.status_code or 0
    test_len = tr.content_len or 0
    if tr.category == "extra_param":
        if sc >= 500 or significant_content_change(baseline.content_len, test_len):
            add(
                4, "Extra parameter triggers error condition",
                "Adding unexpected parameter caused error response or behavior change.",
                "MEDIUM" if sc >= 500 else "LOW",
                {"endpoint": tr.endpoint_url, "sent_params": tr.sent_params, "status_code": sc},
                "Whitelist expected parameters and reject/ignore extras; log suspicious requests for monitoring.",
                "MEDIUM",
            )


def _analyze_cwe_5(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-248: Uncaught Exception."""
    sc = tr.status_code or 0
    body = tr.body_snippet or ""
    if sc >= 500:
        add(
            5, "Uncaught exception (5xx response)",
            "Server returned a 5xx error to edge-case input, indicating unhandled exception or server error.",
            "HIGH",
            {"endpoint": tr.endpoint_url, "method": tr.method, "parameter": tr.parameter,
             "category": tr.category, "payload": tr.payload, "status_code": tr.status_code, "snippet": body},
            "Implement centralized exception handling and return generic error responses to clients while logging details server-side.",
            "HIGH",
        )


def _analyze_cwe_6(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-252: Unchecked Return Value."""
    sc = tr.status_code or 0
    test_len = tr.content_len or 0
    if baseline.status_code == 200 and sc == 200 and significant_content_change(baseline.content_len, test_len, threshold=0.1):
        add(
            6, "Potential unchecked return value",
            "Edge-case input caused subtle response changes without status code change, suggesting error condition not properly checked.",
            "LOW",
            {"endpoint": tr.endpoint_url, "parameter": tr.parameter, "baseline_status": baseline.status_code,
             "test_status": sc, "baseline_size": baseline.content_len, "test_size": test_len, "category": tr.category},
            "Check return values from all operations; propagate errors appropriately rather than silently failing.",
            "LOW",
        )


def _analyze_cwe_7(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-274: Improper Handling of Insufficient Privileges."""
    sc = tr.status_code or 0
    priv_keywords = ["admin", "role", "priv", "permission", "auth", "user"]
    if tr.category == "extra_param" and any(kw in tr.sent_params.keys() for kw in priv_keywords):
        if sc == 200 and baseline.status_code in [401, 403]:
            add(
                7, "Insufficient privilege handling",
                f"Adding privilege-related parameter bypassed authorization (baseline {baseline.status_code} -> {sc}).",
                "HIGH",
                {"endpoint": tr.endpoint_url, "sent_params": tr.sent_params,
                 "baseline_status": baseline.status_code, "test_status": sc},
                "Implement proper authorization checks; whitelist parameters and reject unexpected privilege escalation attempts.",
                "MEDIUM",
            )


def _analyze_cwe_8(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-280: Improper Handling of Insufficient Permissions or Privileges."""
    sc = tr.status_code or 0
    test_len = tr.content_len or 0
    priv_keywords = ["admin", "role", "priv", "permission", "auth", "user"]
    if tr.category == "extra_param" and any(kw in tr.sent_params.keys() for kw in priv_keywords):
        if not (sc == 200 and baseline.status_code in [401, 403]):  # CWE-274 already handles the bypass case
            if significant_content_change(baseline.content_len, test_len):
                add(
                    8, "Improper permission parameter handling",
                    "Privilege-related extra parameter caused behavioral change, suggesting improper permission handling.",
                    "MEDIUM",
                    {"endpoint": tr.endpoint_url, "sent_params": tr.sent_params,
                     "baseline_size": baseline.content_len, "test_size": test_len},
                    "Validate and sanitize all parameters; ignore unexpected permission/privilege parameters.",
                    "LOW",
                )


def _analyze_cwe_9(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-369: Divide By Zero."""
    sc = tr.status_code or 0
    test_len = tr.content_len or 0
    full_body = tr.full_body or ""
    zero_variants = ["0", "0.0", "-0", "00", "0x0"]
    if tr.payload in zero_variants or tr.category == "numeric_edge":
        if (sc >= 500
                or "division by zero" in full_body.lower()
                or "divide by zero" in full_body.lower()
                or significant_content_change(baseline.content_len, test_len)):
            add(
                9, "Potential divide-by-zero vulnerability",
                "Zero input triggered error condition consistent with divide-by-zero or unsafe numeric handling.",
                "MEDIUM",
                {"endpoint": tr.endpoint_url, "parameter": tr.parameter, "status_code": sc},
                "Validate numeric inputs; explicitly guard division operations with zero checks and safe fallbacks.",
                "MEDIUM",
            )


def _analyze_cwe_10(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-390: Detection of Error Condition Without Action."""
    sc = tr.status_code or 0
    body = tr.body_snippet or ""
    error_in_success = [e for e in [
        "error:", "warning:", "exception", "failed", "could not", "unable to",
        "not found" if sc == 200 else None,
    ] if e]
    if sc == 200 and any(err in body.lower() for err in error_in_success):
        add(
            10, "Error condition without proper action",
            "Error message appears in successful response (200), suggesting error detected but not properly handled.",
            "MEDIUM",
            {"endpoint": tr.endpoint_url, "status_code": sc, "parameter": tr.parameter, "snippet": body},
            "Return appropriate error status codes; handle errors properly instead of embedding error messages in successful responses.",
            "MEDIUM",
        )


def _analyze_cwe_11(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-391: Unchecked Error Condition."""
    sc = tr.status_code or 0
    body = tr.body_snippet or ""
    error_in_success = [e for e in [
        "error:", "warning:", "exception", "failed", "could not", "unable to",
        "not found" if sc == 200 else None,
    ] if e]
    if sc == 200 and any(err in body.lower() for err in error_in_success):
        add(
            11, "Unchecked error condition",
            "Error condition appears to be unchecked (error text in 200 response), allowing execution to continue despite failure.",
            "MEDIUM",
            {"endpoint": tr.endpoint_url, "status_code": sc, "parameter": tr.parameter, "snippet": body},
            "Check all error conditions; halt execution or use safe fallbacks rather than continuing with error state.",
            "LOW",
        )


def _analyze_cwe_12(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-394: Unexpected Status Code or Return Value."""
    sc = tr.status_code or 0
    body = tr.body_snippet or ""
    if baseline.status_code and sc and sc != baseline.status_code:
        meaningful = (baseline.status_code < 400 <= sc) or (baseline.status_code >= 400 > sc)
        correct_http_errors = sc in [413, 414, 431]
        if meaningful and not correct_http_errors:
            sev = "HIGH" if sc >= 500 else "MEDIUM"
            add(
                12, "Unexpected status code behavior",
                f"Status code changed from {baseline.status_code} to {sc} for edge-case input. "
                f"This indicates inconsistent error handling or different execution paths.",
                sev,
                {"endpoint": tr.endpoint_url, "baseline_status": baseline.status_code, "test_status": sc,
                 "category": tr.category, "payload": tr.payload, "snippet": body},
                "Ensure consistent, safe error handling across code paths.",
                "MEDIUM",
            )


def _analyze_cwe_13(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-476: NULL Pointer Dereference."""
    sc = tr.status_code or 0
    test_len = tr.content_len or 0
    body = tr.body_snippet or ""
    full_body = tr.full_body or ""
    null_indicators = ["", "null", "NULL", "nil", "None", "undefined", "0", "-1", "999999999"]
    if tr.payload in null_indicators or (isinstance(tr.payload, str) and tr.payload.strip() == ""):
        null_errors = [
            "null pointer", "nullpointer", "null reference",
            "object reference not set", "cannot be null",
            "undefined index", "undefined offset", "undefined variable",
            "trying to get property", "trying to access array offset",
            "undefined array key", "does not exist", "not found in database",
            "null value in column", "violates not-null constraint",
            "cannot read property", "cannot read properties of null",
            "nonetype", "nonetype object",
            "attempt to invoke", "on a null object reference",
        ]
        body_has_null_err = any(err in body.lower() for err in null_errors)
        if sc >= 500 or any(err in full_body.lower() for err in null_errors) or significant_content_change(baseline.content_len, test_len):
            add(
                13, "Null pointer dereference indication",
                f"Null-like input '{tr.payload}' triggered error behavior suggesting improper null handling.",
                "HIGH" if sc >= 500 else "MEDIUM",
                {"endpoint": tr.endpoint_url, "parameter": tr.parameter, "payload": tr.payload,
                 "status_code": sc, "snippet": body if body_has_null_err else None},
                "Add null checks before dereferencing objects; use safe navigation operators or default values.",
                "HIGH" if body_has_null_err else "MEDIUM",
            )


def _analyze_cwe_14(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-550: Server-generated Error Message Containing Sensitive Information."""
    sc = tr.status_code or 0
    body = tr.body_snippet or ""
    full_body = tr.full_body or ""
    server_sensitive = [
        "sql syntax error", "mysql error", "mysqli_", "postgresql error", "pg_query",
        "stack trace:", "traceback (most recent", "call stack:",
        "/var/www/", "/usr/local/", "c:\\\\windows\\\\", "c:\\\\inetpub\\\\",
        " on line ", "error in ", "exception in ",
        "fatal error:", "uncaught exception",
    ]
    if any(sensitive in full_body.lower() for sensitive in server_sensitive):
        add(
            14, "Server error message containing sensitive information",
            "Response contains technical implementation details (SQL queries, database errors, paths, stack traces).",
            "HIGH",
            {"endpoint": tr.endpoint_url, "status_code": sc, "parameter": tr.parameter,
             "payload": tr.payload, "snippet": body},
            "Configure server to suppress technical details in error responses; use custom error handlers.",
            "HIGH",
        )


def _analyze_cwe_15(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-636: Not Failing Securely ('Failing Open')."""
    sc = tr.status_code or 0
    if baseline.status_code in (401, 403) and sc == 200:
        add(
            15, "Potential failing-open behavior",
            f"Baseline indicates access denied ({baseline.status_code}) but edge-case request returned 200. "
            f"This suggests inconsistent authorization checks.",
            "HIGH",
            {"endpoint": tr.endpoint_url, "baseline_status": baseline.status_code, "test_status": sc,
             "category": tr.category, "sent_params": tr.sent_params},
            "Review authorization logic to ensure it fails closed on all exceptional conditions.",
            "LOW",
        )


def _analyze_cwe_16(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-703: Improper Check or Handling of Exceptional Conditions."""
    sc = tr.status_code or 0
    test_len = tr.content_len or 0
    # Signal 1: significant response size change
    if significant_content_change(baseline.content_len, test_len):
        baseline_success = baseline.status_code and 200 <= baseline.status_code < 300
        test_success = sc and 200 <= sc < 300
        if baseline_success == test_success:
            sev = "HIGH" if sc >= 500 or sc == 0 else "MEDIUM"
            add(
                16, "Significant response size anomaly",
                f"Response size changed significantly from baseline ({baseline.content_len}B -> {test_len}B). "
                f"This indicates different code execution path or error handling for edge-case input.",
                sev,
                {"endpoint": tr.endpoint_url, "parameter": tr.parameter, "baseline_size": baseline.content_len,
                 "test_size": test_len, "category": tr.category, "payload": tr.payload, "status_code": tr.status_code},
                "Ensure consistent error handling across all input validation paths.",
                "MEDIUM",
            )
    # Signal 2: rate limiting as positive control
    if sc == 429:
        add(
            16, "Rate limiting detected (positive security control)",
            "Endpoint implements rate limiting (HTTP 429), which helps prevent resource exhaustion and DoS.",
            "LOW",
            {"endpoint": tr.endpoint_url, "status_code": sc, "category": tr.category, "payload": tr.payload},
            "Ensure rate limiting is consistently applied across all endpoints and returns appropriate retry-after headers.",
            "HIGH",
        )


def _analyze_cwe_17(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-754: Improper Check for Unusual or Exceptional Conditions."""
    sc = tr.status_code or 0
    test_time = tr.elapsed_ms or 0
    # Signal 1: timing anomaly
    if significant_timing_change(baseline.elapsed_ms, test_time):
        add(
            17, "Response time anomaly detected",
            f"Response took significantly longer ({test_time}ms vs baseline {baseline.elapsed_ms}ms). "
            f"This can indicate expensive error paths, resource strain, or algorithmic complexity issues.",
            "MEDIUM",
            {"endpoint": tr.endpoint_url, "baseline_ms": baseline.elapsed_ms,
             "test_ms": test_time, "category": tr.category, "payload": tr.payload},
            "Add input validation, throttling, and ensure exceptional-condition handling is efficient and bounded.",
            "LOW",
        )
    # Signal 2: unusual condition categories producing error statuses
    unusual_conditions = [
        (sc == 400 and tr.category == "type_confusion", "Type confusion"),
        (sc == 400 and tr.category == "encoding", "Encoding issue"),
        (sc == 500 and tr.category in ["type_confusion", "encoding", "special_values"], "Unhandled input condition"),
    ]
    for condition, desc in unusual_conditions:
        if condition:
            add(
                17, f"Improper check for unusual condition: {desc}",
                f"Application failed to properly handle unusual input condition ({desc}), returning error status {sc}.",
                "MEDIUM",
                {"endpoint": tr.endpoint_url, "parameter": tr.parameter, "category": tr.category,
                 "payload": str(tr.payload)[:100] if tr.payload else None, "status_code": sc, "condition_type": desc},
                "Implement proper input validation for boundary conditions, size limits, and unusual inputs.",
                "MEDIUM",
            )
            break
    # Signal 3: slow response with no rate limiting
    if test_time > 5000 and sc == 200:
        has_rate_limit = any(
            t.endpoint_url == tr.endpoint_url and t.status_code == 429
            for t in tests
        )
        if not has_rate_limit:
            add(
                17, "Potential resource exhaustion risk (no rate limiting detected)",
                f"Endpoint took {test_time}ms to respond to edge-case input without returning rate limit errors.",
                "MEDIUM",
                {"endpoint": tr.endpoint_url, "test_ms": test_time, "payload": tr.payload, "category": tr.category},
                "Implement rate limiting, request throttling and timeout controls to prevent resource exhaustion.",
                "MEDIUM",
            )


def _analyze_cwe_18(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-755: Improper Handling of Exceptional Conditions."""
    sc = tr.status_code or 0
    if tr.category in ["type_confusion", "special_values"] and sc not in [200, 400, 404, 413, 414, 431]:
        add(
            18, "Improper handling of exceptional input conditions",
            f"Type confusion or special value input resulted in unusual status code {sc}, indicating inadequate exception handling.",
            "MEDIUM",
            {"endpoint": tr.endpoint_url, "parameter": tr.parameter, "category": tr.category,
             "payload": tr.payload, "status_code": sc},
            "Implement comprehensive input validation and exception handling for all data types and edge cases.",
            "MEDIUM",
        )


def _analyze_cwe_19(tr: TestResult, baseline: Baseline, tests: List[TestResult], add) -> None:
    """CWE-756: Missing Custom Error Page."""
    sc = tr.status_code or 0
    body = tr.body_snippet or ""
    default_error_indicators = [
        "apache", "nginx", "iis", "tomcat",
        "500 internal server error", "502 bad gateway", "503 service unavailable",
        "<hr>", "<address>",
    ]
    is_application_error = sc >= 500 or (sc >= 400 and sc not in [413, 414, 431])
    if is_application_error and any(indicator in body.lower() for indicator in default_error_indicators):
        add(
            19, "Default/generic error page detected",
            f"Server returned default error page with technical details (status {sc}), rather than custom page.",
            "LOW",
            {"endpoint": tr.endpoint_url, "status_code": sc, "snippet": body},
            "Implement custom error pages for all error conditions; suppress technical details from default server pages.",
            "MEDIUM" if sc >= 500 else "LOW",
        )


# Map of CWE internal number → its analysis function
_CWE_ANALYZERS = {
    1:  _analyze_cwe_1,
    2:  _analyze_cwe_2,
    3:  _analyze_cwe_3,
    4:  _analyze_cwe_4,
    5:  _analyze_cwe_5,
    6:  _analyze_cwe_6,
    7:  _analyze_cwe_7,
    8:  _analyze_cwe_8,
    9:  _analyze_cwe_9,
    10: _analyze_cwe_10,
    11: _analyze_cwe_11,
    12: _analyze_cwe_12,
    13: _analyze_cwe_13,
    14: _analyze_cwe_14,
    15: _analyze_cwe_15,
    16: _analyze_cwe_16,
    17: _analyze_cwe_17,
    18: _analyze_cwe_18,
    19: _analyze_cwe_19,
}


# Analysis dispatcher
def analyze(
    ep: Endpoint,
    baseline: Baseline,
    tests: List[TestResult],
    enabled_cwe_nums: Set[int],
) -> List[Finding]:
    """
    Run only the analysis functions for the enabled CWEs against every test
    result for this endpoint, then de-duplicate and sort findings.
    """
    findings: List[Finding] = []

    def add(cwe_num: int, title: str, desc: str, sev: str, evidence: Dict[str, object], rec: str, conf: str):
        if cwe_num not in enabled_cwe_nums:
            return
        cwe_id, cwe_name = CWE_LIST[cwe_num]
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

    # Only call analyzers for the enabled CWEs
    active_analyzers = [
        _CWE_ANALYZERS[n] for n in sorted(enabled_cwe_nums) if n in _CWE_ANALYZERS
    ]

    for tr in tests:
        for analyzer in active_analyzers:
            analyzer(tr, baseline, tests, add)

    # De-duplicate by (cwe_num, endpoint, title)
    uniq = {}
    for f in findings:
        key = (f.cwe_num, f.evidence.get("endpoint"), f.title)
        uniq[key] = f
    findings = list(uniq.values())

    # Sort by severity
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

    def build_rec_html(cwe_id: str, fallback_rec: str) -> str:
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
            return f"<span>{summary}</span>{code_block}"
        return f"<span>{escape(fallback_rec)}</span>"

    rows = []
    for f in findings:
        ev = f["evidence"]
        cwe_id = f["cwe_id"]

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

        rows.append(f"""
            <tr>
              <td class="{sev_class(f['severity'])}">{escape(f["severity"])}</td>
              <td><b>{escape(cwe_id)}</b><br><small>{escape(f["cwe_name"])}</small></td>
              <td>{escape(f["title"])}</td>
              <td><code>{escape(str(ev.get("endpoint","")))}</code></td>
              <td>{evidence_html}</td>
              <td>{build_rec_html(cwe_id, f.get("recommendation", ""))}</td>
            </tr>""")

    untested_rows_list = []
    for sc in SAST_ONLY_CWES:
        untested_rows_list.append(f"""      <tr style="background:#fafafa;">
        <td><b>{escape(sc['cwe_id'])}</b></td>
        <td><small>{escape(sc['cwe_name'])}</small></td>
        <td>{build_rec_html(sc['cwe_id'], "See CWE reference for guidance.")}</td>
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


# Orchestrator
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
            print("[+] Verifying access to target URL...")
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

    print("[*] EdgeSentinel - Edge Case Vulnerability Scanner (CLI)")
    print(f"[*] Target: {url}")
    print(f"[*] Mode: {mode}")
    print(f"[*] Crawl: {'OFF' if no_crawl else f'depth={depth}, max_pages={max_pages}'}")
    if not no_crawl and not allow_external_paths:
        start_parsed = urlparse(url)
        path_parts = [p for p in start_parsed.path.split('/') if p]
        if path_parts:
            base_path = '/' + path_parts[0] + '/'
            print(f"[*] Path filter: Only crawling URLs starting with {base_path}")
    print(f"[*] Delay: {delay_s}s | Timeout: {timeout}s")

    # Crawl
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
            stay_in_path=not allow_external_paths,
        )
        if url not in pages:
            pages.insert(0, url)

    print(f"[+] Pages selected: {len(pages)}")

    # Discover endpoints
    print("[+] Discovering endpoints (links + forms)...")
    endpoints = discover_endpoints(session, pages, delay_s=delay_s, timeout=timeout)

    if no_crawl:
        target_parsed = urlparse(url)
        target_base = f"{target_parsed.scheme}://{target_parsed.netloc}{target_parsed.path}"
        filtered_endpoints = [
            ep for ep in endpoints
            if f"{urlparse(ep.url).scheme}://{urlparse(ep.url).netloc}{urlparse(ep.url).path}".rstrip('/') == target_base.rstrip('/')
        ]
        print(f"[+] Endpoints found: {len(endpoints)} (filtered to {len(filtered_endpoints)} on target page)")
        endpoints = filtered_endpoints
    else:
        print(f"[+] Endpoints found: {len(endpoints)}")

    # Check for debug endpoints (CWE-215, internal num 2) — only if CWE-215 is enabled
    all_findings: List[Finding] = []
    if 2 in enabled_cwe_nums:
        print("[+] Checking for debug endpoints...")
        debug_findings = check_debug_endpoints(session=session, base_url=url, timeout=timeout, delay_s=delay_s)
        for f in debug_findings:
            print(f"[!] {f.severity} - {f.cwe_id}: {f.title}")
        all_findings.extend(debug_findings)
    else:
        print("[+] Skipping debug endpoint checks (CWE-215 not enabled)")

    # Generate only the payloads required for the enabled CWEs
    payloads = get_payloads_for_cwes(enabled_cwe_nums)
    active_categories = sorted(payloads.keys())
    total_payloads = sum(len(v) for v in payloads.values())
    print(f"[+] Payload categories active: {active_categories} ({total_payloads} total payloads)")
    all_test_results: List[TestResult] = []

    for idx, ep in enumerate(endpoints, 1):
        print(f"[*] ({idx}/{len(endpoints)}) Baseline: {ep.method} {ep.url} [{', '.join(ep.params[:6])}{'...' if len(ep.params) > 6 else ''}]")
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

        findings = analyze(ep=ep, baseline=base, tests=tests, enabled_cwe_nums=enabled_cwe_nums)
        all_findings.extend(findings)

        for f in findings:
            print(f"[!] {f.severity} - {f.cwe_id}: {f.title}")

    # Build report
    ts = now_stamp()
    parsed = urlparse(url)
    safe_host = re.sub(r"[^a-zA-Z0-9._-]+", "_", parsed.netloc)
    json_path = f"{outdir}/edgesentinel_report_{safe_host}_{ts}.json"
    html_path = f"{outdir}/edgesentinel_report_{safe_host}_{ts}.html"

    test_results_for_json = []
    for r in all_test_results:
        r_dict = asdict(r)
        r_dict.pop("full_body", None)
        test_results_for_json.append(r_dict)

    untested_cwes_for_json = [
        {
            "cwe_id": s["cwe_id"],
            "cwe_name": s["cwe_name"],
            "detection": "SAST only, not detectable by DAST",
            "recommendation": CWE_RECOMMENDATIONS.get(s["cwe_id"], {}).get("summary", ""),
        }
        for s in SAST_ONLY_CWES
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

    os.makedirs(outdir, exist_ok=True)

    if out_format in ("json", "both"):
        write_json_report(json_path, report)
        print(f"[+] JSON report: {json_path}")

    if out_format in ("html", "both"):
        write_html_report(html_path, report)
        print(f"[+] HTML report: {html_path}")

    print("[+] Scan complete.")
    return (json_path if out_format in ("json", "both") else ""), (html_path if out_format in ("html", "both") else None)
