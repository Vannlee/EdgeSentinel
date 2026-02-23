#!/usr/bin/env python3
"""
EdgeSentinel - OWASP A10:2025 Focused Detection Tool

Usage examples:
  python edgesentinel.py https://example.com                  # Full scan (all 19 CWEs)
  python edgesentinel.py https://example.com -q               # Quick scan (CWEs 1-10)
  python edgesentinel.py https://example.com -s 1,3,4,5,12   # Specific CWEs
  python edgesentinel.py https://example.com -dl 2 -m 15     # Custom crawl depth/pages
  python edgesentinel.py https://example.com -n               # No crawl (single URL only)
  python edgesentinel.py https://example.com --param q        # Test one parameter only
"""

import argparse
from argparse import RawTextHelpFormatter
from typing import Set
from cwe_info import QUICK_SCAN_SET
from scanner import DEFAULT_UA, run_scan


def parse_cwe_list(spec: str) -> Set[int]:
    """Parse a comma-separated list of CWE numbers (e.g. '1,3,5') into a set."""
    nums: Set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        n = int(part)
        if n < 1 or n > 19:
            raise ValueError("CWEs specified must be integers from 1-19")
        nums.add(n)
    return nums


def main():
    parser = argparse.ArgumentParser(
        description=(
            "EdgeSentinel - OWASP A10:2025 Focused Detection Tool\n\n"
            "A lightweight scanner that helps testers and developers "
            "quickly surface A10: Mishandling of Exceptional "
            "Conditions vulnerabilities from a target URL.\n\n"
            "Performs bounded crawling, executes curated edge-case "
            "test suites, and generates reports identifying "
            "A10-relevant weaknesses mapped to specific CWEs.\n\n"
            "Features:\n"
            "  - Bounded crawling (configurable depth/page limits)\n"
            "  - Endpoint discovery (links, forms, common API paths)\n"
            "  - Edge-case testing (missing/extra params, type confusion, etc.)\n"
            "  - Behavioral analysis (status codes, response sizes, timing)\n"
            "  - CSRF-aware authentication support\n"
            "  - Structured reporting with remediation guidance\n\n"
            "Scan Modes:\n"
            "  Normal:   All 19 CWEs (default)\n"
            "  Quick:    First 10 CWEs only (-q)\n"
            "  Specific: Selected CWEs only (-s 1,3,5)\n\n"
            "For authorised testing only. Non-destructive payloads."
        ),
        formatter_class=RawTextHelpFormatter,
    )

    parser.add_argument("url", help="Target URL to scan (e.g. http://example.com)")

    # Scan mode arguments
    mode_group = parser.add_mutually_exclusive_group(required=False)
    mode_group.add_argument(
        "-q", "--quick_scan",
        action="store_true",
        help="Quick analysis: first 10 CWEs only (1-10).",
    )
    mode_group.add_argument(
        "-s", "--specify",
        help="Specify CWEs by number separated by commas (e.g. 1,3,5).\n"
        "The list of CWEs are as follows:\n" 
        "1. CWE-209 Generation of Error Message Containing Sensitive Information\n" 
        "2. CWE-215 Insertion of Sensitive Information Into Debugging Code\n"
        "3. CWE-234 Failure to Handle Missing Parameter\n"
        "4. CWE-235 Improper Handling of Extra Parameters\n"
        "5. CWE-248 Uncaught Exception\n"
        "6. CWE-252 Unchecked Return Value\n" 
        "7. CWE-274 Improper Handling of Insufficient Privileges\n" 
        "8. CWE-280 Improper Handling of Insufficient Permissions or Privileges\n"
        "9. CWE-369 Divide By Zero\n"
        "10. CWE-390 Detection of Error Condition Without Action\n" 
        "11. CWE-391 Unchecked Error Condition\n" 
        "12. CWE-394 Unexpected Status Code or Return Value\n" 
        "13. CWE-476 NULL Pointer Dereference\n" 
        "14. CWE-550 Server-generated Error Message Containing Sensitive Information\n" 
        "15. CWE-636 Not Failing Securely ('Failing Open')\n" 
        "16. CWE-703 Improper Check or Handling of Exceptional Conditions\n" 
        "17. CWE-754 Improper Check for Unusual or Exceptional Conditions\n"
        "18. CWE-755 Improper Handling of Exceptional Conditions\n" 
        "19. CWE-756 Missing Custom Error Page"
    )

    # Crawl boundary arguments
    crawl_group = parser.add_argument_group(
        "Crawl boundary control options",
        "Boundary options cannot be used with --no-crawl"
    )
    crawl_group.add_argument(
        "-n", "--no-crawl",
        action="store_true",
        help="Disable crawling and scans only the given URL"
    )
    crawl_group.add_argument(
        "-dl", "--depth-level",
        type=int,
        default=1,
        help="Set crawl depth (Default depth is 1)"
    )
    crawl_group.add_argument(
        "-m", "--max-pages",
        type=int,
        default=10,
        help="Set max pages to crawl for the URL (Max pages is set to 10 "
        "by default)"
    )
    crawl_group.add_argument(
        "-e", "--allow-external-paths",
        action="store_true",
        help="Allow crawling outside the base path (e.g., allow /docs/ when "
        "starting from /dvwa/). By default, crawler stays within the same "
        "path prefix to avoid wandering to documentation or unrelated "
        "sections."
    )

    # Request control arguments
    request_group = parser.add_argument_group("request control options")
    request_group.add_argument(
        "-d", "--delay",
        type=float,
        default=0.3,
        help="Sets timing delay between requests in seconds (Default delay "
        "is 0.3s)"
    )
    request_group.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="Sets timing to wait for request before timeout in seconds "
        "(Default timeout is 10s)"
    )
    request_group.add_argument(
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
    auth_group = parser.add_argument_group(
        "authentication",
        "-l, -u and -p must be provided together"
    )
    auth_group.add_argument(
        "-l", "--login-url",
        help="Specifies URL of the login page/endpoint (optional)"
    )
    auth_group.add_argument(
        "-u", "--username",
        help="Specifies username to be used for authentication with -l flag"
    )
    auth_group.add_argument(
        "-p", "--password",
        help="Specifies password to be used for authentication with -l flag"
    )
    auth_group.add_argument(
        "-uf", "--username-field",
        default="username",
        help="Specifies name of username field in login form (Default is "
        "set to username)"
    )
    auth_group.add_argument(
        "-pf", "--password-field",
        default="password",
        help="Specifies name of password field in login form (Default is "
        "set to password)"
    )

    # Output file arguments
    output_group = parser.add_argument_group("output file options")
    output_group.add_argument(
        "-o", "--outdir",
        default="reports",
        help="Specifies output directory for report generated"
        " (Default directory is reports)"
    )
    output_group.add_argument(
        "-f", "--format",
        choices=["json", "html", "both"],
        default="both",
        help="Specifies format of generated report (Default is both)"
    )

    args = parser.parse_args()

    # Authentication flags validation
    if args.login_url and not (args.username and args.password):
        parser.error("--username and --password flags must be specified when "
                     "--login_url is set. Use -h for more information")
    if (args.username or args.password) and not args.login_url:
        parser.error("--username and --password require --login-url to be set.")

    # Crawl flag validation: crawl options and --no-crawl are mutually exclusive
    crawl_flags_set = args.depth_level != 1 or args.max_pages != 10 or args.allow_external_paths
    if args.no_crawl and crawl_flags_set:
        parser.error("--no-crawl flag cannot be used with --depth-level, "
        "--max-pages or --allow-external-paths flags. Use -h for more " 
        "information.")

    # Resolve scan mode
    if args.quick_scan:
        enabled = set(QUICK_SCAN_SET)
        mode = "quick"
    elif args.specify:
        enabled = parse_cwe_list(args.specify)
        mode = "specific"
    else:
        enabled = set(range(1, 20))
        mode = "normal"

    print("[!] Reminder: Only scan systems you own or have explicit "
          "permission to test.\n")

    run_scan(
        url=args.url,
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
