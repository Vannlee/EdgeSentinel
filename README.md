EdgeSentinel - OWASP A10:2025 Focused Detection Tool

A lightweight scanner that helps testers and developers quickly surface A10: Mishandling of Exceptional Conditions vulnerabilities from a target URL.

Performs bounded crawling, executes curated edge-case test suites, and generates reports identifying A10-relevant weaknesses mapped to specific CWEs.

Features:
  - Bounded crawling (configurable depth/page limits)
  - Endpoint discovery (links, forms, common API paths)
  - Edge-case testing (missing/extra params, type confusion, etc.)
  - Behavioral analysis (status codes, response sizes, timing)
  - CSRF-aware authentication support
  - Structured reporting with remediation guidance

Scan Modes:
  Normal:   All 19 CWEs (default)
  Quick:    First 10 CWEs only (-q)
  Specific: Selected CWEs only (-s 1,3,5)

For testing purposes, destructive payloads have been commented out.

The following CWEs are what EdgeSentinel is able to test and identify:
1. CWE-209 Generation of Error Message Containing Sensitive Information
2. CWE-215 Insertion of Sensitive Information Into Debugging Code
3. CWE-234 Failure to Handle Missing Parameter
4. CWE-235 Improper Handling of Extra Parameters
5. CWE-248 Uncaught Exception
6. CWE-252 Unchecked Return Value
7. CWE-274 Improper Handling of Insufficient Privileges
8. CWE-280 Improper Handling of Insufficient Permissions or Privileges
9. CWE-369 Divide By Zero
10. CWE-390 Detection of Error Condition Without Action
11. CWE-391 Unchecked Error Condition
12. CWE-394 Unexpected Status Code or Return Value
13. CWE-476 NULL Pointer Dereference
14. CWE-550 Server-generated Error Message Containing Sensitive Information
15. CWE-636 Not Failing Securely ('Failing Open')
16. CWE-703 Improper Check or Handling of Exceptional Conditions
17. CWE-754 Improper Check for Unusual or Exceptional Conditions
18. CWE-755 Improper Handling of Exceptional Conditions
    9. CWE-756 Missing Custom Error Page
