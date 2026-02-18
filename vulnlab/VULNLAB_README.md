# VulnLab - Deliberately Vulnerable Test Application

## ⚠️ WARNING
This application contains **intentional security vulnerabilities** for testing EdgeSentinel scanner.
**DO NOT** deploy to production or expose to untrusted networks.
**FOR EDUCATIONAL/TESTING PURPOSES ONLY.**

## Purpose
VulnLab provides test endpoints that demonstrate CWEs missing from DVWA:
- CWE-4 (235): Extra parameters
- CWE-5 (248): Uncaught exception
- CWE-7 (274): Insufficient privileges
- CWE-8 (280): Insufficient permissions
- CWE-9 (369): Divide by zero
- CWE-12 (394): Unexpected status code
- CWE-16 (476): NULL pointer dereference
- CWE-20 (636): Failing open
- CWE-22 (754): Unusual conditions
- CWE-23 (755): Exceptional conditions
- CWE-24 (756): Missing custom error page

## Setup

### 1. Install dependencies
```bash
pip install -r requirements-vulnlab.txt
```

### 2. Run the application
```bash
python vulnlab.py
```

Server will start on `http://127.0.0.1:5000`

## Testing with EdgeSentinel

### Quick scan (all endpoints)
```bash
python testcode.py http://127.0.0.1:5000 --depth 1
```

### Scan without crawling (test specific endpoint)
```bash
python testcode.py http://127.0.0.1:5000/api/calc --no-crawl
```

### Full scan with authentication testing
```bash
python testcode.py http://127.0.0.1:5000 --depth 2 --max-pages 20
```

## Vulnerable Endpoints

### CWE-9: Divide By Zero
- `GET /api/calc?a=10&b=0` - Returns 500 with ZeroDivisionError
- `GET /api/divide?x=100&y=0` - Alternative test

### CWE-16: NULL Pointer Dereference  
- `GET /api/user?id=999` - Returns 500 (user not found → None → AttributeError)
- `GET /api/user?id=` - Empty ID triggers NULL access
- `GET /api/lookup?id=1` - Always returns None, crashes on access

### CWE-4 (Extra Params) + CWE-12 (Status Changes)
- `GET /api/stats?type=summary` - Baseline (200)
- `GET /api/stats?type=summary&admin=true` - Returns 403 (status change)
- `GET /api/stats?type=summary&debug=1` - Returns 500 (status change)
- `GET /api/stats?type=invalid` - Returns 400 (status change)

### CWE-7, CWE-8, CWE-20: Authorization Bypass
- `GET /admin/config?role=admin` - Authorized (200)
- `GET /admin/config?role=user` - Denied (403)
- `GET /admin/config?role=` - **FAILS OPEN** - Returns config (200) ⚠️
- `GET /admin/config` - **FAILS OPEN** - Returns config (200) ⚠️
- `GET /admin/config?role=administrator` - **Bypass** - Returns config ⚠️

### CWE-5, CWE-22, CWE-23: Exceptional Conditions
- `GET /api/process?value=9999999999` - Integer overflow (500)
- `GET /api/process?value=NaN` - Special float value (500)
- `GET /api/process?value=Infinity` - Special float value (500)
- `GET /api/process?value=` + (10000 'A's) - Large input (500)
- `GET /api/process?value=café` - Unicode/encoding issue (500)

### CWE-24: Missing Custom Error Page
- `GET /api/crash` - Returns Flask's default error page with stack trace
- Any endpoint that crashes shows default Werkzeug debugger page

## Expected Scanner Results

After scanning VulnLab, EdgeSentinel should detect:
- **11 CWEs** currently missing from DVWA scans
- Combined with DVWA results: **~19/24 CWEs** total coverage (79%)
- Only 5 CWEs impossible: 13, 14, 15, 17, 18 (require source code analysis)

## Validation Checklist

✅ CWE-4: Extra parameter changes behavior  
✅ CWE-5: Uncaught exceptions (500 errors)  
✅ CWE-7: Privilege handling issues  
✅ CWE-8: Permission handling issues  
✅ CWE-9: Divide-by-zero errors  
✅ CWE-12: Status code changes (200→400, 200→403, 200→500)  
✅ CWE-16: NULL pointer crashes  
✅ CWE-20: Failing open on edge cases  
✅ CWE-22: Unusual input conditions  
✅ CWE-23: Exceptional input handling  
✅ CWE-24: Default error pages with stack traces  

## Troubleshooting

### Flask not installed
```bash
pip install Flask
```

### Port 5000 already in use
Edit `vulnlab.py` line 223 to change port:
```python
app.run(host='127.0.0.1', port=8080, debug=False)
```

### Scanner not detecting vulnerabilities
1. Ensure VulnLab is running (`python vulnlab.py`)
2. Check scanner includes all 24 CWEs (don't use `-q` quick scan)
3. Verify endpoints are being crawled (`--depth 2`)

## Architecture

```
VulnLab (Flask)
├── / (index) - Links to all test endpoints
├── /api/calc - Divide by zero vulnerability
├── /api/user - NULL pointer vulnerability
├── /api/stats - Extra params + status changes
├── /admin/config - Authorization bypass
├── /api/process - Exceptional conditions
├── /api/crash - Error page testing
├── /api/divide - Alternative divide test
└── /api/lookup - Alternative NULL test
```

## License
Educational use only. No warranty. Use at your own risk.
