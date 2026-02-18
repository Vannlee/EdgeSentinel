# Deploying VulnLab to Ubuntu VM (alongside DVWA)

This guide deploys VulnLab to your existing Ubuntu VM running DVWA.

## Prerequisites

- Ubuntu VM with DVWA already installed (at 20.2.209.236)
- SSH access to the VM
- Sudo privileges
- DVWA running on port 80 (Apache)
- VulnLab will run on port 5000

## Architecture

```
Ubuntu VM (20.2.209.236)
├── Port 80  → Apache/DVWA (existing)
└── Port 5000 → VulnLab (new)
```

## Deployment Steps

### 1. Upload Files from Windows to VM

From your Windows machine (in EdgeSentinel directory):

```powershell
# Upload VulnLab application
scp vulnlab.py azureuser@20.2.209.236:/tmp/

# Upload deployment script  
scp deploy-vulnlab.sh azureuser@20.2.209.236:/tmp/

# Upload systemd service file
scp vulnlab.service azureuser@20.2.209.236:/tmp/
```

**Note**: Replace `azureuser` with your actual SSH username.

### 2. SSH into VM

```powershell
ssh azureuser@20.2.209.236
```

### 3. Run Deployment Script

```bash
cd /tmp
chmod +x deploy-vulnlab.sh
sudo bash deploy-vulnlab.sh
```

This script will:
- Install Python 3 and pip
- Create `/var/www/vulnlab` directory
- Set up Python virtual environment
- Install Flask dependencies
- Copy VulnLab application
- Set proper permissions

### 4. Install Systemd Service

```bash
# Copy service file
sudo cp /tmp/vulnlab.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable VulnLab to start on boot
sudo systemctl enable vulnlab

# Start VulnLab
sudo systemctl start vulnlab

# Check status
sudo systemctl status vulnlab
```

Expected output:
```
● vulnlab.service - VulnLab - Deliberately Vulnerable Web Application
   Loaded: loaded (/etc/systemd/system/vulnlab.service; enabled)
   Active: active (running) since Wed 2026-02-19 ...
```

### 5. Configure Firewall

```bash
# Allow port 5000 (ONLY if testing from external network)
sudo ufw allow 5000/tcp

# Check firewall status
sudo ufw status
```

⚠️ **Security Warning**: Only open port 5000 if you need external access. For local testing, skip this step.

### 6. Verify Installation

Test from the VM itself:

```bash
curl http://localhost:5000
```

Should return HTML with "VulnLab - CWE Test Application".

Test from your Windows machine:

```powershell
curl http://20.2.209.236:5000
```

Or open in browser: `http://20.2.209.236:5000`

## Testing with EdgeSentinel

### Scan Both Applications

```powershell
# Scan DVWA (existing)
python testcode.py http://20.2.209.236 --login "http://20.2.209.236/login.php" --username admin --password password

# Scan VulnLab (new)
python testcode.py http://20.2.209.236:5000 --depth 2

# Scan BOTH together (create script)
```

### Combined Scan Script

Create `scan-all.ps1`:

```powershell
# Scan DVWA
Write-Host "Scanning DVWA..." -ForegroundColor Cyan
python testcode.py http://20.2.209.236 --login "http://20.2.209.236/login.php" --username admin --password password

# Scan VulnLab  
Write-Host "`nScanning VulnLab..." -ForegroundColor Cyan
python testcode.py http://20.2.209.236:5000 --depth 2

# Compare results
Write-Host "`nComparing coverage..." -ForegroundColor Cyan
# Add comparison logic here
```

## Service Management

### Check Logs

```bash
# View real-time logs
sudo journalctl -u vulnlab -f

# View last 50 lines
sudo journalctl -u vulnlab -n 50

# View logs since boot
sudo journalctl -u vulnlab -b
```

### Stop/Start/Restart

```bash
sudo systemctl stop vulnlab
sudo systemctl start vulnlab
sudo systemctl restart vulnlab
```

### Disable Auto-Start

```bash
sudo systemctl disable vulnlab
```

## Troubleshooting

### Port 5000 Already in Use

Check what's using port 5000:
```bash
sudo netstat -tulpn | grep 5000
```

Stop the conflicting service or change VulnLab port:

Edit `/var/www/vulnlab/vulnlab.py` line 223:
```python
app.run(host='0.0.0.0', port=8080, debug=False)  # Changed from 5000
```

Then edit `/etc/systemd/system/vulnlab.service` and restart.

### Permission Denied Errors

```bash
sudo chown -R www-data:www-data /var/www/vulnlab
sudo chmod -R 755 /var/www/vulnlab
```

### Service Won't Start

Check detailed errors:
```bash
sudo journalctl -u vulnlab -n 100 --no-pager
```

Common issues:
- Python virtual environment not activated (check ExecStart path)
- Flask not installed in venv (`sudo -u www-data /var/www/vulnlab/venv/bin/pip list`)
- Port already in use
- Permissions on vulnlab.py file

### Can't Access from Windows

1. Check service is running: `sudo systemctl status vulnlab`
2. Check it's listening: `sudo netstat -tulpn | grep 5000`
3. Check firewall: `sudo ufw status`
4. Test locally first: `curl http://localhost:5000`
5. Check Azure NSG (Network Security Group) allows port 5000

## Security Considerations

⚠️ **CRITICAL WARNINGS**:

1. **VulnLab is DELIBERATELY VULNERABLE** - Do not expose to internet
2. **Use only in isolated test environments**
3. **Close firewall port 5000 when not testing**: `sudo ufw delete allow 5000/tcp`
4. **Consider Azure NSG rules** - Only allow your IP to access port 5000
5. **Stop service when not in use**: `sudo systemctl stop vulnlab`

## Recommended Network Setup

```
Your Windows PC (scanner)
    ↓
Azure NSG (Allow YOUR_IP → VM:5000)
    ↓
Ubuntu VM (20.2.209.236)
├── :80   → DVWA (Apache)
└── :5000 → VulnLab (Flask)
```

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop vulnlab
sudo systemctl disable vulnlab

# Remove service file
sudo rm /etc/systemd/system/vulnlab.service
sudo systemctl daemon-reload

# Remove application
sudo rm -rf /var/www/vulnlab

# Close firewall
sudo ufw delete allow 5000/tcp
```

## Next Steps

After successful deployment:

1. ✅ Verify both DVWA and VulnLab are accessible
2. ✅ Run EdgeSentinel against both targets
3. ✅ Compare CWE coverage (DVWA: 8 CWEs, VulnLab: 11 CWEs)
4. ✅ Generate combined report showing ~19/24 CWEs detected
5. ✅ Document findings for your project

## Support

If you encounter issues:
- Check logs: `sudo journalctl -u vulnlab`
- Verify Flask installation: `sudo -u www-data /var/www/vulnlab/venv/bin/python3 -m flask --version`
- Test manually: `curl -v http://localhost:5000/api/calc?a=10&b=2`
