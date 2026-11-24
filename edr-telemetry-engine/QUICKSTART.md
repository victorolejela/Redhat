# Quick Start Guide

## 5-Minute Setup

### Prerequisites Check
```bash
# Verify .NET 8.0 is installed
dotnet --version

# Verify on Windows
where python  # For optional log analysis tools
```

## Step 1: Build the Solution (2 min)

```bash
cd /path/to/edr-telemetry-engine

# Restore NuGet packages
dotnet restore

# Build
dotnet build -c Release

# You should see:
# ✅ EDRTelemetry.Core built successfully
# ✅ EDRTelemetry.Windows built successfully
# ✅ EDRTelemetry.Correlation built successfully
# ✅ EDRTelemetry.Tests built successfully
```

## Step 2: Run Tests (1 min)

```bash
dotnet test

# Expected output:
# Test Run Successful.
# Total tests: 4
# Passed:      4
# Failed:      0
```

## Step 3: Deploy on Windows (Windows Only)

### Option A: Run as Console Application
```powershell
cd src/EDRTelemetry.Windows

# Run directly (requires Admin)
dotnet run --configuration Release

# Output:
# === EDR & Identity Telemetry Auditing Engine ===
# Starting telemetry collection...
# Monitoring Event Logs: Security, Sysmon
# Press any key to stop monitoring...
```

### Option B: Install as Windows Service
```powershell
# 1. Publish release build
dotnet publish -c Release -o "C:\EDRTelemetry"

# 2. Create service (as Administrator)
$params = @{
    Name = 'EDRTelemetryEngine'
    DisplayName = 'EDR Telemetry Auditing Engine'
    BinaryPathName = 'C:\EDRTelemetry\EDRTelemetry.Windows.exe'
    StartupType = 'Automatic'
}
New-Service @params

# 3. Start service
Start-Service -Name EDRTelemetryEngine

# 4. Verify
Get-Service EDRTelemetryEngine
```

## Step 4: Monitor Alerts

### Real-Time Console Output
Alerts print to console in color-coded format:
- 🔴 **CRITICAL** (Red): Immediate action required
- 🟠 **ERROR** (Dark Red): Suspicious activity detected
- 🟡 **WARNING** (Yellow): Anomaly detected, investigate
- ⚪ **INFO** (White): Informational events

### Alert Files
```bash
# View JSON alerts (structured for SIEM)
cat alerts.json | jq '.[0]'

# View CSV alerts (Excel-friendly)
cat alerts.csv | head -20

# Monitor in real-time
tail -f alerts.json
```

## Step 5: Generate Test Alerts

### Windows Only - Use Mock Event Source
```csharp
// In Program.cs, replace WindowsEventLogSource with MockEventSource:
var eventSource = new MockEventSource();
```

### Manual Test - Simulate LSASS Access
```powershell
# Create a test process that attempts LSASS access
# (This requires security-testing environment)

netsh trace start capture=yes tracefile=trace.etl
# Let it run for 30 seconds
netsh trace stop

# Process with your engine
```

## Troubleshooting

### "Access Denied" to Security Event Log
```powershell
# Run as Administrator
# OR add user to Event Log Readers group:
Add-LocalGroupMember -Group "Event Log Readers" `
    -Member $env:USERNAME

# Verify:
Get-LocalGroupMember "Event Log Readers" | Select Name
```

### No alerts being generated
```powershell
# 1. Check if Sysmon is installed
Get-Service Sysmon

# 2. Verify Security event log has recent events
Get-WinEvent Security -MaxEvents 1

# 3. Check engine is actually running
Get-Process EDRTelemetry.Windows
```

### High CPU usage
```
1. Reduce correlation window (default 5 minutes)
2. Disable high-volume events in Sysmon config
3. Batch process events instead of real-time
```

## Next Steps

1. **Integrate with SIEM:**
   - See `docs/DEPLOYMENT_GUIDE.md` for Splunk/ELK/Sentinel setup

2. **Customize Rules:**
   - Add your own detection rules in `src/EDRTelemetry.Correlation/Rules/`
   - Whitelist legitimate processes

3. **Production Deployment:**
   - Follow `docs/DEPLOYMENT_GUIDE.md` for enterprise setup
   - Configure centralized alert collection

4. **Threat Hunting:**
   - Review `docs/THREAT_SCENARIOS.md` for attack patterns
   - Analyze alerts to refine detection rules

## Key Files Reference

| File | Purpose |
|------|---------|
| `src/EDRTelemetry.Core/Models/` | Data structures |
| `src/EDRTelemetry.Windows/Parsers/WindowsEventLogParser.cs` | Event parsing logic |
| `src/EDRTelemetry.Correlation/Rules/DetectionRules.cs` | Detection rules |
| `src/EDRTelemetry.Correlation/Engine/CorrelationEngine.cs` | Alert correlation |
| `src/EDRTelemetry.Windows/Program.cs` | Main application |

## Support

- 📖 Full documentation: See `README.md`
- 🚀 Deployment guide: See `docs/DEPLOYMENT_GUIDE.md`
- 🎯 Scenario validation: See `docs/THREAT_SCENARIOS.md`
- 💬 Questions: Open GitHub issue

---

**Happy hunting!** 🔍
