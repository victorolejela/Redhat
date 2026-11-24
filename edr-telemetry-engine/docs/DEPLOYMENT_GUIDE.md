# Deployment & Integration Guide

## Pre-Deployment Checklist

### System Requirements
- [ ] Windows Server 2019+ or Windows 10 22H2+
- [ ] .NET 8.0 Runtime installed
- [ ] Sysmon agent deployed (recommend v15+)
- [ ] Event Log forwarding configured (if centralized)
- [ ] Adequate disk space for alerts (~1GB per 500K alerts)

### Permissions Required
- [ ] Administrator access on target host
- [ ] "Read" access to Security event log
- [ ] File write permissions to output directory

### Prerequisites

#### 1. Install .NET 8.0 Runtime
```powershell
# Download from https://dotnet.microsoft.com/download
# Or use Windows Update if available

# Verify installation
dotnet --version
```

#### 2. Deploy Sysmon
```powershell
# Download Sysmon from Sysinternals
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with recommended config
.\Sysmon.exe -i sysmon-config.xml

# Verify installation
Get-Service | Where-Object {$_.Name -eq "Sysmon"}
```

**Recommended Sysmon Configuration Excerpt:**
```xml
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <!-- Capture all process creation events -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="is">cmd.exe</CommandLine>
      <CommandLine condition="is">powershell.exe</CommandLine>
    </ProcessCreate>
    
    <!-- Capture all process access to lsass -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="end with">lsass.exe</TargetImage>
    </ProcessAccess>
    
    <!-- Capture image loads -->
    <ImageLoad onmatch="include"/>
  </EventFiltering>
</Sysmon>
```

## Deployment Scenarios

### Scenario 1: Standalone Monitoring
Single host real-time monitoring with local storage.

**Architecture:**
```
┌─ EDR Engine ─────────────────┐
│ Windows Event Log Watcher    │
│ ↓                             │
│ Real-time Correlation        │
│ ↓                             │
│ Local Files (alerts.json)    │
└─────────────────────────────┘
```

**Deployment:**
```powershell
# 1. Build release binary
dotnet publish -c Release -o "C:\EDRTelemetry"

# 2. Create Windows Service (optional)
$serviceName = "EDRTelemetryEngine"
$binaryPath = "C:\EDRTelemetry\EDRTelemetry.Windows.exe"

New-Service -Name $serviceName `
            -DisplayName "EDR Telemetry Engine" `
            -BinaryPathName $binaryPath `
            -StartupType Automatic

# 3. Start service
Start-Service -Name $serviceName

# 4. Monitor alerts
Tail-Object -Path "C:\EDRTelemetry\alerts.json" -Wait
```

### Scenario 2: Centralized Collection (Event Forwarding)
Multiple hosts forward events to central collector.

**Architecture:**
```
Windows Host 1 ────┐
Windows Host 2 ──┐ │
Windows Host N ──┼─┤ Event Collector (WEF) ──→ EDR Engine
                   │
                   └─ Central Event Log
```

**Setup Event Forwarding:**
```powershell
# On Domain Controller / Central Collector
winrm quickconfig

# Create subscription
Invoke-Command -ComputerName collector.local {
    New-WinEventLogSubscription `
        -Name "EDRTelemetry" `
        -Description "Forward security events to EDR engine" `
        -SourceComputer "servers.corp.local" `
        -EventLog "Security" `
        -EventRecordFields @("System/EventID", "EventData/*")
}
```

### Scenario 3: Hybrid - On-Host + Central Correlation
Agents collect locally, central engine correlates across infrastructure.

**Architecture:**
```
Host 1 (EDRTelemetry)      ──→ alerts.json
Host 2 (EDRTelemetry)      ──→ alerts.json
                                ↓
                          Central Aggregator
                                ↓
                          Cross-system Correlation
                                ↓
                          Distributed Alert Portal
```

## Integration with SIEMs

### Splunk Integration

**1. Configure Universal Forwarder on EDR host:**
```
[default]
host = source_hostname
source = EDRTelemetry

[monitor://C:\EDRTelemetry\alerts.json]
sourcetype = edr:alert
index = security

[monitor://C:\EDRTelemetry\alerts.csv]
sourcetype = edr:alert
index = security
```

**2. Create Splunk alerts:**
```spl
sourcetype="edr:alert" Severity=Critical
| stats count by RuleName, Title
| alert
```

### ELK Stack Integration

**Filebeat Configuration:**
```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - C:\EDRTelemetry\alerts.json
  
  json.keys_under_root: true
  json.overwrite_keys: true
  
  tags: ["edr", "telemetry"]

output.elasticsearch:
  hosts: ["elasticsearch.local:9200"]
  index: "edr-telemetry-%{+YYYY.MM.dd}"

processors:
  - add_host_metadata: ~
  - add_process_metadata: ~
```

**Kibana Dashboard Query:**
```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "Severity": "Critical" } },
        { "range": { "DetectionTime": { "gte": "now-24h" } } }
      ]
    }
  }
}
```

### Microsoft Sentinel Integration

**1. Create Logic App connector:**
```json
{
  "name": "EDR-Alert-Ingestion",
  "triggers": {
    "When_files_are_created": {
      "type": "BlobTrigger",
      "inputs": {
        "path": "alerts/json"
      }
    }
  },
  "actions": {
    "Send_to_Log_Analytics": {
      "type": "SendToLogAnalytics",
      "inputs": {
        "workspaceId": "[workspace-id]",
        "body": "@body('Parse_JSON')"
      }
    }
  }
}
```

## Performance Tuning

### High-Volume Environment (>10K events/min)

**1. Event filtering in Sysmon:**
```xml
<!-- Exclude noise -->
<ProcessCreate onmatch="exclude">
  <CommandLine condition="contains">Windows\System32</CommandLine>
</ProcessCreate>
```

**2. Correlation window adjustment:**
```csharp
private readonly TimeSpan _correlationWindow = TimeSpan.FromMinutes(1); // Reduce from 5
```

**3. Alert aggregation:**
```csharp
// Group similar alerts within 60 seconds
var aggregatedAlerts = alerts
    .GroupBy(a => a.RuleId)
    .Select(g => g.First())
    .ToList();
```

### Low-Latency Environments

**1. Use reactive streams:**
```csharp
_eventSource.GetEventStream()
    .Buffer(TimeSpan.FromMilliseconds(100))  // Batch events
    .Subscribe(async batch => {
        var alerts = await correlationEngine.CorrelateAsync(batch);
    });
```

## Monitoring the EDR Engine

### Health Checks

```powershell
# Check if service is running
Get-Service EDRTelemetryEngine

# Monitor memory usage
Get-Process -Name "EDRTelemetry.Windows"

# Check alert generation rate
$lastHour = (Get-Date).AddHours(-1)
(Get-Content alerts.json | ConvertFrom-Json) | Where-Object { $_.DetectionTime -gt $lastHour } | Measure-Object
```

### Logging

Enable diagnostic logging:
```csharp
// In Program.cs
var logFactory = LoggerFactory.Create(builder => {
    builder.AddConsole()
           .SetMinimumLevel(LogLevel.Debug);
});
```

## Troubleshooting

### Issue: "Access Denied" to Security Event Log
```powershell
# Add user to Event Log Readers group
Add-LocalGroupMember -Group "Event Log Readers" `
                     -Member "CORP\EDRServiceAccount"
```

### Issue: High CPU Usage
```powershell
# Reduce event filtering in Sysmon
# Or increase correlation window in engine
# Or batch process events instead of real-time
```

### Issue: False Positives
1. Add whitelist rules:
```csharp
private static readonly HashSet<string> WhitelistedProcesses = new()
{
    "C:\\Program Files\\Adobe\\Reader\\AcroRd32.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
};
```

2. Tune detection thresholds

3. Week-long baseline learning

## Backup & Recovery

### Alert Data Backup
```powershell
# Daily backup
$alertDir = "C:\EDRTelemetry"
$backupDir = "\\backup-server\EDR-Alerts\$(Get-Date -Format 'yyyy-MM-dd')"

New-Item -Path $backupDir -ItemType Directory -Force
Copy-Item "$alertDir\alerts.*" -Destination $backupDir
```

### Disaster Recovery
```powershell
# Restore from backup
Copy-Item "\\backup-server\EDR-Alerts\2024-01-15\alerts.*" -Destination $alertDir -Force

# Rebuild configuration
Remove-Service -Name EDRTelemetryEngine
# Re-deploy following standard deployment steps
```

## Cost Estimation

| Scale | Storage/Month | CPU | RAM | Cost |
|-------|---|---|---|---|
| 10 hosts | 2GB | 5% | 256MB | $50/mo |
| 100 hosts | 20GB | 15% | 512MB | $150/mo |
| 1000 hosts | 200GB | 40% | 2GB | $500/mo |

## Support & Escalation

1. **Low-Risk Issues:** Update rules, adjust thresholds
2. **Medium-Risk Issues:** Add correlation patterns, tune SIEM
3. **High-Risk Issues:** Escalate to Security Ops, consider IR team activation

See README.md for community support channels.
