# EDR & Identity Telemetry Auditing Engine

A high-fidelity, behavioral anomaly detection platform designed for real-time monitoring of Windows environments. Detects LSASS credential dumping attempts, process injection, and Active Directory reconnaissance activities.

## Project Overview

This EDR engine solves three critical security detection gaps:

### 1. **Living-off-the-Land Detection**
- **Problem**: Traditional antivirus checks file signatures on disk, missing in-memory attacks
- **Solution**: Evaluates behavioral execution chains and process relationships to detect fileless malware

### 2. **SOC Alert Fatigue Reduction**
- **Problem**: Thousands of generic alerts overwhelm security teams
- **Solution**: Correlates multiple telemetry sources (process, memory, directory service) to generate high-fidelity alerts

### 3. **LSASS & Credential Dumping Blindness**
- **Problem**: Standard log monitoring misses LSASS memory access and hooking attempts
- **Solution**: Actively tracks handle creation and memory allocation patterns

## Architecture

```
┌─ Telemetry Sources ─────────────────────────────────────┐
│  • Windows Event Log (4688, 1644)                       │
│  • Sysmon (Event IDs 1, 7, 10)                          │
│  • ETW (Event Tracing for Windows)                      │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─ Telemetry Parsers ─────────────────────────────────────┐
│  • WindowsEventLogParser (converts XML to models)       │
│  • ProcessEvent, ProcessAccessEvent, MemoryAllocationEvent
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─ Correlation Engine ────────────────────────────────────┐
│  • Evaluates events against detection rules             │
│  • Correlates multi-event attack patterns               │
│  • 5-minute context window retention                    │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─ Detection Rules ───────────────────────────────────────┐
│  RULE-001: LSASSAccessRule                              │
│  RULE-002: UnbackedMemoryAllocationRule                 │
│  RULE-003: SuspiciousParentChildRule                    │
│  RULE-CORR-01/02: Multi-stage correlation patterns      │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─ Alert Handlers ────────────────────────────────────────┐
│  • Console (real-time display)                          │
│  • JSON File (structured storage)                       │
│  • CSV File (SIEM integration)                          │
└─────────────────────────────────────────────────────────┘
```

## Key Modules

### 1. In-Memory Process Integrity & LSASS Guard

**What it monitors:**
- Handle requests against `lsass.exe` (parsed from Sysmon Event ID 10)
- Access rights: `PROCESS_VM_WRITE`, `PROCESS_VM_READ`, `PROCESS_CREATE_THREAD`

**Detection logic:**
- Flags non-system processes attempting sensitive access
- Tracks unbacked executable memory (PAGE_EXECUTE_READWRITE)

**Implementation:**
```csharp
public class LSASSAccessRule : IDetectionRule
{
    public async Task<Alert?> EvaluateAsync(ProcessAccessEvent access)
    {
        if (!access.IsLsassAccess) return null;
        if (SystemProcesses.Contains(access.SourceImage)) return null;
        
        var isSuspicious = access.RequestedAccessRights.Any(r => 
            r is "PROCESS_VM_READ" or "PROCESS_VM_WRITE" or "PROCESS_CREATE_THREAD");
            
        return isSuspicious ? GenerateAlert() : null;
    }
}
```

### 2. Active Directory Reconnaissance & LDAP Anomaly Detector

**What it monitors:**
- Directory Service Event Log 1644 (LDAP queries)
- Queries requesting `nTSecurityDescriptor` (DACL enumeration)
- Broad wildcard searches `(objectClass=*)`

**Detection logic:**
- Flags sudden bursts of LDAP queries (>10 in 1 minute)
- Detects ACL scanning patterns
- Correlates with process activity

### 3. Behavioral Command-Line & Parent-Child Process Parser

**What it monitors:**
- Process creation events (Event ID 4688, Sysmon Event ID 1)
- Parent-child execution chains
- Command-line obfuscation patterns

**Detection logic:**
- Whitelist known parent-child pairs (explorer.exe → notepad.exe)
- Flag living-off-the-land binaries spawned from unusual parents
- Detect Base64-encoded PowerShell payloads

## Project Structure

```
edr-telemetry-engine/
├── src/
│   ├── EDRTelemetry.Core/           # Interfaces & models
│   │   ├── Models/
│   │   │   ├── TelemetryEvent.cs
│   │   │   ├── ProcessModels.cs
│   │   │   └── DirectoryServiceModels.cs
│   │   └── Interfaces/
│   │       └── ITelemetry.cs
│   │
│   ├── EDRTelemetry.Windows/        # Windows-specific parsers & sources
│   │   ├── Parsers/
│   │   │   └── WindowsEventLogParser.cs
│   │   ├── Sources/
│   │   │   └── WindowsEventLogSource.cs
│   │   └── Program.cs                # Main application
│   │
│   ├── EDRTelemetry.Linux/          # Linux syslog aggregation (future)
│   │
│   └── EDRTelemetry.Correlation/   # Detection & correlation
│       ├── Rules/
│       │   └── DetectionRules.cs
│       ├── Engine/
│       │   └── CorrelationEngine.cs
│       └── Handlers/
│           └── AlertHandlers.cs
│
├── tests/
│   └── EDRTelemetry.Tests/          # Unit tests
│       └── DetectionRulesTests.cs
│
├── docs/                            # Documentation
└── EDRTelemetry.sln                 # Solution file
```

## Getting Started

### Prerequisites
- .NET 8.0 SDK or later
- Windows 10/11 or Windows Server 2019+ (for Event Log access)
- Elevated privileges (to access Security event log)
- Sysmon installed (for enhanced process monitoring)

### Installation

1. Clone the repository:
```bash
cd edr-telemetry-engine
```

2. Restore dependencies:
```bash
dotnet restore
```

3. Build the solution:
```bash
dotnet build -c Release
```

### Running the Engine

```bash
cd src/EDRTelemetry.Windows
dotnet run
```

**Output files:**
- `alerts.json` - Structured alert data
- `alerts.csv` - SIEM-friendly format
- Console real-time display

## Detection Rules

### RULE-001: Suspicious LSASS Access
**Severity:** Critical
**Trigger:** Non-system process accessing LSASS with sensitive rights
**Example indicators:**
- `mimikatz.exe` → `lsass.exe` (PROCESS_VM_READ, PROCESS_VM_WRITE)
- `rundll32.exe` → `lsass.exe` with CREATE_THREAD

### RULE-002: Unbacked Executable Memory
**Severity:** Critical
**Trigger:** Memory allocated as PAGE_EXECUTE_READWRITE without backing file
**Example indicators:**
- Reflective DLL loading
- Shellcode injection
- Code caves in legitimate processes

### RULE-003: Suspicious Process Execution Chain
**Severity:** Warning
**Trigger:** Living-off-the-land binaries launched from suspicious parents
**Example indicators:**
- `explorer.exe` → `powershell.exe`
- `word.exe` → `cmd.exe`
- `w3wp.exe` (IIS) → `powershell.exe`

### RULE-CORR-01: LSASS Access + Process Creation Burst
**Severity:** Critical
**Trigger:** LSASS access within 60 seconds of unusual process spawn
**Context:** Multi-stage attack pattern

### RULE-CORR-02: AD Reconnaissance + Execution Burst
**Severity:** Warning
**Trigger:** LDAP enumeration followed by process creation burst
**Context:** Post-reconnaissance lateral movement

## Configuration

Edit `appsettings.json` (future implementation) to customize:
```json
{
  "telemetry": {
    "correlationWindowMinutes": 5,
    "minEventBurstThreshold": 5,
    "enableLsassMonitoring": true,
    "enableLdapMonitoring": true
  },
  "output": {
    "jsonFilePath": "alerts.json",
    "csvFilePath": "alerts.csv",
    "enableConsoleOutput": true
  }
}
```

## Integration with SIEMs

### Splunk
```
[default]
source = alerts.csv
sourcetype = edr:alert
index = security
```

### ELK Stack
Monitor `alerts.json` with Filebeat:
```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /path/to/alerts.json
  json.keys_under_root: true
```

## Testing

Run unit tests:
```bash
dotnet test
```

### Test Coverage
- Detection rule evaluation
- Event parsing
- Alert correlation
- False positive filtering

## Future Enhancements

1. **Linux Support**
   - auditd integration
   - syslog parsing
   - /proc filesystem analysis

2. **Advanced Correlation**
   - Machine learning anomaly detection
   - Behavioral baseline learning
   - Kill chain visualization

3. **Real-time Response**
   - Process isolation/termination
   - Network isolation
   - Automated threat hunting

4. **Extended Detection**
   - Registry modification monitoring
   - Network connection tracking
   - File system integrity monitoring

## Security Considerations

- **Privileged access required:** Must run as Administrator/root
- **Event log volume:** Can generate high volume on busy systems
- **Performance impact:** Minimal CPU/memory overhead
- **Storage:** ~1-2 MB per 1000 alerts

## Troubleshooting

### No events being collected
```powershell
# Verify Sysmon is installed
Get-Service | Where-Object {$_.Name -eq "Sysmon"}

# Check Event Log Access
wevtutil qs Security
```

### Permission denied errors
```powershell
# Run as Administrator
# Grant necessary permissions to application service account
```

### Missing alerts
- Verify Sysmon configuration
- Check Event Log retention settings
- Review rule configuration

## License

MIT License - See LICENSE file

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Contact & Support

For questions, issues, or feature requests, please open a GitHub issue.
