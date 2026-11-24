# Threat Scenarios & Rule Validation

This document outlines realistic threat scenarios and how the EDR engine detects them.

## Scenario 1: Credential Dumping (Mimikatz)

### Attack Flow
```
1. Attacker gains shell access (compromised service, web app, etc.)
2. Executes mimikatz.exe (or reflective load in-memory)
3. Mimikatz requests PROCESS_VM_READ | PROCESS_VM_WRITE access to lsass.exe
4. Reads process memory to extract plaintext credentials
```

### EDR Detection
**Triggered Rules:**
- ✅ RULE-001: LSASS Access (CRITICAL)
- ✅ RULE-002: Unbacked Memory (if reflective loading used)
- ✅ RULE-CORR-01: Process injection + memory access pattern

**Alert Example:**
```json
{
  "AlertId": "ALERT-2024-001-432",
  "DetectionTime": "2024-01-15T14:32:51Z",
  "RuleId": "RULE-001",
  "RuleName": "Suspicious LSASS Access Detected",
  "Severity": "Critical",
  "Title": "Critical: LSASS Access from Suspicious Process",
  "Description": "Process 'mimikatz.exe' (PID: 5432) attempted to access LSASS.exe with rights: PROCESS_VM_READ, PROCESS_VM_WRITE",
  "CorrelatedEventIds": ["EVT-4648", "EVT-1644"],
  "Context": {
    "SourceProcess": "mimikatz.exe",
    "SourcePID": 5432,
    "AccessRights": ["PROCESS_VM_READ", "PROCESS_VM_WRITE"],
    "Timestamp": "2024-01-15T14:32:51Z"
  },
  "RecommendedAction": "Isolate affected host immediately. Investigate process execution chain. Check for credential dumping tools or malware indicators."
}
```

### Mitigation Actions
1. **Immediate:**
   - Isolate host from network
   - Capture live memory image for forensics
   - Revoke credentials on compromised system

2. **Investigation:**
   - Check if mimikatz was pre-installed or dropped by attacker
   - Review execution history (Event Log)
   - Analyze parent process to identify initial access

3. **Prevention:**
   - Deploy Credential Guard on all endpoints
   - Restrict admin access (eliminate standing privileges)
   - Enable LSA protection registry setting

---

## Scenario 2: Active Directory Reconnaissance (BloodHound/SharpHound)

### Attack Flow
```
1. Attacker gains domain user privileges
2. Runs SharpHound/BloodHound to enumerate AD
3. Queries for nTSecurityDescriptor, ACLs, group memberships
4. Maps privilege escalation paths
```

### EDR Detection
**Triggered Rules:**
- ✅ RULE (future): DirectoryServiceReconnaissanceRule
- ✅ RULE-CORR-02: LDAP burst + process creation correlation

**Telemetry Captured:**
```
DirectoryServiceEvent {
  QueryFilter: "(&(objectClass=user)(nTSecurityDescriptor=*))",
  SearchBase: "DC=corp,DC=local",
  QueryCount: 247,  // Unusual volume
  IsNTSecurityDescriptorQuery: true,
  IsDACLEnumeration: true,
  Severity: "Warning"
}
```

### Mitigation Actions
1. **Immediate:**
   - Check SharpHound output files on endpoint
   - Review compromised account permissions
   - Force password reset on domain accounts touched

2. **Investigation:**
   - Correlate process execution with LDAP queries
   - Analyze output BloodHound JSON database
   - Identify privilege paths already exploited

3. **Prevention:**
   - Restrict LDAP query permissions (object-level access control)
   - Monitor PAS (Privilege Account Store) for unusual access
   - Implement LAPS (Local Administrator Password Solution)

---

## Scenario 3: Living-off-the-Land - PowerShell Encoded Attack

### Attack Flow
```
1. Phishing email → word.exe process
2. Malicious macro → spawns powershell.exe
3. PowerShell encoded command: -e JABjPSdodHRw...
4. Downloads and executes secondary payload
```

### EDR Detection
**Triggered Rules:**
- ✅ RULE-003: Suspicious Parent-Child
- ✅ RULE-002: Unbacked memory (secondary payload)

**ParsedEvent:**
```csharp
ProcessEvent {
  ImageName: "C:\\Windows\\System32\\powershell.exe",
  CommandLine: "powershell.exe -e JABjPSdodHRwOi8vZXhhbXBsZS5jb20v...",
  ParentProcessId: 1234,
  // Parent identified as word.exe
  Severity: "Warning"  // Elevated by rule
}
```

**Alert Generated:**
```json
{
  "RuleId": "RULE-003",
  "Title": "Warning: Suspicious Process Execution Chain",
  "Description": "Suspicious child process 'powershell.exe' spawned by 'word.exe' (CommandLine: powershell.exe -e JAB...)",
  "RecommendedAction": "Review process execution and check for obfuscated command lines. Verify legitimacy of application launch."
}
```

### Mitigation Actions
1. **Immediate:**
   - Kill PowerShell process
   - Isolate endpoint from network

2. **Investigation:**
   - Check command-line arguments (full -e parameter)
   - Decode Base64 payload to see actual command
   - Check network connections from PowerShell process
   - Review file system changes during execution window

3. **Prevention:**
   - Disable PowerShell v2 runtime
   - Enforce PowerShell Script Block logging
   - Use Constrained Language Mode in UAC-restricted contexts
   - Block Office macros via GPO

---

## Scenario 4: Process Injection - Rundll32 Injector

### Attack Flow
```
1. Rundll32.exe launched (legitimate windows component)
2. Attacker injects code via CreateRemoteThread
3. Injects into legitimate system process (svchost.exe)
4. Bypasses detection via process whitelisting
```

### EDR Detection
**Triggered Rules:**
- ✅ RULE-002: Unbacked Memory in svchost.exe
- ✅ Custom rule: ProcessInject pattern (multiple threads created)

**MemoryAllocationEvent:**
```csharp
MemoryAllocationEvent {
  ProcessId: 892,  // svchost.exe
  AllocationAddress: 0x7FFF0000,
  AllocationProtection: "PAGE_EXECUTE_READWRITE",
  IsUnbacked: true,  // No backing DLL
  Severity: "Critical"
}
```

### Mitigation Actions
1. **Immediate:**
   - Terminate svchost process (will restart)
   - Capture memory dump for analysis

2. **Investigation:**
   - Analyze unbacked memory region for shellcode signatures
   - Trace parent of rundll32 (where did injector come from?)
   - Look for API hook patterns

3. **Prevention:**
   - Enable Control Flow Guard (CFG)
   - Use Hardware-enforced Stack Protection
   - Implement Code Integrity checking
   - Restrict DLL loading via app whitelisting

---

## Scenario 5: Multi-Stage Co-Infection Attack

### Attack Flow
```
Event 1 (T):14:30:00 - Process creation: powershell.exe
Event 2 (T+2s):14:30:02 - LDAP query: (&(objectClass=user))
Event 3 (T+45s):14:30:45 - LSASS access: rundll32.exe + PROCESS_VM_READ
Event 4 (T+60s):14:31:00 - ProcessCreate: cmd.exe from Unknown parent
```

### EDR Correlation
**RULE-CORR-01 Triggered:**
```json
{
  "RuleId": "RULE-CORR-01",
  "RuleName": "LSASS Access + Suspicious Process Creation",
  "Severity": "Critical",
  "Title": "Critical: Multi-stage Attack Pattern Detected",
  "Description": "LSASS access correlates with suspicious process creation. Likely credential dumping attack.",
  "CorrelatedEventIds": [
    "EVT-4688-PSH",
    "EVT-1644-LDAP",
    "EVT-10-LSASS",
    "EVT-4688-CMD"
  ],
  "Context": {
    "AttackPhases": [
      "Initial access (PowerShell)",
      "Reconnaissance (LDAP)",
      "Credential Access (LSASS)",
      "Execution (cmd.exe)"
    ],
    "Timeline": "All activity within 90 seconds",
    "Confidence": "Very High"
  }
}
```

### Incident Response Procedure
1. **Containment (0-5 min):**
   - Isolate host from network
   - Disable host account in AD
   - Capture all volatile memory

2. **Analysis (5-60 min):**
   - Analyze correlated events for attack narrative
   - Extract credentials from memory dump
   - Perform credential triage (how many accounts compromised?)

3. **Recovery (60+ min):**
   - Force password resets for all compromised accounts
   - Scan entire domain for lateral movement
   - Rebuild affected server from clean media

---

## False Positive Scenarios

### Scenario: Legitimate Sysmon Query Tool
**False Positive When:** An admin runs sysmon.exe with  `-i` (install) flag
```
Process: "sysmon.exe -i sysmon-config.xml"
Parent:  "cmd.exe"
```
**Why Triggered:** cmd.exe → sysmon.exe pattern looks suspicious
**Mitigation:** Whitelist sysmon.exe parent from System/TrustedInstallers

### Scenario: Backup Software LSASS Access
**False Positive When:** Backup agent requests LSASS handle for VSS (Volume Shadow Copy)
**Why Triggered:** RULE-001 doesn't distinguish VSS backups
**Mitigation:** Add backup software service account to whitelist

### Scenario: Windows Update Process Memory
**False Positive When:** Windows Update injects code into legitimate processes
**Why Triggered:** RULE-002 flags all unbacked executable memory
**Mitigation:** Baseline legitimate memory patterns, add Windows Update PID to whitelist

---

## Testing with Mock Events

### Generate Test Events
```powershell
# Mock LSASS access
& {
    param(
        [uint32]$SourcePID = 5432,
        [string]$ImageName = "C:\temp\attacker.exe"
    )
    
    # Simulate Sysmon Event ID 10 (ProcessAccess)
    # In production, actually uses ETW/Sysmon
    Write-Host "Generating mock LSASS access event..."
}
```

### Validate Rule Triggers
```bash
dotnet test --filter "LSASSAccessRule_ShouldDetectSuspiciousLSASSAccess"
```

Expected output: ✅ PASSED

---

## Continuous Improvement

### Metrics to Track
- **Detection Accuracy:** True positives vs false positives
- **Response Time:**Time from event to alert generation
- **Coverage Gaps:** Missed attacks (post-incident analysis)
- **Rule Performance:** CPU/memory impact per rule

### Regular Review (Weekly)
```
1. Review all generated alerts
2. Validate findings with SOC team
3. Update whitelists based on legitimate activity
4. Refine correlation patterns
```

### Quarterly Tuning
```
1. Re-baseline system behavior
2. Adjust thresholds based on environment changes
3. Add new detection patterns from threat intelligence
4. Remove rules with excessive false positives
```

Refer to the main README.md and DEPLOYMENT_GUIDE.md for operational procedures.
