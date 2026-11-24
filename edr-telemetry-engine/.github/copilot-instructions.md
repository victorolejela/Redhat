<!-- Use this file to provide workspace-specific custom instructions to Copilot. -->

# EDR & Identity Telemetry Auditing Engine

## Project Overview
This is a defensive security project - an advanced Endpoint Detection & Response (EDR) and Identity Telemetry Auditing Engine designed to detect LSASS credential dumping, process injection, and Active Directory reconnaissance attacks in real-time.

## Architecture & Key Modules

### 1. Telemetry Collection (Windows)
- **Files:** `src/EDRTelemetry.Windows/Sources/` and `src/EDRTelemetry.Windows/Parsers/`
- **Purpose:** Parse Windows Event Log (4688, 1644) and Sysmon events
- **Key Classes:** `WindowsEventLogSource`, `WindowsEventLogParser`

### 2. Core Models & Interfaces
- **Files:** `src/EDRTelemetry.Core/Models/`, `src/EDRTelemetry.Core/Interfaces/`
- **Models:** `TelemetryEvent`, `ProcessEvent`, `ProcessAccessEvent`, `DirectoryServiceEvent`, `Alert`
- **Interfaces:** `ITelemetryParser`, `IDetectionRule`, `ICorrelationEngine`, `ITelemetrySource`, `IAlertHandler`

### 3. Detection Rules
- **Files:** `src/EDRTelemetry.Correlation/Rules/DetectionRules.cs`
- **Rules:**
  - `LSASSAccessRule` - Detects non-system processes accessing LSASS.exe
  - `UnbackedMemoryAllocationRule` - Detects PAGE_EXECUTE_READWRITE memory without backing DLL
  - `SuspiciousParentChildRule` - Flags anomalous process execution chains
- **Correlation Patterns:** RULE-CORR-01 (LSASS + process burst), RULE-CORR-02 (LDAP + execution)

### 4. Correlation Engine
- **File:** `src/EDRTelemetry.Correlation/Engine/CorrelationEngine.cs`
- **Purpose:** Evaluate events against rules and correlate multi-stage attacks
- **Key Features:** 5-minute event window, pattern matching

### 5. Alert Handlers
- **File:** `src/EDRTelemetry.Correlation/Handlers/AlertHandlers.cs`
- **Handlers:** `JsonFileAlertHandler`, `CsvAlertHandler`, `ConsoleAlertHandler`

### 6. Tests
- **File:** `tests/EDRTelemetry.Tests/DetectionRulesTests.cs`
- **Framework:** xUnit
- **Coverage:** Detection rule evaluation, event parsing

## Coding Standards

### Language & Framework
- **Language:** C# (.NET 8.0)
- **Style:** Follow Microsoft C# Coding Conventions
- **Namespace:** Use hierarchical namespacing matching folder structure
- **Nullable:** Enable `<Nullable>enable</Nullable>` in all projects

### Key Patterns
1. **Async/Await:** All I/O operations must be async
2. **Reactive Streams:** Use System.Reactive for event handling
3. **Dependency Injection:** (To be implemented) Use IServiceProvider
4. **Logging:** Microsoft.Extensions.Logging.Abstractions

### Example Code Style
```csharp
public class ExampleRule : IDetectionRule
{
    public string RuleId => "RULE-NNN";
    
    public async Task<Alert?> EvaluateAsync(TelemetryEvent @event)
    {
        if (@event is not SpecificEventType typedEvent)
            return null;
            
        if (!IsAnomalous(typedEvent))
            return null;
            
        return new Alert
        {
            RuleId = RuleId,
            Title = "Descriptive Title",
            Severity = SeverityLevel.Critical,
            // ... rest of properties
        };
    }
}
```

## Adding New Detection Rules

1. Create class implementing `IDetectionRule` in `Rules/`
2. Implement `RuleId` (RULE-NNN format), `RuleName`, `Description`, `DefaultSeverity`
3. Implement `EvaluateAsync()` method
4. Register in `src/EDRTelemetry.Windows/Program.cs`: `correlationEngine.RegisterRule(new YourRule());`
5. Add unit tests to `tests/EDRTelemetry.Tests/`

## Adding New Alert Handlers

1. Create class implementing `IAlertHandler` in `Handlers/`
2. Implement `HandleAsync()` method
3. Add thread-safe file/network write logic
4. Register in `Program.cs`: `await Task.WhenAll(handlerInstance.HandleAsync(alert))`

## Building & Testing

```bash
# Build
dotnet build -c Release

# Run Tests
dotnet test

# Publish Release
dotnet publish -c Release -o "./publish"
```

## Debugging Notes

- Enable debug output: Set breakpoints in `Program.cs` event subscription
- Monitor event cache: Check `_eventCache` dictionary in `CorrelationEngine`
- Validate parsing: Add print statements in `WindowsEventLogParser.cs`

## Project Dependencies

- `Microsoft.Extensions.Logging.Abstractions` (8.0.1)
- `System.Reactive` (5.4.1)
- `System.Diagnostics.EventLog` (8.0.0) - Windows only

## Documentation Files

- `README.md` - Overview, architecture, getting started
- `docs/DEPLOYMENT_GUIDE.md` - Enterprise deployment scenarios, SIEM integration
- `docs/THREAT_SCENARIOS.md` - Real-world attack examples with detection validation

## Future Enhancement Areas

1. **Linux Support:** Requires new `EDRTelemetry.Linux` module for auditd/syslog
2. **Machine Learning:** Integration point in `CorrelationEngine.CorrelateAsync()`
3. **Distributed Deployment:** Central aggregator consuming from multiple hosts
4. **Configuration Management:** External ruleset and whitelist loading
5. **REST API:** HTTP endpoint for rule updates and alert querying

## Security Considerations for Contributions

- ✅ Only accept source code additions (no credentials/keys in code)
- ✅ Validate all user input (event data)
- ✅ Use parameterized queries when accessing external data
- ✅ Log security-relevant events (rule evasion, parser errors)
- ✅ Respect privacy (PII in alerts should be configurable)

## Building & Running Checklist

- [ ] `dotnet restore` - Install NuGet packages
- [ ] `dotnet build` - Verify compilation
- [ ] `dotnet test` - Run unit tests (must pass)
- [ ] On Windows: Run as Administrator for Event Log access
- [ ] Sysmon must be installed for production data

---

**Last Updated:** 2024
**Maintainer:** Security Team
