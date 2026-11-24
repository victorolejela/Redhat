namespace EDRTelemetry.Correlation.Rules;

using EDRTelemetry.Core.Interfaces;
using EDRTelemetry.Core.Models;

/// <summary>
/// Rule 1: Detects suspicious access to LSASS.exe
/// </summary>
public class LSASSAccessRule : IDetectionRule
{
    public string RuleId => "RULE-001";
    public string RuleName => "Suspicious LSASS Access Detected";
    public string Description => "Monitors for non-system processes requesting sensitive access rights to lsass.exe";
    public SeverityLevel DefaultSeverity => SeverityLevel.Critical;

    private static readonly HashSet<string> SystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "services.exe", "lsass.exe", "csrss.exe", "winlogon.exe"
    };

    public Task<Alert?> EvaluateAsync(TelemetryEvent @event)
    {
        if (@event is not ProcessAccessEvent processAccess)
            return Task.FromResult<Alert?>(null);

        if (!processAccess.IsLsassAccess)
            return Task.FromResult<Alert?>(null);

        var isSuspiciousSource = !SystemProcesses.Contains(
            Path.GetFileName(processAccess.SourceImageName));

        var hasSuspiciousAccess = processAccess.RequestedAccessRights.Any(r =>
            r is "PROCESS_VM_READ" or "PROCESS_VM_WRITE" or "PROCESS_CREATE_THREAD");

        if (!isSuspiciousSource || !hasSuspiciousAccess)
            return Task.FromResult<Alert?>(null);

        var alert = new Alert
        {
            RuleId = RuleId,
            RuleName = RuleName,
            Severity = SeverityLevel.Critical,
            Title = "Critical: LSASS Access from Suspicious Process",
            Description = $"Process '{processAccess.SourceImageName}' (PID: {processAccess.SourceProcessId}) " +
                         $"attempted to access LSASS.exe with rights: {string.Join(", ", processAccess.RequestedAccessRights)}",
            CorrelatedEventIds = new List<string> { @event.EventId },
            Context = new Dictionary<string, object>
            {
                { "SourceProcess", processAccess.SourceImageName },
                { "SourcePID", processAccess.SourceProcessId },
                { "AccessRights", processAccess.RequestedAccessRights },
                { "Timestamp", @event.Timestamp }
            },
            RecommendedAction = "Isolate affected host immediately. Investigate process execution chain. " +
                               "Check for credential dumping tools or malware indicators."
        };

        return Task.FromResult<Alert?>(alert);
    }
}

/// <summary>
/// Rule 2: Detects unbacked executable memory allocations
/// </summary>
public class UnbackedMemoryAllocationRule : IDetectionRule
{
    public string RuleId => "RULE-002";
    public string RuleName => "Unbacked Executable Memory Detected";
    public string Description => "Detects memory allocations marked PAGE_EXECUTE_READWRITE without backing DLL";
    public SeverityLevel DefaultSeverity => SeverityLevel.Critical;

    public Task<Alert?> EvaluateAsync(TelemetryEvent @event)
    {
        if (@event is not MemoryAllocationEvent memEvent)
            return Task.FromResult<Alert?>(null);

        if (!memEvent.IsUnbacked || !memEvent.AllocationProtection.Contains("EXECUTE"))
            return Task.FromResult<Alert?>(null);

        var alert = new Alert
        {
            RuleId = RuleId,
            RuleName = RuleName,
            Severity = SeverityLevel.Critical,
            Title = "Critical: Unbacked Executable Memory Allocated",
            Description = $"Process '{memEvent.ImageName}' (PID: {memEvent.ProcessId}) allocated " +
                         $"executable memory at 0x{memEvent.AllocationAddress:X} without disk backing. " +
                         $"Possible shellcode injection or reflective DLL loading.",
            CorrelatedEventIds = new List<string> { @event.EventId },
            Context = new Dictionary<string, object>
            {
                { "ProcessName", memEvent.ImageName },
                { "ProcessID", memEvent.ProcessId },
                { "AllocationAddress", $"0x{memEvent.AllocationAddress:X}" },
                { "AllocationSize", memEvent.AllocationSize },
                { "Protection", memEvent.AllocationProtection }
            },
            RecommendedAction = "Immediately suspend process for forensic analysis. " +
                               "Scan for known injector signatures and malware indicators."
        };

        return Task.FromResult<Alert?>(alert);
    }
}

/// <summary>
/// Rule 3: Detects suspicious parent-child execution chains
/// </summary>
public class SuspiciousParentChildRule : IDetectionRule
{
    public string RuleId => "RULE-003";
    public string RuleName => "Suspicious Process Execution Chain";
    public string Description => "Flags unusual parent-child process relationships";
    public SeverityLevel DefaultSeverity => SeverityLevel.Warning;

    private static readonly Dictionary<string, HashSet<string>> WhitelistedChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        { "explorer.exe", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "notepad.exe", "calc.exe" } },
        { "services.exe", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "svchost.exe" } }
    };

    private static readonly HashSet<string> SuspiciousChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "cmd.exe", "rundll32.exe", "regsvcs.exe", "wmic.exe"
    };

    public Task<Alert?> EvaluateAsync(TelemetryEvent @event)
    {
        if (@event is not ProcessEvent processEvent || processEvent.EventType != "ProcessCreation")
            return Task.FromResult<Alert?>(null);

        var childName = Path.GetFileName(processEvent.ImageName);
        var parentName = processEvent.ParentProcessId > 0 ? "Unknown" : "System";

        if (!SuspiciousChildren.Contains(childName))
            return Task.FromResult<Alert?>(null);

        // Check if this is an anomalous parent-child pair
        var isAnomaly = true;
        if (WhitelistedChildren.TryGetValue(parentName, out var whitelist))
        {
            isAnomaly = !whitelist.Contains(childName);
        }

        if (!isAnomaly)
            return Task.FromResult<Alert?>(null);

        var alert = new Alert
        {
            RuleId = RuleId,
            RuleName = RuleName,
            Severity = SeverityLevel.Warning,
            Title = "Warning: Suspicious Process Execution Chain",
            Description = $"Suspicious child process '{childName}' spawned by '{parentName}' " +
                         $"(CommandLine: {processEvent.CommandLine})",
            CorrelatedEventIds = new List<string> { @event.EventId },
            Context = new Dictionary<string, object>
            {
                { "ChildProcess", childName },
                { "ParentProcess", parentName },
                { "CommandLine", processEvent.CommandLine },
                { "User", processEvent.User }
            },
            RecommendedAction = "Review process execution and check for obfuscated command lines. " +
                               "Verify legitimacy of application launch."
        };

        return Task.FromResult<Alert?>(alert);
    }
}
