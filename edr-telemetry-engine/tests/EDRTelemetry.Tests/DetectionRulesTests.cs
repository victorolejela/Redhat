using EDRTelemetry.Core.Models;
using EDRTelemetry.Correlation.Rules;
using Xunit;

namespace EDRTelemetry.Tests;

public class DetectionRulesTests
{
    [Fact]
    public async Task LSASSAccessRule_ShouldDetectSuspiciousLSASSAccess()
    {
        // Arrange
        var rule = new LSASSAccessRule();
        var processAccess = new ProcessAccessEvent
        {
            EventId = Guid.NewGuid().ToString(),
            Timestamp = DateTime.UtcNow,
            Source = "Test",
            EventType = "ProcessAccess",
            SourceProcessId = 1234,
            SourceImageName = "C:\\temp\\mimikatz.exe",
            TargetProcessId = 456,
            TargetImageName = "C:\\Windows\\System32\\lsass.exe",
            AccessMask = 0x0430,
            IsLsassAccess = true,
            RequestedAccessRights = new List<string> { "PROCESS_VM_READ", "PROCESS_VM_WRITE" }
        };

        // Act
        var alert = await rule.EvaluateAsync(processAccess);

        // Assert
        Assert.NotNull(alert);
        Assert.Equal("RULE-001", alert.RuleId);
        Assert.Equal(SeverityLevel.Critical, alert.Severity);
    }

    [Fact]
    public async Task LSASSAccessRule_ShouldIgnoreSystemProcessAccess()
    {
        // Arrange
        var rule = new LSASSAccessRule();
        var processAccess = new ProcessAccessEvent
        {
            EventId = Guid.NewGuid().ToString(),
            Timestamp = DateTime.UtcNow,
            Source = "Test",
            EventType = "ProcessAccess",
            SourceProcessId = 100,
            SourceImageName = "C:\\Windows\\System32\\svchost.exe",
            TargetProcessId = 456,
            TargetImageName = "C:\\Windows\\System32\\lsass.exe",
            IsLsassAccess = true,
            RequestedAccessRights = new List<string> { "PROCESS_VM_READ" }
        };

        // Act
        var alert = await rule.EvaluateAsync(processAccess);

        // Assert
        Assert.Null(alert);
    }

    [Fact]
    public async Task UnbackedMemoryAllocationRule_ShouldDetectExecutableMemory()
    {
        // Arrange
        var rule = new UnbackedMemoryAllocationRule();
        var memEvent = new MemoryAllocationEvent
        {
            EventId = Guid.NewGuid().ToString(),
            Timestamp = DateTime.UtcNow,
            Source = "Test",
            EventType = "MemoryAllocation",
            ProcessId = 1234,
            ImageName = "C:\\Program Files\\App\\app.exe",
            AllocationAddress = 0x140000000,
            AllocationSize = 4096,
            AllocationProtection = "PAGE_EXECUTE_READWRITE",
            IsUnbacked = true
        };

        // Act
        var alert = await rule.EvaluateAsync(memEvent);

        // Assert
        Assert.NotNull(alert);
        Assert.Equal("RULE-002", alert.RuleId);
        Assert.Equal(SeverityLevel.Critical, alert.Severity);
    }

    [Fact]
    public async Task SuspiciousParentChildRule_ShouldDetectAnomalousChain()
    {
        // Arrange
        var rule = new SuspiciousParentChildRule();
        var processEvent = new ProcessEvent
        {
            EventId = Guid.NewGuid().ToString(),
            Timestamp = DateTime.UtcNow,
            Source = "Test",
            EventType = "ProcessCreation",
            ProcessId = 5678,
            ParentProcessId = 100,
            ImageName = "C:\\Windows\\System32\\powershell.exe",
            CommandLine = "powershell.exe -enc JABjPSdodHRwOi8vZXhhbXBsZS5jb20vY21kLnBz'",
            User = "Administrator",
            Domain = "CORP"
        };

        // Act
        var alert = await rule.EvaluateAsync(processEvent);

        // Assert
        Assert.NotNull(alert);
        Assert.Equal("RULE-003", alert.RuleId);
    }
}
