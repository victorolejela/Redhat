namespace EDRTelemetry.Core.Models;

/// <summary>
/// Represents a telemetry event from Windows Event Log or system monitoring
/// </summary>
public class TelemetryEvent
{
    public string EventId { get; set; } = Guid.NewGuid().ToString();
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Source { get; set; } = string.Empty; // "EventLog", "Sysmon", "ETW", etc.
    public string EventType { get; set; } = string.Empty; // "ProcessCreation", "HandleAccess", "RegistryModification"
    public Dictionary<string, object> Properties { get; set; } = new();
    public string RawData { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; } = SeverityLevel.Informational;
}

public enum SeverityLevel
{
    Informational = 0,
    Warning = 1,
    Error = 2,
    Critical = 3
}
