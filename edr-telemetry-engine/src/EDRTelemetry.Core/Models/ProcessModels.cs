namespace EDRTelemetry.Core.Models;

/// <summary>
/// Represents process execution context
/// </summary>
public class ProcessEvent : TelemetryEvent
{
    public uint ProcessId { get; set; }
    public uint ParentProcessId { get; set; }
    public string ImageName { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public string User { get; set; } = string.Empty;
    public string Domain { get; set; } = string.Empty;
    public uint IntegrityLevel { get; set; }
    public bool IsElevated { get; set; }
    public DateTime CreationTime { get; set; }
    public List<string> LoadedModules { get; set; } = new();
}

/// <summary>
/// Represents process handle/memory access patterns
/// </summary>
public class ProcessAccessEvent : TelemetryEvent
{
    public uint SourceProcessId { get; set; }
    public string SourceImageName { get; set; } = string.Empty;
    public uint TargetProcessId { get; set; }
    public string TargetImageName { get; set; } = string.Empty;
    public uint AccessMask { get; set; }
    public string CallStack { get; set; } = string.Empty;
    public bool IsLsassAccess { get; set; }
    
    // Decoded access rights for analysis
    public List<string> RequestedAccessRights { get; set; } = new();
}

/// <summary>
/// Represents memory allocation patterns
/// </summary>
public class MemoryAllocationEvent : TelemetryEvent
{
    public uint ProcessId { get; set; }
    public string ImageName { get; set; } = string.Empty;
    public ulong AllocationAddress { get; set; }
    public uint AllocationSize { get; set; }
    public string AllocationProtection { get; set; } = string.Empty; // PAGE_EXECUTE_READWRITE, etc.
    public bool IsUnbacked { get; set; } // Allocated memory not backed by disk file
    public List<string> BackingModules { get; set; } = new();
}
