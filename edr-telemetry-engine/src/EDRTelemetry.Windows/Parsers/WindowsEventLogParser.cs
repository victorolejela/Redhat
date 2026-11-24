namespace EDRTelemetry.Windows.Parsers;

using EDRTelemetry.Core.Interfaces;
using EDRTelemetry.Core.Models;
using System.Diagnostics.Eventing.Reader;
using System.Xml;

/// <summary>
/// Parses Windows Event Log events (4688, 1644, and Sysmon events)
/// </summary>
public class WindowsEventLogParser : ITelemetryParser
{
    public string EventSource => "WindowsEventLog";

    public Task<TelemetryEvent?> ParseAsync(string rawEventData)
    {
        try
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(rawEventData);

            var root = xmlDoc.DocumentElement;
            if (root == null) return Task.FromResult<TelemetryEvent?>(null);

            var eventId = root.SelectSingleNode("//EventID")?.InnerText ?? "Unknown";
            var systemNode = root.SelectSingleNode("//System");
            var dataNode = root.SelectSingleNode("//EventData");

            return eventId switch
            {
                "4688" => Task.FromResult<TelemetryEvent?>(ParseProcessCreation(xmlDoc)),
                "1644" => Task.FromResult<TelemetryEvent?>(ParseDirectoryServiceAccess(xmlDoc)),
                "10" => Task.FromResult<TelemetryEvent?>(ParseSysmonProcessAccess(xmlDoc)), // Sysmon
                "7" => Task.FromResult<TelemetryEvent?>(ParseSysmonImageLoaded(xmlDoc)),  // Sysmon
                _ => Task.FromResult<TelemetryEvent?>(null)
            };
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Parse error: {ex.Message}");
            return Task.FromResult<TelemetryEvent?>(null);
        }
    }

    public bool CanParse(string rawEventData)
    {
        try
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(rawEventData);
            var eventId = xmlDoc.DocumentElement?.SelectSingleNode("//EventID")?.InnerText;
            return eventId is "4688" or "1644" or "10" or "7";
        }
        catch
        {
            return false;
        }
    }

    private ProcessEvent? ParseProcessCreation(XmlDocument xmlDoc)
    {
        var eventData = xmlDoc.DocumentElement?.SelectSingleNode("//EventData");
        if (eventData == null) return null;

        var getDataByName = (string name) => 
            eventData.SelectSingleNode($"//Data[@Name='{name}']")?.InnerText ?? string.Empty;

        var processEvent = new ProcessEvent
        {
            EventType = "ProcessCreation",
            Source = EventSource,
            ProcessId = uint.TryParse(getDataByName("NewProcessId"), System.Globalization.NumberStyles.HexNumber, null, out var pid) ? pid : 0,
            ParentProcessId = uint.TryParse(getDataByName("ParentProcessId"), System.Globalization.NumberStyles.HexNumber, null, out var ppid) ? ppid : 0,
            ImageName = getDataByName("NewProcessName"),
            CommandLine = getDataByName("CommandLine"),
            User = getDataByName("TargetUserName"),
            Domain = getDataByName("TargetDomainName"),
            IsElevated = getDataByName("TokenElevationType") == "%%1937"
        };

        // Check for suspicious patterns
        if (IsSuspiciousCommandLine(processEvent.CommandLine))
        {
            processEvent.Severity = SeverityLevel.Warning;
        }

        return processEvent;
    }

    private DirectoryServiceEvent? ParseDirectoryServiceAccess(XmlDocument xmlDoc)
    {
        var eventData = xmlDoc.DocumentElement?.SelectSingleNode("//EventData");
        if (eventData == null) return null;

        var getDataByName = (string name) => 
            eventData.SelectSingleNode($"//Data[@Name='{name}']")?.InnerText ?? string.Empty;

        var filter = getDataByName("SearchFilter");
        var dsEvent = new DirectoryServiceEvent
        {
            EventType = "DirectoryServiceAccess",
            Source = EventSource,
            QueryFilter = filter,
            SearchBase = getDataByName("SearchBase"),
            SourceHost = getDataByName("ComputerName"),
            QueryCount = 1
        };

        // Detect reconnaissance patterns
        dsEvent.IsNTSecurityDescriptorQuery = filter.Contains("nTSecurityDescriptor", StringComparison.OrdinalIgnoreCase);
        dsEvent.IsBroadWildcardSearch = filter.Contains("objectClass=*") || filter.Contains("(&(objectClass");
        dsEvent.IsDACLEnumeration = filter.Contains("(|(dn=", StringComparison.OrdinalIgnoreCase) && 
                                    filter.Contains("nTSecurityDescriptor", StringComparison.OrdinalIgnoreCase);

        if (dsEvent.IsNTSecurityDescriptorQuery)
        {
            dsEvent.SuspiciousAttributes.Add("nTSecurityDescriptor");
            dsEvent.Severity = SeverityLevel.Warning;
        }

        return dsEvent;
    }

    private ProcessAccessEvent? ParseSysmonProcessAccess(XmlDocument xmlDoc)
    {
        var eventData = xmlDoc.DocumentElement?.SelectSingleNode("//EventData");
        if (eventData == null) return null;

        var getDataByName = (string name) => 
            eventData.SelectSingleNode($"//Data[@Name='{name}']")?.InnerText ?? string.Empty;

        var accessMaskHex = getDataByName("GrantedAccess");
        uint accessMask = string.IsNullOrEmpty(accessMaskHex) ? 0 : 
            uint.TryParse(accessMaskHex, System.Globalization.NumberStyles.HexNumber, null, out var mask) ? mask : 0;

        var processAccessEvent = new ProcessAccessEvent
        {
            EventType = "ProcessAccess",
            Source = EventSource,
            SourceProcessId = uint.TryParse(getDataByName("SourceProcessId"), out var spid) ? spid : 0,
            SourceImageName = getDataByName("SourceImage"),
            TargetProcessId = uint.TryParse(getDataByName("TargetProcessId"), out var tpid) ? tpid : 0,
            TargetImageName = getDataByName("TargetImage"),
            AccessMask = accessMask,
            IsLsassAccess = getDataByName("TargetImage").EndsWith("lsass.exe", StringComparison.OrdinalIgnoreCase)
        };

        // Decode access rights
        DecodeAccessRights(accessMask, processAccessEvent.RequestedAccessRights);

        // Flag suspicious LSASS accesses
        if (processAccessEvent.IsLsassAccess && IsSuspiciousAccessToLSASS(processAccessEvent.RequestedAccessRights))
        {
            processAccessEvent.Severity = SeverityLevel.Critical;
        }

        return processAccessEvent;
    }

    private ProcessEvent? ParseSysmonImageLoaded(XmlDocument xmlDoc)
    {
        var eventData = xmlDoc.DocumentElement?.SelectSingleNode("//EventData");
        if (eventData == null) return null;

        var getDataByName = (string name) => 
            eventData.SelectSingleNode($"//Data[@Name='{name}']")?.InnerText ?? string.Empty;

        return new ProcessEvent
        {
            EventType = "ImageLoaded",
            Source = EventSource,
            ProcessId = uint.TryParse(getDataByName("ProcessId"), out var pid) ? pid : 0,
            ImageName = getDataByName("Image"),
            LoadedModules = new List<string> { getDataByName("ImageLoaded") }
        };
    }

    private void DecodeAccessRights(uint accessMask, List<string> rights)
    {
        const uint PROCESS_TERMINATE = 0x0001;
        const uint PROCESS_CREATE_THREAD = 0x0002;
        const uint PROCESS_SET_SESSIONID = 0x0004;
        const uint PROCESS_VM_OPERATION = 0x0008;
        const uint PROCESS_VM_READ = 0x0010;
        const uint PROCESS_VM_WRITE = 0x0020;
        const uint PROCESS_DUP_HANDLE = 0x0040;

        if ((accessMask & PROCESS_TERMINATE) != 0) rights.Add("PROCESS_TERMINATE");
        if ((accessMask & PROCESS_CREATE_THREAD) != 0) rights.Add("PROCESS_CREATE_THREAD");
        if ((accessMask & PROCESS_VM_READ) != 0) rights.Add("PROCESS_VM_READ");
        if ((accessMask & PROCESS_VM_WRITE) != 0) rights.Add("PROCESS_VM_WRITE");
        if ((accessMask & PROCESS_DUP_HANDLE) != 0) rights.Add("PROCESS_DUP_HANDLE");
    }

    private bool IsSuspiciousAccessToLSASS(List<string> accessRights)
    {
        return accessRights.Contains("PROCESS_VM_READ") || 
               accessRights.Contains("PROCESS_VM_WRITE") ||
               accessRights.Contains("PROCESS_CREATE_THREAD");
    }

    private bool IsSuspiciousCommandLine(string commandLine)
    {
        var suspiciousPatterns = new[]
        {
            "powershell", "-enc", "-e ", "base64", 
            "cmd.exe /c", "cmd.exe /k",
            "rundll32.exe", "regsvcs.exe", "regasm.exe",
            "-nop", "-w hidden", "-executionpolicy bypass"
        };

        var lowerCmd = commandLine.ToLower();
        return suspiciousPatterns.Any(pattern => lowerCmd.Contains(pattern));
    }
}
