namespace EDRTelemetry.Correlation.Engine;

using EDRTelemetry.Core.Interfaces;
using EDRTelemetry.Core.Models;
using System.Collections.Concurrent;

/// <summary>
/// Core correlation engine that evaluates telemetry against detection rules
/// </summary>
public class CorrelationEngine : ICorrelationEngine
{
    private readonly List<IDetectionRule> _rules = new();
    private readonly ConcurrentDictionary<string, TelemetryEvent> _eventCache = new();
    private readonly TimeSpan _correlationWindow = TimeSpan.FromMinutes(5);

    public void RegisterRule(IDetectionRule rule)
    {
        _rules.Add(rule);
    }

    public async Task<List<Alert>> CorrelateAsync(List<TelemetryEvent> events)
    {
        var alerts = new List<Alert>();

        foreach (var @event in events)
        {
            // Cache event for correlation
            _eventCache.TryAdd(@event.EventId, @event);

            // Evaluate against all rules
            foreach (var rule in _rules)
            {
                var alert = await rule.EvaluateAsync(@event);
                if (alert != null)
                {
                    alerts.Add(alert);
                }
            }

            // Run correlation patterns
            var correlatedAlerts = EvaluateCorrelationPatterns(@event);
            alerts.AddRange(correlatedAlerts);
        }

        // Cleanup old events
        CleanupOldEvents();

        return alerts;
    }

    private List<Alert> EvaluateCorrelationPatterns(TelemetryEvent @event)
    {
        var alerts = new List<Alert>();

        // Pattern 1: LSASS Access + Process Creation from same host
        if (@event is ProcessAccessEvent lsassAccess && lsassAccess.IsLsassAccess)
        {
            var recentProcessEvents = GetEventsInWindow<ProcessEvent>(
                DateTime.UtcNow.Subtract(_correlationWindow), 
                DateTime.UtcNow);

            if (recentProcessEvents.Any(p => p.ProcessId == lsassAccess.SourceProcessId))
            {
                var alert = new Alert
                {
                    RuleId = "RULE-CORR-01",
                    RuleName = "LSASS Access + Suspicious Process Creation",
                    Severity = SeverityLevel.Critical,
                    Title = "Critical: Multi-stage Attack Pattern Detected",
                    Description = "LSASS access correlates with suspicious process creation. Likely credential dumping attack.",
                    CorrelatedEventIds = recentProcessEvents.Select(p => p.EventId).ToList()
                };
                alerts.Add(alert);
            }
        }

        // Pattern 2: Mass LDAP queries + Process creation burst
        if (@event is DirectoryServiceEvent ldapEvent && ldapEvent.IsAnomalous)
        {
            var recentProcesses = GetEventsInWindow<ProcessEvent>(
                @event.Timestamp.Subtract(TimeSpan.FromSeconds(30)),
                @event.Timestamp.Add(TimeSpan.FromSeconds(30)));

            if (recentProcesses.Count > 5)
            {
                var alert = new Alert
                {
                    RuleId = "RULE-CORR-02",
                    RuleName = "AD Reconnaissance + Process Execution Burst",
                    Severity = SeverityLevel.Warning,
                    Title = "Warning: Reconnaissance + Execution Pattern Detected",
                    Description = $"Detected {recentProcesses.Count} process creation events within 60 seconds " +
                                 "of LDAP enumeration activity.",
                    CorrelatedEventIds = new List<string> { @event.EventId }
                        .Union(recentProcesses.Select(p => p.EventId))
                        .ToList()
                };
                alerts.Add(alert);
            }
        }

        return alerts;
    }

    private List<T> GetEventsInWindow<T>(DateTime startTime, DateTime endTime) where T : TelemetryEvent
    {
        return _eventCache.Values
            .OfType<T>()
            .Where(e => e.Timestamp >= startTime && e.Timestamp <= endTime)
            .ToList();
    }

    private void CleanupOldEvents()
    {
        var cutoffTime = DateTime.UtcNow.Subtract(_correlationWindow);
        var oldEventIds = _eventCache
            .Where(kvp => kvp.Value.Timestamp < cutoffTime)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var eventId in oldEventIds)
        {
            _eventCache.TryRemove(eventId, out _);
        }
    }
}
