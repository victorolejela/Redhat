namespace EDRTelemetry.Core.Interfaces;

using EDRTelemetry.Core.Models;

/// <summary>
/// Interface for telemetry event parsers
/// </summary>
public interface ITelemetryParser
{
    string EventSource { get; }
    Task<TelemetryEvent?> ParseAsync(string rawEventData);
    bool CanParse(string rawEventData);
}

/// <summary>
/// Interface for detection rules
/// </summary>
public interface IDetectionRule
{
    string RuleId { get; }
    string RuleName { get; }
    string Description { get; }
    SeverityLevel DefaultSeverity { get; }
    
    Task<Alert?> EvaluateAsync(TelemetryEvent @event);
}

/// <summary>
/// Interface for correlation engines
/// </summary>
public interface ICorrelationEngine
{
    Task<List<Alert>> CorrelateAsync(List<TelemetryEvent> events);
    void RegisterRule(IDetectionRule rule);
}

/// <summary>
/// Interface for telemetry sources
/// </summary>
public interface ITelemetrySource
{
    string SourceName { get; }
    IObservable<TelemetryEvent> GetEventStream();
    Task StartAsync();
    Task StopAsync();
}

/// <summary>
/// Interface for alert handlers
/// </summary>
public interface IAlertHandler
{
    Task HandleAsync(Alert alert);
}
