namespace EDRTelemetry.Correlation.Handlers;

using EDRTelemetry.Core.Interfaces;
using EDRTelemetry.Core.Models;
using System.Text.Json;

/// <summary>
/// Outputs alerts to JSON file
/// </summary>
public class JsonFileAlertHandler : IAlertHandler
{
    private readonly string _outputPath;
    private readonly object _lockObject = new();

    public JsonFileAlertHandler(string outputPath = "alerts.json")
    {
        _outputPath = outputPath;
    }

    public async Task HandleAsync(Alert alert)
    {
        lock (_lockObject)
        {
            try
            {
                var options = new JsonSerializerOptions { WriteIndented = true };
                var json = JsonSerializer.Serialize(alert, options);

                File.AppendAllText(_outputPath, json + Environment.NewLine + Environment.NewLine);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Alert handler error: {ex.Message}");
            }
        }

        await Task.CompletedTask;
    }
}

/// <summary>
/// Outputs alerts to console
/// </summary>
public class ConsoleAlertHandler : IAlertHandler
{
    public async Task HandleAsync(Alert alert)
    {
        var color = alert.Severity switch
        {
            SeverityLevel.Critical => ConsoleColor.Red,
            SeverityLevel.Error => ConsoleColor.DarkRed,
            SeverityLevel.Warning => ConsoleColor.Yellow,
            _ => ConsoleColor.White
        };

        Console.ForegroundColor = color;
        Console.WriteLine($"[{alert.Severity}] {alert.Title}");
        Console.WriteLine($"Rule: {alert.RuleName} ({alert.RuleId})");
        Console.WriteLine($"Description: {alert.Description}");
        Console.WriteLine($"Recommended Action: {alert.RecommendedAction}");
        Console.WriteLine($"Time: {alert.DetectionTime:O}");
        Console.WriteLine("---");
        Console.ResetColor();

        await Task.CompletedTask;
    }
}

/// <summary>
/// Outputs alerts to CSV file
/// </summary>
public class CsvAlertHandler : IAlertHandler
{
    private readonly string _outputPath;
    private readonly object _lockObject = new();
    private bool _headerWritten = false;

    public CsvAlertHandler(string outputPath = "alerts.csv")
    {
        _outputPath = outputPath;
    }

    public async Task HandleAsync(Alert alert)
    {
        lock (_lockObject)
        {
            try
            {
                if (!_headerWritten)
                {
                    File.WriteAllText(_outputPath, 
                        "AlertId,Timestamp,RuleId,RuleName,Severity,Title,Description,CorrelatedEvents,RecommendedAction\n");
                    _headerWritten = true;
                }

                var correlatedEvents = string.Join(";", alert.CorrelatedEventIds);
                var csvLine = $"\"{alert.AlertId}\",\"{alert.DetectionTime:O}\"," +
                             $"\"{alert.RuleId}\",\"{alert.RuleName}\",\"{alert.Severity}\"," +
                             $"\"{EscapeCsv(alert.Title)}\",\"{EscapeCsv(alert.Description)}\"," +
                             $"\"{correlatedEvents}\",\"{EscapeCsv(alert.RecommendedAction)}\"\n";

                File.AppendAllText(_outputPath, csvLine);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"CSV handler error: {ex.Message}");
            }
        }

        await Task.CompletedTask;
    }

    private string EscapeCsv(string value)
    {
        return value.Replace("\"", "\"\"");
    }
}
