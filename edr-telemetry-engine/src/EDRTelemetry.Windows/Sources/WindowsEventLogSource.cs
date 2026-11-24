namespace EDRTelemetry.Windows.Sources;

using EDRTelemetry.Core.Interfaces;
using EDRTelemetry.Core.Models;
using System.Diagnostics.Eventing.Reader;
using System.Reactive.Subjects;

/// <summary>
/// Collects events from Windows Event Log in real-time
/// </summary>
public class WindowsEventLogSource : ITelemetrySource
{
    public string SourceName => "WindowsEventLog";

    private readonly Subject<TelemetryEvent> _eventStream = new();
    private EventLogWatcher? _watcher;
    private readonly List<string> _eventQueries;
    private bool _isRunning = false;

    public WindowsEventLogSource()
    {
        // Define XPath queries for relevant events
        _eventQueries = new List<string>
        {
            // Process Creation
            @"*[System[(EventID=4688)]]", 
            // Directory Service Access
            @"*[System[(EventID=1644)]]",
            // Sysmon - Process Access
            @"*[System[(Provider[@Name='Microsoft-Windows-Sysmon/Operational']) and EventID=10]]",
            // Sysmon - Image Loaded
            @"*[System[(Provider[@Name='Microsoft-Windows-Sysmon/Operational']) and EventID=7]]"
        };
    }

    public IObservable<TelemetryEvent> GetEventStream()
    {
        return _eventStream;
    }

    public async Task StartAsync()
    {
        if (_isRunning) return;

        await Task.Run(() =>
        {
            try
            {
                // Combine queries
                var combinedQuery = string.Join(" or ", _eventQueries);
                var eventQuery = new EventLogQuery("Security", PathType.LogName, combinedQuery)
                {
                    ReverseDirection = false
                };

                _watcher = new EventLogWatcher(eventQuery, null, false);
                _watcher.EventRecordWritten += OnEventRecordWritten;
                _watcher.Enabled = true;
                _isRunning = true;

                System.Diagnostics.Debug.WriteLine("Windows Event Log source started");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error starting event log watcher: {ex.Message}");
            }
        });
    }

    public async Task StopAsync()
    {
        await Task.Run(() =>
        {
            if (_watcher != null)
            {
                _watcher.Enabled = false;
                _watcher.EventRecordWritten -= OnEventRecordWritten;
                _watcher.Dispose();
            }
            _isRunning = false;
            _eventStream.OnCompleted();
        });
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        try
        {
            if (e.EventRecord == null) return;

            var xmlContent = e.EventRecord.ToXml();
            var telemetryEvent = new TelemetryEvent
            {
                EventId = Guid.NewGuid().ToString(),
                Timestamp = e.EventRecord.TimeCreated ?? DateTime.UtcNow,
                Source = SourceName,
                RawData = xmlContent,
                EventType = "RawEventLog"
            };

            _eventStream.OnNext(telemetryEvent);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error processing event: {ex.Message}");
        }
    }
}

/// <summary>
/// Mock event source for testing
/// </summary>
public class MockEventSource : ITelemetrySource
{
    public string SourceName => "MockEventSource";

    private readonly Subject<TelemetryEvent> _eventStream = new();
    private CancellationTokenSource? _cancellationSource;

    public IObservable<TelemetryEvent> GetEventStream()
    {
        return _eventStream;
    }

    public Task StartAsync()
    {
        _cancellationSource = new CancellationTokenSource();

        _ = Task.Run(async () =>
        {
            while (!_cancellationSource.Token.IsCancellationRequested)
            {
                // Emit test events
                _eventStream.OnNext(GenerateMockProcessCreationEvent());
                await Task.Delay(TimeSpan.FromSeconds(2));
            }
        });

        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        _cancellationSource?.Cancel();
        _eventStream.OnCompleted();
        return Task.CompletedTask;
    }

    private ProcessEvent GenerateMockProcessCreationEvent()
    {
        return new ProcessEvent
        {
            EventId = Guid.NewGuid().ToString(),
            Timestamp = DateTime.UtcNow,
            Source = SourceName,
            EventType = "ProcessCreation",
            ProcessId = (uint)Random.Shared.Next(1000, 9999),
            ParentProcessId = 4,
            ImageName = "C:\\Windows\\System32\\cmd.exe",
            CommandLine = "cmd.exe /c whoami",
            User = "Administrator",
            Domain = "CORP"
        };
    }
}
