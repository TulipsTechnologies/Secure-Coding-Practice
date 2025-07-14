# Secure Coding Practices for .NET API: Addressing OWASP Top 10 (A09:2021 - Security Logging and Monitoring Failures)

## Comprehensive Security Monitoring Framework

### 1. Centralized Security Event Logging

#### Structured Logging Service Implementation

```csharp
public class SecurityEventLogger : ISecurityEventLogger
{
    private readonly ILogger<SecurityEventLogger> _logger;
    private readonly IEventAggregator _eventAggregator;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public SecurityEventLogger(
        ILogger<SecurityEventLogger> logger,
        IEventAggregator eventAggregator,
        IHttpContextAccessor httpContextAccessor)
    {
        _logger = logger;
        _eventAggregator = eventAggregator;
        _httpContextAccessor = httpContextAccessor;
    }

    public void LogSecurityEvent(SecurityEvent securityEvent)
    {
        try
        {
            // Enrich with contextual information
            securityEvent.Timestamp = DateTime.UtcNow;
            securityEvent.CorrelationId = GetCorrelationId();
            securityEvent.IpAddress = GetIpAddress();
            securityEvent.UserAgent = GetUserAgent();
            securityEvent.UserId = GetUserId();

            // Structured logging with Serilog
            _logger.LogInformation("Security event: {@SecurityEvent}", securityEvent);

            // Publish to event bus for real-time processing
            _eventAggregator.Publish(new SecurityEventNotification(securityEvent));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to log security event");
        }
    }

    public void LogAuthenticationEvent(AuthenticationEvent authEvent)
    {
        var securityEvent = new SecurityEvent
        {
            EventType = authEvent.Success ? "AuthenticationSuccess" : "AuthenticationFailure",
            Severity = authEvent.Success ? SecurityEventSeverity.Information : SecurityEventSeverity.Warning,
            Details = new
            {
                authEvent.Username,
                authEvent.AuthenticationMethod,
                authEvent.FailureReason
            }
        };

        LogSecurityEvent(securityEvent);
    }

    public void LogAuthorizationEvent(AuthorizationEvent authzEvent)
    {
        var securityEvent = new SecurityEvent
        {
            EventType = authzEvent.Success ? "AuthorizationSuccess" : "AuthorizationFailure",
            Severity = authzEvent.Success ? SecurityEventSeverity.Information : SecurityEventSeverity.Warning,
            Details = new
            {
                authzEvent.UserId,
                authzEvent.Resource,
                authzEvent.Action,
                authzEvent.DeniedReason
            }
        };

        LogSecurityEvent(securityEvent);
    }

    private string GetCorrelationId()
    {
        return _httpContextAccessor.HttpContext?
            .Request.Headers["X-Correlation-ID"].FirstOrDefault() ?? Guid.NewGuid().ToString();
    }

    private string GetIpAddress()
    {
        return _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    private string GetUserAgent()
    {
        return _httpContextAccessor.HttpContext?
            .Request.Headers["User-Agent"].FirstOrDefault() ?? "unknown";
    }

    private string GetUserId()
    {
        return _httpContextAccessor.HttpContext?.User?
            .FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
    }
}
```

### 2. Real-time Security Monitoring

#### Anomaly Detection Service

```csharp
public class AnomalyDetectionService : IHostedService
{
    private readonly ISecurityEventQueue _eventQueue;
    private readonly IEnumerable<IAnomalyDetector> _detectors;
    private readonly ILogger<AnomalyDetectionService> _logger;
    private Timer _timer;

    public AnomalyDetectionService(
        ISecurityEventQueue eventQueue,
        IEnumerable<IAnomalyDetector> detectors,
        ILogger<AnomalyDetectionService> logger)
    {
        _eventQueue = eventQueue;
        _detectors = detectors;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _timer = new Timer(ProcessEvents, null, TimeSpan.Zero, TimeSpan.FromSeconds(30));
        return Task.CompletedTask;
    }

    private void ProcessEvents(object state)
    {
        try
        {
            var events = _eventQueue.DequeueRecentEvents();
            if (!events.Any()) return;

            Parallel.ForEach(_detectors, detector =>
            {
                try
                {
                    var anomalies = detector.Detect(events);
                    foreach (var anomaly in anomalies)
                    {
                        _logger.LogWarning("Security anomaly detected: {AnomalyType}", anomaly.Type);
                        AlertSecurityTeam(anomaly);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Anomaly detector failed");
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Anomaly detection processing failed");
        }
    }

    private void AlertSecurityTeam(SecurityAnomaly anomaly)
    {
        // Implementation to notify security team via preferred channels
        // (email, Slack, PagerDuty, etc.)
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _timer?.Dispose();
        return Task.CompletedTask;
    }
}

// Example detector for brute force attacks
public class BruteForceDetector : IAnomalyDetector
{
    private readonly ILogger<BruteForceDetector> _logger;

    public BruteForceDetector(ILogger<BruteForceDetector> logger)
    {
        _logger = logger;
    }

    public IEnumerable<SecurityAnomaly> Detect(IEnumerable<SecurityEvent> events)
    {
        var failedAuths = events
            .Where(e => e.EventType == "AuthenticationFailure")
            .GroupBy(e => e.Details.Username)
            .Where(g => g.Count() > 5)
            .ToList();

        foreach (var group in failedAuths)
        {
            _logger.LogWarning(
                "Possible brute force attack against account {Username} - {Count} attempts",
                group.Key, group.Count());

            yield return new SecurityAnomaly
            {
                Type = "BruteForceAttempt",
                Severity = SecurityAnomalySeverity.High,
                Details = new
                {
                    Username = group.Key,
                    AttemptCount = group.Count(),
                    FirstAttempt = group.Min(e => e.Timestamp),
                    LastAttempt = group.Max(e => e.Timestamp),
                    IpAddresses = group.Select(e => e.IpAddress).Distinct()
                }
            };
        }
    }
}
```

### 3. Audit Trail Implementation

#### Comprehensive Audit Service

```csharp
public class AuditService : IAuditService
{
    private readonly IAuditRepository _repository;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuditService> _logger;

    public AuditService(
        IAuditRepository repository,
        IHttpContextAccessor httpContextAccessor,
        ILogger<AuditService> logger)
    {
        _repository = repository;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task RecordActionAsync(AuditAction action, object target, string description)
    {
        try
        {
            var auditRecord = new AuditRecord
            {
                Timestamp = DateTime.UtcNow,
                Action = action.ToString(),
                UserId = GetCurrentUserId(),
                IpAddress = GetIpAddress(),
                UserAgent = GetUserAgent(),
                TargetType = target.GetType().Name,
                TargetId = GetTargetId(target),
                Description = description,
                Details = JsonSerializer.Serialize(target)
            };

            await _repository.AddAsync(auditRecord);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to record audit action");
        }
    }

    public async Task<IEnumerable<AuditRecord>> QueryAsync(AuditQuery query)
    {
        try
        {
            return await _repository.QueryAsync(query);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Audit query failed");
            throw;
        }
    }

    private string GetCurrentUserId()
    {
        return _httpContextAccessor.HttpContext?.User?
            .FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "system";
    }

    private string GetIpAddress()
    {
        return _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    private string GetUserAgent()
    {
        return _httpContextAccessor.HttpContext?.Request.Headers["User-Agent"].ToString() ?? "unknown";
    }

    private string GetTargetId(object target)
    {
        return target switch
        {
            IHasId entity => entity.Id.ToString(),
            _ => target.GetHashCode().ToString()
        };
    }
}

// Example usage in controllers
[HttpPut("users/{id}")]
[Authorize(Roles = "Admin")]
public async Task<IActionResult> UpdateUser(string id, [FromBody] UserUpdateDto updateDto)
{
    var existingUser = await _userService.GetByIdAsync(id);
    
    await _auditService.RecordActionAsync(
        AuditAction.Update, 
        existingUser, 
        $"User update initiated by {User.Identity.Name}");
    
    var updatedUser = await _userService.UpdateAsync(id, updateDto);
    
    await _auditService.RecordActionAsync(
        AuditAction.Update, 
        updatedUser, 
        $"User update completed by {User.Identity.Name}");
    
    return Ok(updatedUser);
}
```

### 4. Security Alerting System

#### Multi-Channel Alerting Service

```csharp
public class SecurityAlertService : ISecurityAlertService
{
    private readonly IEnumerable<IAlertNotifier> _notifiers;
    private readonly ILogger<SecurityAlertService> _logger;

    public SecurityAlertService(
        IEnumerable<IAlertNotifier> notifiers,
        ILogger<SecurityAlertService> logger)
    {
        _notifiers = notifiers;
        _logger = logger;
    }

    public async Task RaiseAlertAsync(SecurityAlert alert)
    {
        _logger.LogWarning(
            "Security alert raised: {AlertTitle} (Severity: {AlertSeverity})", 
            alert.Title, alert.Severity);

        var tasks = _notifiers
            .Where(n => n.SupportsSeverity(alert.Severity))
            .Select(n => NotifyAsync(n, alert))
            .ToList();

        await Task.WhenAll(tasks);
    }

    private async Task NotifyAsync(IAlertNotifier notifier, SecurityAlert alert)
    {
        try
        {
            await notifier.NotifyAsync(alert);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send alert via {NotifierName}", notifier.GetType().Name);
        }
    }
}

// Email notifier implementation
public class EmailAlertNotifier : IAlertNotifier
{
    private readonly IEmailService _emailService;
    private readonly AlertingConfiguration _config;

    public EmailAlertNotifier(
        IEmailService emailService,
        IOptions<AlertingConfiguration> config)
    {
        _emailService = emailService;
        _config = config.Value;
    }

    public bool SupportsSeverity(SecurityAlertSeverity severity)
    {
        return severity >= SecurityAlertSeverity.Medium;
    }

    public async Task NotifyAsync(SecurityAlert alert)
    {
        var message = new EmailMessage
        {
            To = _config.SecurityTeamEmail,
            Subject = $"[Security Alert] {alert.Title}",
            Body = FormatAlertBody(alert)
        };

        await _emailService.SendAsync(message);
    }

    private string FormatAlertBody(SecurityAlert alert)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"<h1>Security Alert: {alert.Title}</h1>");
        sb.AppendLine($"<p><strong>Severity:</strong> {alert.Severity}</p>");
        sb.AppendLine($"<p><strong>Timestamp:</strong> {alert.Timestamp:yyyy-MM-dd HH:mm:ss}</p>");
        sb.AppendLine($"<p><strong>Details:</strong></p>");
        sb.AppendLine($"<pre>{alert.Details}</pre>");
        
        if (alert.Remediation != null)
        {
            sb.AppendLine($"<p><strong>Recommended Actions:</strong></p>");
            sb.AppendLine($"<ul>{string.Join("", alert.Remediation.Select(r => $"<li>{r}</li>"))}</ul>");
        }
        
        return sb.ToString();
    }
}
```

### 5. Log Protection Mechanisms

#### Secure Log Management Service

```csharp
public class SecureLogService : ILogService
{
    private readonly ILogger _logger;
    private readonly IDataProtector _protector;
    private readonly ILogSanitizer _sanitizer;

    public SecureLogService(
        ILogger<SecureLogService> logger,
        IDataProtectionProvider protectionProvider,
        ILogSanitizer sanitizer)
    {
        _logger = logger;
        _protector = protectionProvider.CreateProtector("LogProtection");
        _sanitizer = sanitizer;
    }

    public void LogInformation(string message, params object[] args)
    {
        var sanitizedArgs = SanitizeArguments(args);
        _logger.LogInformation(message, sanitizedArgs);
    }

    public void LogWarning(string message, params object[] args)
    {
        var sanitizedArgs = SanitizeArguments(args);
        _logger.LogWarning(message, sanitizedArgs);
    }

    public void LogError(Exception exception, string message, params object[] args)
    {
        var sanitizedArgs = SanitizeArguments(args);
        _logger.LogError(exception, message, sanitizedArgs);
    }

    public void LogSensitive(string sensitiveMessage, params object[] sensitiveArgs)
    {
        var protectedMessage = _protector.Protect(sensitiveMessage);
        var protectedArgs = sensitiveArgs.Select(a => 
            a is string s ? _protector.Protect(s) : a).ToArray();
            
        _logger.LogInformation("[Protected] " + protectedMessage, protectedArgs);
    }

    private object[] SanitizeArguments(object[] args)
    {
        return args.Select(arg =>
        {
            if (arg is string s)
            {
                return _sanitizer.Sanitize(s);
            }
            return arg;
        }).ToArray();
    }
}

// Log sanitizer implementation
public class LogSanitizer : ILogSanitizer
{
    private readonly string _replacement = "[REDACTED]";
    private readonly string[] _sensitivePatterns = new[]
    {
        @"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", // Credit cards
        @"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b", // SSN
        @"(?i)\bpassword\b[^=]*=[^=]*\b\w+\b", // Password=value
        @"(?i)\bapi[-_]?key\b[^=]*=[^=]*\b\w+\b", // API_KEY=value
    };

    public string Sanitize(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        foreach (var pattern in _sensitivePatterns)
        {
            input = Regex.Replace(input, pattern, _replacement);
        }

        return input;
    }
}
```

## Implementation Checklist

1. **Comprehensive Logging**
   - Log all security-relevant events
   - Include sufficient context (timestamps, user IDs, IPs)
   - Use structured logging format

2. **Real-time Monitoring**
   - Implement anomaly detection
   - Set up alerts for suspicious activities
   - Correlate events across systems

3. **Audit Trails**
   - Record sensitive operations
   - Protect audit logs from tampering
   - Implement secure audit log access

4. **Alerting System**
   - Multi-channel notifications
   - Appropriate severity levels
   - Include remediation steps

5. **Log Protection**
   - Sanitize sensitive data
   - Encrypt confidential information
   - Control log access

6. **Retention Policy**
   - Define log retention periods
   - Comply with regulatory requirements
   - Implement secure log archival

7. **Incident Response**
   - Document investigation procedures
   - Establish escalation paths
   - Conduct regular drills
