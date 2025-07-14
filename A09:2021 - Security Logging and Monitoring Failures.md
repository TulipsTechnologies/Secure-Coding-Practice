# Secure Coding Practices for PHP (WordPress and Laravel): Addressing OWASP Top 10 (A09:2021 - Security Logging and Monitoring Failures)

## Comprehensive Security Monitoring Framework

### 1. Centralized Security Event Logging

#### Structured Logging Implementation

```php
class SecurityEventLogger
{
    private $logger;
    private $eventDispatcher;

    public function __construct(
        LoggerInterface $logger,
        EventDispatcherInterface $eventDispatcher
    ) {
        $this->logger = $logger;
        $this->eventDispatcher = $eventDispatcher;
    }

    public function logSecurityEvent(SecurityEvent $event): void
    {
        try {
            // Enrich with contextual information
            $event->setTimestamp(new DateTime());
            $event->setIpAddress($this->getIpAddress());
            $event->setUserAgent($this->getUserAgent());
            $event->setUserId($this->getUserId());

            // Structured logging
            $this->logger->info('Security event', [
                'event' => $event->getType(),
                'severity' => $event->getSeverity(),
                'details' => $event->getDetails(),
                'ip' => $event->getIpAddress(),
                'user' => $event->getUserId(),
                'timestamp' => $event->getTimestamp()->format(DateTime::ATOM)
            ]);

            // Dispatch for real-time processing
            $this->eventDispatcher->dispatch(
                new SecurityEventNotification($event)
            );
        } catch (Exception $e) {
            $this->logger->error('Failed to log security event', [
                'error' => $e->getMessage()
            ]);
        }
    }

    public function logAuthenticationEvent(AuthenticationEvent $authEvent): void
    {
        $securityEvent = new SecurityEvent(
            $authEvent->isSuccess() ? 'AuthenticationSuccess' : 'AuthenticationFailure',
            $authEvent->isSuccess() ? SecurityEventSeverity::INFO : SecurityEventSeverity::WARNING,
            [
                'username' => $authEvent->getUsername(),
                'method' => $authEvent->getMethod(),
                'reason' => $authEvent->getFailureReason()
            ]
        );

        $this->logSecurityEvent($securityEvent);
    }

    private function getIpAddress(): string
    {
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    private function getUserAgent(): string
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    }

    private function getUserId(): string
    {
        // Laravel example:
        // return auth()->id() ?? 'anonymous';
        
        // WordPress example:
        // return get_current_user_id() ?: 'anonymous';
    }
}
```

### 2. Real-time Security Monitoring

#### Anomaly Detection Service

```php
class AnomalyDetectionService
{
    private $eventQueue;
    private $detectors;
    private $logger;

    public function __construct(
        SecurityEventQueue $eventQueue,
        iterable $detectors,
        LoggerInterface $logger
    ) {
        $this->eventQueue = $eventQueue;
        $this->detectors = $detectors;
        $this->logger = $logger;
    }

    public function processEvents(): void
    {
        try {
            $events = $this->eventQueue->dequeueRecentEvents();
            if (empty($events)) {
                return;
            }

            foreach ($this->detectors as $detector) {
                try {
                    $anomalies = $detector->detect($events);
                    foreach ($anomalies as $anomaly) {
                        $this->logger->warning('Security anomaly detected', [
                            'type' => $anomaly->getType()
                        ]);
                        $this->alertSecurityTeam($anomaly);
                    }
                } catch (Exception $e) {
                    $this->logger->error('Anomaly detector failed', [
                        'error' => $e->getMessage()
                    ]);
                }
            }
        } catch (Exception $e) {
            $this->logger->error('Anomaly detection processing failed', [
                'error' => $e->getMessage()
            ]);
        }
    }

    private function alertSecurityTeam(SecurityAnomaly $anomaly): void
    {
        // Implementation to notify security team
    }
}

// Example Brute Force Detector
class BruteForceDetector
{
    public function detect(array $events): array
    {
        $failedAuths = array_filter($events, function($e) {
            return $e->getType() === 'AuthenticationFailure';
        });

        $grouped = [];
        foreach ($failedAuths as $event) {
            $username = $event->getDetails()['username'] ?? 'unknown';
            if (!isset($grouped[$username])) {
                $grouped[$username] = [];
            }
            $grouped[$username][] = $event;
        }

        $anomalies = [];
        foreach ($grouped as $username => $events) {
            if (count($events) > 5) {
                $anomalies[] = new SecurityAnomaly(
                    'BruteForceAttempt',
                    SecurityAnomalySeverity::HIGH,
                    [
                        'username' => $username,
                        'attempts' => count($events),
                        'first' => min(array_map(fn($e) => $e->getTimestamp(), $events)),
                        'last' => max(array_map(fn($e) => $e->getTimestamp(), $events)),
                        'ips' => array_unique(array_map(fn($e) => $e->getIpAddress(), $events))
                    ]
                );
            }
        }

        return $anomalies;
    }
}
```

### 3. Audit Trail Implementation

#### Comprehensive Audit Service

```php
class AuditService
{
    private $repository;
    private $logger;

    public function __construct(
        AuditRepository $repository,
        LoggerInterface $logger
    ) {
        $this->repository = $repository;
        $this->logger = $logger;
    }

    public function recordAction(
        string $action,
        $target,
        string $description
    ): void {
        try {
            $record = new AuditRecord(
                new DateTime(),
                $action,
                $this->getCurrentUserId(),
                $this->getIpAddress(),
                $this->getUserAgent(),
                is_object($target) ? get_class($target) : gettype($target),
                $this->getTargetId($target),
                $description,
                json_encode($target)
            );

            $this->repository->add($record);
        } catch (Exception $e) {
            $this->logger->error('Failed to record audit action', [
                'error' => $e->getMessage()
            ]);
        }
    }

    public function query(AuditQuery $query): array
    {
        try {
            return $this->repository->query($query);
        } catch (Exception $e) {
            $this->logger->error('Audit query failed', [
                'error' => $e->getMessage()
            ]);
            throw $e;
        }
    }

    private function getCurrentUserId(): string
    {
        // Laravel: return auth()->id() ?? 'system';
        // WordPress: return get_current_user_id() ?: 'system';
    }

    private function getIpAddress(): string
    {
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    private function getUserAgent(): string
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    }

    private function getTargetId($target): string
    {
        if (is_object($target) && method_exists($target, 'getId')) {
            return $target->getId();
        }
        return (string) spl_object_hash($target);
    }
}

// Example usage in Laravel controller
public function updateUser(Request $request, $id)
{
    $user = User::findOrFail($id);
    
    $this->auditService->recordAction(
        'update',
        $user,
        "User update initiated by " . auth()->user()->name
    );
    
    $user->update($request->all());
    
    $this->auditService->recordAction(
        'update',
        $user,
        "User update completed by " . auth()->user()->name
    );
    
    return response()->json($user);
}
```

### 4. Security Alerting System

#### Multi-Channel Alerting Service

```php
class SecurityAlertService
{
    private $notifiers;
    private $logger;

    public function __construct(
        iterable $notifiers,
        LoggerInterface $logger
    ) {
        $this->notifiers = $notifiers;
        $this->logger = $logger;
    }

    public function raiseAlert(SecurityAlert $alert): void
    {
        $this->logger->warning('Security alert raised', [
            'title' => $alert->getTitle(),
            'severity' => $alert->getSeverity()
        ]);

        foreach ($this->notifiers as $notifier) {
            if ($notifier->supportsSeverity($alert->getSeverity())) {
                try {
                    $notifier->notify($alert);
                } catch (Exception $e) {
                    $this->logger->error('Failed to send alert', [
                        'notifier' => get_class($notifier),
                        'error' => $e->getMessage()
                    ]);
                }
            }
        }
    }
}

// Email Notifier Implementation
class EmailAlertNotifier
{
    private $mailer;
    private $config;

    public function __construct(
        MailerInterface $mailer,
        array $config
    ) {
        $this->mailer = $mailer;
        $this->config = $config;
    }

    public function supportsSeverity(string $severity): bool
    {
        return $severity >= SecurityAlertSeverity::MEDIUM;
    }

    public function notify(SecurityAlert $alert): void
    {
        $message = (new Email())
            ->to($this->config['security_team_email'])
            ->subject("[Security Alert] {$alert->getTitle()}")
            ->html($this->formatAlertBody($alert));

        $this->mailer->send($message);
    }

    private function formatAlertBody(SecurityAlert $alert): string
    {
        $body = "<h1>Security Alert: {$alert->getTitle()}</h1>";
        $body .= "<p><strong>Severity:</strong> {$alert->getSeverity()}</p>";
        $body .= "<p><strong>Timestamp:</strong> {$alert->getTimestamp()->format('Y-m-d H:i:s')}</p>";
        $body .= "<p><strong>Details:</strong></p>";
        $body .= "<pre>{$alert->getDetails()}</pre>";
        
        if ($alert->getRemediation()) {
            $body .= "<p><strong>Recommended Actions:</strong></p>";
            $body .= "<ul>";
            foreach ($alert->getRemediation() as $action) {
                $body .= "<li>{$action}</li>";
            }
            $body .= "</ul>";
        }
        
        return $body;
    }
}
```

### 5. Log Protection Mechanisms

#### Secure Log Management Service

```php
class SecureLogService
{
    private $logger;
    private $sanitizer;
    private $encryptionKey;

    public function __construct(
        LoggerInterface $logger,
        LogSanitizer $sanitizer,
        string $encryptionKey
    ) {
        $this->logger = $logger;
        $this->sanitizer = $sanitizer;
        $this->encryptionKey = $encryptionKey;
    }

    public function info(string $message, array $context = []): void
    {
        $this->logger->info(
            $this->sanitizer->sanitize($message),
            $this->sanitizeContext($context)
        );
    }

    public function warning(string $message, array $context = []): void
    {
        $this->logger->warning(
            $this->sanitizer->sanitize($message),
            $this->sanitizeContext($context)
        );
    }

    public function error(string $message, array $context = []): void
    {
        $this->logger->error(
            $this->sanitizer->sanitize($message),
            $this->sanitizeContext($context)
        );
    }

    public function sensitive(string $message, array $context = []): void
    {
        $encrypted = $this->encrypt($message);
        $encryptedContext = [];
        
        foreach ($context as $key => $value) {
            $encryptedContext[$key] = is_string($value) 
                ? $this->encrypt($value)
                : $value;
        }
        
        $this->logger->info(
            "[ENCRYPTED] " . $encrypted,
            $encryptedContext
        );
    }

    private function sanitizeContext(array $context): array
    {
        $sanitized = [];
        foreach ($context as $key => $value) {
            $sanitized[$key] = is_string($value)
                ? $this->sanitizer->sanitize($value)
                : $value;
        }
        return $sanitized;
    }

    private function encrypt(string $data): string
    {
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt(
            $data,
            'aes-256-cbc',
            $this->encryptionKey,
            0,
            $iv
        );
        return base64_encode($iv . $encrypted);
    }
}

// Log Sanitizer Implementation
class LogSanitizer
{
    private $patterns = [
        '/\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/' => '[CREDIT_CARD]',
        '/\b\d{3}[- ]?\d{2}[- ]?\d{4}\b/' => '[SSN]',
        '/(?i)\bpassword\b[^=]*=[^=]*\b\w+\b/' => '[PASSWORD]',
        '/(?i)\bapi[-_]?key\b[^=]*=[^=]*\b\w+\b/' => '[API_KEY]'
    ];

    public function sanitize(string $input): string
    {
        if (empty($input)) {
            return $input;
        }

        foreach ($this->patterns as $pattern => $replacement) {
            $input = preg_replace($pattern, $replacement, $input);
        }

        return $input;
    }
}
```

## Implementation Checklist

1. **Comprehensive Logging**
   - Log all authentication attempts (success/failure)
   - Record authorization decisions
   - Track sensitive data access
   - Include sufficient context (user, IP, timestamp)

2. **Log Protection**
   - Sanitize sensitive data before logging
   - Encrypt highly sensitive log entries
   - Implement access controls for log files

3. **Monitoring & Alerting**
   - Detect brute force attacks
   - Identify unusual access patterns
   - Monitor for data exfiltration attempts
   - Set up multi-channel alerts (email, SMS, Slack)

4. **Audit Trails**
   - Record administrative actions
   - Track configuration changes
   - Log data export activities
   - Protect audit logs from tampering

5. **Log Management**
   - Define retention policies
   - Implement log rotation
   - Centralize log collection
   - Regularly review logs

6. **Incident Response**
   - Document investigation procedures
   - Establish escalation paths
   - Conduct regular security drills
   - Maintain forensic capabilities

## PHP-Specific Recommendations

1. **Error Handling**
   - Disable display_errors in production
   - Log errors to secure files
   - Implement custom error handlers

2. **WordPress Specific**
   - Enable security logging plugins
   - Monitor for plugin vulnerabilities
   - Audit user role changes
   - Log file modification attempts

3. **Laravel Specific**
   - Use built-in logging channels
   - Implement request/response logging
   - Monitor queue failures
   - Audit artisan command usage

4. **General PHP Security**
   - Secure log file permissions
   - Monitor for suspicious PHP execution
   - Track file uploads
   - Log database query errors

## Example Deployment Configuration

```bash
# Configure PHP logging
sed -i 's/display_errors = On/display_errors = Off/' /etc/php/8.1/fpm/php.ini
sed -i 's/log_errors = Off/log_errors = On/' /etc/php/8.1/fpm/php.ini
sed -i 's/error_log = .*/error_log = \/var\/log\/php\/error.log/' /etc/php/8.1/fpm/php.ini

# Secure log directory
mkdir -p /var/log/php
chown www-data:www-data /var/log/php
chmod 750 /var/log/php

# Configure logrotate
cat > /etc/logrotate.d/php <<EOL
/var/log/php/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 www-data www-data
    sharedscripts
    postrotate
        /usr/bin/systemctl reload php8.1-fpm.service > /dev/null
    endscript
}
EOL

# Install monitoring agent
apt-get install -y ossec-hids
```

This implementation provides a comprehensive security logging and monitoring framework for PHP applications that addresses OWASP A09 requirements while being adaptable to both WordPress and Laravel environments.
