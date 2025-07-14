# Secure Coding Practices for PHP (WordPress and Laravel): Addressing OWASP Top 10 (A07:2021 - Identification and Authentication Failures)

## Comprehensive Authentication Security Implementation

### 1. Multi-Factor Authentication Framework

#### Core MFA Service Implementation

```php
class MultiFactorAuthService
{
    private $userRepository;
    private $totpProvider;
    private $smsSender;
    private $emailService;
    private $logger;

    public function __construct(
        UserRepository $userRepository,
        TotpProvider $totpProvider,
        SmsSender $smsSender,
        EmailService $emailService,
        LoggerInterface $logger
    ) {
        $this->userRepository = $userRepository;
        $this->totpProvider = $totpProvider;
        $this->smsSender = $smsSender;
        $this->emailService = $emailService;
        $this->logger = $logger;
    }

    public function requestMfaChallenge(string $userId, string $method): MfaResult
    {
        $user = $this->userRepository->findById($userId);
        if (!$user) {
            $this->logger->warning("MFA request for non-existent user {$userId}");
            return new MfaResult(false, "User not found");
        }

        $challenge = new MfaChallenge(
            $userId,
            $method,
            new DateTime(),
            (new DateTime())->add(new DateInterval('PT5M')),
            $this->totpProvider->generateCode($user->getMfaSecret()),
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_USER_AGENT']
        );

        switch ($method) {
            case 'sms':
                $this->smsSender->send(
                    $user->getPhoneNumber(), 
                    "Your verification code is: {$challenge->getCode()}"
                );
                break;
            case 'email':
                $this->emailService->send(
                    $user->getEmail(),
                    "Verification Code",
                    "Your code is: {$challenge->getCode()}"
                );
                break;
            case 'authenticator':
                // No need to send, user has app
                break;
            default:
                throw new InvalidArgumentException("Invalid MFA method: {$method}");
        }

        $this->userRepository->saveChallenge($challenge);
        return new MfaResult(true, $challenge->getId());
    }

    public function verifyMfaChallenge(
        string $challengeId, 
        string $code, 
        string $userId
    ): MfaVerificationResult {
        $challenge = $this->userRepository->getChallenge($challengeId);
        if (!$challenge || $challenge->getUserId() !== $userId) {
            $this->logger->warning("Invalid MFA challenge {$challengeId} for user {$userId}");
            return new MfaVerificationResult(false, "Invalid challenge");
        }

        if ($challenge->getExpiresAt() < new DateTime()) {
            $this->logger->warning("Expired MFA challenge {$challengeId}");
            return new MfaVerificationResult(false, "Challenge expired");
        }

        $user = $this->userRepository->findById($userId);
        $isValid = $this->totpProvider->validateCode(
            $user->getMfaSecret(),
            $code,
            120 // 2 minutes window
        );

        if (!$isValid) {
            $this->logger->warning("Invalid MFA code for challenge {$challengeId}");
            $this->userRepository->recordFailedAttempt($userId);
            return new MfaVerificationResult(false, "Invalid code");
        }

        $this->userRepository->clearChallenge($challengeId);
        $this->userRepository->resetFailedAttempts($userId);

        return new MfaVerificationResult(
            true,
            $this->generateAuthToken($user),
            $this->generateSessionCookie($user)
        );
    }
}
```

### 2. Password Security Architecture

#### Secure Password Policy Enforcement

```php
class PasswordPolicyService
{
    private $options;
    private $breachedPasswordService;
    private $logger;

    public function __construct(
        array $options,
        BreachedPasswordService $breachedPasswordService,
        LoggerInterface $logger
    ) {
        $this->options = $options;
        $this->breachedPasswordService = $breachedPasswordService;
        $this->logger = $logger;
    }

    public function validatePassword(string $password, ?string $userId = null): PasswordValidationResult
    {
        $result = new PasswordValidationResult();

        // Check against previous passwords if user exists
        if ($userId !== null) {
            $previousPasswords = $this->userRepository->getPreviousPasswords($userId, 5);
            foreach ($previousPasswords as $previousPassword) {
                if (password_verify($password, $previousPassword)) {
                    $result->addError("Cannot reuse previous passwords");
                    break;
                }
            }
        }

        // Check against breached passwords
        if ($this->breachedPasswordService->isPasswordBreached($password)) {
            $result->addError("Password has been compromised in a data breach");
            $this->logger->warning("Breached password attempt detected");
        }

        // Complexity requirements
        if (strlen($password) < $this->options['min_length']) {
            $result->addError("Password must be at least {$this->options['min_length']} characters");
        }

        if ($this->options['require_digit'] && !preg_match('/\d/', $password)) {
            $result->addError("Password must contain at least one digit");
        }

        if ($this->options['require_lowercase'] && !preg_match('/[a-z]/', $password)) {
            $result->addError("Password must contain at least one lowercase letter");
        }

        if ($this->options['require_uppercase'] && !preg_match('/[A-Z]/', $password)) {
            $result->addError("Password must contain at least one uppercase letter");
        }

        if ($this->options['require_special'] && !preg_match('/[^a-zA-Z0-9]/', $password)) {
            $result->addError("Password must contain at least one special character");
        }

        return $result;
    }
}

// Password hashing service using Argon2
class AdvancedPasswordHasher
{
    private $options;

    public function __construct(array $options)
    {
        $this->options = $options;
    }

    public function hashPassword(string $password): string
    {
        return password_hash(
            $password,
            PASSWORD_ARGON2ID,
            [
                'memory_cost' => $this->options['memory_cost'],
                'time_cost' => $this->options['time_cost'],
                'threads' => $this->options['threads']
            ]
        );
    }

    public function verifyPassword(string $hashedPassword, string $providedPassword): bool
    {
        return password_verify($providedPassword, $hashedPassword);
    }
}
```

### 3. Secure Session Management

#### JWT Token Service with Advanced Security

```php
class JwtTokenService
{
    private $secret;
    private $issuer;
    private $audience;
    private $tokenLifetime;
    private $logger;

    public function __construct(
        string $secret,
        string $issuer,
        string $audience,
        int $tokenLifetime,
        LoggerInterface $logger
    ) {
        $this->secret = $secret;
        $this->issuer = $issuer;
        $this->audience = $audience;
        $this->tokenLifetime = $tokenLifetime;
        $this->logger = $logger;
    }

    public function generateToken(User $user, array $additionalClaims = []): string
    {
        $now = new DateTimeImmutable();
        $expire = $now->add(new DateInterval("PT{$this->tokenLifetime}M"));

        $claims = [
            'iat' => $now->getTimestamp(),
            'iss' => $this->issuer,
            'nbf' => $now->getTimestamp(),
            'exp' => $expire->getTimestamp(),
            'aud' => $this->audience,
            'sub' => $user->getId(),
            'name' => $user->getUsername(),
            'email' => $user->getEmail(),
            'mfa_verified' => false
        ];

        $claims = array_merge($claims, $additionalClaims);

        return JWT::encode(
            $claims,
            $this->secret,
            'HS512'
        );
    }

    public function validateToken(string $token): array
    {
        try {
            $decoded = JWT::decode(
                $token,
                $this->secret,
                ['HS512']
            );

            return (array)$decoded;
        } catch (ExpiredException $e) {
            $this->logger->warning("Expired token attempt: {$token}");
            throw new AuthException("Token has expired", 0, $e);
        } catch (Exception $e) {
            $this->logger->warning("Invalid token attempt: {$token}");
            throw new AuthException("Invalid token", 0, $e);
        }
    }

    public function validateTokenWithDetails(string $token): TokenValidationReport
    {
        $report = new TokenValidationReport();

        try {
            // Decode without verification first to get header
            $tks = explode('.', $token);
            if (count($tks) != 3) {
                throw new UnexpectedValueException('Wrong number of segments');
            }
            $header = json_decode(base64_decode(strtr($tks[0], '-_', '+/')), true);
            
            // Check algorithm
            if ($header['alg'] !== 'HS512') {
                $report->weakAlgorithm = true;
            }

            // Now decode with verification
            $decoded = JWT::decode($token, $this->secret, ['HS512']);
            $decodedArray = (array)$decoded;
            
            $report->tokenDetails = $decodedArray;
            
            // Check expiration
            $now = new DateTimeImmutable();
            if ($decodedArray['exp'] < $now->getTimestamp()) {
                $report->expired = true;
                $report->expiryTime = (new DateTime())->setTimestamp($decodedArray['exp']);
            }
            
            // Check issuer
            if ($decodedArray['iss'] !== $this->issuer) {
                $report->invalidIssuer = true;
            }
            
            $report->valid = !$report->expired && !$report->invalidIssuer && !$report->weakAlgorithm;
        } catch (Exception $e) {
            $report->validationException = $e;
            $report->valid = false;
        }
        
        return $report;
    }
}
```

### 4. Account Protection Services

#### Account Lockout and Brute Force Protection

```php
class AccountProtectionService
{
    private $lockoutStore;
    private $settings;
    private $logger;

    public function __construct(
        AccountLockoutStore $lockoutStore,
        array $settings,
        LoggerInterface $logger
    ) {
        $this->lockoutStore = $lockoutStore;
        $this->settings = $settings;
        $this->logger = $logger;
    }

    public function checkAccountStatus(string $userId): AccountStatus
    {
        $status = $this->lockoutStore->getStatus($userId);
        
        if ($status->isLocked()) {
            return AccountStatus::locked($status->getLockedUntil());
        }
        
        if ($status->getFailedAttempts() >= $this->settings['max_failed_attempts']) {
            $this->lockAccount($userId);
            return AccountStatus::locked(
                (new DateTime())->add(
                    new DateInterval($this->settings['lockout_duration'])
                )
            );
        }
        
        return AccountStatus::active();
    }

    public function recordFailedAttempt(string $userId, string $ipAddress): void
    {
        $status = $this->lockoutStore->getStatus($userId);
        $status->incrementFailedAttempts();
        $status->setLastFailedAttempt(new DateTime());
        $status->setFailedAttemptIp($ipAddress);
        
        $this->lockoutStore->updateStatus($status);
        
        $this->logger->warning(
            "Failed login attempt for user {$userId} from {$ipAddress}. Attempt {$status->getFailedAttempts()}"
        );
            
        if ($status->getFailedAttempts() % 3 === 0) {
            SecurityAlertService::raiseAlert(
                "Repeated failed attempts for user {$userId}",
                "Now at {$status->getFailedAttempts()} failed attempts from {$ipAddress}",
                AlertSeverity::MEDIUM
            );
        }
    }

    public function resetFailedAttempts(string $userId): void
    {
        $status = $this->lockoutStore->getStatus($userId);
        $status->resetFailedAttempts();
        $this->lockoutStore->updateStatus($status);
    }

    private function lockAccount(string $userId): void
    {
        $status = $this->lockoutStore->getStatus($userId);
        $status->lockUntil(
            (new DateTime())->add(
                new DateInterval($this->settings['lockout_duration'])
            )
        );
        
        $this->lockoutStore->updateStatus($status);
        
        $this->logger->warning(
            "Account {$userId} locked until {$status->getLockedUntil()->format('Y-m-d H:i:s')}"
        );
            
        SecurityAlertService::raiseAlert(
            "Account {$userId} locked due to too many failed attempts",
            "Account locked until {$status->getLockedUntil()->format('Y-m-d H:i:s')}",
            AlertSeverity::HIGH
        );
    }
}
```

### 5. Authentication Event Logging

#### Comprehensive Auth Audit System

```php
class AuthenticationAuditService
{
    private $eventStore;
    private $logger;

    public function __construct(
        AuditEventStore $eventStore,
        LoggerInterface $logger
    ) {
        $this->eventStore = $eventStore;
        $this->logger = $logger;
    }

    public function logAuthenticationEvent(
        string $userId,
        string $eventType,
        string $ipAddress,
        string $userAgent,
        ?string $deviceId = null,
        ?bool $success = null,
        ?string $additionalInfo = null
    ): void {
        $auditEvent = new AuthAuditEvent(
            new DateTime(),
            $userId,
            $eventType,
            $ipAddress,
            $userAgent,
            $deviceId,
            $success,
            $additionalInfo
        );

        $this->eventStore->storeEvent($auditEvent);
        
        if (in_array($eventType, [AuthEventType::FAILED_LOGIN, AuthEventType::SUSPICIOUS_ACTIVITY])) {
            $this->logger->warning(
                "Auth event {$eventType} for user {$userId} from {$ipAddress} - {$additionalInfo}"
            );
        }
    }

    public function analyzeRecentActivity(string $userId): void
    {
        $recentEvents = $this->eventStore->getRecentEvents($userId, new DateInterval('P7D'));
        
        // Detect suspicious login patterns
        $distinctIps = [];
        foreach ($recentEvents as $event) {
            if ($event->getEventType() === AuthEventType::LOGIN) {
                $distinctIps[$event->getIpAddress()] = true;
            }
        }
        
        if (count($distinctIps) > 3) {
            $this->logAuthenticationEvent(
                $userId,
                AuthEventType::SUSPICIOUS_ACTIVITY,
                null,
                null,
                null,
                null,
                "Multiple IPs detected: " . count($distinctIps)
            );
                
            SecurityAlertService::raiseAlert(
                "Suspicious login pattern for user {$userId}",
                "Logged in from " . count($distinctIps) . " different IPs recently",
                AlertSeverity::MEDIUM
            );
        }
        
        // Check for failed login spikes
        $failedCount = 0;
        foreach ($recentEvents as $event) {
            if ($event->getEventType() === AuthEventType::FAILED_LOGIN) {
                $failedCount++;
            }
        }
            
        if ($failedCount > 5) {
            $this->logAuthenticationEvent(
                $userId,
                AuthEventType::SUSPICIOUS_ACTIVITY,
                null,
                null,
                null,
                null,
                "Multiple failed attempts: {$failedCount}"
            );
        }
    }
}
```

## Best Practices Implementation Checklist

1. **Multi-Factor Authentication**
   - Implement TOTP, SMS, and email verification options
   - Enforce MFA for admin/sensitive operations
   - Store MFA secrets securely (encrypted)

2. **Password Security**
   - Enforce strong password policies (min 12 chars, complexity)
   - Use modern hashing (Argon2id, bcrypt)
   - Check against breached password databases
   - Prevent password reuse (last 5 passwords)

3. **Session Management**
   - Use secure, signed tokens with short lifespans
   - Implement token invalidation on logout
   - Enforce HTTPS for all auth communications
   - Use secure cookie attributes (HttpOnly, Secure, SameSite)

4. **Account Protection**
   - Implement progressive account lockout
   - Detect and prevent brute force attacks
   - Monitor for suspicious login patterns
   - Provide secure account recovery (no security questions)

5. **Secure Authentication Protocols**
   - Implement OAuth 2.0/OpenID Connect correctly
   - Validate ID tokens properly
   - Use PKCE for public clients
   - Store client secrets securely (not in code)

6. **Comprehensive Logging**
   - Log all authentication attempts (success/failure)
   - Include contextual data (IP, user agent, timestamp)
   - Detect and alert on suspicious patterns
   - Protect audit logs from tampering

7. **Continuous Monitoring**
   - Monitor for authentication anomalies
   - Alert on security events (failed logins, lockouts)
   - Regularly review access patterns
   - Update security measures based on threats

## Additional PHP-Specific Recommendations

1. **PHP Configuration**
   - Set `session.cookie_httponly = 1`
   - Set `session.cookie_secure = 1`
   - Set `session.use_strict_mode = 1`
   - Disable dangerous functions (`exec`, `system`, etc.)

2. **WordPress Specific**
   - Limit login attempts (plugin or custom solution)
   - Disable XML-RPC if not needed
   - Use application passwords for API access
   - Implement two-factor authentication

3. **Laravel Specific**
   - Use built-in auth scaffolding
   - Implement Laravel Sanctum/Fortify for API auth
   - Use Laravel's rate limiting for login attempts
   - Enable CSRF protection for web routes

4. **General PHP Applications**
   - Use prepared statements to prevent SQL injection
   - Implement proper password reset flows
   - Sanitize all user input
   - Validate all user output (XSS protection)
