# Secure Coding Practices for .NET API: Addressing OWASP Top 10 (A07:2021 - Identification and Authentication Failures)

## Comprehensive Authentication Security Implementation

### 1. Multi-Factor Authentication Framework

#### Core MFA Service Implementation

```csharp
public class MultiFactorAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly ITotpProvider _totpProvider;
    private readonly ISmsSender _smsSender;
    private readonly IEmailService _emailService;
    private readonly ILogger<MultiFactorAuthService> _logger;

    public MultiFactorAuthService(
        IUserRepository userRepository,
        ITotpProvider totpProvider,
        ISmsSender smsSender,
        IEmailService emailService,
        ILogger<MultiFactorAuthService> logger)
    {
        _userRepository = userRepository;
        _totpProvider = totpProvider;
        _smsSender = smsSender;
        _emailService = emailService;
        _logger = logger;
    }

    public async Task<MfaResult> RequestMfaChallengeAsync(string userId, MfaMethod method)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            _logger.LogWarning("MFA request for non-existent user {UserId}", userId);
            return MfaResult.Failed("User not found");
        }

        var challenge = new MfaChallenge
        {
            UserId = userId,
            Method = method,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5),
            Code = _totpProvider.GenerateCode(user.MfaSecret),
            IpAddress = HttpContext.Current.Connection.RemoteIpAddress?.ToString(),
            UserAgent = HttpContext.Current.Request.Headers["User-Agent"]
        };

        switch (method)
        {
            case MfaMethod.Sms:
                await _smsSender.SendAsync(user.PhoneNumber, 
                    $"Your verification code is: {challenge.Code}");
                break;
            case MfaMethod.Email:
                await _emailService.SendAsync(user.Email, 
                    "Verification Code", 
                    $"Your code is: {challenge.Code}");
                break;
            case MfaMethod.Authenticator:
                // No need to send, user has app
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(method), method, null);
        }

        await _userRepository.SaveChallengeAsync(challenge);
        return MfaResult.Success(challenge.Id);
    }

    public async Task<MfaVerificationResult> VerifyMfaChallengeAsync(
        string challengeId, string code, string userId)
    {
        var challenge = await _userRepository.GetChallengeAsync(challengeId);
        if (challenge == null || challenge.UserId != userId)
        {
            _logger.LogWarning("Invalid MFA challenge {ChallengeId} for user {UserId}", 
                challengeId, userId);
            return MfaVerificationResult.Failed("Invalid challenge");
        }

        if (challenge.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("Expired MFA challenge {ChallengeId}", challengeId);
            return MfaVerificationResult.Failed("Challenge expired");
        }

        var user = await _userRepository.GetByIdAsync(userId);
        var isValid = _totpProvider.ValidateCode(
            user.MfaSecret, 
            code, 
            TimeSpan.FromMinutes(2));

        if (!isValid)
        {
            _logger.LogWarning("Invalid MFA code for challenge {ChallengeId}", challengeId);
            await _userRepository.RecordFailedAttemptAsync(userId);
            return MfaVerificationResult.Failed("Invalid code");
        }

        await _userRepository.ClearChallengeAsync(challengeId);
        await _userRepository.ResetFailedAttemptsAsync(userId);

        return MfaVerificationResult.Success(
            GenerateAuthToken(user),
            GenerateSessionCookie(user));
    }
}
```

### 2. Password Security Architecture

#### Secure Password Policy Enforcement

```csharp
public class PasswordPolicyService
{
    private readonly PasswordOptions _options;
    private readonly IBreachedPasswordService _breachedPasswordService;
    private readonly ILogger<PasswordPolicyService> _logger;

    public PasswordPolicyService(
        IOptions<PasswordOptions> options,
        IBreachedPasswordService breachedPasswordService,
        ILogger<PasswordPolicyService> logger)
    {
        _options = options.Value;
        _breachedPasswordService = breachedPasswordService;
        _logger = logger;
    }

    public async Task<PasswordValidationResult> ValidatePasswordAsync(
        string password, string userId = null)
    {
        var result = new PasswordValidationResult();

        // Check against previous passwords if user exists
        if (userId != null)
        {
            var previousPasswords = await _userRepository.GetPreviousPasswordsAsync(userId, 5);
            if (previousPasswords.Any(p => PasswordHasher.VerifyHashedPassword(p, password)))
            {
                result.AddError("Cannot reuse previous passwords");
            }
        }

        // Check against breached passwords
        if (await _breachedPasswordService.IsPasswordBreached(password))
        {
            result.AddError("Password has been compromised in a data breach");
            _logger.LogWarning("Breached password attempt detected");
        }

        // Complexity requirements
        if (password.Length < _options.RequiredLength)
        {
            result.AddError($"Password must be at least {_options.RequiredLength} characters");
        }

        if (_options.RequireDigit && !password.Any(char.IsDigit))
        {
            result.AddError("Password must contain at least one digit");
        }

        if (_options.RequireLowercase && !password.Any(char.IsLower))
        {
            result.AddError("Password must contain at least one lowercase letter");
        }

        if (_options.RequireUppercase && !password.Any(char.IsUpper))
        {
            result.AddError("Password must contain at least one uppercase letter");
        }

        if (_options.RequireNonAlphanumeric && password.All(char.IsLetterOrDigit))
        {
            result.AddError("Password must contain at least one special character");
        }

        return result;
    }
}

// Password hashing service using Argon2
public class AdvancedPasswordHasher : IPasswordHasher
{
    private readonly Argon2Config _config;

    public AdvancedPasswordHasher(IOptions<Argon2Config> config)
    {
        _config = config.Value;
    }

    public string HashPassword(string password)
    {
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = RandomNumberGenerator.GetBytes(16),
            DegreeOfParallelism = _config.DegreeOfParallelism,
            Iterations = _config.Iterations,
            MemorySize = _config.MemorySize
        };

        var hash = argon2.GetBytes(32);
        return Convert.ToBase64String(hash);
    }

    public bool VerifyPassword(string hashedPassword, string providedPassword)
    {
        var hashBytes = Convert.FromBase64String(hashedPassword);
        var providedHash = HashPassword(providedPassword);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(hashedPassword),
            Encoding.UTF8.GetBytes(providedHash));
    }
}
```

### 3. Secure Session Management

#### JWT Token Service with Advanced Security

```csharp
public class JwtTokenService
{
    private readonly JwtSettings _settings;
    private readonly TokenValidationParameters _validationParameters;
    private readonly ILogger<JwtTokenService> _logger;

    public JwtTokenService(
        IOptions<JwtSettings> settings,
        ILogger<JwtTokenService> logger)
    {
        _settings = settings.Value;
        _logger = logger;
        
        _validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _settings.Issuer,
            ValidateAudience = true,
            ValidAudience = _settings.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_settings.Secret)),
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.Zero,
            NameClaimType = JwtRegisteredClaimNames.Sub,
            RoleClaimType = ClaimTypes.Role
        };
    }

    public string GenerateToken(User user, IEnumerable<Claim> additionalClaims = null)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
            new(ClaimTypes.Name, user.UserName),
            new(ClaimTypes.Email, user.Email),
            new("mfa_verified", "false") // Will be updated after MFA
        };

        if (additionalClaims != null)
        {
            claims.AddRange(additionalClaims);
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.Secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(
            issuer: _settings.Issuer,
            audience: _settings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_settings.TokenLifetimeMinutes),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public ClaimsPrincipal ValidateToken(string token)
    {
        try
        {
            var principal = new JwtSecurityTokenHandler()
                .ValidateToken(token, _validationParameters, out var validatedToken);

            if (validatedToken is not JwtSecurityToken jwtToken ||
                !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha512Signature, 
                    StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }
        catch (SecurityTokenExpiredException ex)
        {
            _logger.LogWarning("Expired token attempt: {Token}", token);
            throw new AuthException("Token has expired", ex);
        }
        catch (SecurityTokenValidationException ex)
        {
            _logger.LogWarning("Invalid token attempt: {Token}", token);
            throw new AuthException("Invalid token", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token validation error");
            throw new AuthException("Token validation failed", ex);
        }
    }

    public TokenValidationReport ValidateTokenWithDetails(string token)
    {
        var report = new TokenValidationReport();
        
        try
        {
            var handler = new JwtSecurityTokenHandler();
            
            // Initial validation without lifetime check
            var validationParams = _validationParameters.Clone();
            validationParams.ValidateLifetime = false;
            
            handler.ValidateToken(token, validationParams, out var securityToken);
            
            if (securityToken is JwtSecurityToken jwtToken)
            {
                report.TokenDetails = jwtToken;
                
                // Check expiration separately
                var now = DateTime.UtcNow;
                if (jwtToken.ValidTo < now)
                {
                    report.Expired = true;
                    report.ExpiryTime = jwtToken.ValidTo;
                }
                
                // Check issuer
                if (!jwtToken.Issuer.Equals(_settings.Issuer))
                {
                    report.InvalidIssuer = true;
                }
                
                // Check algorithm
                if (!jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha512Signature))
                {
                    report.WeakAlgorithm = true;
                }
            }
            
            report.Valid = !report.Expired && !report.InvalidIssuer && !report.WeakAlgorithm;
        }
        catch (Exception ex)
        {
            report.ValidationException = ex;
            report.Valid = false;
        }
        
        return report;
    }
}
```

### 4. Account Protection Services

#### Account Lockout and Brute Force Protection

```csharp
public class AccountProtectionService
{
    private readonly IAccountLockoutStore _lockoutStore;
    private readonly ILogger<AccountProtectionService> _logger;
    private readonly SecuritySettings _settings;

    public AccountProtectionService(
        IAccountLockoutStore lockoutStore,
        IOptions<SecuritySettings> settings,
        ILogger<AccountProtectionService> logger)
    {
        _lockoutStore = lockoutStore;
        _settings = settings.Value;
        _logger = logger;
    }

    public async Task<AccountStatus> CheckAccountStatusAsync(string userId)
    {
        var status = await _lockoutStore.GetStatusAsync(userId);
        
        if (status.LockedUntil > DateTime.UtcNow)
        {
            return AccountStatus.Locked(status.LockedUntil);
        }
        
        if (status.FailedAttempts >= _settings.MaxFailedAttempts)
        {
            await LockAccountAsync(userId);
            return AccountStatus.Locked(DateTime.UtcNow.Add(_settings.LockoutDuration));
        }
        
        return AccountStatus.Active();
    }

    public async Task RecordFailedAttemptAsync(string userId, string ipAddress)
    {
        var status = await _lockoutStore.GetStatusAsync(userId);
        status.FailedAttempts++;
        status.LastFailedAttempt = DateTime.UtcNow;
        status.FailedAttemptIp = ipAddress;
        
        await _lockoutStore.UpdateStatusAsync(status);
        
        _logger.LogWarning(
            "Failed login attempt for user {UserId} from {IP}. Attempt {AttemptCount}",
            userId, ipAddress, status.FailedAttempts);
            
        if (status.FailedAttempts % 3 == 0)
        {
            SecurityAlertService.RaiseAlert(
                $"Repeated failed attempts for user {userId}",
                $"Now at {status.FailedAttempts} failed attempts from {ipAddress}",
                AlertSeverity.Medium);
        }
    }

    public async Task ResetFailedAttemptsAsync(string userId)
    {
        var status = await _lockoutStore.GetStatusAsync(userId);
        status.FailedAttempts = 0;
        status.LastFailedAttempt = null;
        await _lockoutStore.UpdateStatusAsync(status);
    }

    private async Task LockAccountAsync(string userId)
    {
        var status = await _lockoutStore.GetStatusAsync(userId);
        status.LockedUntil = DateTime.UtcNow.Add(_settings.LockoutDuration);
        await _lockoutStore.UpdateStatusAsync(status);
        
        _logger.LogWarning(
            "Account {UserId} locked until {LockoutEnd}", 
            userId, status.LockedUntil);
            
        SecurityAlertService.RaiseAlert(
            $"Account {userId} locked due to too many failed attempts",
            $"Account locked until {status.LockedUntil}",
            AlertSeverity.High);
    }
}
```

### 5. Authentication Event Logging

#### Comprehensive Auth Audit System

```csharp
public class AuthenticationAuditService
{
    private readonly IAuditEventStore _eventStore;
    private readonly ILogger<AuthenticationAuditService> _logger;

    public AuthenticationAuditService(
        IAuditEventStore eventStore,
        ILogger<AuthenticationAuditService> logger)
    {
        _eventStore = eventStore;
        _logger = logger;
    }

    public async Task LogAuthenticationEventAsync(
        string userId, 
        AuthEventType eventType, 
        string ipAddress, 
        string userAgent, 
        string deviceId = null,
        bool? success = null,
        string additionalInfo = null)
    {
        var auditEvent = new AuthAuditEvent
        {
            Timestamp = DateTime.UtcNow,
            UserId = userId,
            EventType = eventType,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            DeviceId = deviceId,
            Success = success,
            AdditionalInfo = additionalInfo
        };

        await _eventStore.StoreEventAsync(auditEvent);
        
        if (eventType == AuthEventType.FailedLogin || 
            eventType == AuthEventType.SuspiciousActivity)
        {
            _logger.LogWarning(
                "Auth event {EventType} for user {UserId} from {IP} - {Info}",
                eventType, userId, ipAddress, additionalInfo);
        }
    }

    public async Task AnalyzeRecentActivityAsync(string userId)
    {
        var recentEvents = await _eventStore.GetRecentEventsAsync(userId, TimeSpan.FromDays(7));
        
        // Detect suspicious login patterns
        var distinctIpCount = recentEvents
            .Where(e => e.EventType == AuthEventType.Login)
            .Select(e => e.IpAddress)
            .Distinct()
            .Count();
            
        if (distinctIpCount > 3)
        {
            await LogAuthenticationEventAsync(
                userId,
                AuthEventType.SuspiciousActivity,
                null, null,
                additionalInfo: $"Multiple IPs detected: {distinctIpCount}");
                
            SecurityAlertService.RaiseAlert(
                $"Suspicious login pattern for user {userId}",
                $"Logged in from {distinctIpCount} different IPs recently",
                AlertSeverity.Medium);
        }
        
        // Check for failed login spikes
        var failedCount = recentEvents
            .Count(e => e.EventType == AuthEventType.FailedLogin);
            
        if (failedCount > 5)
        {
            await LogAuthenticationEventAsync(
                userId,
                AuthEventType.SuspiciousActivity,
                null, null,
                additionalInfo: $"Multiple failed attempts: {failedCount}");
        }
    }
}
```

## Best Practices Implementation Checklist

1. **Multi-Factor Authentication**
   - Implement TOTP, SMS, and email verification options
   - Enforce MFA for privileged operations
   - Store MFA secrets securely

2. **Password Security**
   - Enforce strong password policies (min 12 chars, complexity)
   - Implement secure password hashing (Argon2, PBKDF2)
   - Check against breached password databases
   - Prevent password reuse

3. **Session Management**
   - Use secure, signed tokens with short lifespans
   - Implement token revocation
   - Enforce HTTPS for all auth communications
   - Use secure cookie attributes (HttpOnly, Secure, SameSite)

4. **Account Protection**
   - Implement progressive account lockout
   - Detect and prevent brute force attacks
   - Monitor for suspicious login patterns
   - Provide secure account recovery

5. **Secure Authentication Protocols**
   - Implement OAuth 2.0/OpenID Connect correctly
   - Validate ID tokens properly
   - Use PKCE for public clients
   - Store client secrets securely

6. **Comprehensive Logging**
   - Log all authentication events
   - Include contextual data (IP, user agent)
   - Detect and alert on suspicious patterns
   - Protect audit logs from tampering

7. **Continuous Monitoring**
   - Monitor for authentication anomalies
   - Alert on security events
   - Regularly review access patterns
   - Update security measures based on threats
