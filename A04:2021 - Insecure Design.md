# Secure Coding Practices for .NET API: Addressing OWASP Top 10 (A04:2021 - Insecure Design)

## Introduction to Insecure Design Risks

Insecure Design is a new category in the 2021 OWASP Top 10, focusing on risks related to design flaws rather than implementation bugs. These vulnerabilities occur when security is not adequately considered during the architecture and design phases of application development.

## Common Insecure Design Patterns in .NET APIs

1. **Missing Threat Modeling**
2. **Inadequate Authentication/Authorization Architecture**
3. **Business Logic Flaws**
4. **Improper Data Flow Design**
5. **Lack of Security Controls in Workflows**
6. **Insecure Default Configurations**
7. **Failure to Enforce Security Boundaries**

## Step-by-Step Secure Design Implementation

### 1. Threat Modeling Implementation

#### Using Microsoft Threat Modeling Tool

```csharp
// Example security requirements derived from threat modeling
public class PaymentServiceDesign
{
    /*
    THREAT MODEL:
    - STRIDE Classification: Tampering with payment amounts
    - Mitigation: Cryptographic signing of transaction requests
    */
    
    private readonly ICryptographicSigner _signer;
    
    public PaymentServiceDesign(ICryptographicSigner signer)
    {
        _signer = signer;
    }
    
    public async Task<PaymentResult> ProcessPayment(PaymentRequest request)
    {
        // Verify cryptographic signature
        if (!_signer.VerifySignature(request.ToBytes(), request.Signature))
        {
            throw new SecurityException("Invalid payment request signature");
        }
        
        // Additional validation
        if (request.Amount <= 0)
        {
            throw new BusinessRuleException("Invalid payment amount");
        }
        
        // Process payment
        return await _paymentProcessor.Execute(request);
    }
}

public interface ICryptographicSigner
{
    bool VerifySignature(byte[] data, byte[] signature);
    byte[] SignData(byte[] data);
}
```

### 2. Secure Authentication/Authorization Architecture

#### Policy-Based Authorization Design

```csharp
// Program.cs - Comprehensive auth setup
builder.Services.AddAuthorization(options =>
{
    // Financial transaction policy
    options.AddPolicy("HighValueTransaction", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("TwoFactorVerified", "true");
        policy.RequireRole("VerifiedCustomer");
        policy.Requirements.Add(new MinimumAgeRequirement(18));
        policy.Requirements.Add(new TransactionLimitRequirement(10000));
    });
    
    // Admin policy with MFA
    options.AddPolicy("ElevatedAdminAccess", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireRole("Administrator");
        policy.Requirements.Add(new MfaRequirement("strong"));
    });
});

// Custom requirement handlers
builder.Services.AddSingleton<IAuthorizationHandler, MinimumAgeHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, TransactionLimitHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, MfaHandler>();
```

### 3. Business Logic Protection Patterns

#### Anti-Abuse Pattern for Financial Transactions

```csharp
public class FinancialTransactionService
{
    private readonly ITransactionValidator _validator;
    private readonly IFraudDetector _fraudDetector;
    private readonly ITransactionLimiter _limiter;
    
    public FinancialTransactionService(
        ITransactionValidator validator,
        IFraudDetector fraudDetector,
        ITransactionLimiter limiter)
    {
        _validator = validator;
        _fraudDetector = fraudDetector;
        _limiter = limiter;
    }
    
    public async Task<TransactionResult> ExecuteTransaction(TransactionRequest request)
    {
        // Step 1: Basic validation
        await _validator.Validate(request);
        
        // Step 2: Fraud detection
        var fraudScore = await _fraudDetector.Analyze(request);
        if (fraudScore > 0.8)
        {
            throw new FraudDetectionException("Potential fraudulent transaction");
        }
        
        // Step 3: Rate limiting
        if (!await _limiter.CheckLimit(request.UserId, request.Amount))
        {
            throw new RateLimitException("Transaction limit exceeded");
        }
        
        // Step 4: Execute with verification
        return await _transactionProcessor.ExecuteWithVerification(request);
    }
}

// Decorator pattern for additional security checks
public class VerifiedTransactionProcessor : ITransactionProcessor
{
    private readonly ITransactionProcessor _inner;
    private readonly IVerificationService _verification;
    
    public VerifiedTransactionProcessor(
        ITransactionProcessor inner,
        IVerificationService verification)
    {
        _inner = inner;
        _verification = verification;
    }
    
    public async Task<TransactionResult> ExecuteWithVerification(TransactionRequest request)
    {
        if (request.Amount > 5000)
        {
            await _verification.RequireManualApproval(request);
        }
        
        return await _inner.Execute(request);
    }
}
```

### 4. Secure Data Flow Design

#### Data Classification and Handling

```csharp
// Attribute-based data classification
[DataClassification(SensitivityLevel.High)]
public class PaymentInformation
{
    [Encrypted]
    public string CardNumber { get; set; }
    
    [Masked]
    public string CardHolderName { get; set; }
    
    [Encrypted]
    public string Cvv { get; set; }
    
    public string ExpiryDate { get; set; }
}

// Secure DTO transformation
public class SecureDtoMapper
{
    private readonly IDataProtector _protector;
    
    public SecureDtoMapper(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("PaymentData");
    }
    
    public PaymentDto ToSecureDto(PaymentInformation payment)
    {
        return new PaymentDto
        {
            // Only include masked data
            CardNumber = Mask(payment.CardNumber),
            CardHolderName = payment.CardHolderName, // Already marked as masked
            ExpiryDate = payment.ExpiryDate
        };
    }
    
    public PaymentInformation FromDto(PaymentDto dto)
    {
        // Decryption would happen during validation
        return new PaymentInformation
        {
            CardNumber = dto.CardNumber,
            CardHolderName = dto.CardHolderName,
            ExpiryDate = dto.ExpiryDate
        };
    }
    
    private string Mask(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length < 4)
            return "****";
            
        return value.Substring(value.Length - 4).PadLeft(value.Length, '*');
    }
}
```

### 5. Workflow Security Controls

#### Secure Multi-Step Transaction Pattern

```csharp
public class SecureWorkflowOrchestrator
{
    private readonly IWorkflowStateStore _stateStore;
    private readonly IWorkflowValidator _validator;
    private readonly IAuditLogger _auditLogger;
    
    public SecureWorkflowOrchestrator(
        IWorkflowStateStore stateStore,
        IWorkflowValidator validator,
        IAuditLogger auditLogger)
    {
        _stateStore = stateStore;
        _validator = validator;
        _auditLogger = auditLogger;
    }
    
    public async Task<WorkflowResult> ProcessStep(WorkflowStep step)
    {
        // 1. Validate step sequence
        var state = await _stateStore.GetState(step.SessionId);
        if (!_validator.IsValidNextStep(state.CurrentStep, step.StepType))
        {
            await _auditLogger.LogInvalidTransition(state.CurrentStep, step.StepType);
            throw new WorkflowException("Invalid workflow step sequence");
        }
        
        // 2. Verify anti-CSRF token
        if (!_validator.VerifyAntiForgeryToken(step.SessionId, step.AntiForgeryToken))
        {
            await _auditLogger.LogSecurityViolation("Invalid anti-forgery token");
            throw new SecurityException("Invalid request");
        }
        
        // 3. Check time window
        if ((DateTime.UtcNow - state.LastUpdated) > TimeSpan.FromMinutes(30))
        {
            await _auditLogger.LogSecurityViolation("Expired workflow session");
            throw new TimeoutException("Workflow session expired");
        }
        
        // 4. Process step
        var result = await _stepProcessor.Execute(step, state);
        
        // 5. Update state
        var newState = state with 
        {
            CurrentStep = step.StepType,
            LastUpdated = DateTime.UtcNow
        };
        
        await _stateStore.UpdateState(newState);
        
        return result;
    }
}
```

### 6. Secure Default Configurations

#### Secure Defaults Framework

```csharp
// Secure defaults configuration
public static class SecureDefaults
{
    public static IServiceCollection AddSecureDefaults(this IServiceCollection services)
    {
        // Security headers
        services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN";
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        });
        
        // HTTPS enforcement
        services.AddHttpsRedirection(options =>
        {
            options.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
            options.HttpsPort = 443;
        });
        
        // Secure cookie policies
        services.Configure<CookiePolicyOptions>(options =>
        {
            options.MinimumSameSitePolicy = SameSiteMode.Strict;
            options.HttpOnly = HttpOnlyPolicy.Always;
            options.Secure = CookieSecurePolicy.Always;
        });
        
        // API security defaults
        services.AddApiSecurityDefaults();
        
        return services;
    }
    
    private static IServiceCollection AddApiSecurityDefaults(this IServiceCollection services)
    {
        services.AddControllers(options =>
        {
            // Add global filters
            options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
            options.Filters.Add(new RequireHttpsAttribute());
            
            // Input validation
            options.ModelValidatorProviders.Add(new StrictModelValidatorProvider());
        });
        
        return services;
    }
}

// Usage in Program.cs
builder.Services.AddSecureDefaults();
```

### 7. Security Boundary Enforcement

#### Microservice Security Gateway

```csharp
// Secure service-to-service communication
public class SecureServiceGateway
{
    private readonly HttpClient _httpClient;
    private readonly IServiceAuthenticator _authenticator;
    private readonly IRequestSigner _signer;
    
    public SecureServiceGateway(
        HttpClient httpClient,
        IServiceAuthenticator authenticator,
        IRequestSigner signer)
    {
        _httpClient = httpClient;
        _authenticator = authenticator;
        _signer = signer;
    }
    
    public async Task<TResponse> CallService<TRequest, TResponse>(
        string serviceName,
        string endpoint,
        TRequest request)
    {
        // 1. Authenticate with service mesh
        var authToken = await _authenticator.GetServiceToken(serviceName);
        
        // 2. Create signed request
        var requestMessage = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = JsonContent.Create(request)
        };
        
        requestMessage.Headers.Authorization = 
            new AuthenticationHeaderValue("Bearer", authToken);
        
        var signature = _signer.SignRequest(requestMessage);
        requestMessage.Headers.Add("X-Request-Signature", signature);
        
        // 3. Send with timeout
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        
        try
        {
            var response = await _httpClient.SendAsync(requestMessage, cts.Token);
            response.EnsureSuccessStatusCode();
            
            return await response.Content.ReadFromJsonAsync<TResponse>();
        }
        catch (TaskCanceledException)
        {
            throw new TimeoutException($"Service {serviceName} call timed out");
        }
    }
}
```

## Design Validation Techniques

### 1. Security Checklist Verification

```csharp
// Automated design validation
public class SecurityDesignValidator
{
    public DesignValidationResult ValidateController(Type controllerType)
    {
        var result = new DesignValidationResult();
        
        // Check for authorization attributes
        if (!controllerType.GetCustomAttributes<AuthorizeAttribute>().Any())
        {
            result.AddWarning(
                "Controller missing authorization",
                "All controllers should have explicit authorization");
        }
        
        // Check for sensitive data exposure
        var methods = controllerType.GetMethods();
        foreach (var method in methods)
        {
            ValidateMethod(method, result);
        }
        
        return result;
    }
    
    private void ValidateMethod(MethodInfo method, DesignValidationResult result)
    {
        // Check for input validation
        if (method.GetParameters().Any(p => 
            !p.GetCustomAttributes<ValidateInputAttribute>().Any()))
        {
            result.AddWarning(
                $"Method {method.Name} missing input validation",
                "All parameters should have explicit validation");
        }
        
        // Check for sensitive operations
        if (method.Name.Contains("Admin") || 
            method.Name.Contains("Delete") ||
            method.Name.Contains("Update"))
        {
            if (!method.GetCustomAttributes<AuthorizeAttribute>()
                .Any(a => a.Roles?.Contains("Admin") == true))
            {
                result.AddError(
                    $"Admin operation {method.Name} missing proper authorization",
                    "Sensitive operations must require admin role");
            }
        }
    }
}

// Usage during code reviews
var validator = new SecurityDesignValidator();
var result = validator.ValidateController(typeof(PaymentController));

if (result.HasErrors)
{
    throw new DesignValidationException(result.ToString());
}
```

### 2. Secure Design Pattern Catalog

```csharp
// Secure factory pattern for sensitive operations
public class SecureOperationFactory
{
    private readonly ISecurityContext _securityContext;
    
    public SecureOperationFactory(ISecurityContext securityContext)
    {
        _securityContext = securityContext;
    }
    
    public IDataAccess CreateDataAccess()
    {
        if (_securityContext.IsHighSecurityMode)
        {
            return new AuditedEncryptedDataAccess(
                new DataAccess(),
                _securityContext.AuditLogger);
        }
        
        return new DataAccess();
    }
    
    public IReportGenerator CreateReportGenerator()
    {
        var generator = new ReportGenerator();
        
        if (_securityContext.CurrentUser.IsPrivileged)
        {
            return generator;
        }
        
        return new SanitizedReportGenerator(generator);
    }
}
```

## Threat Modeling Integration

### 1. Automated Threat Analysis

```csharp
// Automated STRIDE analysis
public class StrideAnalyzer
{
    public IEnumerable<Threat> AnalyzeComponent(Component component)
    {
        var threats = new List<Threat>();
        
        // Spoofing analysis
        if (component.AuthenticationMechanism == AuthenticationType.None)
        {
            threats.Add(new Threat(
                "Spoofing",
                "Component lacks authentication",
                "Implement proper authentication"));
        }
        
        // Tampering analysis
        if (component.DataValidation == DataValidationType.None)
        {
            threats.Add(new Threat(
                "Tampering",
                "No input validation",
                "Implement comprehensive validation"));
        }
        
        // Information Disclosure
        if (component.SensitiveDataHandling == SensitiveDataHandlingType.Plaintext)
        {
            threats.Add(new Threat(
                "Information Disclosure",
                "Sensitive data stored in plaintext",
                "Implement encryption for data at rest"));
        }
        
        // Add more STRIDE analysis...
        
        return threats;
    }
}

// Usage in CI pipeline
public class SecurityGate
{
    public void ValidateComponent(Component component)
    {
        var analyzer = new StrideAnalyzer();
        var threats = analyzer.AnalyzeComponent(component);
        
        if (threats.Any(t => t.Severity == ThreatSeverity.High))
        {
            throw new SecurityValidationException(
                "High severity threats detected in component design");
        }
    }
}
```

## Best Practices Summary

1. **Integrate Threat Modeling** - Use tools like Microsoft Threat Modeling Tool during design
2. **Secure by Design Principles**:
   - Apply the principle of least privilege
   - Implement defense in depth
   - Fail securely
   - Separation of duties
3. **Business Logic Protection**:
   - Validate all transitions in workflows
   - Implement anti-abuse patterns
   - Enforce transaction verification
4. **Data Flow Security**:
   - Classify data by sensitivity
   - Implement proper data handling at each tier
   - Use secure transformation patterns
5. **Secure Defaults**:
   - Default to most secure configuration
   - Automate security baseline enforcement
6. **Security Boundaries**:
   - Clearly define trust boundaries
   - Validate cross-boundary communications
7. **Design Validation**:
   - Implement security checklists
   - Use secure design patterns
   - Automate design analysis
8. **Continuous Improvement**:
   - Maintain a security pattern catalog
   - Conduct regular design reviews
   - Learn from security incidents
