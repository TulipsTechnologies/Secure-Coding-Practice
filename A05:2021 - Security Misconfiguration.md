# Secure Coding Practices for .NET API: Addressing OWASP Top 10 (A05:2021 - Security Misconfiguration)

## Introduction to Security Misconfiguration Risks

Security Misconfiguration moves up to #5 in the OWASP Top 10 2021. This occurs when security settings are undefined, misconfigured, or left at default values. For .NET APIs, this includes insecure server configurations, improper error handling, unnecessary features enabled, and more.

## Common Security Misconfigurations in .NET APIs

1. **Insecure Default Configurations**
2. **Verbose Error Messages**
3. **Unnecessary HTTP Methods Enabled**
4. **Improper CORS Configuration**
5. **Missing Security Headers**
6. **Debug Features Enabled in Production**
7. **Insecure File/Directory Permissions**

## Step-by-Step Secure Configuration Guide

### 1. Secure Application Startup

#### Program.cs Secure Defaults

```csharp
var builder = WebApplication.CreateBuilder(args);

// 1. Remove server header
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.AddServerHeader = false;
});

// 2. Configure strict transport security
builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365);
    options.ExcludedHosts.Clear();
});

// 3. Add security headers middleware
builder.Services.AddSecurityHeaders();

// 4. Configure production-ready error handling
if (!builder.Environment.IsDevelopment())
{
    builder.Services.AddExceptionHandler<ProductionExceptionHandler>();
    builder.WebHost.UseSetting("detailedErrors", "false");
}

var app = builder.Build();

// 5. Enforce security middleware
app.UseSecurityHeaders();
app.UseHsts();
app.UseHttpsRedirection();
```

### 2. Security Headers Configuration

#### Comprehensive Security Headers Middleware

```csharp
public static class SecurityHeadersMiddlewareExtensions
{
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
    {
        var policyCollection = new HeaderPolicyCollection()
            .AddFrameOptionsDeny()
            .AddXssProtectionBlock()
            .AddContentTypeOptionsNoSniff()
            .AddReferrerPolicyStrictOriginWhenCrossOrigin()
            .AddCrossOriginOpenerPolicy(builder => builder.SameOrigin())
            .AddCrossOriginResourcePolicy(builder => builder.SameOrigin())
            .AddCrossOriginEmbedderPolicy(builder => builder.RequireCorp())
            .AddContentSecurityPolicy(builder =>
            {
                builder.AddObjectSrc().None();
                builder.AddFormAction().Self();
                builder.AddFrameAncestors().None();
                builder.AddDefaultSrc().Self();
                builder.AddScriptSrc().Self().WithNonce();
                builder.AddStyleSrc().Self().WithNonce();
                builder.AddImgSrc().Self().Data();
            })
            .RemoveServerHeader()
            .AddPermissionsPolicy(builder =>
            {
                builder.AddAccelerometer().None();
                builder.AddCamera().None();
                builder.AddGeolocation().None();
                builder.AddMicrophone().None();
                builder.AddPayment().None();
            });

        return app.UseSecurityHeaders(policyCollection);
    }
}
```

### 3. Production Exception Handling

#### Secure Exception Handler

```csharp
public class ProductionExceptionHandler : IExceptionHandler
{
    private readonly ILogger<ProductionExceptionHandler> _logger;

    public ProductionExceptionHandler(ILogger<ProductionExceptionHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        _logger.LogError(
            exception, "An unhandled exception has occurred");
        
        var problemDetails = new ProblemDetails
        {
            Title = "An error occurred",
            Status = StatusCodes.Status500InternalServerError,
            Instance = httpContext.Request.Path
        };

        // Sanitize error details in production
        if (httpContext.RequestServices.GetRequiredService<IWebHostEnvironment>().IsDevelopment())
        {
            problemDetails.Detail = exception.ToString();
        }
        else
        {
            problemDetails.Detail = "An unexpected error occurred. Please try again later.";
        }

        httpContext.Response.StatusCode = problemDetails.Status.Value;
        await httpContext.Response.WriteAsJsonAsync(problemDetails, cancellationToken);

        return true;
    }
}
```

### 4. Secure CORS Configuration

#### Granular CORS Policy

```csharp
// Program.cs
var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("ProductionCors", policy =>
    {
        policy.WithOrigins(allowedOrigins)
              .WithMethods("GET", "POST", "PUT", "DELETE")
              .AllowAnyHeader()
              .SetPreflightMaxAge(TimeSpan.FromSeconds(86400))
              .WithExposedHeaders("X-Correlation-ID");
    });

    // Strict policy for sensitive endpoints
    options.AddPolicy("StrictCors", policy =>
    {
        policy.WithOrigins(allowedOrigins[0]) // Only primary origin
              .WithMethods("POST")
              .WithHeaders("Content-Type", "Authorization")
              .SetPreflightMaxAge(TimeSpan.FromSeconds(3600));
    });
});

// Apply in controllers
[ApiController]
[Route("api/[controller]")]
[EnableCors("ProductionCors")]
public class ProductsController : ControllerBase
{
    [EnableCors("StrictCors")]
    [HttpPost("purchase")]
    public IActionResult Purchase([FromBody] PurchaseRequest request)
    {
        // Sensitive operation
    }
}
```

### 5. HTTP Method Restrictions

#### Endpoint-Level Method Filtering

```csharp
// Middleware to restrict HTTP methods
public class HttpMethodRestrictionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<HttpMethodRestrictionMiddleware> _logger;
    private readonly string[] _allowedMethods = { "GET", "POST", "PUT", "DELETE" };

    public HttpMethodRestrictionMiddleware(
        RequestDelegate next,
        ILogger<HttpMethodRestrictionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        if (!_allowedMethods.Contains(context.Request.Method))
        {
            _logger.LogWarning(
                "Blocked disallowed HTTP method {Method} for {Path}",
                context.Request.Method,
                context.Request.Path);
            
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            await context.Response.WriteAsync("Method not allowed");
            return;
        }

        await _next(context);
    }
}

// Register in Program.cs
app.UseMiddleware<HttpMethodRestrictionMiddleware>();
```

### 6. Secure File/Directory Permissions

#### Secure File Access Service

```csharp
public class SecureFileService
{
    private readonly string _rootPath;
    private readonly ILogger<SecureFileService> _logger;

    public SecureFileService(
        IWebHostEnvironment env,
        ILogger<SecureFileService> logger)
    {
        _rootPath = Path.Combine(env.ContentRootPath, "SecureFiles");
        _logger = logger;
        
        // Ensure directory exists with secure permissions
        if (!Directory.Exists(_rootPath))
        {
            Directory.CreateDirectory(_rootPath);
            SetSecurePermissions(_rootPath);
        }
    }

    public async Task<string> ReadSecureFileAsync(string fileName)
    {
        var filePath = GetSecurePath(fileName);
        
        // Verify file is within secure directory
        if (!filePath.StartsWith(_rootPath))
        {
            _logger.LogError("Path traversal attempt detected: {Path}", filePath);
            throw new SecurityException("Invalid file path");
        }

        return await File.ReadAllTextAsync(filePath);
    }

    private string GetSecurePath(string fileName)
    {
        // Sanitize file name
        var safeFileName = Path.GetFileName(fileName);
        if (string.IsNullOrEmpty(safeFileName))
        {
            throw new ArgumentException("Invalid file name");
        }
        
        return Path.Combine(_rootPath, safeFileName);
    }

    private void SetSecurePermissions(string path)
    {
        try
        {
            // Windows ACLs
            var directoryInfo = new DirectoryInfo(path);
            var directorySecurity = directoryInfo.GetAccessControl();
            
            directorySecurity.AddAccessRule(
                new FileSystemAccessRule(
                    "Authenticated Users",
                    FileSystemRights.ReadAndExecute,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            
            directoryInfo.SetAccessControl(directorySecurity);
        }
        catch (PlatformNotSupportedException)
        {
            // Linux/Unix systems
            File.SetUnixFileMode(path, 
                UnixFileMode.UserRead | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
        }
    }
}
```

### 7. Secure Configuration Management

#### Configuration Validation

```csharp
public class SecurityConfigurationValidator
{
    private readonly IConfiguration _config;
    private readonly ILogger<SecurityConfigurationValidator> _logger;

    public SecurityConfigurationValidator(
        IConfiguration config,
        ILogger<SecurityConfigurationValidator> logger)
    {
        _config = config;
        _logger = logger;
    }

    public void Validate()
    {
        CheckForDefaultCredentials();
        CheckForDebugSettings();
        ValidateEncryptionKeys();
        CheckCorsOrigins();
    }

    private void CheckForDefaultCredentials()
    {
        var adminUser = _config["AdminCredentials:Username"];
        var adminPass = _config["AdminCredentials:Password"];
        
        if (adminUser == "admin" || adminPass == "admin123")
        {
            _logger.LogCritical("Default admin credentials detected!");
            throw new SecurityConfigurationException("Default credentials are not allowed");
        }
    }

    private void CheckForDebugSettings()
    {
        if (_config.GetValue<bool>("EnableDebugFeatures"))
        {
            _logger.LogWarning("Debug features are enabled in configuration");
        }
    }

    private void ValidateEncryptionKeys()
    {
        var keys = new[]
        {
            _config["DataProtection:Key"],
            _config["Jwt:SecretKey"],
            _config["Encryption:MasterKey"]
        };

        if (keys.Any(k => string.IsNullOrEmpty(k) || k.Length < 32))
        {
            throw new SecurityConfigurationException("Encryption keys are not properly configured");
        }
    }

    private void CheckCorsOrigins()
    {
        var origins = _config.GetSection("Cors:AllowedOrigins").Get<string[]>();
        if (origins?.Contains("*") == true)
        {
            _logger.LogCritical("Dangerous CORS configuration - wildcard origin allowed");
            throw new SecurityConfigurationException("Wildcard CORS origin is not allowed");
        }
    }
}

// Register in Program.cs
builder.Services.AddHostedService<ConfigurationValidationService>();
```

## Automated Security Scanning

### 1. Configuration Health Check

```csharp
public class SecurityConfigurationHealthCheck : IHealthCheck
{
    private readonly IConfiguration _config;
    
    public SecurityConfigurationHealthCheck(IConfiguration config)
    {
        _config = config;
    }
    
    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var issues = new List<string>();
        
        // Check for debug mode
        if (_config.GetValue<bool>("EnableDebugFeatures"))
        {
            issues.Add("Debug features are enabled in production");
        }
        
        // Check for default passwords
        if (_config["AdminPassword"] == "admin123")
        {
            issues.Add("Default admin password detected");
        }
        
        // Check HTTPS enforcement
        if (!_config.GetValue<bool>("EnforceHttps"))
        {
            issues.Add("HTTPS enforcement is disabled");
        }
        
        return issues.Any() 
            ? Task.FromResult(HealthCheckResult.Unhealthy(
                "Security configuration issues: " + string.Join(", ", issues)))
            : Task.FromResult(HealthCheckResult.Healthy());
    }
}

// Register in Program.cs
builder.Services.AddHealthChecks()
    .AddCheck<SecurityConfigurationHealthCheck>("security_config");
```

### 2. Security Middleware Scanner

```csharp
public class SecurityMiddlewareScanner
{
    private readonly IApplicationBuilder _app;
    private readonly ILogger<SecurityMiddlewareScanner> _logger;
    
    public SecurityMiddlewareScanner(
        IApplicationBuilder app,
        ILogger<SecurityMiddlewareScanner> logger)
    {
        _app = app;
        _logger = logger;
    }
    
    public void Scan()
    {
        var middlewareTypes = GetMiddlewareTypes();
        
        CheckForRequiredMiddleware(middlewareTypes);
        CheckForDangerousMiddleware(middlewareTypes);
    }
    
    private IEnumerable<Type> GetMiddlewareTypes()
    {
        // Reflection to inspect middleware pipeline
        var field = _app.GetType().GetField("_components", 
            BindingFlags.NonPublic | BindingFlags.Instance);
        
        if (field?.GetValue(_app) is not List<Func<RequestDelegate, RequestDelegate>> components)
            return Enumerable.Empty<Type>();
        
        return components.Select(c => 
            c.Target?.GetType().GetField("middleware")?.GetValue(c.Target)?.GetType())
            .Where(t => t != null)!;
    }
    
    private void CheckForRequiredMiddleware(IEnumerable<Type> middlewareTypes)
    {
        var requiredMiddleware = new[]
        {
            typeof(HstsMiddleware),
            typeof(HttpsRedirectionMiddleware),
            typeof(AuthorizationMiddleware)
        };
        
        foreach (var required in requiredMiddleware)
        {
            if (!middlewareTypes.Contains(required))
            {
                _logger.LogWarning("Missing required middleware: {Middleware}", required.Name);
            }
        }
    }
    
    private void CheckForDangerousMiddleware(IEnumerable<Type> middlewareTypes)
    {
        var dangerousMiddleware = new[]
        {
            typeof(DeveloperExceptionPageMiddleware)
        };
        
        foreach (var dangerous in dangerousMiddleware)
        {
            if (middlewareTypes.Contains(dangerous))
            {
                _logger.LogError("Dangerous middleware detected in production: {Middleware}", 
                    dangerous.Name);
            }
        }
    }
}
```

## Best Practices Summary

1. **Remove Default Configurations** - Never ship with default credentials or settings
2. **Implement Security Headers** - Comprehensive protection via headers
3. **Proper Error Handling** - Never expose stack traces in production
4. **Granular CORS Policies** - Restrict origins, methods, and headers
5. **HTTP Method Restrictions** - Allow only necessary methods
6. **Secure File Permissions** - Principle of least privilege for filesystem access
7. **Configuration Validation** - Automated checks for insecure settings
8. **Health Monitoring** - Continuous security configuration checks
9. **Middleware Scanning** - Verify security middleware is properly configured
10. **Automated Scanning** - Regular checks for misconfigurations
