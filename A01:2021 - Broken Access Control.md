# Secure Coding Practices for .NET API: Addressing OWASP Top 10 (A01:2021 - Broken Access Control)

## Introduction to Broken Access Control

Broken Access Control is now the #1 security risk in web applications according to OWASP. It occurs when restrictions on what authenticated users are allowed to do are not properly enforced, allowing attackers to access unauthorized functionality or data.

## Common Broken Access Control Scenarios in .NET APIs

1. **Insecure Direct Object References (IDOR)**
2. **Missing or Improper Authorization Checks**
3. **Elevation of Privilege**
4. **CORS Misconfiguration**
5. **API Endpoint Access Without Proper Scopes**

## Step-by-Step Implementation Guide

### 1. Setting Up Authorization in .NET API

First, ensure you have proper authentication configured:

```csharp
// Program.cs
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

builder.Services.AddAuthorization();
```

### 2. Implementing Role-Based Access Control (RBAC)

```csharp
// In your controller
[Authorize(Roles = "Admin")]
[HttpGet("api/sensitive-data")]
public IActionResult GetSensitiveData()
{
    // Only users with Admin role can access this
    return Ok(new { data = "Very sensitive information" });
}
```

### 3. Resource-Based Authorization

For more granular control, implement resource-based authorization:

```csharp
// Create an authorization handler
public class ResourceOwnerAuthorizationHandler : AuthorizationHandler<ResourceOwnerRequirement, IUserOwnedResource>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
                                                   ResourceOwnerRequirement requirement,
                                                   IUserOwnedResource resource)
    {
        if (context.User.IsInRole("Admin") || 
            context.User.FindFirstValue(ClaimTypes.NameIdentifier) == resource.UserId)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

// Register the handler in Program.cs
builder.Services.AddSingleton<IAuthorizationHandler, ResourceOwnerAuthorizationHandler>();

// Use it in your controller
[Authorize]
[HttpGet("api/user-data/{id}")]
public async Task<IActionResult> GetUserData(int id)
{
    var data = await _repository.GetByIdAsync(id);
    
    var authorizationResult = await _authorizationService.AuthorizeAsync(
        User, data, "ResourceOwner");
    
    if (!authorizationResult.Succeeded)
    {
        return Forbid();
    }
    
    return Ok(data);
}
```

### 4. Preventing Insecure Direct Object References (IDOR)

```csharp
// Bad practice - exposes internal IDs
[HttpGet("api/orders/{orderId}")]
public IActionResult GetOrder(int orderId)
{
    var order = _dbContext.Orders.Find(orderId);
    return Ok(order);
}

// Secure alternative
[HttpGet("api/orders/{orderGuid}")]
public IActionResult GetOrder(Guid orderGuid)
{
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    var order = _dbContext.Orders
        .FirstOrDefault(o => o.PublicGuid == orderGuid && o.UserId == userId);
    
    if (order == null) return NotFound();
    
    return Ok(order);
}
```

### 5. Proper CORS Configuration

```csharp
// Program.cs - Avoid using AllowAll
var allowedOrigins = builder.Configuration.GetSection("AllowedOrigins").Get<string[]>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("SpecificOrigins", policy =>
    {
        policy.WithOrigins(allowedOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

// Then in your endpoints
app.UseCors("SpecificOrigins");
```

### 6. Rate Limiting to Prevent Brute Force Attacks

```csharp
// Program.cs
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("api", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.User.Identity?.Name ?? context.Request.Headers["X-Client-Id"] ?? context.Connection.RemoteIpAddress?.ToString(),
            factory: partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1)
            }));
});

// Apply to your controllers
[EnableRateLimiting("api")]
public class MyController : ControllerBase
```

### 7. Secure Defaults with Policy-Based Authorization

```csharp
// Program.cs
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
        
    options.AddPolicy("RequireAdminRole", policy => 
        policy.RequireRole("Admin"));
        
    options.AddPolicy("EditContent", policy =>
        policy.RequireClaim("permission", "content.edit"));
});

// Apply default policy to all controllers
[Authorize]
public class MyController : ControllerBase
```

### 8. Protecting Sensitive Operations with Two-Factor Requirements

```csharp
// Custom authorization requirement
public class TwoFactorRequired : IAuthorizationRequirement { }

public class TwoFactorHandler : AuthorizationHandler<TwoFactorRequired>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
                                               TwoFactorRequired requirement)
    {
        var twoFactorClaim = context.User.FindFirst("amr")?.Value;
        if (twoFactorClaim != null && twoFactorClaim.Contains("mfa"))
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}

// Register the handler
builder.Services.AddSingleton<IAuthorizationHandler, TwoFactorHandler>();

// Use in controller
[Authorize]
[HttpPost("api/transfer-funds")]
[RequiredScope("financial.transfer")]
public async Task<IActionResult> TransferFunds([FromBody] TransferRequest request)
{
    var authorizationResult = await _authorizationService.AuthorizeAsync(
        User, null, "TwoFactorRequired");
        
    if (!authorizationResult.Succeeded)
    {
        return Challenge(new AuthenticationProperties 
        { 
            RedirectUri = "/account/enable2fa",
            Items = { ["ReturnUrl"] = Request.Path }
        }, "Identity.TwoFactorUserId");
    }
    
    // Process transfer
}
```

## Testing Your Access Controls

Implement unit and integration tests to verify your authorization:

```csharp
[Fact]
public async Task AdminEndpoint_ShouldFail_ForNonAdminUsers()
{
    // Arrange
    var client = _factory.WithWebHostBuilder(builder =>
    {
        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication("Test")
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(
                    "Test", options => { });
        });
    }).CreateClient();
    
    client.DefaultRequestHeaders.Authorization = 
        new AuthenticationHeaderValue("Test");
    
    // Act
    var response = await client.GetAsync("/api/sensitive-data");
    
    // Assert
    Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
}

[Fact]
public async Task UserDataEndpoint_ShouldReturnOnlyOwnedData()
{
    // Arrange
    var client = _factory.WithWebHostBuilder(builder =>
    {
        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication("Test")
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(
                    "Test", options => { });
        });
    }).CreateClient();
    
    client.DefaultRequestHeaders.Authorization = 
        new AuthenticationHeaderValue("Test");
    
    // Act - try to access another user's data
    var response = await client.GetAsync("/api/user-data/999");
    
    // Assert
    Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
}
```

## Monitoring and Logging Access Control Failures

```csharp
// Middleware to log authorization failures
public class AccessControlMonitoringMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AccessControlMonitoringMiddleware> _logger;

    public AccessControlMonitoringMiddleware(
        RequestDelegate next,
        ILogger<AccessControlMonitoringMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        await _next(context);
        
        if (context.Response.StatusCode == 403)
        {
            _logger.LogWarning("Access denied to {User} for {Path}",
                context.User.Identity?.Name ?? "anonymous",
                context.Request.Path);
                
            // Optionally notify security team
            await _securityNotificationService.NotifyAccessDeniedAsync(
                context.User.Identity?.Name,
                context.Request.Path,
                context.Connection.RemoteIpAddress?.ToString());
        }
    }
}

// Register in Program.cs
app.UseMiddleware<AccessControlMonitoringMiddleware>();
```

## Best Practices Summary

1. **Always enforce authorization** on all endpoints (use `[Authorize]` by default)
2. **Use GUIDs** instead of sequential IDs for public references
3. **Implement proper role and claim checks** for all sensitive operations
4. **Validate ownership** of resources before allowing access
5. **Log all authorization failures** for monitoring and auditing
6. **Limit CORS** to only necessary origins
7. **Implement rate limiting** to prevent brute force attacks
8. **Require MFA** for sensitive operations
9. **Regularly test** your authorization logic
10. **Keep audit logs** of who accessed what and when
