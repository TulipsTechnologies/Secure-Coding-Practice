# Secure Coding Practices for .NET API: Addressing OWASP Top 10 (A03:2021 - Injection)

## Introduction to Injection Vulnerabilities

Injection flaws, now ranked #3 in the OWASP Top 10, occur when untrusted data is sent to an interpreter as part of a command or query. In .NET APIs, this most commonly manifests as SQL injection, but can also include LDAP injection, OS command injection, and other variants.

## Common Injection Scenarios in .NET APIs

1. **SQL Injection**
2. **NoSQL Injection**
3. **LDAP Injection**
4. **Command Injection**
5. **Cross-Site Scripting (XSS)** (now included in this category)
6. **XML Injection**
7. **Template Injection**

## Step-by-Step Implementation Guide

### 1. Preventing SQL Injection

#### Parameterized Queries with Entity Framework Core

```csharp
// Safe: Parameterized queries with Entity Framework
public async Task<User> GetUserSafeAsync(string username)
{
    // This is safe as EF Core uses parameterized queries
    return await _context.Users
        .FirstOrDefaultAsync(u => u.Username == username);
}

// Safe: Explicit parameterized query
public async Task<User> GetUserSafeRawAsync(string username)
{
    return await _context.Users
        .FromSqlInterpolated($"SELECT * FROM Users WHERE Username = {username}")
        .FirstOrDefaultAsync();
}

// Dangerous: String concatenation (NEVER DO THIS)
public async Task<User> GetUserUnsafeAsync(string username)
{
    var sql = $"SELECT * FROM Users WHERE Username = '{username}'";
    return await _context.Users
        .FromSqlRaw(sql) // Vulnerable to SQL injection!
        .FirstOrDefaultAsync();
}
```

#### Stored Procedures with Parameters

```csharp
public async Task<User> GetUserByEmailSafeAsync(string email)
{
    // Using stored procedure with parameters
    return await _context.Users
        .FromSqlRaw("EXEC dbo.GetUserByEmail @Email", 
            new SqlParameter("@Email", email))
        .FirstOrDefaultAsync();
}
```

### 2. Preventing NoSQL Injection

#### Secure MongoDB Queries

```csharp
// Safe: Using filter builders
public async Task<User> GetUserFromMongoSafeAsync(string username)
{
    var filter = Builders<User>.Filter.Eq(u => u.Username, username);
    return await _mongoCollection.Find(filter).FirstOrDefaultAsync();
}

// Dangerous: Concatenating query (NEVER DO THIS)
public async Task<User> GetUserFromMongoUnsafeAsync(string username)
{
    var jsonQuery = "{ 'Username': '" + username + "' }";
    return await _mongoCollection.Find(BsonDocument.Parse(jsonQuery))
                                .FirstOrDefaultAsync();
}
```

### 3. Preventing LDAP Injection

```csharp
// Safe: Using parameterized LDAP queries
public async Task<DirectoryEntry> FindLdapUserSafeAsync(string username)
{
    using var entry = new DirectoryEntry("LDAP://domain.com");
    using var searcher = new DirectorySearcher(entry);
    
    // Escape special LDAP characters
    var safeUsername = EscapeLdapSearchFilter(username);
    searcher.Filter = $"(&(objectClass=user)(sAMAccountName={safeUsername}))";
    
    return await Task.Run(() => searcher.FindOne());
}

private static string EscapeLdapSearchFilter(string input)
{
    var specialChars = new[] { '\\', '*', '(', ')', '\0', '/' };
    var escaped = new StringBuilder();
    
    foreach (var c in input)
    {
        if (specialChars.Contains(c))
        {
            escaped.Append($"\\{(int)c:X2}");
        }
        else
        {
            escaped.Append(c);
        }
    }
    
    return escaped.ToString();
}
```

### 4. Preventing Command Injection

```csharp
// Safe: Avoiding shell execution
public async Task<string> RunProcessSafeAsync(string fileName, string arguments)
{
    var process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            RedirectStandardOutput = true,
            UseShellExecute = false, // Critical!
            CreateNoWindow = true
        }
    };
    
    process.Start();
    return await process.StandardOutput.ReadToEndAsync();
}

// Dangerous: Shell execution with user input (NEVER DO THIS)
public async Task<string> RunProcessUnsafeAsync(string command)
{
    var process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/C {command}",
            RedirectStandardOutput = true,
            UseShellExecute = false
        }
    };
    
    process.Start();
    return await process.StandardOutput.ReadToEndAsync();
}
```

### 5. Preventing Cross-Site Scripting (XSS)

#### Input Sanitization

```csharp
// HTML sanitizer service
public class HtmlSanitizerService
{
    private readonly HtmlSanitizer _sanitizer;

    public HtmlSanitizerService()
    {
        _sanitizer = new HtmlSanitizer();
        
        // Configure allowed elements and attributes
        _sanitizer.AllowedTags.Add("b");
        _sanitizer.AllowedTags.Add("i");
        _sanitizer.AllowedTags.Add("u");
        _sanitizer.AllowedAttributes.Add("class");
        
        // Remove all other tags and attributes
        _sanitizer.AllowedSchemes.Clear();
        _sanitizer.AllowedCssProperties.Clear();
    }

    public string SanitizeHtml(string input)
    {
        return _sanitizer.Sanitize(input);
    }
}
```

#### Content Security Policy (CSP) Headers

```csharp
// Middleware to add CSP headers
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        // Add CSP header
        context.Response.Headers.Add(
            "Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' https://cdn.example.com; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "media-src 'self'; " +
            "object-src 'none'; " +
            "frame-ancestors 'none'; " +
            "base-uri 'self'; " +
            "form-action 'self'; " +
            "upgrade-insecure-requests;");
            
        await _next(context);
    }
}

// Register in Program.cs
app.UseMiddleware<SecurityHeadersMiddleware>();
```

### 6. Preventing XML Injection (XXE)

```csharp
// Safe XML reader settings
public class SafeXmlParser
{
    public XDocument ParseXmlSafe(Stream xmlStream)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null, // Disable external references
            MaxCharactersFromEntities = 0
        };
        
        using var reader = XmlReader.Create(xmlStream, settings);
        return XDocument.Load(reader);
    }

    public XDocument ParseXmlUnsafe(Stream xmlStream)
    {
        // Dangerous: Allows XXE attacks
        return XDocument.Load(xmlStream);
    }
}
```

### 7. Preventing Template Injection

```csharp
// Safe template rendering
public class SafeTemplateRenderer
{
    private readonly RazorLightEngine _engine;

    public SafeTemplateRenderer()
    {
        _engine = new RazorLightEngineBuilder()
            .UseMemoryCachingProvider()
            .Build();
    }

    public async Task<string> RenderTemplateSafeAsync<T>(string template, T model)
    {
        // Ensure template doesn't contain dangerous directives
        if (template.Contains("@inherits") || template.Contains("@section"))
        {
            throw new SecurityException("Dangerous template directive detected");
        }
        
        return await _engine.CompileRenderStringAsync(
            Guid.NewGuid().ToString(),
            template,
            model);
    }
}
```

## Input Validation Framework

```csharp
// Comprehensive input validation
public class InputValidator
{
    public ValidationResult ValidateUserInput(UserInput input)
    {
        var result = new ValidationResult();
        
        // Validate username
        if (string.IsNullOrWhiteSpace(input.Username))
        {
            result.AddError("Username is required");
        }
        else if (input.Username.Length > 50)
        {
            result.AddError("Username too long");
        }
        else if (!Regex.IsMatch(input.Username, @"^[a-zA-Z0-9_\-\.]+$"))
        {
            result.AddError("Username contains invalid characters");
        }
        
        // Validate email
        if (!IsValidEmail(input.Email))
        {
            result.AddError("Invalid email format");
        }
        
        // Validate against common injection patterns
        var injectionPatterns = new[] 
        {
            "<script", 
            "--", 
            ";", 
            "/*", 
            "*/", 
            "xp_", 
            "char(",
            "waitfor delay",
            "select ",
            "insert ",
            "update ",
            "delete ",
            "drop ",
            "create ",
            "alter ",
            "exec ",
            "union "
        };
        
        foreach (var prop in input.GetType().GetProperties())
        {
            if (prop.PropertyType != typeof(string)) continue;
            
            var value = prop.GetValue(input) as string;
            if (string.IsNullOrEmpty(value)) continue;
            
            foreach (var pattern in injectionPatterns)
            {
                if (value.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    result.AddError($"Potential injection pattern detected in {prop.Name}");
                    break;
                }
            }
        }
        
        return result;
    }

    private bool IsValidEmail(string email)
    {
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }
}

public class ValidationResult
{
    public bool IsValid => !Errors.Any();
    public List<string> Errors { get; } = new List<string>();
    
    public void AddError(string error)
    {
        Errors.Add(error);
    }
}
```

## Testing for Injection Vulnerabilities

```csharp
[Fact]
public async Task GetUser_WithMaliciousInput_DoesNotExecuteInjection()
{
    // Arrange
    var client = _factory.CreateClient();
    var maliciousInput = "admin' OR '1'='1";
    
    // Act
    var response = await client.GetAsync($"/api/users?username={maliciousInput}");
    var content = await response.Content.ReadAsStringAsync();
    
    // Assert
    Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    Assert.DoesNotContain("administrator", content);
}

[Fact]
public async Task SearchUsers_WithXssAttempt_SanitizesOutput()
{
    // Arrange
    var client = _factory.CreateClient();
    var xssAttempt = "<script>alert('xss')</script>";
    
    // Act
    var response = await client.GetAsync($"/api/users/search?term={xssAttempt}");
    var content = await response.Content.ReadAsStringAsync();
    
    // Assert
    Assert.DoesNotContain("<script>", content);
    Assert.Contains("&lt;script&gt;", content);
}

[Fact]
public void EscapeLdapSearchFilter_WithSpecialChars_EscapesCorrectly()
{
    // Arrange
    var input = "admin)(objectClass=*))";
    var expected = "admin\\29\\28objectClass=\\2A\\29\\29";
    
    // Act
    var result = EscapeLdapSearchFilter(input);
    
    // Assert
    Assert.Equal(expected, result);
}
```

## Monitoring and Logging Injection Attempts

```csharp
// Injection attempt detection middleware
public class InjectionDetectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<InjectionDetectionMiddleware> _logger;

    public InjectionDetectionMiddleware(
        RequestDelegate next,
        ILogger<InjectionDetectionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        // Check query string
        foreach (var (key, value) in context.Request.Query)
        {
            if (IsPotentialInjection(value))
            {
                LogInjectionAttempt(context, key, value, "query string");
                await BlockRequest(context);
                return;
            }
        }
        
        // Check form data
        if (context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync();
            foreach (var (key, value) in form)
            {
                if (IsPotentialInjection(value))
                {
                    LogInjectionAttempt(context, key, value, "form data");
                    await BlockRequest(context);
                    return;
                }
            }
        }
        
        await _next(context);
    }

    private bool IsPotentialInjection(string value)
    {
        if (string.IsNullOrEmpty(value)) return false;
        
        var patterns = new[]
        {
            "--", ";", "/*", "*/", "xp_", 
            "char(", "waitfor delay", "select ", 
            "insert ", "update ", "delete ", 
            "drop ", "create ", "alter ", "exec ", 
            "union ", "<script", "document.cookie",
            "onload=", "onerror=", "onclick="
        };
        
        return patterns.Any(p => 
            value.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    private void LogInjectionAttempt(HttpContext context, string key, 
                                   string value, string source)
    {
        _logger.LogWarning(
            "Potential injection attempt detected from {IP}. Source: {Source}, Key: {Key}, Value: {Value}",
            context.Connection.RemoteIpAddress,
            source,
            key,
            value);
            
        // Alert security team
        SecurityAlertService.RaiseAlert(
            $"Injection attempt detected in {context.Request.Path}",
            AlertSeverity.High);
    }

    private async Task BlockRequest(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsync("Invalid request detected");
    }
}

// Register in Program.cs
app.UseMiddleware<InjectionDetectionMiddleware>();
```

## Best Practices Summary

1. **Always use parameterized queries** - Never concatenate SQL queries
2. **Use ORM safely** - Even with Entity Framework, avoid raw SQL with user input
3. **Validate all inputs** - Whitelist acceptable characters and patterns
4. **Sanitize output** - Especially for HTML, XML, and other structured output
5. **Use secure APIs** - Prefer safe methods over potentially dangerous ones
6. **Implement Content Security Policy** - Mitigate impact of successful XSS
7. **Disable dangerous features** - Like DTD processing in XML parsers
8. **Escape special characters** - When working with LDAP, OS commands, etc.
9. **Log injection attempts** - Monitor for attack patterns
10. **Regularly test** - Use both automated scanning and manual testing
