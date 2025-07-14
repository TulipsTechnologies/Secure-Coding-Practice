# Secure Coding Practices for .NET API: Addressing OWASP Top 10 (A10:2021 - Server-Side Request Forgery)

## Comprehensive SSRF Protection System

### 1. Request Validation Framework

#### SSRF Protection Middleware

```csharp
public class SsrfProtectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SsrfProtectionMiddleware> _logger;
    private readonly ISsrfValidator _ssrfValidator;

    public SsrfProtectionMiddleware(
        RequestDelegate next,
        ILogger<SsrfProtectionMiddleware> logger,
        ISsrfValidator ssrfValidator)
    {
        _next = next;
        _logger = logger;
        _ssrfValidator = ssrfValidator;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Check for potential SSRF vectors in the request
        if (context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync();
            foreach (var field in form)
            {
                if (_ssrfValidator.IsPotentialSsrfVector(field.Value))
                {
                    _logger.LogWarning("Potential SSRF attempt detected in form field {FieldName}", field.Key);
                    await BlockRequest(context, field.Key);
                    return;
                }
            }
        }

        foreach (var query in context.Request.Query)
        {
            if (_ssrfValidator.IsPotentialSsrfVector(query.Value))
            {
                _logger.LogWarning("Potential SSRF attempt detected in query parameter {ParamName}", query.Key);
                await BlockRequest(context, query.Key);
                return;
            }
        }

        if (context.Request.Headers.TryGetValue("Forwarded", out var forwarded))
        {
            if (_ssrfValidator.IsPotentialSsrfVector(forwarded))
            {
                _logger.LogWarning("Potential SSRF attempt detected in Forwarded header");
                await BlockRequest(context, "Forwarded");
                return;
            }
        }

        await _next(context);
    }

    private async Task BlockRequest(HttpContext context, string vectorName)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsync($"Invalid request detected in parameter: {vectorName}");
        
        // Log security event
        var securityEvent = new SecurityEvent
        {
            EventType = "SSRF_Attempt",
            Severity = SecurityEventSeverity.High,
            Details = new {
                IpAddress = context.Connection.RemoteIpAddress?.ToString(),
                Vector = vectorName,
                Path = context.Request.Path
            }
        };
        
        SecurityEventLogger.LogEvent(securityEvent);
    }
}
```

### 2. Secure URL Fetching Service

#### Whitelist-Based HTTP Client

```csharp
public class SecureHttpClient
{
    private readonly HttpClient _httpClient;
    private readonly IAllowedDomainService _domainService;
    private readonly ILogger<SecureHttpClient> _logger;

    public SecureHttpClient(
        HttpClient httpClient,
        IAllowedDomainService domainService,
        ILogger<SecureHttpClient> logger)
    {
        _httpClient = httpClient;
        _domainService = domainService;
        _logger = logger;
        
        // Security hardening
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "InternalService/1.0");
        _httpClient.Timeout = TimeSpan.FromSeconds(30);
    }

    public async Task<string> GetStringAsync(string url, CancellationToken cancellationToken = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException("Invalid URL format");
        }

        if (!await _domainService.IsAllowed(uri.Host))
        {
            _logger.LogWarning("SSRF attempt blocked - disallowed domain: {Domain}", uri.Host);
            throw new SecurityException($"Access to {uri.Host} is not permitted");
        }

        if (IsPrivateIpAddress(uri.Host))
        {
            _logger.LogWarning("SSRF attempt blocked - private IP access: {Host}", uri.Host);
            throw new SecurityException("Internal resource access not allowed");
        }

        try
        {
            var response = await _httpClient.GetAsync(url, cancellationToken);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to fetch URL {Url}", url);
            throw;
        }
    }

    private bool IsPrivateIpAddress(string host)
    {
        if (IPAddress.TryParse(host, out var ip))
        {
            var bytes = ip.GetAddressBytes();
            return bytes[0] switch
            {
                10 => true, // 10.0.0.0/8
                172 => bytes[1] >= 16 && bytes[1] <= 31, // 172.16.0.0/12
                192 => bytes[1] == 168, // 192.168.0.0/16
                _ => ip.Equals(IPAddress.Loopback) || 
                     ip.Equals(IPAddress.IPv6Loopback)
            };
        }
        return false;
    }
}
```

### 3. DNS Rebinding Protection

#### DNS Resolution Validator

```csharp
public class DnsResolutionValidator
{
    private readonly IDnsResolver _dnsResolver;
    private readonly ILogger<DnsResolutionValidator> _logger;

    public DnsResolutionValidator(
        IDnsResolver dnsResolver,
        ILogger<DnsResolutionValidator> logger)
    {
        _dnsResolver = dnsResolver;
        _logger = logger;
    }

    public async Task ValidateUrlAsync(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException("Invalid URL");
        }

        var host = uri.Host;
        var requestedIps = await _dnsResolver.GetHostAddressesAsync(host);

        // Check for DNS rebinding attempts
        var currentIps = await _dnsResolver.GetHostAddressesAsync(host);
        if (!requestedIps.SequenceEqual(currentIps))
        {
            _logger.LogWarning(
                "DNS rebinding detected for {Host}. Initial: {InitialIPs}, Current: {CurrentIPs}",
                host, 
                string.Join(",", requestedIps.Select(ip => ip.ToString())),
                string.Join(",", currentIps.Select(ip => ip.ToString())));
                
            throw new SecurityException("DNS rebinding attempt detected");
        }

        // Check against private IPs
        foreach (var ip in currentIps)
        {
            if (IsPrivateIp(ip))
            {
                _logger.LogWarning("Private IP access attempt: {IP} for host {Host}", ip, host);
                throw new SecurityException("Internal resource access not allowed");
            }
        }
    }

    private bool IsPrivateIp(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        
        var bytes = ip.GetAddressBytes();
        return bytes[0] switch
        {
            10 => true, // 10.0.0.0/8
            172 => bytes[1] >= 16 && bytes[1] <= 31, // 172.16.0.0/12
            192 => bytes[1] == 168, // 192.168.0.0/16
            169 => bytes[1] == 254, // 169.254.0.0/16
            _ => false
        };
    }
}
```

### 4. URL Schema Restriction

#### Secure URL Parser

```csharp
public class SecureUrlParser
{
    private static readonly string[] AllowedSchemes = { "https", "http" };
    private static readonly string[] BlockedSchemes = 
    { 
        "file", "gopher", "ftp", "smtp", 
        "telnet", "ldap", "dict" 
    };

    public Uri ParseAndValidate(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException("Invalid URL format");
        }

        if (BlockedSchemes.Contains(uri.Scheme, StringComparer.OrdinalIgnoreCase))
        {
            throw new SecurityException($"URL scheme '{uri.Scheme}' is not allowed");
        }

        if (!AllowedSchemes.Contains(uri.Scheme, StringComparer.OrdinalIgnoreCase))
        {
            throw new SecurityException($"URL scheme '{uri.Scheme}' is not permitted");
        }

        // Additional validation for http URLs
        if (uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase))
        {
            if (!uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
                !uri.Host.Equals("127.0.0.1"))
            {
                throw new SecurityException("HTTP is only allowed for localhost");
            }
        }

        return uri;
    }
}
```

### 5. Cloud Metadata API Protection

#### Cloud Metadata Shield

```csharp
public class CloudMetadataShield
{
    private readonly IReadOnlyList<string> _cloudMetadataEndpoints = new List<string>
    {
        "http://169.254.169.254", // AWS, Azure, GCP
        "http://metadata.google.internal", // GCP
        "http://169.254.169.254/metadata", // Azure
        "http://100.100.100.200", // Alibaba Cloud
        "http://192.0.0.192" // Oracle Cloud
    };

    private readonly ILogger<CloudMetadataShield> _logger;

    public CloudMetadataShield(ILogger<CloudMetadataShield> logger)
    {
        _logger = logger;
    }

    public bool IsCloudMetadataRequest(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;

        try
        {
            var uri = new Uri(url);
            foreach (var endpoint in _cloudMetadataEndpoints)
            {
                if (uri.Host.Equals(new Uri(endpoint).Host, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("Cloud metadata access attempt detected: {Url}", url);
                    return true;
                }
            }
        }
        catch (UriFormatException)
        {
            return false;
        }

        return false;
    }

    public void ValidateNoMetadataAccess(HttpRequestMessage request)
    {
        if (IsCloudMetadataRequest(request.RequestUri?.ToString()))
        {
            throw new SecurityException("Cloud metadata API access is prohibited");
        }
    }
}
```

### 6. Outbound Request Monitoring

#### Secure Outbound HTTP Handler

```csharp
public class SecureHttpClientHandler : HttpClientHandler
{
    private readonly IRequestValidator _requestValidator;
    private readonly ILogger<SecureHttpClientHandler> _logger;

    public SecureHttpClientHandler(
        IRequestValidator requestValidator,
        ILogger<SecureHttpClientHandler> logger)
    {
        _requestValidator = requestValidator;
        _logger = logger;
        
        // Security hardening
        this.AllowAutoRedirect = false;
        this.UseProxy = false;
        this.MaxConnectionsPerServer = 4;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        // Validate the request before sending
        _requestValidator.ValidateOutboundRequest(request);

        // Log the outbound request
        _logger.LogInformation("Outbound request to {Host}", request.RequestUri.Host);

        var response = await base.SendAsync(request, cancellationToken);

        // Additional validation of the response
        if ((int)response.StatusCode >= 400)
        {
            _logger.LogWarning("Outbound request failed with {StatusCode}", response.StatusCode);
        }

        return response;
    }
}

public class OutboundRequestValidator : IRequestValidator
{
    private readonly ILogger<OutboundRequestValidator> _logger;
    private readonly IAllowedDomainService _domainService;
    private readonly CloudMetadataShield _metadataShield;

    public OutboundRequestValidator(
        ILogger<OutboundRequestValidator> logger,
        IAllowedDomainService domainService,
        CloudMetadataShield metadataShield)
    {
        _logger = logger;
        _domainService = domainService;
        _metadataShield = metadataShield;
    }

    public void ValidateOutboundRequest(HttpRequestMessage request)
    {
        var uri = request.RequestUri;
        if (uri == null) return;

        // Check for cloud metadata endpoints
        if (_metadataShield.IsCloudMetadataRequest(uri.ToString()))
        {
            _logger.LogWarning("Cloud metadata access attempt blocked");
            throw new SecurityException("Cloud metadata access is prohibited");
        }

        // Validate the host is allowed
        if (!_domainService.IsAllowed(uri.Host).GetAwaiter().GetResult())
        {
            _logger.LogWarning("Outbound request to blocked domain: {Domain}", uri.Host);
            throw new SecurityException($"Requests to {uri.Host} are not permitted");
        }

        // Check for private IP addresses
        if (IsPrivateIpAddress(uri.Host))
        {
            _logger.LogWarning("Outbound request to private IP blocked: {Host}", uri.Host);
            throw new SecurityException("Internal resource access not allowed");
        }

        // Validate HTTP headers for security
        ValidateHeaders(request.Headers);
    }

    private bool IsPrivateIpAddress(string host)
    {
        if (IPAddress.TryParse(host, out var ip))
        {
            var bytes = ip.GetAddressBytes();
            return bytes[0] switch
            {
                10 => true, // 10.0.0.0/8
                172 => bytes[1] >= 16 && bytes[1] <= 31, // 172.16.0.0/12
                192 => bytes[1] == 168, // 192.168.0.0/16
                _ => ip.Equals(IPAddress.Loopback) || 
                     ip.Equals(IPAddress.IPv6Loopback)
            };
        }
        return false;
    }

    private void ValidateHeaders(HttpRequestHeaders headers)
    {
        // Remove sensitive headers that might be added by default
        headers.Remove("Authorization");
        headers.Remove("Cookie");
        headers.Remove("X-Forwarded-For");
        
        // Validate no sensitive information is being sent
        foreach (var header in headers)
        {
            if (header.Key.ToLower().Contains("token") || 
                header.Key.ToLower().Contains("secret"))
            {
                _logger.LogWarning("Sensitive header detected in outbound request: {Header}", header.Key);
                throw new SecurityException("Sensitive headers are not allowed in outbound requests");
            }
        }
    }
}
```

## Implementation Checklist

1. **Input Validation**
   - Validate all user-supplied URLs
   - Restrict allowed URL schemes
   - Block internal/private IP addresses

2. **Network Layer Controls**
   - Implement egress firewalls
   - Restrict outbound connections
   - Use network segmentation

3. **Application Layer Controls**
   - Use whitelists for allowed domains
   - Implement secure HTTP clients
   - Validate DNS resolutions

4. **Cloud Protections**
   - Block access to cloud metadata APIs
   - Restrict instance permissions
   - Use service accounts with minimal privileges

5. **Monitoring & Logging**
   - Log all outbound requests
   - Monitor for suspicious patterns
   - Alert on SSRF attempts

6. **Defense in Depth**
   - Use multiple validation layers
   - Combine static and runtime checks
   - Implement request signing where possible

7. **Regular Testing**
   - Conduct SSRF penetration tests
   - Review outbound traffic patterns
   - Audit all URL fetching functionality
