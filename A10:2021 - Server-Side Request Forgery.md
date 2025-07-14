# Secure Coding Practices for PHP (WordPress and Laravel): Addressing OWASP Top 10 (A10:2021 - Server-Side Request Forgery)

## Comprehensive SSRF Protection System

### 1. Request Validation Framework

#### SSRF Protection Middleware

```php
class SsrfProtectionMiddleware
{
    private $next;
    private $logger;
    private $validator;

    public function __construct(
        callable $next,
        LoggerInterface $logger,
        SsrfValidator $validator
    ) {
        $this->next = $next;
        $this->logger = $logger;
        $this->validator = $validator;
    }

    public function __invoke(Request $request, Response $response)
    {
        // Check POST data
        foreach ($request->getParsedBody() as $key => $value) {
            if ($this->validator->isPotentialSsrfVector($value)) {
                $this->logger->warning('Potential SSRF in POST field', ['field' => $key]);
                return $this->blockRequest($response, $key);
            }
        }

        // Check query parameters
        foreach ($request->getQueryParams() as $key => $value) {
            if ($this->validator->isPotentialSsrfVector($value)) {
                $this->logger->warning('Potential SSRF in query param', ['param' => $key]);
                return $this->blockRequest($response, $key);
            }
        }

        // Check headers
        if ($request->hasHeader('Forwarded')) {
            $forwarded = $request->getHeaderLine('Forwarded');
            if ($this->validator->isPotentialSsrfVector($forwarded)) {
                $this->logger->warning('Potential SSRF in Forwarded header');
                return $this->blockRequest($response, 'Forwarded');
            }
        }

        // Call next middleware
        return ($this->next)($request, $response);
    }

    private function blockRequest(Response $response, string $vector): Response
    {
        $securityEvent = new SecurityEvent(
            'SSRF_Attempt',
            SecurityEventSeverity::HIGH,
            [
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'vector' => $vector,
                'path' => $_SERVER['REQUEST_URI'] ?? 'unknown'
            ]
        );
        
        SecurityEventLogger::logEvent($securityEvent);
        
        return $response
            ->withStatus(400)
            ->withHeader('Content-Type', 'text/plain')
            ->write("Invalid request detected in parameter: $vector");
    }
}
```

### 2. Secure URL Fetching Service

#### Whitelist-Based HTTP Client

```php
class SecureHttpClient
{
    private $client;
    private $domainService;
    private $logger;

    public function __construct(
        ClientInterface $client,
        AllowedDomainService $domainService,
        LoggerInterface $logger
    ) {
        $this->client = $client;
        $this->domainService = $domainService;
        $this->logger = $logger;
    }

    public function get(string $url): string
    {
        $uri = $this->validateUrl($url);
        
        if (!$this->domainService->isAllowed($uri->getHost())) {
            $this->logger->warning('SSRF attempt blocked - disallowed domain', ['domain' => $uri->getHost()]);
            throw new SecurityException("Access to {$uri->getHost()} is not permitted");
        }

        if ($this->isPrivateIpAddress($uri->getHost())) {
            $this->logger->warning('SSRF attempt blocked - private IP access', ['host' => $uri->getHost()]);
            throw new SecurityException("Internal resource access not allowed");
        }

        try {
            $response = $this->client->request('GET', $url, [
                'timeout' => 30,
                'headers' => ['User-Agent' => 'InternalService/1.0']
            ]);
            
            return (string)$response->getBody();
        } catch (Exception $e) {
            $this->logger->error('Failed to fetch URL', ['url' => $url, 'error' => $e->getMessage()]);
            throw $e;
        }
    }

    private function validateUrl(string $url): UriInterface
    {
        try {
            $uri = new Uri($url);
            
            if (!in_array($uri->getScheme(), ['http', 'https'])) {
                throw new SecurityException("URL scheme '{$uri->getScheme()}' is not allowed");
            }
            
            if ($uri->getScheme() === 'http' && 
                !in_array($uri->getHost(), ['localhost', '127.0.0.1'])) {
                throw new SecurityException("HTTP is only allowed for localhost");
            }
            
            return $uri;
        } catch (InvalidArgumentException $e) {
            throw new SecurityException("Invalid URL format");
        }
    }

    private function isPrivateIpAddress(string $host): bool
    {
        if (!filter_var($host, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        $ip = ip2long($host);
        if (!$ip) {
            return false;
        }
        
        // Private IP ranges
        $privateRanges = [
            ['10.0.0.0', '10.255.255.255'],       // 10.0.0.0/8
            ['172.16.0.0', '172.31.255.255'],     // 172.16.0.0/12
            ['192.168.0.0', '192.168.255.255'],   // 192.168.0.0/16
            ['169.254.0.0', '169.254.255.255'],   // Link-local
            ['127.0.0.0', '127.255.255.255']      // Loopback
        ];
        
        foreach ($privateRanges as $range) {
            $start = ip2long($range[0]);
            $end = ip2long($range[1]);
            
            if ($ip >= $start && $ip <= $end) {
                return true;
            }
        }
        
        return false;
    }
}
```

### 3. DNS Rebinding Protection

#### DNS Resolution Validator

```php
class DnsResolutionValidator
{
    private $logger;

    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    public function validateUrl(string $url): void
    {
        $uri = new Uri($url);
        $host = $uri->getHost();
        
        $initialIps = $this->resolveHost($host);
        $currentIps = $this->resolveHost($host);
        
        if ($initialIps != $currentIps) {
            $this->logger->warning('DNS rebinding detected', [
                'host' => $host,
                'initial' => implode(',', $initialIps),
                'current' => implode(',', $currentIps)
            ]);
            throw new SecurityException('DNS rebinding attempt detected');
        }
        
        foreach ($currentIps as $ip) {
            if ($this->isPrivateIp($ip)) {
                $this->logger->warning('Private IP access attempt', ['ip' => $ip, 'host' => $host]);
                throw new SecurityException('Internal resource access not allowed');
            }
        }
    }

    private function resolveHost(string $host): array
    {
        $ips = gethostbynamel($host);
        return $ips ?: [];
    }

    private function isPrivateIp(string $ip): bool
    {
        return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }
}
```

### 4. URL Schema Restriction

#### Secure URL Parser

```php
class SecureUrlParser
{
    private static $allowedSchemes = ['http', 'https'];
    private static $blockedSchemes = ['file', 'gopher', 'ftp', 'smtp', 'telnet', 'ldap', 'dict'];

    public function parseAndValidate(string $url): UriInterface
    {
        try {
            $uri = new Uri($url);
            
            if (in_array(strtolower($uri->getScheme()), self::$blockedSchemes)) {
                throw new SecurityException("URL scheme '{$uri->getScheme()}' is not allowed");
            }
            
            if (!in_array(strtolower($uri->getScheme()), self::$allowedSchemes)) {
                throw new SecurityException("URL scheme '{$uri->getScheme()}' is not permitted");
            }
            
            // Additional validation for http URLs
            if (strtolower($uri->getScheme()) === 'http' && 
                !in_array(strtolower($uri->getHost()), ['localhost', '127.0.0.1'])) {
                throw new SecurityException("HTTP is only allowed for localhost");
            }
            
            return $uri;
        } catch (InvalidArgumentException $e) {
            throw new SecurityException("Invalid URL format");
        }
    }
}
```

### 5. Cloud Metadata API Protection

#### Cloud Metadata Shield

```php
class CloudMetadataShield
{
    private $metadataEndpoints = [
        '169.254.169.254',
        'metadata.google.internal',
        '100.100.100.200',
        '192.0.0.192'
    ];

    private $logger;

    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    public function isCloudMetadataRequest(string $url): bool
    {
        try {
            $host = parse_url($url, PHP_URL_HOST);
            if (!$host) {
                return false;
            }
            
            foreach ($this->metadataEndpoints as $endpoint) {
                if ($host === $endpoint || strpos($host, $endpoint) !== false) {
                    $this->logger->warning('Cloud metadata access attempt', ['url' => $url]);
                    return true;
                }
            }
        } catch (Exception $e) {
            return false;
        }
        
        return false;
    }
}
```

### 6. Outbound Request Monitoring

#### Secure HTTP Handler

```php
class SecureHttpHandler
{
    private $validator;
    private $logger;

    public function __construct(
        RequestValidator $validator,
        LoggerInterface $logger
    ) {
        $this->validator = $validator;
        $this->logger = $logger;
    }

    public function send(RequestInterface $request): ResponseInterface
    {
        $this->validator->validateOutboundRequest($request);
        $this->logger->info('Outbound request', ['host' => $request->getUri()->getHost()]);
        
        $client = new Client([
            'timeout' => 30,
            'allow_redirects' => false
        ]);
        
        try {
            $response = $client->send($request);
            
            if ($response->getStatusCode() >= 400) {
                $this->logger->warning('Outbound request failed', [
                    'status' => $response->getStatusCode(),
                    'url' => (string)$request->getUri()
                ]);
            }
            
            return $response;
        } catch (Exception $e) {
            $this->logger->error('Outbound request error', [
                'url' => (string)$request->getUri(),
                'error' => $e->getMessage()
            ]);
            throw $e;
        }
    }
}

class OutboundRequestValidator
{
    private $domainService;
    private $metadataShield;
    private $logger;

    public function __construct(
        AllowedDomainService $domainService,
        CloudMetadataShield $metadataShield,
        LoggerInterface $logger
    ) {
        $this->domainService = $domainService;
        $this->metadataShield = $metadataShield;
        $this->logger = $logger;
    }

    public function validateOutboundRequest(RequestInterface $request): void
    {
        $uri = $request->getUri();
        
        if ($this->metadataShield->isCloudMetadataRequest((string)$uri)) {
            $this->logger->warning('Cloud metadata access blocked');
            throw new SecurityException('Cloud metadata access is prohibited');
        }
        
        if (!$this->domainService->isAllowed($uri->getHost())) {
            $this->logger->warning('Outbound request to blocked domain', ['domain' => $uri->getHost()]);
            throw new SecurityException("Requests to {$uri->getHost()} are not permitted");
        }
        
        if ($this->isPrivateIpAddress($uri->getHost())) {
            $this->logger->warning('Outbound request to private IP blocked', ['host' => $uri->getHost()]);
            throw new SecurityException('Internal resource access not allowed');
        }
        
        $this->validateHeaders($request->getHeaders());
    }

    private function isPrivateIpAddress(string $host): bool
    {
        if (!filter_var($host, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        return !filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    private function validateHeaders(array $headers): void
    {
        foreach ($headers as $name => $values) {
            $lowerName = strtolower($name);
            
            if (strpos($lowerName, 'token') !== false || 
                strpos($lowerName, 'secret') !== false) {
                $this->logger->warning('Sensitive header detected', ['header' => $name]);
                throw new SecurityException('Sensitive headers are not allowed in outbound requests');
            }
        }
    }
}
```

## Implementation Checklist

1. **Input Validation**
   - Validate all user-supplied URLs and hosts
   - Restrict allowed URL schemes (block file://, ftp://, etc.)
   - Block internal/private IP addresses and domains

2. **Network Controls**
   - Implement egress firewalls to restrict outbound connections
   - Use network segmentation to isolate sensitive services
   - Configure web server to restrict local file access

3. **Application Controls**
   - Use whitelists for allowed domains and endpoints
   - Implement secure HTTP clients with timeouts and redirect limits
   - Validate DNS resolutions to prevent rebinding attacks

4. **Cloud Protections**
   - Block access to cloud metadata APIs (169.254.169.254)
   - Restrict instance permissions using IAM roles
   - Use service accounts with minimal privileges

5. **Monitoring & Logging**
   - Log all outbound HTTP requests with source and destination
   - Monitor for suspicious request patterns (internal IPs, metadata endpoints)
   - Set up alerts for potential SSRF attempts

6. **Defense in Depth**
   - Implement multiple validation layers (input, DNS, network)
   - Combine static and runtime checks
   - Use request signing for sensitive internal services

7. **Regular Testing**
   - Conduct SSRF penetration tests using various payloads
   - Review outbound traffic patterns and logs
   - Audit all URL fetching functionality in the application

## PHP-Specific Recommendations

1. **Configuration Hardening**
   - Disable dangerous PHP functions (fsockopen, curl_exec, file_get_contents)
   - Set open_basedir restrictions
   - Configure allow_url_fopen=Off in production

2. **WordPress Specific**
   - Validate all URLs in plugin settings and custom fields
   - Use wp_http_validate_url() for URL validation
   - Implement security plugins that detect SSRF attempts

3. **Laravel Specific**
   - Use Guzzle with custom handlers for outbound requests
   - Implement middleware to validate request parameters
   - Use Laravel's validation system for URL inputs

4. **General Best Practices**
   - Use PHP's filter_var() for URL validation
   - Prefer curl over file_get_contents for HTTP requests
   - Implement proper error handling to avoid exposing internal information

## Example Deployment Configuration

```bash
# PHP.ini security settings
sed -i 's/allow_url_fopen = On/allow_url_fopen = Off/' /etc/php/8.1/fpm/php.ini
sed -i 's/disable_functions =.*/disable_functions = fsockopen,pfsockopen,stream_socket_client,curl_exec/' /etc/php/8.1/fpm/php.ini

# Configure open_basedir
echo 'open_basedir = /var/www:/tmp' >> /etc/php/8.1/fpm/php.ini

# Network egress restrictions
iptables -A OUTPUT -p tcp --dport 80 -j ALLOWED_OUT
iptables -A OUTPUT -p tcp --dport 443 -j ALLOWED_OUT
iptables -A OUTPUT -p tcp -d 169.254.169.254 --dport 80 -j DROP
iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport 80 -j DROP

# Restart services
systemctl restart php8.1-fpm
systemctl restart nginx
```
