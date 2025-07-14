# Secure Coding Practices for PHP (WordPress and Laravel): Addressing OWASP Top 10 (A03:2021 - Injection)

## Introduction to Injection Vulnerabilities

Injection flaws rank #3 in the OWASP Top 10 and occur when untrusted data is sent to an interpreter as part of a command or query. In PHP applications, this most commonly manifests as SQL injection, but can also include NoSQL injection, command injection, and Cross-Site Scripting (XSS).

## Common Injection Scenarios in PHP Applications

1. **SQL Injection**
2. **NoSQL Injection**
3. **Command Injection**
4. **Cross-Site Scripting (XSS)**
5. **LDAP Injection**
6. **XML Injection (XXE)**
7. **Template Injection**

## Step-by-Step Implementation Guide

### 1. Preventing SQL Injection

#### Parameterized Queries with PDO (PHP Data Objects)

```php
// Safe: Parameterized queries with PDO
function getUserSafe(PDO $pdo, string $username): ?array {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
    $stmt->execute(['username' => $username]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// Laravel: Safe Eloquent ORM usage
function getUserSafeLaravel(string $email): ?User {
    return User::where('email', $email)->first();
}

// WordPress: Safe queries with $wpdb
function getUserSafeWordPress(string $username) {
    global $wpdb;
    return $wpdb->get_row(
        $wpdb->prepare("SELECT * FROM $wpdb->users WHERE user_login = %s", $username)
    );
}

// Dangerous: String concatenation (NEVER DO THIS)
function getUserUnsafe(PDO $pdo, string $username): ?array {
    $sql = "SELECT * FROM users WHERE username = '$username'";
    return $pdo->query($sql)->fetch(PDO::FETCH_ASSOC);
}
```

### 2. Preventing NoSQL Injection

#### Secure MongoDB Queries

```php
// Safe: Using parameterized MongoDB queries
function getUserFromMongoSafe(MongoDB\Collection $collection, string $username): ?array {
    return $collection->findOne(['username' => $username]);
}

// Dangerous: JSON string concatenation (NEVER DO THIS)
function getUserFromMongoUnsafe(MongoDB\Collection $collection, string $username): ?array {
    $json = '{"username": "' . $username . '"}';
    return $collection->findOne(MongoDB\BSON\Document::fromPHP(json_decode($json)));
}
```

### 3. Preventing Command Injection

```php
// Safe: Avoiding shell execution with user input
function getFileContentsSafe(string $filename): string {
    if (!preg_match('/^[a-zA-Z0-9_\-\.]+$/', $filename)) {
        throw new InvalidArgumentException('Invalid filename');
    }
    $path = '/safe/directory/' . $filename;
    return file_get_contents($path);
}

// Safe alternative with escapeshellarg
function pingHostSafe(string $host): string {
    if (!filter_var($host, FILTER_VALIDATE_IP)) {
        throw new InvalidArgumentException('Invalid IP address');
    }
    return shell_exec('ping -c 1 ' . escapeshellarg($host));
}

// Dangerous: Direct user input in shell commands (NEVER DO THIS)
function pingHostUnsafe(string $host): string {
    return shell_exec('ping -c 1 ' . $host);
}
```

### 4. Preventing Cross-Site Scripting (XSS)

#### Output Encoding

```php
// HTML Context
function safeEcho(string $input): void {
    echo htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// JavaScript Context
function safeJs(string $input): string {
    return json_encode($input, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
}

// URL Context
function safeUrl(string $input): string {
    return urlencode($input);
}

// Laravel Blade templates automatically escape by default
// {{ $userInput }} is safe

// WordPress: Use esc_* functions
function displayContentWordPress(string $content): void {
    echo esc_html($content); // For HTML content
    echo esc_js($content);   // For JavaScript
    echo esc_url($content);  // For URLs
    echo esc_attr($content); // For HTML attributes
}
```

### 5. Preventing LDAP Injection

```php
// Safe: Using proper escaping
function searchLdapSafe(LDAP\Connection $ldap, string $username): ?array {
    $safeUsername = ldap_escape($username, null, LDAP_ESCAPE_FILTER);
    $filter = "(cn={$safeUsername})";
    $result = ldap_search($ldap, "dc=example,dc=com", $filter);
    return ldap_get_entries($ldap, $result);
}

// WordPress: Safe LDAP integration
function searchLdapWordPress(string $username): ?array {
    $safeUsername = ldap_escape($username, null, LDAP_ESCAPE_FILTER);
    $filter = apply_filters('ldap_search_filter', "(cn={$safeUsername})", $username);
    // ... rest of LDAP search
}
```

### 6. Preventing XML Injection (XXE)

```php
// Safe: Disabling XXE in PHP
function parseXmlSafe(string $xmlString): SimpleXMLElement {
    $oldValue = libxml_disable_entity_loader(true);
    $dom = new DOMDocument();
    $dom->loadXML($xmlString, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR | LIBXML_NONET);
    libxml_disable_entity_loader($oldValue);
    return simplexml_import_dom($dom);
}

// Laravel: Safe XML processing
function parseXmlLaravel(string $xmlString): array {
    return XmlParser::parse($xmlString, false); // Disable external entities
}
```

### 7. Preventing Template Injection

```php
// Safe: Using Twig with auto-escaping
function renderTemplateSafe(Twig\Environment $twig, string $template, array $data): string {
    return $twig->render($template, $data);
}

// Configure Twig to auto-escape
$twig = new \Twig\Environment($loader, [
    'autoescape' => 'html',
    'auto_reload' => true,
]);

// WordPress: Safe template rendering
function renderTemplateWordPress(string $template, array $data): string {
    ob_start();
    extract($data, EXTR_SKIP); // Only extract allowed variables
    include locate_template($template);
    return ob_get_clean();
}
```

## Input Validation Framework

```php
class InputValidator {
    private array $errors = [];

    public function validateEmail(string $email): self {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->errors['email'] = 'Invalid email format';
        }
        return $this;
    }

    public function validateUsername(string $username): self {
        if (!preg_match('/^[a-zA-Z0-9_\-]{3,20}$/', $username)) {
            $this->errors['username'] = 'Username must be 3-20 characters (letters, numbers, _, -)';
        }
        return $this;
    }

    public function checkForInjection(string $input, string $fieldName): self {
        $patterns = [
            '/<script/i', '/--/', '/;/', '/\/\*/', '/\*\//', 
            '/select\s+/i', '/insert\s+/i', '/update\s+/i', 
            '/delete\s+/i', '/drop\s+/i', '/union\s+/i', '/exec\s+/i'
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                $this->errors[$fieldName] = 'Potential injection attempt detected';
                break;
            }
        }
        return $this;
    }

    public function isValid(): bool {
        return empty($this->errors);
    }

    public function getErrors(): array {
        return $this->errors;
    }
}

// Usage
$validator = new InputValidator();
$validator->validateEmail($email)
          ->validateUsername($username)
          ->checkForInjection($searchTerm, 'search');

if (!$validator->isValid()) {
    $errors = $validator->getErrors();
    // Handle errors
}
```

## Testing for Injection Vulnerabilities

```php
class InjectionTests extends TestCase {
    public function testSqlInjectionProtection() {
        $pdo = new PDO(/* ... */);
        $maliciousInput = "admin' OR '1'='1";
        
        $user = getUserSafe($pdo, $maliciousInput);
        
        $this->assertNull($user, 'SQL injection attempt should return no results');
    }

    public function testXssProtection() {
        $xssAttempt = "<script>alert('xss')</script>";
        $safeOutput = htmlspecialchars($xssAttempt, ENT_QUOTES, 'UTF-8');
        
        $this->assertStringNotContainsString('<script>', $safeOutput);
        $this->assertStringContainsString('&lt;script&gt;', $safeOutput);
    }

    public function testCommandInjectionProtection() {
        $maliciousInput = "localhost; rm -rf /";
        $this->expectException(InvalidArgumentException::class);
        
        pingHostSafe($maliciousInput);
    }
}
```

## Monitoring and Logging Injection Attempts

```php
class SecurityLogger {
    public static function logInjectionAttempt(string $type, string $input, string $source = ''): void {
        $logMessage = sprintf(
            "[%s] Potential %s injection attempt from IP %s. Input: %s. Source: %s",
            date('Y-m-d H:i:s'),
            $type,
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            substr($input, 0, 100), // Limit length
            $source
        );
        
        error_log($logMessage);
        
        // Optionally send to security team
        if (in_array($type, ['SQL', 'Command', 'XSS'])) {
            self::alertSecurityTeam($logMessage);
        }
    }
    
    private static function alertSecurityTeam(string $message): void {
        // Implement alerting (email, Slack, etc.)
    }
}

// Middleware for Laravel
class InjectionDetectionMiddleware {
    public function handle($request, Closure $next) {
        foreach ($request->all() as $key => $value) {
            if (is_string($value) && $this->isPotentialInjection($value)) {
                SecurityLogger::logInjectionAttempt(
                    $this->detectInjectionType($value),
                    $value,
                    $request->fullUrl()
                );
                
                return response('Invalid input detected', 400);
            }
        }
        
        return $next($request);
    }
    
    private function isPotentialInjection(string $value): bool {
        $patterns = [
            '/<script/i', '/--/', '/;/', '/\/\*/', '/\*\//', 
            '/select\s+/i', '/insert\s+/i', '/update\s+/i', 
            '/delete\s+/i', '/drop\s+/i', '/union\s+/i', '/exec\s+/i',
            '/`/', '/\$\(/', '/\|/', '/&/', '/>/', '/</'
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $value)) {
                return true;
            }
        }
        return false;
    }
    
    private function detectInjectionType(string $value): string {
        if (preg_match('/<script/i', $value)) return 'XSS';
        if (preg_match('/(select|insert|update|delete|drop|union)\s+/i', $value)) return 'SQL';
        if (preg_match('/(;|\||&|`|\$\(|>|<)/', $value)) return 'Command';
        return 'Unknown';
    }
}

// WordPress: Hook into input processing
add_filter('preprocess_comment', function($commentData) {
    if (preg_match('/<script|--|;|\/\*|\*\//i', $commentData['comment_content'])) {
        SecurityLogger::logInjectionAttempt(
            'XSS', 
            $commentData['comment_content'], 
            'comment'
        );
        wp_die('Invalid input detected');
    }
    return $commentData;
});
```

## Best Practices Summary for PHP

1. **Always use parameterized queries**:
   - PDO for SQL databases
   - Prepared statements in WordPress ($wpdb->prepare())
   - Eloquent ORM in Laravel

2. **Validate all inputs**:
   - Use filter_var() for emails, URLs, etc.
   - Whitelist acceptable characters with regex
   - Implement strict type checking

3. **Escape all outputs**:
   - htmlspecialchars() for HTML context
   - json_encode() for JavaScript context
   - urlencode() for URL parameters
   - Use WordPress esc_* functions

4. **Use secure configuration**:
   - Disable register_globals (PHP.ini)
   - Set open_basedir restrictions
   - Disable dangerous PHP functions (exec, system, etc.)

5. **Implement Content Security Policy (CSP)**:
   - Add CSP headers to responses
   - Restrict sources for scripts, styles, etc.

6. **Secure file operations**:
   - Validate file paths
   - Restrict file permissions
   - Use basename() to prevent directory traversal

7. **Framework-specific protections**:
   - **Laravel**: Use built-in CSRF protection, validation, and ORM
   - **WordPress**: Use nonces, capabilities, and sanitization functions

8. **Regular security updates**:
   - Keep PHP and all libraries updated
   - Monitor security advisories

9. **Log and monitor**:
   - Log potential injection attempts
   - Set up alerts for suspicious activity

10. **Security headers**:
    - Implement X-XSS-Protection
    - Use X-Content-Type-Options: nosniff
    - Set X-Frame-Options: DENY
    - Enable HTTP Strict Transport Security (HSTS)
