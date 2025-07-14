# Secure Coding Practices for PHP (WordPress and Laravel): Addressing OWASP Top 10 (A05:2021 - Security Misconfiguration)

## Introduction to Security Misconfiguration Risks

Security Misconfiguration ranks #5 in the OWASP Top 10 2021. This occurs when security settings are improperly configured, left at default values, or completely undefined. For PHP applications (including WordPress and Laravel), this includes insecure server configurations, verbose error reporting, unnecessary features enabled, and more.

## Common Security Misconfigurations in PHP Applications

1. **Insecure Default Configurations**
2. **Verbose Error Reporting in Production**
3. **Unnecessary PHP Modules Enabled**
4. **Improper File/Directory Permissions**
5. **Missing Security Headers**
6. **Debug Features Enabled in Production**
7. **Insecure .htaccess/wp-config.php Settings**

## Step-by-Step Secure Configuration Guide

### 1. Secure PHP Configuration (php.ini)

#### Essential Security Settings

```ini
; Disable dangerous functions
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

; Security-focused settings
expose_php = Off
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
allow_url_fopen = Off
allow_url_include = Off
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
session.cookie_samesite = Strict
```

### 2. Secure Laravel Configuration

#### config/app.php and .env Settings

```php
// config/app.php
'debug' => env('APP_DEBUG', false),
'env' => env('APP_ENV', 'production'),

// .env
APP_ENV=production
APP_DEBUG=false
APP_URL=https://yourdomain.com

# Session configuration
SESSION_DRIVER=cookie
SESSION_SECURE_COOKIE=true
SESSION_HTTP_ONLY=true
SESSION_SAME_SITE=strict
```

#### Middleware for Security Headers

```php
// app/Http/Middleware/SecureHeadersMiddleware.php
namespace App\Http\Middleware;

use Closure;

class SecureHeadersMiddleware
{
    private $unwantedHeaders = [
        'X-Powered-By',
        'Server',
    ];

    public function handle($request, Closure $next)
    {
        $response = $next($request);

        foreach ($this->unwantedHeaders as $header) {
            header_remove($header);
        }

        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-XSS-Protection', '1; mode=block');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        
        $csp = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com;";
        $response->headers->set('Content-Security-Policy', $csp);
        
        $response->headers->set('Permissions-Policy', [
            'geolocation=()',
            'camera=()',
            'microphone=()',
            'payment=()'
        ]);

        return $response;
    }
}

// Register in app/Http/Kernel.php
protected $middleware = [
    \App\Http\Middleware\SecureHeadersMiddleware::class,
    // other middleware...
];
```

### 3. Secure WordPress Configuration

#### wp-config.php Hardening

```php
// Disable file editing
define('DISALLOW_FILE_EDIT', true);

// Force SSL for admin and logins
define('FORCE_SSL_ADMIN', true);

// Block external requests
define('WP_HTTP_BLOCK_EXTERNAL', true);

// Allow only specific hosts (if external requests needed)
define('WP_ACCESSIBLE_HOSTS', 'api.example.com,cdn.example.com');

// Security keys - generate unique values
define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
define('LOGGED_IN_KEY',    'put your unique phrase here');
define('NONCE_KEY',        'put your unique phrase here');
// ... (all 8 keys should be unique and random)
```

#### .htaccess Security Rules

```apache
# Block directory browsing
Options -Indexes

# Protect wp-config.php
<Files wp-config.php>
    Order allow,deny
    Deny from all
</Files>

# Disable XML-RPC (if not needed)
<Files xmlrpc.php>
    Order allow,deny
    Deny from all
</Files>

# Prevent PHP execution in uploads
<Directory /wp-content/uploads>
    <Files *.php>
        Deny from all
    </Files>
</Directory>

# Security Headers
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Remove server headers
    Header unset X-Powered-By
    Header unset Server
</IfModule>
```

### 4. File and Directory Permissions

#### Secure Permission Structure

```bash
# Recommended permissions for WordPress
find /path/to/wordpress/ -type d -exec chmod 755 {} \;
find /path/to/wordpress/ -type f -exec chmod 644 {} \;

# wp-config.php should be readable only by web server
chmod 640 /path/to/wordpress/wp-config.php

# wp-content/uploads may need write access
chmod -R 755 /path/to/wordpress/wp-content/uploads

# Laravel storage and bootstrap/cache need write access
chmod -R 775 /path/to/laravel/storage
chmod -R 775 /path/to/laravel/bootstrap/cache
```

### 5. Production Error Handling

#### Laravel Error Configuration

```php
// app/Exceptions/Handler.php
public function register()
{
    $this->renderable(function (Throwable $e, $request) {
        if (!config('app.debug')) {
            return response()->json([
                'message' => 'An error occurred. Please try again later.'
            ], 500);
        }
    });
}
```

#### WordPress Error Handling

```php
// wp-config.php
define('WP_DEBUG', false);
define('WP_DEBUG_DISPLAY', false);
define('WP_DEBUG_LOG', true); // Log errors to wp-content/debug.log

// Custom error page in theme's functions.php
function custom_error_handler() {
    if (!WP_DEBUG && is_404()) {
        status_header(404);
        include(get_template_directory() . '/404.php');
        exit;
    }
}
add_action('template_redirect', 'custom_error_handler');
```

### 6. Secure Database Configuration

#### Laravel Database Security

```php
// config/database.php
'mysql' => [
    'driver' => 'mysql',
    'url' => env('DATABASE_URL'),
    'host' => env('DB_HOST', '127.0.0.1'),
    'port' => env('DB_PORT', '3306'),
    'database' => env('DB_DATABASE', 'forge'),
    'username' => env('DB_USERNAME', 'forge'),
    'password' => env('DB_PASSWORD', ''),
    'unix_socket' => env('DB_SOCKET', ''),
    'charset' => 'utf8mb4',
    'collation' => 'utf8mb4_unicode_ci',
    'prefix' => '',
    'prefix_indexes' => true,
    'strict' => true, // Enable strict mode
    'engine' => null,
    'options' => extension_loaded('pdo_mysql') ? array_filter([
        PDO::MYSQL_ATTR_SSL_CA => env('MYSQL_ATTR_SSL_CA'),
        PDO::ATTR_EMULATE_PREPARES => false, // Force real prepared statements
    ]) : [],
],
```

#### WordPress Database Security

```sql
-- MySQL user should have least privileges
CREATE USER 'wpuser'@'localhost' IDENTIFIED BY 'strongpassword';
GRANT SELECT, INSERT, UPDATE, DELETE ON wpdatabase.* TO 'wpuser'@'localhost';
FLUSH PRIVILEGES;
```

### 7. Security Scanning and Monitoring

#### Laravel Security Checker

```bash
# Install security checker
composer require enlightn/security-checker

# Run security checks
php artisan security:check
```

#### WordPress Security Plugins

```php
// Recommended security plugins
- Wordfence Security
- Sucuri Security
- iThemes Security
```

#### Automated Configuration Scanner

```php
class SecurityConfigScanner {
    private $checks = [
        'debug_mode' => [
            'file' => 'config/app.php',
            'pattern' => "/'debug'\s*=>\s*true/",
            'message' => 'Debug mode should be disabled in production'
        ],
        'app_key' => [
            'file' => '.env',
            'pattern' => "/APP_KEY=\s*$/",
            'message' => 'Application key is not set'
        ],
        // Add more checks...
    ];

    public function scan() {
        $results = [];
        
        foreach ($this->checks as $check) {
            $content = file_get_contents(base_path($check['file']));
            if (preg_match($check['pattern'], $content)) {
                $results[] = $check['message'];
            }
        }
        
        return $results;
    }
}

// Usage in a console command
protected function handle() {
    $scanner = new SecurityConfigScanner();
    $issues = $scanner->scan();
    
    if (!empty($issues)) {
        $this->error('Security configuration issues found:');
        foreach ($issues as $issue) {
            $this->line('- ' . $issue);
        }
        return 1;
    }
    
    $this->info('No security configuration issues found');
    return 0;
}
```

## Best Practices Summary

1. **Harden PHP Configuration**:
   - Disable dangerous functions
   - Turn off error display in production
   - Secure session settings

2. **Secure Framework Configurations**:
   - Disable debug mode in production
   - Set proper environment variables
   - Implement security middleware

3. **File System Security**:
   - Set proper file/directory permissions
   - Restrict access to sensitive files
   - Prevent PHP execution in uploads

4. **Database Security**:
   - Use least privilege principle for DB users
   - Enable strict mode
   - Use SSL for database connections when possible

5. **Security Headers**:
   - Implement CSP, X-Frame-Options, etc.
   - Remove server identification headers
   - Set secure cookie attributes

6. **Error Handling**:
   - Never expose stack traces in production
   - Log errors securely
   - Customize error pages

7. **Regular Scanning**:
   - Automated configuration checks
   - Security plugin scans
   - Manual security audits

8. **Keep Updated**:
   - Regularly update PHP, WordPress, Laravel
   - Update plugins and dependencies
   - Monitor security advisories

9. **Backup and Monitoring**:
   - Regular backups with secure storage
   - File integrity monitoring
   - Security incident logging

10. **Least Privilege Principle**:
    - Minimal necessary permissions for web server
    - Separate database users for different operations
    - Restrict admin access to trusted IPs when possible
