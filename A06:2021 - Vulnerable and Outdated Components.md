# Secure Coding Practices for PHP (WordPress and Laravel): Addressing OWASP Top 10 (A06:2021 - Vulnerable and Outdated Components)

## Introduction to Component Risks

Vulnerable and Outdated Components ranks #6 in the OWASP Top 10 2021. This risk occurs when using libraries, frameworks, and other dependencies with known vulnerabilities. For PHP applications, this includes Composer packages, WordPress plugins/themes, server software, and PHP runtime itself.

## Common Component Risks in PHP Applications

1. **Outdated PHP Versions**
2. **Vulnerable Composer Packages**
3. **Unpatched WordPress Core/Plugins/Themes**
4. **Insecure Server Software (Apache/Nginx)**
5. **Unmaintained Third-Party Libraries**
6. **Transitive Dependency Vulnerabilities**
7. **Build Toolchain Weaknesses**

## Step-by-Step Secure Component Management

### 1. Dependency Management Framework

#### Secure Composer Configuration

```json
{
  "config": {
    "platform-check": true,
    "preferred-install": "dist",
    "sort-packages": true,
    "allow-plugins": {
      "composer/installers": true,
      "php-http/discovery": true
    }
  },
  "require": {
    "php": "^8.1",
    "laravel/framework": "^10.0",
    "guzzlehttp/guzzle": "^7.7" 
  },
  "require-dev": {
    "roave/security-advisories": "dev-latest"
  },
  "scripts": {
    "post-update-cmd": [
      "@composer audit"
    ]
  }
}
```

#### Automated Vulnerability Scanning

```bash
# Install security checker
composer require enlightn/security-checker --dev

# Add to CI pipeline
composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader
composer audit
vendor/bin/security-checker security:check
```

### 2. WordPress Component Security

#### Plugin/Theme Management

```php
// Disable plugin/theme editing
define('DISALLOW_FILE_EDIT', true);

// Auto-update controls
define('WP_AUTO_UPDATE_CORE', 'minor'); // Only auto-update minor releases
add_filter('auto_update_plugin', '__return_true');
add_filter('auto_update_theme', '__return_true');

// Security scanner function
function scan_vulnerable_plugins() {
    $plugins = get_plugins();
    $vulnerabilities = [];
    
    foreach ($plugins as $path => $plugin) {
        $response = wp_remote_get(
            "https://wpvulndb.com/api/v3/plugins/" . $plugin['TextDomain']
        );
        
        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
            $data = json_decode(wp_remote_retrieve_body($response), true);
            if (!empty($data[$plugin['TextDomain']]['vulnerabilities'])) {
                $vulnerabilities[$path] = $data[$plugin['TextDomain']]['vulnerabilities'];
            }
        }
    }
    
    return $vulnerabilities;
}

// Hook into admin notices
add_action('admin_notices', function() {
    $vulns = scan_vulnerable_plugins();
    if (!empty($vulns)) {
        echo '<div class="notice notice-error">';
        echo '<p><strong>Security Alert:</strong> Vulnerable plugins detected:</p>';
        foreach ($vulns as $plugin => $issues) {
            echo "<p>{$plugin}: " . count($issues) . " vulnerabilities</p>";
        }
        echo '</div>';
    }
});
```

### 3. Runtime Security Monitoring

#### PHP Version Checker

```php
class PhpSecurityMonitor {
    private $minVersion = '8.1.0';
    private $currentVersion;
    
    public function __construct() {
        $this->currentVersion = phpversion();
    }
    
    public function checkVersion() {
        if (version_compare($this->currentVersion, $this->minVersion, '<')) {
            error_log("Security Alert: Outdated PHP version {$this->currentVersion}");
            return false;
        }
        return true;
    }
    
    public function checkExtensions() {
        $required = ['filter', 'hash', 'openssl'];
        $missing = array_diff($required, get_loaded_extensions());
        
        if (!empty($missing)) {
            error_log("Security Alert: Missing required extensions: " . implode(', ', $missing));
            return false;
        }
        return true;
    }
}

// Usage
$monitor = new PhpSecurityMonitor();
if (!$monitor->checkVersion() || !$monitor->checkExtensions()) {
    // Alert admin or take action
}
```

### 4. Patch Management Automation

#### Automated Update Script

```bash
#!/bin/bash
# Automated security update script for PHP applications

# Update OS packages
apt-get update
apt-get upgrade -y

# Update PHP
apt-get install --only-upgrade php8.1 php8.1-common php8.1-opcache

# For Laravel projects
cd /var/www/laravel-app
composer update --no-dev --prefer-dist --optimize-autoloader
php artisan migrate --force

# For WordPress
cd /var/www/wordpress
wp core update --minor
wp plugin update --all
wp theme update --all
wp core update-db

# Restart services
systemctl restart apache2 php8.1-fpm
```

### 5. Component Bill of Materials (BOM)

#### Software BOM Generator

```php
class SoftwareBomGenerator {
    public function generateLaravelBom() {
        $composer = json_decode(file_get_contents('composer.lock'), true);
        
        $bom = [
            'metadata' => [
                'generated' => date('c'),
                'tool' => 'LaravelBomGenerator/1.0'
            ],
            'components' => []
        ];
        
        foreach ($composer['packages'] as $package) {
            $bom['components'][] = [
                'type' => 'library',
                'name' => $package['name'],
                'version' => $package['version'],
                'homepage' => $package['homepage'] ?? '',
                'license' => $package['license'] ?? []
            ];
        }
        
        return json_encode($bom, JSON_PRETTY_PRINT);
    }
    
    public function generateWordPressBom() {
        $bom = [
            'metadata' => [
                'generated' => date('c'),
                'tool' => 'WordPressBomGenerator/1.0'
            ],
            'components' => []
        ];
        
        // Core
        $bom['components'][] = [
            'type' => 'core',
            'name' => 'wordpress',
            'version' => get_bloginfo('version')
        ];
        
        // Plugins
        foreach (get_plugins() as $path => $plugin) {
            $bom['components'][] = [
                'type' => 'plugin',
                'name' => $plugin['Name'],
                'version' => $plugin['Version'],
                'path' => $path
            ];
        }
        
        // Themes
        foreach (wp_get_themes() as $theme) {
            $bom['components'][] = [
                'type' => 'theme',
                'name' => $theme->get('Name'),
                'version' => $theme->get('Version')
            ];
        }
        
        return json_encode($bom, JSON_PRETTY_PRINT);
    }
}
```

### 6. Dependency Firewall

#### Composer Package Validator

```php
class ComposerFirewall {
    private $blocklist = [
        'laravel/framework' => '<10.0',
        'symfony/symfony' => '<6.0',
        'monolog/monolog' => '<2.0'
    ];
    
    private $vulnerabilitySources = [
        'https://packagesecurity.org/api/v1/advisories'
    ];
    
    public function validateInstall($package, $version) {
        // Check blocklist
        foreach ($this->blocklist as $blocked => $constraint) {
            if (strtolower($package) === strtolower($blocked)) {
                if (Composer\Semver\Semver::satisfies($version, $constraint)) {
                    throw new RuntimeException("Package {$package}@{$version} is blocklisted");
                }
            }
        }
        
        // Check known vulnerabilities
        foreach ($this->vulnerabilitySources as $source) {
            $response = file_get_contents("{$source}?package={$package}&version={$version}");
            $data = json_decode($response, true);
            
            if (!empty($data['advisories'])) {
                throw new RuntimeException(
                    "Package {$package}@{$version} has known vulnerabilities: " .
                    implode(', ', array_column($data['advisories'], 'title'))
                );
            }
        }
        
        return true;
    }
}

// Usage in custom installer
$firewall = new ComposerFirewall();
$firewall->validateInstall('guzzlehttp/guzzle', '7.4.0');
```

### 7. Server Security Scanning

#### Server Configuration Scanner

```php
class ServerSecurityScanner {
    public function scan() {
        $checks = [
            'PHP Version' => $this->checkPhpVersion(),
            'Dangerous Functions' => $this->checkDisabledFunctions(),
            'SSL Configuration' => $this->checkSsl(),
            'File Permissions' => $this->checkPermissions(),
            'Server Headers' => $this->checkHeaders()
        ];
        
        return $checks;
    }
    
    private function checkPhpVersion() {
        return version_compare(phpversion(), '8.1.0', '>=');
    }
    
    private function checkDisabledFunctions() {
        $dangerous = ['exec', 'passthru', 'shell_exec', 'system', 'proc_open'];
        $disabled = array_map('trim', explode(',', ini_get('disable_functions')));
        
        return count(array_intersect($dangerous, $disabled)) === count($dangerous);
    }
    
    private function checkSsl() {
        return extension_loaded('openssl') && 
               version_compare(OPENSSL_VERSION_TEXT, '1.1.1', '>=');
    }
    
    private function checkPermissions() {
        $paths = [
            __DIR__ . '/../.env',
            __DIR__ . '/../storage',
            __DIR__ . '/../bootstrap/cache'
        ];
        
        foreach ($paths as $path) {
            if (file_exists($path)) {
                $perms = substr(sprintf('%o', fileperms($path)), -4);
                if ($perms !== '0640' && $perms !== '0644') {
                    return false;
                }
            }
        }
        return true;
    }
    
    private function checkHeaders() {
        $headers = headers_list();
        $leaks = ['Server', 'X-Powered-By'];
        
        foreach ($leaks as $header) {
            foreach ($headers as $h) {
                if (stripos($h, $header) === 0) {
                    return false;
                }
            }
        }
        return true;
    }
}
```

## Best Practices Summary

1. **Maintain an Inventory** - Keep track of all components (SBOM)
2. **Monitor Vulnerabilities** - Use tools like `composer audit`, WP Scan
3. **Update Regularly** - Establish patch management processes
4. **Remove Unused Components** - Reduce attack surface
5. **Secure Configuration** - Harden server and application settings
6. **Version Pinning** - Avoid floating versions in production
7. **Security Headers** - Implement proper HTTP security headers
8. **Automate Scanning** - Integrate security checks into CI/CD
9. **Runtime Protection** - Use WAFs and security plugins
10. **Emergency Response** - Have a plan for critical vulnerabilities

## Implementation Checklist

- [ ] Enable Composer security auditing (`composer audit`)
- [ ] Configure automatic security updates for WordPress core
- [ ] Pin PHP version in `composer.json`
- [ ] Regularly scan for vulnerable plugins/themes
- [ ] Implement server configuration scanning
- [ ] Generate and maintain a software BOM
- [ ] Set up monitoring for outdated components
- [ ] Establish patch management procedures
- [ ] Remove unused dependencies and plugins
- [ ] Configure proper file permissions
- [ ] Subscribe to security mailing lists (PHP, WordPress, etc.)
