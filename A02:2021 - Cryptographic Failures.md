# Secure Coding Practices for PHP (WordPress and Laravel): Addressing OWASP Top 10 (A02:2021 - Cryptographic Failures)

## Introduction to Cryptographic Failures

Cryptographic failures (previously called "Sensitive Data Exposure") rank as the #2 security risk in the OWASP Top 10. In PHP applications, we need to ensure proper handling of encryption, hashing, keys, and certificates to protect sensitive data.

## Common Cryptographic Failures in PHP Applications

1. **Insecure or Deprecated Algorithms** (MD5, SHA1, DES)
2. **Improper Key Management**
3. **Hardcoded Secrets**
4. **Insufficient Entropy**
5. **Insecure Random Number Generation**
6. **Improper Certificate Validation**
7. **Weak Password Hashing**

## Step-by-Step Implementation Guide

### 1. Data Encryption Best Practices

#### Symmetric Encryption (AES)

```php
// Laravel: Using OpenSSL for AES encryption
class AesEncryptionService
{
    private $key;
    private $cipher = 'aes-256-cbc';

    public function __construct()
    {
        $this->key = config('app.encryption_key');
        
        if (strlen($this->key) !== 32) {
            throw new InvalidArgumentException("Key must be 32 bytes for AES-256");
        }
    }

    public function encrypt($plainText)
    {
        $iv = random_bytes(openssl_cipher_iv_length($this->cipher));
        $cipherText = openssl_encrypt(
            $plainText,
            $this->cipher,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        // Combine IV and cipher text for storage
        return base64_encode($iv . $cipherText);
    }

    public function decrypt($cipherText)
    {
        $data = base64_decode($cipherText);
        $ivLength = openssl_cipher_iv_length($this->cipher);
        $iv = substr($data, 0, $ivLength);
        $cipherText = substr($data, $ivLength);
        
        return openssl_decrypt(
            $cipherText,
            $this->cipher,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv
        );
    }
}

// WordPress: Similar approach but integrated with options API
function wp_encrypt_data($data) {
    $key = defined('ENCRYPTION_KEY') ? ENCRYPTION_KEY : '';
    if (empty($key) || strlen($key) < 32) {
        wp_die('Encryption key not properly configured');
    }
    
    $iv = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
    return base64_encode($iv . $encrypted);
}

function wp_decrypt_data($encrypted) {
    $key = defined('ENCRYPTION_KEY') ? ENCRYPTION_KEY : '';
    $data = base64_decode($encrypted);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'aes-256-cbc', $key, 0, $iv);
}
```

### 2. Secure Key Management

```php
// Laravel: Using environment variables and key management services
// .env file
ENCRYPTION_KEY=base64:your_32_byte_base64_encoded_key_here

// For production, use AWS KMS or similar
use Aws\Kms\KmsClient;

class KmsEncryptionService
{
    private $kmsClient;
    private $keyId;

    public function __construct()
    {
        $this->kmsClient = new KmsClient([
            'region' => config('services.kms.region'),
            'version' => 'latest',
            'credentials' => [
                'key' => config('services.kms.key'),
                'secret' => config('services.kms.secret'),
            ]
        ]);
        $this->keyId = config('services.kms.key_id');
    }

    public function encrypt($data)
    {
        $result = $this->kmsClient->encrypt([
            'KeyId' => $this->keyId,
            'Plaintext' => $data,
        ]);
        
        return base64_encode($result['CiphertextBlob']);
    }

    public function decrypt($encrypted)
    {
        $result = $this->kmsClient->decrypt([
            'CiphertextBlob' => base64_decode($encrypted),
        ]);
        
        return $result['Plaintext'];
    }
}

// WordPress: Using constants in wp-config.php
// wp-config.php
define('ENCRYPTION_KEY', 'your_32_byte_secret_key_here'); // Generate a proper key
```

### 3. Secure Password Hashing

```php
// Laravel: Built-in password hashing (uses bcrypt)
$hashedPassword = Hash::make('plain-text-password');

// Verify password
if (Hash::check('plain-text-password', $hashedPassword)) {
    // Password matches
}

// WordPress: Using wp_hash_password() and wp_check_password()
$hashed = wp_hash_password($password);
$check = wp_check_password($password, $hashed);

// For custom applications (PHP native)
function hash_password($password) {
    // Use Argon2 if available (PHP 7.2+)
    if (defined('PASSWORD_ARGON2ID')) {
        return password_hash($password, PASSWORD_ARGON2ID);
    }
    // Fallback to bcrypt
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function verify_password($password, $hash) {
    return password_verify($password, $hash);
}
```

### 4. Secure Random Number Generation

```php
// Laravel and WordPress: Using random_bytes() or openssl_random_pseudo_bytes()
function generate_secure_token($length = 32) {
    return bin2hex(random_bytes($length));
}

function generate_csrf_token() {
    if (function_exists('random_bytes')) {
        return bin2hex(random_bytes(32));
    }
    if (function_exists('openssl_random_pseudo_bytes')) {
        return bin2hex(openssl_random_pseudo_bytes(32));
    }
    // Last resort - not cryptographically secure!
    return md5(uniqid(mt_rand(), true));
}

// Laravel helper
$random = Str::random(32);
```

### 5. Secure Certificate Validation

```php
// Laravel: Guzzle HTTP client with certificate verification
$client = new GuzzleHttp\Client([
    'verify' => true, // Enable SSL verification
    'cert' => '/path/to/cert.pem',
    'ssl_key' => ['/path/to/key.pem', 'passphrase']
]);

// WordPress: WP_Http class with SSL verification
add_filter('https_ssl_verify', '__return_true');
add_filter('https_local_ssl_verify', '__return_true');

// Custom cURL with certificate pinning
function curl_with_pinning($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_CAINFO, '/path/to/cacert.pem');
    
    // Certificate pinning
    curl_setopt($ch, CURLOPT_PINNEDPUBLICKEY, 'sha256//your-public-key-hash');
    
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
```

### 6. Protecting Sensitive Data in Configuration

```php
// Laravel: Environment variables and encrypted configuration
// .env file
DB_PASSWORD=your_db_password
API_SECRET=your_api_secret

// Access in code
$dbPassword = env('DB_PASSWORD');

// For highly sensitive data, use encrypted values
php artisan encrypt:secret
// Then store in .env as encrypted

// WordPress: wp-config.php best practices
// wp-config.php
define('DB_PASSWORD', 'your_db_password');

// Move wp-config.php above web root
// Set proper permissions (400 or 440)
```

### 7. Secure JWT Token Handling

```php
// Laravel: Using tymon/jwt-auth package
// config/jwt.php
return [
    'secret' => env('JWT_SECRET'),
    'algo' => 'HS256',
    'keys' => [
        'public' => env('JWT_PUBLIC_KEY'),
        'private' => env('JWT_PRIVATE_KEY'),
        'passphrase' => env('JWT_PASSPHRASE'),
    ],
    // Other config
];

// WordPress: Using JWT plugins or custom implementation
function generate_jwt_token($user_id) {
    $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : '';
    $issued_at = time();
    $expiration = $issued_at + (DAY_IN_SECONDS * 7); // Token valid for 7 days
    
    $payload = [
        'iss' => get_bloginfo('url'),
        'iat' => $issued_at,
        'nbf' => $issued_at,
        'exp' => $expiration,
        'data' => [
            'user' => [
                'id' => $user_id,
            ],
        ],
    ];
    
    return \Firebase\JWT\JWT::encode($payload, $secret_key, 'HS256');
}

function validate_jwt_token($token) {
    try {
        $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : '';
        $decoded = \Firebase\JWT\JWT::decode($token, $secret_key, ['HS256']);
        return $decoded->data->user->id;
    } catch (Exception $e) {
        return false;
    }
}
```

## Testing Cryptographic Implementations

```php
// PHPUnit tests for Laravel
class EncryptionTest extends TestCase
{
    public function test_aes_encryption_decryption()
    {
        $service = new AesEncryptionService();
        $original = 'Sensitive data';
        
        $encrypted = $service->encrypt($original);
        $decrypted = $service->decrypt($encrypted);
        
        $this->assertEquals($original, $decrypted);
        $this->assertNotEquals($original, $encrypted);
    }
    
    public function test_password_hashing()
    {
        $password = 'SecurePassword123!';
        $wrongPassword = 'WrongPassword456?';
        
        $hashed = hash_password($password);
        $verifyCorrect = verify_password($password, $hashed);
        $verifyWrong = verify_password($wrongPassword, $hashed);
        
        $this->assertTrue($verifyCorrect);
        $this->assertFalse($verifyWrong);
    }
}

// WordPress: PHPUnit tests for custom functions
class WpCryptographyTest extends WP_UnitTestCase
{
    public function test_wp_encryption_functions()
    {
        $original = 'Test data';
        $encrypted = wp_encrypt_data($original);
        $decrypted = wp_decrypt_data($encrypted);
        
        $this->assertEquals($original, $decrypted);
        $this->assertNotEquals($original, $encrypted);
    }
    
    public function test_jwt_token_generation()
    {
        $user_id = $this->factory->user->create();
        $token = generate_jwt_token($user_id);
        $decoded_id = validate_jwt_token($token);
        
        $this->assertEquals($user_id, $decoded_id);
    }
}
```

## Monitoring and Logging Cryptographic Operations

```php
// Laravel: Logging encryption operations
class AuditedEncryptionService
{
    protected $encryptor;
    protected $logger;

    public function __construct(AesEncryptionService $encryptor, LoggerInterface $logger)
    {
        $this->encryptor = $encryptor;
        $this->logger = $logger;
    }

    public function encrypt($data)
    {
        try {
            $result = $this->encryptor->encrypt($data);
            $this->logger->info('Data encrypted successfully', ['length' => strlen($data)]);
            return $result;
        } catch (Exception $e) {
            $this->logger->error('Encryption failed', ['error' => $e->getMessage()]);
            throw $e;
        }
    }
}

// WordPress: Action hooks for security logging
add_action('wp_login_failed', function($username) {
    error_log('Failed login attempt for username: ' . $username);
});

add_action('password_reset', function($user, $new_pass) {
    error_log('Password reset for user ID: ' . $user->ID);
}, 10, 2);
```

## Best Practices Summary for PHP

1. **Use modern, vetted cryptographic libraries**:
   - OpenSSL for encryption
   - password_hash()/password_verify() for password hashing
   - random_bytes() for secure randomness

2. **Choose appropriate algorithms**:
   - Encryption: AES-256-CBC or AES-256-GCM
   - Password hashing: Argon2id (PHP 7.2+), bcrypt
   - Hashing: SHA-256 or SHA-3

3. **Secure key management**:
   - Store keys in environment variables (not in code)
   - Use services like AWS KMS for production
   - Rotate keys periodically

4. **Proper configuration**:
   - Set appropriate permissions on config files
   - Move sensitive files outside web root
   - Use HTTPS everywhere

5. **Input validation and output encoding**:
   - Always validate before processing
   - Escape output to prevent XSS

6. **Secure session management**:
   - Use secure and HttpOnly flags for cookies
   - Regenerate session IDs after login

7. **Regular updates**:
   - Keep PHP and all libraries updated
   - Monitor for security advisories

8. **Framework-specific recommendations**:
   - **Laravel**: Use built-in security features (CSRF protection, encryption, hashing)
   - **WordPress**: Follow WordPress coding standards, use nonces, validate/sanitize all inputs

9. **Audit and monitor**:
   - Log security-relevant events
   - Implement intrusion detection
   - Regular security audits

10. **Disable dangerous functions**:
    - In php.ini: disable exec, system, passthru, etc.
    - Use open_basedir restriction
