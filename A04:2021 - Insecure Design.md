# Secure Coding Practices for PHP (WordPress and Laravel): Addressing OWASP Top 10 (A04:2021 - Insecure Design)

## Introduction to Insecure Design Risks

Insecure Design is a critical category in the OWASP Top 10 that focuses on security flaws arising from architectural decisions rather than implementation bugs. These vulnerabilities occur when security isn't properly considered during the design phase of application development.

## Common Insecure Design Patterns in PHP Applications

1. **Lack of Threat Modeling**
2. **Weak Authentication/Authorization Architecture**
3. **Business Logic Bypass Vulnerabilities**
4. **Improper Data Flow Handling**
5. **Missing Security Controls in Workflows**
6. **Insecure Default Configurations**
7. **Failure to Enforce Security Boundaries**

## Secure Design Implementation Guide

### 1. Threat Modeling Implementation

#### Using OWASP Threat Dragon or Microsoft Threat Modeling Tool

```php
// Payment processing with threat-modeled security controls
class PaymentProcessor {
    private $signer;
    private $logger;
    
    public function __construct(SignerInterface $signer, LoggerInterface $logger) {
        $this->signer = $signer;
        $this->logger = $logger;
    }
    
    public function processPayment(PaymentRequest $request): PaymentResult {
        // Threat: Tampering with payment amounts
        // Mitigation: Verify cryptographic signature
        if (!$this->signer->verify($request->getData(), $request->getSignature())) {
            $this->logger->securityAlert('Invalid payment signature');
            throw new SecurityException('Invalid payment request');
        }
        
        // Threat: Invalid business logic
        // Mitigation: Validate business rules
        if ($request->amount <= 0) {
            throw new BusinessLogicException('Invalid payment amount');
        }
        
        return $this->executePayment($request);
    }
}
```

### 2. Secure Authentication/Authorization Architecture

#### Policy-Based Authorization in Laravel

```php
// AuthServiceProvider.php
public function boot() {
    Gate::define('high-value-transaction', function (User $user) {
        return $user->hasVerifiedEmail() &&
               $user->hasTwoFactorEnabled() &&
               $user->age >= 18;
    });

    Gate::define('admin-access', function (User $user) {
        return $user->isAdmin() && $user->hasStrongMfa();
    });
}

// WordPress capability management
add_filter('user_has_cap', function($allcaps, $caps, $args) {
    // High-value transactions require 2FA
    if (in_array('make_transaction', $caps)) {
        if (!get_user_meta($args[1], '2fa_verified', true)) {
            $allcaps['make_transaction'] = false;
        }
    }
    return $allcaps;
}, 10, 3);
```

### 3. Business Logic Protection Patterns

#### Anti-Abuse Pattern for Financial Operations

```php
class TransactionService {
    private $validator;
    private $fraudDetector;
    private $limiter;
    
    public function __construct(
        TransactionValidator $validator,
        FraudDetector $fraudDetector,
        RateLimiter $limiter
    ) {
        $this->validator = $validator;
        $this->fraudDetector = $fraudDetector;
        $this->limiter = $limiter;
    }
    
    public function executeTransaction(Transaction $tx): TransactionResult {
        // Step 1: Basic validation
        $this->validator->validate($tx);
        
        // Step 2: Fraud detection
        $fraudScore = $this->fraudDetector->analyze($tx);
        if ($fraudScore > 0.8) {
            throw new FraudException('Potential fraud detected');
        }
        
        // Step 3: Rate limiting
        if (!$this->limiter->check($tx->userId, $tx->amount)) {
            throw new RateLimitException('Transaction limit exceeded');
        }
        
        return $this->processor->execute($tx);
    }
}
```

### 4. Secure Data Flow Design

#### Data Classification and Handling

```php
class PaymentDataHandler {
    public function processPaymentData(array $data): PaymentDTO {
        // Validate and sanitize input
        $sanitized = $this->sanitizeInput($data);
        
        // Classify data
        $classified = new PaymentData(
            $this->encrypt($sanitized['card_number']),
            $this->mask($sanitized['card_holder']),
            $sanitized['expiry_date']
        );
        
        return new PaymentDTO($classified);
    }
    
    private function mask(string $value): string {
        if (strlen($value) < 4) return '****';
        return str_repeat('*', strlen($value) - 4) . substr($value, -4);
    }
}
```

### 5. Workflow Security Controls

#### Secure Multi-Step Process

```php
class OrderWorkflow {
    private $stateStore;
    private $validator;
    
    public function processStep(WorkflowStep $step): void {
        // Validate step sequence
        $state = $this->stateStore->get($step->sessionId);
        if (!$this->validator->isValidNextStep($state, $step)) {
            throw new WorkflowException('Invalid step sequence');
        }
        
        // Verify CSRF token
        if (!$this->validator->verifyToken($step->sessionId, $step->token)) {
            throw new SecurityException('Invalid CSRF token');
        }
        
        // Check timeout
        if ($state->isExpired()) {
            throw new TimeoutException('Session expired');
        }
        
        $this->executeStep($step, $state);
    }
}
```

### 6. Secure Default Configurations

#### Security-First Configuration

```php
// Laravel default middleware
protected $middleware = [
    \App\Http\Middleware\TrustProxies::class,
    \App\Http\Middleware\PreventRequestsDuringMaintenance::class,
    \Illuminate\Http\Middleware\ValidatePostSize::class,
    \App\Http\Middleware\TrimStrings::class,
    \Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull::class,
    \App\Http\Middleware\SecureHeadersMiddleware::class,
];

// WordPress security hardening
define('DISALLOW_FILE_EDIT', true);
define('FORCE_SSL_ADMIN', true);
define('WP_HTTP_BLOCK_EXTERNAL', true);

// Secure PHP.ini defaults
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);
```

### 7. Security Boundary Enforcement

#### Service-to-Service Communication

```php
class SecureServiceClient {
    public function callService(string $service, string $endpoint, array $data) {
        $token = $this->auth->getServiceToken($service);
        
        $request = new Request('POST', $endpoint, [
            'Authorization' => 'Bearer ' . $token,
            'X-Request-Signature' => $this->signer->sign($data)
        ], json_encode($data));
        
        try {
            $response = $this->client->send($request, ['timeout' => 30]);
            return json_decode($response->getBody());
        } catch (RequestException $e) {
            throw new ServiceException('Service call failed');
        }
    }
}
```

## Design Validation Techniques

### 1. Security Checklist Verification

```php
class SecurityDesignValidator {
    public function validateController(string $className): ValidationResult {
        $result = new ValidationResult();
        $reflection = new ReflectionClass($className);
        
        // Check for authorization
        if (!$this->hasAuthAttributes($reflection)) {
            $result->addWarning('Missing authorization');
        }
        
        // Check methods
        foreach ($reflection->getMethods() as $method) {
            $this->validateMethod($method, $result);
        }
        
        return $result;
    }
    
    private function validateMethod(ReflectionMethod $method, ValidationResult $result): void {
        // Check sensitive operations
        if (preg_match('/admin|delete|update/i', $method->name)) {
            if (!$this->hasAdminAuth($method)) {
                $result->addError('Admin operation without protection');
            }
        }
    }
}
```

### 2. Secure Design Pattern Catalog

```php
class SecureFactory {
    public function createDataAccess(User $user): DataAccessInterface {
        if ($user->isAdmin()) {
            return new AdminDataAccess();
        }
        return new RegularDataAccess();
    }
    
    public function createReportGenerator(User $user): ReportGeneratorInterface {
        $generator = new ReportGenerator();
        return $user->isPrivileged() ? $generator : new SanitizedReportGenerator($generator);
    }
}
```

## Threat Modeling Integration

### Automated Threat Analysis

```php
class StrideAnalyzer {
    public function analyze(Component $component): array {
        $threats = [];
        
        if (!$component->hasAuthentication()) {
            $threats[] = new Threat('Spoofing', 'Missing authentication');
        }
        
        if (!$component->validatesInput()) {
            $threats[] = new Threat('Tampering', 'No input validation');
        }
        
        if ($component->handlesSensitiveData() && !$component->encryptsData()) {
            $threats[] = new Threat('Information Disclosure', 'Unencrypted sensitive data');
        }
        
        return $threats;
    }
}
```

## Best Practices Summary

1. **Threat Modeling**:
   - Conduct threat modeling during design
   - Use tools like OWASP Threat Dragon
   - Document and address identified threats

2. **Secure Architecture**:
   - Implement least privilege principles
   - Use defense in depth
   - Design for fail-safe defaults

3. **Business Logic Protection**:
   - Validate all state transitions
   - Implement anti-abuse measures
   - Enforce verification for critical operations

4. **Data Flow Security**:
   - Classify data by sensitivity
   - Implement proper handling at each stage
   - Use secure transformation patterns

5. **Secure Defaults**:
   - Harden configurations by default
   - Automate security baseline enforcement
   - Disable unnecessary features

6. **Security Boundaries**:
   - Define clear trust boundaries
   - Validate cross-boundary communications
   - Implement secure service-to-service patterns

7. **Design Validation**:
   - Use security checklists
   - Maintain secure design patterns
   - Automate design analysis

8. **Continuous Improvement**:
   - Learn from security incidents
   - Update threat models regularly
   - Stay current with security trends
