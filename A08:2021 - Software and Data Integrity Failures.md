# Secure Coding Practices for PHP (WordPress and Laravel): Addressing OWASP Top 10 (A08:2021 - Software and Data Integrity Failures)

## Comprehensive Data Integrity Protection System

### 1. Secure Code Deployment Pipeline

#### Code Signing and Verification Implementation

```php
class CodeSigningService
{
    private $privateKey;
    private $publicKey;
    private $logger;

    public function __construct(
        string $privateKeyPath,
        string $publicKeyPath,
        LoggerInterface $logger
    ) {
        $this->privateKey = openssl_pkey_get_private(
            file_get_contents($privateKeyPath),
            $_ENV['CODE_SIGNING_KEY_PASS']
        );
        $this->publicKey = openssl_pkey_get_public(
            file_get_contents($publicKeyPath)
        );
        $this->logger = $logger;
    }

    public function signFile(string $filePath): string
    {
        $fileContent = file_get_contents($filePath);
        openssl_sign($fileContent, $signature, $this->privateKey, OPENSSL_ALGO_SHA256);
        
        $this->logger->info("File signed successfully", ['file' => $filePath]);
        return base64_encode($signature);
    }

    public function verifyFile(string $filePath, string $signature): bool
    {
        $fileContent = file_get_contents($filePath);
        $signature = base64_decode($signature);
        $result = openssl_verify(
            $fileContent, 
            $signature, 
            $this->publicKey, 
            OPENSSL_ALGO_SHA256
        );
        
        if ($result !== 1) {
            $this->logger->warning("File verification failed", ['file' => $filePath]);
        }
        
        return $result === 1;
    }

    public function verifyGitCommit(string $commitHash): bool
    {
        $output = shell_exec("git verify-commit $commitHash 2>&1");
        $verified = strpos($output, 'Good signature') !== false;
        
        if (!$verified) {
            $this->logger->error("Invalid commit signature", ['commit' => $commitHash]);
        }
        
        return $verified;
    }
}
```

### 2. Secure Update Mechanism

#### Cryptographic Update Verification

```php
class SecureUpdateService
{
    private $signingService;
    private $updateRepository;
    private $logger;

    public function __construct(
        CodeSigningService $signingService,
        UpdateRepository $updateRepository,
        LoggerInterface $logger
    ) {
        $this->signingService = $signingService;
        $this->updateRepository = $updateRepository;
        $this->logger = $logger;
    }

    public function verifyUpdatePackage(string $packagePath): UpdateVerificationResult
    {
        $result = new UpdateVerificationResult();
        
        try {
            $package = $this->updateRepository->getPackage($packagePath);
            
            // 1. Verify package signature
            if (!$this->signingService->verifyFile($packagePath, $package->getSignature())) {
                $result->addError("Invalid package signature");
                $this->logger->error("Update package signature verification failed");
                return $result;
            }

            // 2. Verify manifest integrity
            $manifestHash = $this->computeManifestHash($package->getManifest());
            if (!hash_equals($manifestHash, $package->getManifestHash())) {
                $result->addError("Manifest integrity check failed");
                $this->logger->error("Update package manifest verification failed");
                return $result;
            }

            // 3. Verify dependency graph
            $dependencyResult = $this->verifyDependencies($package->getManifest());
            if (!$dependencyResult->isValid()) {
                $result->addErrors($dependencyResult->getErrors());
                return $result;
            }

            $result->setValid(true);
            return $result;
        } catch (Exception $e) {
            $this->logger->error("Update verification failed", ['error' => $e->getMessage()]);
            $result->addError("Update verification process failed");
            return $result;
        }
    }

    private function computeManifestHash(UpdateManifest $manifest): string
    {
        return hash('sha256', json_encode($manifest));
    }

    private function verifyDependencies(UpdateManifest $manifest): DependencyVerificationResult
    {
        $result = new DependencyVerificationResult();
        
        foreach ($manifest->getDependencies() as $dependency) {
            if (!$this->updateRepository->isDependencyAllowed($dependency)) {
                $result->addError("Dependency {$dependency->getName()}@{$dependency->getVersion()} is not allowed");
            }
        }
        
        return $result;
    }
}
```

### 3. Data Integrity Protection

#### Cryptographic Data Integrity Service

```php
class DataIntegrityService
{
    private $keyVault;
    private $logger;

    public function __construct(
        KeyVaultService $keyVault,
        LoggerInterface $logger
    ) {
        $this->keyVault = $keyVault;
        $this->logger = $logger;
    }

    public function signData(string $data, string $keyId): SignedData
    {
        try {
            $hash = hash('sha256', $data, true);
            $signature = $this->keyVault->sign($keyId, $hash);
            
            return new SignedData(
                $data,
                $signature,
                $keyId,
                'SHA256withRSA',
                new DateTime()
            );
        } catch (Exception $e) {
            $this->logger->error("Data signing failed", ['error' => $e->getMessage()]);
            throw new DataIntegrityException("Data signing operation failed");
        }
    }

    public function verifyData(SignedData $signedData): bool
    {
        try {
            $hash = hash('sha256', $signedData->getData(), true);
            return $this->keyVault->verify(
                $signedData->getKeyId(),
                $hash,
                $signedData->getSignature()
            );
        } catch (Exception $e) {
            $this->logger->error("Data verification failed", ['error' => $e->getMessage()]);
            return false;
        }
    }

    public function encryptData(string $data, string $keyId): EncryptedData
    {
        try {
            // Generate random AES key
            $aesKey = random_bytes(32);
            $iv = random_bytes(16);
            
            // Encrypt data with AES
            $cipherText = openssl_encrypt(
                $data,
                'aes-256-cbc',
                $aesKey,
                OPENSSL_RAW_DATA,
                $iv
            );
            
            // Encrypt AES key with RSA
            $encryptedKey = $this->keyVault->encrypt($keyId, $aesKey);
            
            return new EncryptedData(
                $cipherText,
                $encryptedKey,
                $iv,
                $keyId,
                'AES-256-CBC with RSA-OAEP',
                new DateTime()
            );
        } catch (Exception $e) {
            $this->logger->error("Data encryption failed", ['error' => $e->getMessage()]);
            throw new DataIntegrityException("Data encryption failed");
        }
    }

    public function decryptData(EncryptedData $encryptedData): string
    {
        try {
            // Decrypt AES key with RSA
            $aesKey = $this->keyVault->decrypt(
                $encryptedData->getKeyId(),
                $encryptedData->getEncryptedKey()
            );
            
            // Decrypt data with AES
            return openssl_decrypt(
                $encryptedData->getCipherText(),
                'aes-256-cbc',
                $aesKey,
                OPENSSL_RAW_DATA,
                $encryptedData->getIv()
            );
        } catch (Exception $e) {
            $this->logger->error("Data decryption failed", ['error' => $e->getMessage()]);
            throw new DataIntegrityException("Data decryption failed");
        }
    }
}
```

### 4. Secure Deserialization

#### Safe Serialization with Validation

```php
class SecureSerializer
{
    private $allowedTypes;
    private $logger;

    public function __construct(
        array $allowedTypes,
        LoggerInterface $logger
    ) {
        $this->allowedTypes = $allowedTypes;
        $this->logger = $logger;
    }

    public function serialize($data): string
    {
        return json_encode($data);
    }

    public function deserialize(string $json, string $expectedType)
    {
        if (!in_array($expectedType, $this->allowedTypes)) {
            $this->logger->warning("Attempt to deserialize unauthorized type", ['type' => $expectedType]);
            throw new SecureSerializationException("Unauthorized type: $expectedType");
        }

        $data = json_decode($json, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->logger->warning("Invalid JSON data during deserialization");
            throw new SecureSerializationException("Invalid JSON data");
        }

        // Validate the structure matches expected type
        $validationResult = $this->validateDataStructure($data, $expectedType);
        if (!$validationResult->isValid()) {
            $this->logger->warning("Data structure validation failed", [
                'errors' => $validationResult->getErrors()
            ]);
            throw new SecureSerializationException("Data structure validation failed");
        }

        return $this->hydrateObject($data, $expectedType);
    }

    private function validateDataStructure(array $data, string $expectedType): ValidationResult
    {
        $result = new ValidationResult();
        
        // Implementation would validate the array structure
        // matches the expected type's requirements
        
        return $result;
    }

    private function hydrateObject(array $data, string $className)
    {
        // Implementation would create and hydrate
        // an object of the specified class
    }
}
```

### 5. CI/CD Pipeline Security

#### Secure Build Validation

```php
class BuildSecurityValidator
{
    private $dependencyScanner;
    private $codeAnalyzer;
    private $logger;

    public function __construct(
        DependencyScanner $dependencyScanner,
        CodeAnalyzer $codeAnalyzer,
        LoggerInterface $logger
    ) {
        $this->dependencyScanner = $dependencyScanner;
        $this->codeAnalyzer = $codeAnalyzer;
        $this->logger = $logger;
    }

    public function validateBuild(BuildArtifact $artifact): BuildValidationResult
    {
        $result = new BuildValidationResult();
        
        // 1. Dependency scanning
        $dependencyResult = $this->dependencyScanner->scan($artifact);
        if ($dependencyResult->hasVulnerabilities()) {
            foreach ($dependencyResult->getVulnerabilities() as $vuln) {
                $result->addError("Dependency vulnerability: {$vuln->getPackageName()}@{$vuln->getPackageVersion()} - {$vuln->getDescription()}");
            }
        }

        // 2. Static code analysis
        $codeAnalysisResult = $this->codeAnalyzer->analyze($artifact);
        foreach ($codeAnalysisResult->getIssues() as $issue) {
            if ($issue->getSeverity() >= IssueSeverity::HIGH) {
                $result->addError("Code issue: {$issue->getDescription()} in {$issue->getFilePath()}");
            }
        }

        // 3. Validate build signatures
        if (!$artifact->isSigned()) {
            $result->addError("Build artifact is not signed");
        }

        // 4. Validate build environment
        if (!$artifact->getBuildEnvironment()->isTrusted()) {
            $result->addError("Build was not performed in a trusted environment");
        }

        return $result;
    }
}
```

## Implementation Checklist

1. **Code Integrity**
   - Implement code signing for critical files
   - Verify signatures before deployment
   - Secure your build pipeline against tampering

2. **Update Security**
   - Use cryptographic signatures for update packages
   - Verify updates before installation
   - Secure your update distribution mechanism

3. **Data Protection**
   - Implement end-to-end encryption for sensitive data
   - Use digital signatures for critical data
   - Protect data in transit and at rest

4. **Secure Serialization**
   - Avoid unserializing user input
   - Implement strict type checking
   - Validate all deserialized data

5. **CI/CD Security**
   - Secure your build environment
   - Scan for vulnerabilities during build
   - Verify artifacts before deployment

6. **Runtime Protection**
   - Implement integrity checks
   - Monitor for tampering attempts
   - Respond to integrity violations

## PHP-Specific Recommendations

1. **Secure File Uploads**
   - Verify file signatures (not just extensions)
   - Store uploads outside web root
   - Disable PHP execution in upload directories

2. **Composer Security**
   - Use `composer audit` to check for vulnerabilities
   - Prefer stable package versions
   - Review dependency changes before updates

3. **WordPress Specific**
   - Verify plugin/theme checksums before installation
   - Use signed updates from trusted sources
   - Disable file editing in admin panel

4. **Laravel Specific**
   - Use signed URLs for sensitive actions
   - Validate signed route parameters
   - Protect against mass assignment

5. **General PHP Security**
   - Disable dangerous PHP functions
   - Use `hash_equals()` for timing-safe comparisons
   - Generate cryptographically secure random values

## Example Secure Deployment Workflow

```bash
#!/bin/bash
# Secure deployment script for PHP applications

# 1. Verify git commit signature
if ! git verify-commit HEAD; then
    echo "Error: Invalid commit signature"
    exit 1
fi

# 2. Verify Composer dependencies
composer install --no-dev --prefer-dist --optimize-autoloader
composer audit
if [ $? -ne 0 ]; then
    echo "Error: Vulnerable dependencies detected"
    exit 1
fi

# 3. Verify build artifacts
php artisan build:verify --signature=$BUILD_SIGNATURE
if [ $? -ne 0 ]; then
    echo "Error: Build verification failed"
    exit 1
fi

# 4. Deploy to staging for final checks
rsync -avz --checksum ./ user@staging:/var/www/app

# 5. Run integration tests on staging
ssh user@staging "cd /var/www/app && php artisan test"
if [ $? -ne 0 ]; then
    echo "Error: Staging tests failed"
    exit 1
fi

# 6. Final production deployment
rsync -avz --checksum ./ user@production:/var/www/app
ssh user@production "cd /var/www/app && php artisan migrate --force"
```
