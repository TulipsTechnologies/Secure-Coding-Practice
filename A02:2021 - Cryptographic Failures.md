# Secure Coding Practices for .NET API: Addressing OWASP Top 10 (A02:2021 - Cryptographic Failures)

## Introduction to Cryptographic Failures

Cryptographic failures (previously called "Sensitive Data Exposure") rank as the #2 security risk. This category focuses on failures related to cryptography which often lead to exposure of sensitive data or system compromise. In .NET APIs, we need to ensure proper handling of encryption, hashing, keys, and certificates.

## Common Cryptographic Failures in .NET APIs

1. **Insecure or Deprecated Algorithms**
2. **Improper Key Management**
3. **Hardcoded Secrets**
4. **Insufficient Entropy**
5. **Insecure Random Number Generation**
6. **Improper Certificate Validation**
7. **Weak Password Hashing**

## Step-by-Step Implementation Guide

### 1. Data Encryption Best Practices

#### Symmetric Encryption (AES)

```csharp
// Service for handling AES encryption
public class AesEncryptionService
{
    private readonly byte[] _key;
    
    public AesEncryptionService(IConfiguration configuration)
    {
        // Key should be 128, 192, or 256 bits (16, 24, or 32 bytes)
        _key = Convert.FromBase64String(configuration["Encryption:Key"]);
        
        if (_key.Length != 16 && _key.Length != 24 && _key.Length != 32)
            throw new ArgumentException("Invalid key size");
    }

    public string Encrypt(string plainText)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.GenerateIV(); // Important: Never reuse IV
        
        using var encryptor = aes.CreateEncryptor();
        using var ms = new MemoryStream();
        
        // Write IV first (unencrypted)
        ms.Write(aes.IV, 0, aes.IV.Length);
        
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        using (var sw = new StreamWriter(cs))
        {
            sw.Write(plainText);
        }
        
        return Convert.ToBase64String(ms.ToArray());
    }

    public string Decrypt(string cipherText)
    {
        var buffer = Convert.FromBase64String(cipherText);
        
        using var aes = Aes.Create();
        aes.Key = _key;
        
        // Read IV from first 16 bytes
        var iv = new byte[16];
        Array.Copy(buffer, 0, iv, 0, iv.Length);
        aes.IV = iv;
        
        using var decryptor = aes.CreateDecryptor();
        using var ms = new MemoryStream();
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write);
        
        // Write the rest of the ciphertext
        cs.Write(buffer, iv.Length, buffer.Length - iv.Length);
        cs.FlushFinalBlock();
        
        return Encoding.UTF8.GetString(ms.ToArray());
    }
}
```

#### Asymmetric Encryption (RSA)

```csharp
public class RsaEncryptionService
{
    private readonly RSA _rsa;

    public RsaEncryptionService(IConfiguration configuration)
    {
        _rsa = RSA.Create();
        
        // Load key from configuration (better to use certificate)
        var keyXml = configuration["Encryption:RsaPrivateKey"];
        _rsa.FromXmlString(keyXml);
    }

    public string Encrypt(string plainText)
    {
        var bytes = Encoding.UTF8.GetBytes(plainText);
        var encrypted = _rsa.Encrypt(bytes, RSAEncryptionPadding.OaepSHA256);
        return Convert.ToBase64String(encrypted);
    }

    public string Decrypt(string cipherText)
    {
        var bytes = Convert.FromBase64String(cipherText);
        var decrypted = _rsa.Decrypt(bytes, RSAEncryptionPadding.OaepSHA256);
        return Encoding.UTF8.GetString(decrypted);
    }
}
```

### 2. Secure Key Management

```csharp
// Program.cs - Using Azure Key Vault
builder.Services.AddAzureKeyVault(
    new Uri(builder.Configuration["KeyVault:VaultUri"]),
    new DefaultAzureCredential());

// Key rotation service
public class KeyRotationService : BackgroundService
{
    private readonly IKeyVaultClient _keyVaultClient;
    private readonly IConfiguration _configuration;
    
    public KeyRotationService(IKeyVaultClient keyVaultClient, IConfiguration configuration)
    {
        _keyVaultClient = keyVaultClient;
        _configuration = configuration;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            // Rotate keys every 30 days
            await Task.Delay(TimeSpan.FromDays(30), stoppingToken);
            
            try
            {
                var newKey = await _keyVaultClient.CreateKeyAsync(
                    _configuration["KeyVault:KeyName"],
                    KeyType.Rsa,
                    new KeyCreateOptions
                    {
                        KeySize = 2048,
                        Expires = DateTimeOffset.Now.AddDays(90)
                    });
                
                // Update configuration
                _configuration["Encryption:RsaPublicKey"] = newKey.Key.ToXmlString(false);
            }
            catch (Exception ex)
            {
                // Log and retry
            }
        }
    }
}
```

### 3. Secure Password Hashing (Argon2 or PBKDF2)

```csharp
// Using the libsodium-net library for Argon2
public class PasswordHasher
{
    public string HashPassword(string password)
    {
        // Generate a 16-byte salt
        var salt = Sodium.PasswordHash.ArgonGenerateSalt();
        
        // Hash with Argon2id (recommended parameters)
        var hash = Sodium.PasswordHash.ArgonHashString(
            password,
            salt,
            opsLimit: Sodium.PasswordHash.ArgonOpsLimitInteractive,
            memLimit: Sodium.PasswordHash.ArgonMemLimitInteractive);
            
        return hash;
    }

    public bool VerifyPassword(string hashedPassword, string password)
    {
        return Sodium.PasswordHash.ArgonHashStringVerify(hashedPassword, password);
    }
}

// Alternative using PBKDF2 (built into .NET)
public class Pbkdf2PasswordHasher
{
    private const int SaltSize = 16; // 128 bits
    private const int HashSize = 32; // 256 bits
    private const int Iterations = 100000;

    public string HashPassword(string password)
    {
        // Generate salt
        using var rng = RandomNumberGenerator.Create();
        var salt = new byte[SaltSize];
        rng.GetBytes(salt);
        
        // Generate hash
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
        var hash = pbkdf2.GetBytes(HashSize);
        
        // Combine salt and hash
        var hashBytes = new byte[SaltSize + HashSize];
        Array.Copy(salt, 0, hashBytes, 0, SaltSize);
        Array.Copy(hash, 0, hashBytes, SaltSize, HashSize);
        
        return Convert.ToBase64String(hashBytes);
    }

    public bool VerifyPassword(string hashedPassword, string password)
    {
        // Extract bytes
        var hashBytes = Convert.FromBase64String(hashedPassword);
        
        // Get salt
        var salt = new byte[SaltSize];
        Array.Copy(hashBytes, 0, salt, 0, SaltSize);
        
        // Compute hash
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
        var hash = pbkdf2.GetBytes(HashSize);
        
        // Compare
        for (var i = 0; i < HashSize; i++)
        {
            if (hashBytes[i + SaltSize] != hash[i])
                return false;
        }
        
        return true;
    }
}
```

### 4. Secure Random Number Generation

```csharp
// Proper random number generation
public class SecureRandomGenerator
{
    public int GenerateSecureRandom(int minValue, int maxValue)
    {
        if (minValue >= maxValue)
            throw new ArgumentException("minValue must be less than maxValue");
            
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[4];
        rng.GetBytes(bytes);
        
        // Convert to positive integer
        var randomValue = Math.Abs(BitConverter.ToInt32(bytes, 0));
        
        // Scale to range
        return minValue + (randomValue % (maxValue - minValue));
    }

    public string GenerateSecureToken(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._";
        using var rng = RandomNumberGenerator.Create();
        var data = new byte[length];
        rng.GetBytes(data);
        
        var result = new StringBuilder(length);
        foreach (var b in data)
        {
            result.Append(chars[b % chars.Length]);
        }
        
        return result.ToString();
    }
}
```

### 5. Secure Certificate Validation

```csharp
// Custom certificate validation for HttpClient
public class CertificateValidationHandler : HttpClientHandler
{
    private readonly string _thumbprint;

    public CertificateValidationHandler(string thumbprint)
    {
        _thumbprint = thumbprint;
        ServerCertificateCustomValidationCallback = ValidateCertificate;
    }

    private bool ValidateCertificate(HttpRequestMessage request, 
                                   X509Certificate2 cert, 
                                   X509Chain chain, 
                                   SslPolicyErrors errors)
    {
        // Check for basic SSL policy errors
        if (errors != SslPolicyErrors.None)
            return false;
            
        // Verify thumbprint matches expected
        return string.Equals(
            cert.Thumbprint,
            _thumbprint,
            StringComparison.OrdinalIgnoreCase);
    }
}

// Usage
var handler = new CertificateValidationHandler("A909502DD82AE41433E6F83886B00D4277A32A7B");
var httpClient = new HttpClient(handler);
```

### 6. Protecting Sensitive Data in Configuration

```csharp
// Using Azure App Configuration with Key Vault references
builder.Configuration.AddAzureAppConfiguration(options =>
{
    options.Connect(builder.Configuration["ConnectionStrings:AppConfig"])
           .ConfigureKeyVault(kv =>
           {
               kv.SetCredential(new DefaultAzureCredential());
           });
});

// Using Data Protection API for local secrets
builder.Services.AddDataProtection()
    .PersistKeysToAzureBlobStorage(new Uri(builder.Configuration["DataProtection:BlobUri"]))
    .ProtectKeysWithAzureKeyVault(
        new Uri(builder.Configuration["KeyVault:KeyIdentifier"]),
        new DefaultAzureCredential());
```

### 7. Secure JWT Token Handling

```csharp
// JWT configuration with strong security settings
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidateAudience = true,
            ValidAudience = builder.Configuration["Jwt:Audience"],
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.Zero, // No tolerance for expired tokens
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new X509SecurityKey(
                new X509Certificate2(
                    builder.Configuration["Jwt:CertificatePath"],
                    builder.Configuration["Jwt:CertificatePassword"]))
        };
        
        // Additional security
        options.RequireHttpsMetadata = true;
        options.SaveToken = false; // Don't store token in AuthenticationProperties
    });
```

## Testing Cryptographic Implementations

```csharp
[Fact]
public void AesEncryption_Decrypts_WhatItEncrypts()
{
    // Arrange
    var config = new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string>
        {
            ["Encryption:Key"] = Convert.ToBase64String(new byte[] { 
                // 256-bit key
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
            })
        }.Build());
    
    var service = new AesEncryptionService(config);
    var original = "Sensitive data";
    
    // Act
    var encrypted = service.Encrypt(original);
    var decrypted = service.Decrypt(encrypted);
    
    // Assert
    Assert.Equal(original, decrypted);
}

[Fact]
public void PasswordHasher_Verifies_CorrectPassword()
{
    // Arrange
    var hasher = new PasswordHasher();
    var password = "SecurePassword123!";
    
    // Act
    var hash = hasher.HashPassword(password);
    var result = hasher.VerifyPassword(hash, password);
    
    // Assert
    Assert.True(result);
}

[Fact]
public void PasswordHasher_Rejects_IncorrectPassword()
{
    // Arrange
    var hasher = new PasswordHasher();
    var password = "SecurePassword123!";
    var wrongPassword = "WrongPassword456?";
    
    // Act
    var hash = hasher.HashPassword(password);
    var result = hasher.VerifyPassword(hash, wrongPassword);
    
    // Assert
    Assert.False(result);
}
```

## Monitoring and Logging Cryptographic Operations

```csharp
// Audit logging for cryptographic operations
public class CryptographicAuditLogger
{
    private readonly ILogger<CryptographicAuditLogger> _logger;
    
    public CryptographicAuditLogger(ILogger<CryptographicAuditLogger> logger)
    {
        _logger = logger;
    }
    
    public void LogEncryptionOperation(string operation, string keyId, bool success)
    {
        _logger.LogInformation("Crypto operation {Operation} with key {KeyId} - Success: {Success}",
            operation,
            keyId,
            success);
            
        if (!success)
        {
            _logger.LogWarning("Failed crypto operation detected");
            // Alert security team
        }
    }
    
    public void LogKeyRotation(string keyId, string operation)
    {
        _logger.LogInformation("Key rotation {Operation} for key {KeyId}",
            operation,
            keyId);
    }
}

// Example usage in encryption service
public class AuditedEncryptionService
{
    private readonly AesEncryptionService _encryptionService;
    private readonly CryptographicAuditLogger _auditLogger;
    
    public AuditedEncryptionService(AesEncryptionService encryptionService, 
                                  CryptographicAuditLogger auditLogger)
    {
        _encryptionService = encryptionService;
        _auditLogger = auditLogger;
    }
    
    public string Encrypt(string plainText)
    {
        try
        {
            var result = _encryptionService.Encrypt(plainText);
            _auditLogger.LogEncryptionOperation("Encrypt", "AES-256", true);
            return result;
        }
        catch
        {
            _auditLogger.LogEncryptionOperation("Encrypt", "AES-256", false);
            throw;
        }
    }
}
```

## Best Practices Summary

1. **Always use standard, vetted cryptographic libraries** - Never implement your own crypto
2. **Use appropriate algorithms**:
   - Symmetric: AES (128-bit or higher)
   - Asymmetric: RSA (2048-bit or higher) or ECC (256-bit or higher)
   - Hashing: SHA-2 or SHA-3 family (SHA256, SHA512, etc.)
   - Password hashing: Argon2, PBKDF2, bcrypt
3. **Proper key management**:
   - Store keys in secure key vaults (Azure Key Vault, AWS KMS, etc.)
   - Implement key rotation policies
   - Never hardcode keys in source code
4. **Use proper random number generation**:
   - `RandomNumberGenerator` for crypto purposes
   - Never use `System.Random` for security-related randomness
5. **Secure configuration**:
   - Use secure storage for secrets
   - Encrypt sensitive configuration values
6. **Certificate validation**:
   - Always validate certificates
   - Pin certificates when possible
7. **Password handling**:
   - Use strong, adaptive hashing algorithms
   - Add salt to every hash
   - Use high iteration counts/work factors
8. **Audit and monitor**:
   - Log cryptographic operations
   - Alert on failures
9. **Stay updated**:
   - Monitor for deprecated algorithms
   - Update libraries regularly
