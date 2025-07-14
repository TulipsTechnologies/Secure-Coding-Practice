# Secure Coding Practices for .NET API: Addressing OWASP Top 10 (A08:2021 - Software and Data Integrity Failures)

## Comprehensive Data Integrity Protection System

### 1. Secure Code Deployment Pipeline

#### Code Signing and Verification Service

```csharp
public class CodeSigningService
{
    private readonly X509Certificate2 _signingCertificate;
    private readonly ILogger<CodeSigningService> _logger;

    public CodeSigningService(
        IConfiguration config,
        ILogger<CodeSigningService> logger)
    {
        _signingCertificate = LoadCertificate(config["CodeSigning:CertPath"], 
                                           config["CodeSigning:CertPassword"]);
        _logger = logger;
    }

    public byte[] SignAssembly(byte[] assemblyBytes)
    {
        using var rsa = _signingCertificate.GetRSAPrivateKey();
        var hash = SHA256.HashData(assemblyBytes);
        var signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        _logger.LogInformation("Assembly signed with certificate {Thumbprint}", 
            _signingCertificate.Thumbprint);
            
        return signature;
    }

    public bool VerifyAssembly(byte[] assemblyBytes, byte[] signature)
    {
        using var rsa = _signingCertificate.GetRSAPublicKey();
        var hash = SHA256.HashData(assemblyBytes);
        var isValid = rsa.VerifyHash(hash, signature, 
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            
        if (!isValid)
        {
            _logger.LogWarning("Assembly signature verification failed");
        }
        
        return isValid;
    }

    private X509Certificate2 LoadCertificate(string path, string password)
    {
        try
        {
            return new X509Certificate2(path, password, 
                X509KeyStorageFlags.EphemeralKeySet | 
                X509KeyStorageFlags.Exportable);
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "Failed to load code signing certificate");
            throw new SecurityException("Code signing certificate load failed", ex);
        }
    }
}

// CI/CD Integration Example
public class BuildPipelineService
{
    private readonly CodeSigningService _signingService;
    private readonly IArtifactRepository _artifactRepo;

    public BuildPipelineService(
        CodeSigningService signingService,
        IArtifactRepository artifactRepo)
    {
        _signingService = signingService;
        _artifactRepo = artifactRepo;
    }

    public async Task<BuildResult> BuildAndSignAsync(ProjectBuildRequest request)
    {
        var buildResult = await BuildProjectAsync(request);
        
        // Sign all output assemblies
        foreach (var artifact in buildResult.Artifacts)
        {
            var signature = _signingService.SignAssembly(artifact.Content);
            artifact.Signature = signature;
        }
        
        // Store signed artifacts
        await _artifactRepo.StoreAsync(buildResult);
        
        return buildResult;
    }
}
```

### 2. Secure Update Mechanism

#### Cryptographic Update Verification System

```csharp
public class SecureUpdateService
{
    private readonly IUpdateRepository _updateRepo;
    private readonly CodeSigningService _signingService;
    private readonly ILogger<SecureUpdateService> _logger;

    public SecureUpdateService(
        IUpdateRepository updateRepo,
        CodeSigningService signingService,
        ILogger<SecureUpdateService> logger)
    {
        _updateRepo = updateRepo;
        _signingService = signingService;
        _logger = logger;
    }

    public async Task<UpdateVerificationResult> VerifyUpdateAsync(
        string updatePackagePath)
    {
        var result = new UpdateVerificationResult();
        
        try
        {
            // Step 1: Verify package signature
            var package = await _updateRepo.GetPackageAsync(updatePackagePath);
            if (!_signingService.VerifyAssembly(
                package.Content, package.Signature))
            {
                result.Errors.Add("Invalid package signature");
                _logger.LogError("Update package signature verification failed");
                return result;
            }

            // Step 2: Verify manifest integrity
            var manifestHash = ComputeManifestHash(package.Manifest);
            if (!manifestHash.SequenceEqual(package.ManifestHash))
            {
                result.Errors.Add("Manifest integrity check failed");
                _logger.LogError("Update package manifest verification failed");
                return result;
            }

            // Step 3: Verify dependency graph
            var dependencyResult = VerifyDependencies(package.Manifest);
            if (!dependencyResult.IsValid)
            {
                result.Errors.AddRange(dependencyResult.Errors);
                return result;
            }

            result.IsValid = true;
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Update verification failed");
            result.Errors.Add("Update verification process failed");
            return result;
        }
    }

    private byte[] ComputeManifestHash(UpdateManifest manifest)
    {
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(Encoding.UTF8.GetBytes(manifest.ToJson()));
    }

    private DependencyVerificationResult VerifyDependencies(UpdateManifest manifest)
    {
        var result = new DependencyVerificationResult();
        
        foreach (var dependency in manifest.Dependencies)
        {
            if (!_updateRepo.IsDependencyAllowed(dependency))
            {
                result.Errors.Add($"Dependency {dependency.Name}@{dependency.Version} is not allowed");
            }
        }
        
        result.IsValid = !result.Errors.Any();
        return result;
    }
}
```

### 3. Data Integrity Protection

#### Cryptographic Data Integrity Service

```csharp
public class DataIntegrityService
{
    private readonly IKeyVaultService _keyVault;
    private readonly ILogger<DataIntegrityService> _logger;

    public DataIntegrityService(
        IKeyVaultService keyVault,
        ILogger<DataIntegrityService> logger)
    {
        _keyVault = keyVault;
        _logger = logger;
    }

    public async Task<SignedData> SignDataAsync(byte[] data, string keyId)
    {
        try
        {
            var key = await _keyVault.GetKeyAsync(keyId);
            var hash = SHA256.HashData(data);
            var signature = await _keyVault.SignAsync(keyId, hash);
            
            return new SignedData
            {
                Data = data,
                Signature = signature,
                KeyId = keyId,
                Algorithm = "SHA256withRSA",
                Timestamp = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Data signing failed");
            throw new DataIntegrityException("Data signing operation failed", ex);
        }
    }

    public async Task<bool> VerifyDataAsync(SignedData signedData)
    {
        try
        {
            var hash = SHA256.HashData(signedData.Data);
            return await _keyVault.VerifyAsync(
                signedData.KeyId, 
                hash, 
                signedData.Signature);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Data verification failed");
            return false;
        }
    }

    public async Task<EncryptedData> EncryptDataAsync(byte[] data, string keyId)
    {
        try
        {
            // Generate random AES key
            var aesKey = GenerateAesKey();
            
            // Encrypt data with AES
            var iv = GenerateRandomIv();
            var encryptedData = EncryptWithAes(data, aesKey, iv);
            
            // Encrypt AES key with RSA
            var encryptedKey = await _keyVault.EncryptAsync(keyId, aesKey);
            
            return new EncryptedData
            {
                CipherText = encryptedData,
                EncryptedKey = encryptedKey,
                Iv = iv,
                KeyId = keyId,
                Algorithm = "AES-256-CBC with RSA-OAEP",
                Timestamp = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Data encryption failed");
            throw new DataIntegrityException("Data encryption failed", ex);
        }
    }

    public async Task<byte[]> DecryptDataAsync(EncryptedData encryptedData)
    {
        try
        {
            // Decrypt AES key with RSA
            var aesKey = await _keyVault.DecryptAsync(
                encryptedData.KeyId, 
                encryptedData.EncryptedKey);
                
            // Decrypt data with AES
            return DecryptWithAes(
                encryptedData.CipherText, 
                aesKey, 
                encryptedData.Iv);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Data decryption failed");
            throw new DataIntegrityException("Data decryption failed", ex);
        }
    }
}
```

### 4. Secure Deserialization

#### Safe Serialization Service with Validation

```csharp
public class SecureSerializer
{
    private readonly JsonSerializerSettings _settings;
    private readonly ILogger<SecureSerializer> _logger;

    public SecureSerializer(
        ITypeResolver typeResolver,
        ILogger<SecureSerializer> logger)
    {
        _logger = logger;
        
        _settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.None, // Critical for security
            ContractResolver = new SecureContractResolver(typeResolver),
            MissingMemberHandling = MissingMemberHandling.Error,
            DateParseHandling = DateParseHandling.None,
            MaxDepth = 32,
            SerializationBinder = new BlockedTypesBinder()
        };
    }

    public string Serialize<T>(T obj)
    {
        return JsonConvert.SerializeObject(obj, _settings);
    }

    public T Deserialize<T>(string json)
    {
        try
        {
            return JsonConvert.DeserializeObject<T>(json, _settings);
        }
        catch (JsonSerializationException ex)
        {
            _logger.LogWarning(ex, "Potential unsafe deserialization attempt");
            throw new SecureSerializationException("Invalid JSON structure", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Deserialization failed");
            throw new SecureSerializationException("Deserialization error", ex);
        }
    }
}

public class BlockedTypesBinder : ISerializationBinder
{
    private readonly HashSet<string> _allowedTypes = new()
    {
        "System.String", "System.Int32", "System.DateTime",
        "MyApp.Models.SafeType1", "MyApp.Models.SafeType2"
    };

    public Type BindToType(string assemblyName, string typeName)
    {
        var fullName = $"{typeName}, {assemblyName}";
        if (!_allowedTypes.Contains(fullName))
        {
            throw new JsonSerializationException(
                $"Type {fullName} is not allowed for deserialization");
        }
        
        return Type.GetType(fullName);
    }

    public void BindToName(Type serializedType, out string assemblyName, out string typeName)
    {
        assemblyName = null;
        typeName = null;
    }
}
```

### 5. CI/CD Pipeline Security

#### Secure Build Validation Service

```csharp
public class BuildSecurityValidator
{
    private readonly IDependencyScanner _dependencyScanner;
    private readonly ICodeAnalyzer _codeAnalyzer;
    private readonly ILogger<BuildSecurityValidator> _logger;

    public BuildSecurityValidator(
        IDependencyScanner dependencyScanner,
        ICodeAnalyzer codeAnalyzer,
        ILogger<BuildSecurityValidator> logger)
    {
        _dependencyScanner = dependencyScanner;
        _codeAnalyzer = codeAnalyzer;
        _logger = logger;
    }

    public async Task<BuildValidationResult> ValidateBuildAsync(BuildArtifact artifact)
    {
        var result = new BuildValidationResult();
        
        // 1. Dependency scanning
        var dependencyResult = await _dependencyScanner.ScanAsync(artifact);
        if (dependencyResult.Vulnerabilities.Any())
        {
            result.Errors.AddRange(dependencyResult.Vulnerabilities
                .Select(v => $"Dependency vulnerability: {v.PackageName}@{v.PackageVersion} - {v.Description}"));
        }

        // 2. Static code analysis
        var codeAnalysisResult = await _codeAnalyzer.AnalyzeAsync(artifact);
        if (codeAnalysisResult.Issues.Any())
        {
            result.Errors.AddRange(codeAnalysisResult.Issues
                .Where(i => i.Severity >= IssueSeverity.High)
                .Select(i => $"Code issue: {i.Description} in {i.FilePath}"));
        }

        // 3. Validate build signatures
        if (!artifact.IsSigned)
        {
            result.Errors.Add("Build artifact is not signed");
        }

        // 4. Validate build environment
        if (!artifact.BuildEnvironment.IsTrusted)
        {
            result.Errors.Add("Build was not performed in a trusted environment");
        }

        result.IsValid = !result.Errors.Any();
        return result;
    }
}
```

## Implementation Checklist

1. **Code Integrity**
   - Implement code signing for all assemblies
   - Verify signatures before loading/executing code
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
   - Avoid dangerous serialization formats
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
