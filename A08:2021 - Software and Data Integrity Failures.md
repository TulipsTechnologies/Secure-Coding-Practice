# Secure Coding Practices for Next.js API: Addressing OWASP Top 10 (A08:2021 - Software and Data Integrity Failures)

---

## Comprehensive Data Integrity Protection System for Next.js

---

### 1️⃣ Secure Code Deployment Pipeline

#### Code Signing & Verification Middleware

```ts
// lib/codeSigning.ts
import crypto from "crypto";
import fs from "fs";
import path from "path";

const privateKeyPath = process.env.CODE_SIGNING_PRIVATE_KEY_PATH!;
const publicKeyPath = process.env.CODE_SIGNING_PUBLIC_KEY_PATH!;

export function signCode(buffer: Buffer): Buffer {
  const privateKey = fs.readFileSync(privateKeyPath, "utf8");
  const signer = crypto.createSign("SHA256");
  signer.update(buffer);
  signer.end();
  return signer.sign(privateKey);
}

export function verifyCode(buffer: Buffer, signature: Buffer): boolean {
  const publicKey = fs.readFileSync(publicKeyPath, "utf8");
  const verifier = crypto.createVerify("SHA256");
  verifier.update(buffer);
  verifier.end();
  return verifier.verify(publicKey, signature);
}
```

**CI/CD Integration Example (Node.js script)**

```ts
import { signCode } from "./lib/codeSigning";
import fs from "fs";

async function buildAndSign() {
  // Simulate build artifact reading
  const artifactBuffer = fs.readFileSync("./build/main.js");

  // Sign artifact
  const signature = signCode(artifactBuffer);

  // Save signature alongside artifact
  fs.writeFileSync("./build/main.js.sig", signature);

  console.log("Build artifact signed successfully");
}

buildAndSign().catch(console.error);
```

---

### 2️⃣ Secure Update Mechanism

#### Cryptographic Update Package Verification

```ts
// lib/updateVerifier.ts
import crypto from "crypto";
import fs from "fs";

export async function verifyUpdatePackage(
  packagePath: string,
  signaturePath: string,
  publicKeyPath: string
): Promise<boolean> {
  const packageData = fs.readFileSync(packagePath);
  const signature = fs.readFileSync(signaturePath);
  const publicKey = fs.readFileSync(publicKeyPath, "utf8");

  const verify = crypto.createVerify("SHA256");
  verify.update(packageData);
  verify.end();

  return verify.verify(publicKey, signature);
}
```

**Manifest and Dependency Verification**

```ts
// lib/manifestVerifier.ts
import crypto from "crypto";

interface UpdateManifest {
  version: string;
  dependencies: { name: string; version: string }[];
  hash: string; // SHA256 hash of manifest content
}

export function computeManifestHash(manifest: UpdateManifest): string {
  const json = JSON.stringify(manifest, Object.keys(manifest).sort());
  return crypto.createHash("sha256").update(json).digest("hex");
}

export function verifyManifest(manifest: UpdateManifest): boolean {
  const computedHash = computeManifestHash(manifest);
  return computedHash === manifest.hash;
}

export function verifyAllowedDependencies(
  manifest: UpdateManifest,
  allowedDeps: Record<string, string>
): string[] {
  return manifest.dependencies
    .filter(dep => allowedDeps[dep.name] !== dep.version)
    .map(dep => `Dependency ${dep.name}@${dep.version} not allowed`);
}
```

---

### 3️⃣ Data Integrity Protection

#### Cryptographic Signing and Verification of Data

```ts
// lib/dataIntegrity.ts
import crypto from "crypto";

export function signData(data: Buffer, privateKeyPem: string): Buffer {
  const signer = crypto.createSign("SHA256");
  signer.update(data);
  signer.end();
  return signer.sign(privateKeyPem);
}

export function verifyData(
  data: Buffer,
  signature: Buffer,
  publicKeyPem: string
): boolean {
  const verifier = crypto.createVerify("SHA256");
  verifier.update(data);
  verifier.end();
  return verifier.verify(publicKeyPem, signature);
}

// AES-256-CBC Encryption/Decryption

export function encryptData(data: Buffer, key: Buffer, iv: Buffer): Buffer {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

export function decryptData(data: Buffer, key: Buffer, iv: Buffer): Buffer {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}
```

---

### 4️⃣ Secure Deserialization

#### Safe JSON Parsing with Schema Validation

```ts
// lib/secureDeserialize.ts
import Ajv, { JSONSchemaType } from "ajv";

const ajv = new Ajv();

interface SafePayload {
  id: string;
  name: string;
  timestamp: string;
}

const schema: JSONSchemaType<SafePayload> = {
  type: "object",
  properties: {
    id: { type: "string" },
    name: { type: "string" },
    timestamp: { type: "string", format: "date-time" },
  },
  required: ["id", "name", "timestamp"],
  additionalProperties: false,
};

const validate = ajv.compile(schema);

export function deserializeSafePayload(jsonString: string): SafePayload {
  const parsed = JSON.parse(jsonString);

  if (!validate(parsed)) {
    throw new Error(`Invalid payload: ${ajv.errorsText(validate.errors)}`);
  }

  return parsed;
}
```

**Key Points:**

* Avoid `eval()` or deserializing arbitrary types.
* Use strict schema validation (e.g., with Ajv).
* Reject unexpected or extra properties.
* Validate data formats strictly.

---

### 5️⃣ CI/CD Pipeline Security

#### Static Code Analysis & Dependency Checks Integration (Example with Node.js tools)

```json
// package.json scripts
{
  "scripts": {
    "lint": "eslint . --ext .ts,.tsx",
    "security-check": "npm audit --json > audit-report.json",
    "test": "jest",
    "build": "next build"
  }
}
```

**Pipeline Script (simplified)**

```bash
#!/bin/bash
set -e

# 1. Run static code analysis
npm run lint

# 2. Run security audit
npm audit --json > audit-report.json
if grep -q '"severity": "high"' audit-report.json; then
  echo "High severity vulnerabilities found. Failing build."
  exit 1
fi

# 3. Run tests
npm test

# 4. Build project
npm run build

# 5. (Optional) Sign build artifact using Node.js script (see #1)
node scripts/signBuild.js
```

---

## Implementation Checklist

| #   | Best Practice                                                                            |
| --- | ---------------------------------------------------------------------------------------- |
| 1️⃣ | Sign JavaScript bundles and server code; verify signatures before deploy or runtime load |
| 2️⃣ | Verify update packages cryptographically before applying                                 |
| 3️⃣ | Validate manifest and dependencies strictly                                              |
| 4️⃣ | Sign and verify critical data; use AES + RSA hybrid encryption if needed                 |
| 5️⃣ | Avoid unsafe deserialization; use strict JSON schema validation                          |
| 6️⃣ | Integrate static code analysis, dependency audit, and signing in CI/CD pipelines         |
| 7️⃣ | Secure private keys and signing credentials in environment or vaults                     |
| 8️⃣ | Monitor runtime integrity; detect unexpected code or config changes                      |
| 9️⃣ | Limit build environment to trusted runners with audit logging                            |
| 🔟  | Keep dependencies and security tools up to date                                          |

---

This approach secures the full chain of code and data integrity for Next.js applications—mirroring your .NET example but adapted to JavaScript/TypeScript ecosystem with practical, ready-to-use code snippets.
