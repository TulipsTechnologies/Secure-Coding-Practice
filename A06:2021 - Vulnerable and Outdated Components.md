## 🔐 Secure Coding Practices for **Next.js Frontend**

**OWASP A06:2021 — Vulnerable and Outdated Components**

---

### 📌 Why this matters for **frontend devs**

A vulnerable React/Next.js project can:

* Include unpatched npm packages
* Leak security bugs from old Node.js runtimes
* Be compromised by supply chain attacks (npm typosquatting, malicious packages)
* Have unverified dependencies or indirect dependencies with CVEs
* Bundle infected third-party scripts (CDNs, fonts, analytics)

---

## ⚡️ Common Weak Points

✅ Unpinned `package.json` versions (`"^"` or `"*"`)
✅ Old Node.js runtime in production
✅ No lockfile enforcement (`package-lock.json` or `pnpm-lock.yaml`)
✅ No scanning for known CVEs in packages
✅ Bundling unverified external scripts or libraries
✅ Ignoring transitive dependencies
✅ No monitoring of new CVEs after deploy

---

## 🔒 Step-by-Step Secure Component Management

---

### ✅ 1️⃣ Enforce strict version pinning

**Bad:**

```json
"dependencies": {
  "next": "^13.4.0",
  "react": "^18.2.0"
}
```

**Good:**

```json
"dependencies": {
  "next": "13.4.21",
  "react": "18.2.0"
}
```

✔️ Use `npm ci` or `pnpm install --frozen-lockfile` in CI/CD to prevent accidental drift.

---

### ✅ 2️⃣ Lock your lockfile

* Commit `package-lock.json` or `pnpm-lock.yaml`
* Never delete it in CI
* Validate checksum with `npm audit` or `pnpm audit`

---

### ✅ 3️⃣ Use reliable registry mirrors

Use `.npmrc`:

```bash
registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
strict-ssl=true
```

✔️ Use **npm’s 2FA** for publishing if you maintain your own packages.

---

### ✅ 4️⃣ Automate CVE scanning in CI/CD

**GitHub Actions example:**

```yaml
name: "Dependency Audit"

on:
  pull_request:
  push:
    branches: [ main ]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm audit --audit-level=high
```

✔️ Fail the build if `npm audit` finds known CVEs.

---

### ✅ 5️⃣ Watch for indirect vulnerabilities

Use:

* `npm audit` or `pnpm audit`
* `npm outdated` for version drift
* `npm ls <package>` to find where a risky indirect dependency comes from

---

### ✅ 6️⃣ Validate Node.js runtime version

Use `.nvmrc`:

```
20.11.1
```

Or `engines` in `package.json`:

```json
"engines": {
  "node": ">=20.11.0 <21"
}
```

✔️ This makes Vercel, Netlify or CI pipelines fail with the wrong runtime.

---

### ✅ 7️⃣ Monitor published CVEs

* Subscribe to GitHub Dependabot alerts.
* Enable `dependabot.yml` to auto-create PRs:

```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
```

---

### ✅ 8️⃣ Don’t trust unknown scripts

Example:

```tsx
{/* 🚫 Risky */}
<script src="https://randomcdn.com/unknown.js"></script>

{/* ✅ Better */}
<script src="https://trustedcdn.com/verified-lib.js" integrity="sha384-..."></script>
```

✔️ Use `integrity` with SRI hashes.

---

### ✅ 9️⃣ Validate containers if you use Docker

```dockerfile
# Use official LTS base images only
FROM node:20.11.1-alpine

WORKDIR /app
COPY . .
RUN npm ci && npm run build

CMD ["npm", "start"]
```

✔️ Use `docker scan` or `trivy` to check your Node image for CVEs.

---

### ✅ 🔟 Keep a Software BOM

Use `cyclonedx-npm`:

```bash
npx @cyclonedx/cyclonedx-npm --output bom.json
```

Upload to your security tools.

---

## ⚙️ Example: **Full Safe `package.json`**

```json
{
  "name": "my-nextjs-app",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "build": "next build",
    "start": "next start",
    "lint": "next lint",
    "audit": "npm audit"
  },
  "dependencies": {
    "next": "13.4.21",
    "react": "18.2.0",
    "react-dom": "18.2.0"
  },
  "engines": {
    "node": ">=20.11.0 <21"
  }
}
```

---

## ✅ Final Secure Component Checklist

| ✔️ | Practice                |
| -- | ----------------------- |
| ✅  | Pin versions            |
| ✅  | Commit lockfiles        |
| ✅  | Audit dependencies      |
| ✅  | Monitor runtime version |
| ✅  | Use trusted registries  |
| ✅  | Run CI checks for CVEs  |
| ✅  | Validate containers     |
| ✅  | Use SRI for scripts     |
| ✅  | Automate Dependabot     |
| ✅  | Keep an SBOM            |

---

## 📌 Summary

🛡️ Frontend supply chain attacks are real.
**Don’t assume “it’s just the backend’s job”!**
Lock, audit, patch — and automate. 🚀
