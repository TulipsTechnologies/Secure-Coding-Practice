# Secure Coding Priorities for Next.js / Node.js Developers to Prevent OWASP Top 10 Vulnerabilities

---

### 1. **Security Mindset Shift**

* **Assume all external input is hostile** — validate, sanitize, and escape *everything*: `req.query`, `req.body`, headers, cookies, even environment variables.
* **Principle of Least Privilege** — minimize permissions on API tokens, DB users, file access.
* **Fail Securely** — default deny, explicit allow only.
* **Secure by Design** — bake security into architecture and code from day one.

---

### 2. **Core Code-Level Practices**

#### A. Input Validation & Output Encoding

* Use strict **allowlists** for input (e.g., expected values, URL patterns).
* Validate types, lengths, and formats *before* processing or querying DB.
* Escape/encode output to prevent XSS on rendered React components:

  ```js
  // Next.js: use built-in escaping, avoid dangerouslySetInnerHTML unless sanitized
  <div>{userInput}</div>  // React auto-escapes by default
  ```
* Sanitize HTML input when accepting rich text using libraries like [`sanitize-html`](https://www.npmjs.com/package/sanitize-html).

#### B. Authentication & Session Management

* Use battle-tested libraries: [NextAuth.js](https://next-auth.js.org/) or OAuth providers.
* Enforce **Multi-Factor Authentication (MFA)** on sensitive routes/actions.
* Store **password hashes** using secure algorithms (e.g., bcrypt with `bcryptjs` or `argon2`).
* Use **HttpOnly** and **Secure** cookies for session tokens.
* Invalidate sessions on logout and after inactivity.

#### C. Secure Data Handling

* Use HTTPS everywhere, enforce TLS 1.2+.
* Encrypt sensitive data at rest (e.g., via DB encryption or encrypted environment variables).
* Never commit secrets to code or repos — load from env vars or secret managers.
* Use `.env.local` with `.gitignore` to keep secrets out of source control.

#### D. Dependency Hygiene

* Scan dependencies regularly with `npm audit` or tools like [Snyk](https://snyk.io/).
* Pin exact versions in `package.json` and `package-lock.json`.
* Update dependencies regularly; avoid deprecated or unmaintained packages.

---

### 3. **Defensive Coding Practices**

#### A. Error Handling

* **Avoid leaking sensitive info** in error responses. Show generic errors to users, log detailed errors internally.
* Use centralized error handling middleware in Next.js API routes.

```js
export default function handler(req, res) {
  try {
    // your logic
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
}
```

#### B. API Security

* Implement **rate limiting** with middleware like [`express-rate-limit`](https://www.npmjs.com/package/express-rate-limit) or Vercel’s built-in features.
* Validate `Content-Type` headers; e.g., accept only `application/json` for APIs expecting JSON.
* Protect against **CSRF** on state-changing routes with tokens or SameSite cookies.
* Use **CORS** properly; allow only trusted origins.

#### C. SSRF Mitigation

* Validate and sanitize all URLs accepted from user input.
* Use **domain allowlists** and reject requests to private IP ranges (e.g., 127.0.0.1, 10.0.0.0/8).
* Block access to cloud metadata IPs (`169.254.169.254`).
* Wrap outbound HTTP requests (e.g., `fetch` or Axios) with security checks.

---

### 4. **Automation & Tooling**

* **Static Analysis (SAST):** Integrate ESLint with security plugins ([eslint-plugin-security](https://github.com/nodesecurity/eslint-plugin-security)).
* **Dynamic Analysis (DAST):** Use OWASP ZAP or Burp Suite to scan deployed endpoints.
* **Secret Scanning:** Use [GitHub’s secret scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning) or tools like [GitLeaks](https://github.com/zricethezav/gitleaks).
* **CI/CD Security:** Add linting, tests, security scans in pipelines before deployment.

---

### 5. **Secure Design Principles**

* Apply **Zero Trust**: never implicitly trust client input or third-party APIs.
* Use **Immutable Infrastructure**: containers or serverless functions should be immutable and ephemeral.
* Employ **Threat Modeling**: proactively identify abuse cases during design reviews.

---

### 6. **Must-Know Libraries & Tools for Next.js**

| Purpose          | Libraries / Tools                                                                           |
| ---------------- | ------------------------------------------------------------------------------------------- |
| Input validation | `zod`, `joi`, `yup`                                                                         |
| Sanitization     | `sanitize-html`, `dompurify` (in frontend)                                                  |
| Authentication   | `next-auth`, `passport`, `jsonwebtoken`                                                     |
| Rate limiting    | `express-rate-limit`, `rate-limiter-flexible`                                               |
| SSRF protection  | Custom wrappers for `node-fetch` / `axios`                                                  |
| Environment vars | `dotenv`, [Vercel secrets](https://vercel.com/docs/concepts/projects/environment-variables) |
| Static analysis  | `eslint`, `eslint-plugin-security`                                                          |

---

### 7. **Developer’s Pre-Commit Security Checklist**

* [ ] Validate & sanitize all user inputs?
* [ ] No sensitive secrets or keys in code?
* [ ] Dependencies free of known vulnerabilities?
* [ ] API error messages don’t leak stack traces?
* [ ] Rate limiting applied on critical endpoints?
* [ ] Secure cookie flags set (`HttpOnly`, `Secure`, `SameSite`)?
* [ ] Outbound requests restricted & validated?
* [ ] Logging does not expose sensitive info?
* [ ] Static & dynamic security tests passed?

---

### Final Thought

> Security isn’t an add-on—**it’s woven into every line of code and every system design decision**.
> Stay vigilant, automate checks, and embrace a mindset where every user input, every API call, and every deployment could be a potential attack vector. The more security is baked in early, the fewer bugs and breaches you'll face in production.
