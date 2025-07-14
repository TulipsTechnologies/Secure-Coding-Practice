## ✅ Secure Coding Practices for **Next.js Frontend**

**OWASP A03:2021 — Injection**

---

### 📌 Why Injection Matters on the Frontend

While classic SQL injection happens on the server, injection risks on the **frontend** include:

* **XSS** — the main injection vector in browsers.
* **Template injection** — using `dangerouslySetInnerHTML` unsafely.
* **Client-side eval()**, new Function(), or dynamic imports with user input.
* **Insecure user input used in client-side rendering (React).**

---

## ⚠️ Common Frontend Injection Scenarios

1️⃣ **Cross-Site Scripting (XSS)** — injecting scripts into rendered HTML.

2️⃣ **DOM-Based XSS** — manipulating DOM with untrusted input.

3️⃣ **Client-side template injection** — rendering user data in React without escaping.

4️⃣ **Insecure dynamic code execution** — `eval()`, `new Function()`.

5️⃣ **Unsafe URL redirection** — open redirect vulnerabilities.

---

## ✅ Next.js Secure Coding Patterns

---

### 1️⃣ Always Escape / Sanitize User-Generated HTML

React escapes output by default, **except**:

```jsx
{/* ❌ Unsafe */}
<div dangerouslySetInnerHTML={{ __html: userInput }} />

{/* ✅ Safe */}
import DOMPurify from 'dompurify';

const safeHtml = DOMPurify.sanitize(userInput);
<div dangerouslySetInnerHTML={{ __html: safeHtml }} />;
```

✔️ If you **must** render raw HTML: **sanitize** first.

---

### 2️⃣ Never Use `eval()` or `new Function()`

```js
// ❌ Don't
eval(userInput);
const f = new Function(userInput);

// ✅ Instead
// Use safe JSON.parse if needed
const obj = JSON.parse(userInput);
```

---

### 3️⃣ Validate URLs for Redirects

**❌ Bad:**

```js
// Redirect to any URL the user gives
router.push(userInputRedirect);
```

**✅ Good:**

```js
// Validate that it’s an internal route
if (userRedirect.startsWith('/')) {
  router.push(userRedirect);
} else {
  router.push('/'); // fallback
}
```

---

### 4️⃣ Prevent DOM-Based XSS

Never trust values used in:

* `innerHTML`
* `document.write`
* `document.location`
* `document.cookie`

Example:

```js
// ❌ Vulnerable
document.body.innerHTML = location.hash;

// ✅ Safe
import DOMPurify from 'dompurify';
document.body.innerHTML = DOMPurify.sanitize(location.hash);
```

---

### 5️⃣ Use CSP Headers in Next.js

Set strict **Content-Security-Policy** headers.

`next.config.js`:

```js
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'"
    ].join('; ')
  }
];

module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ];
  },
};
```

---

### 6️⃣ Escape Dynamic Data in URLs

When building query params, **use URLSearchParams**:

```js
const params = new URLSearchParams({ term: userInput });
fetch(`/api/search?${params.toString()}`);
```

---

### 7️⃣ Never Trust Query Params or Local Storage

Validate and sanitize everything:

```ts
import DOMPurify from 'dompurify';

const term = router.query.term;
const safeTerm = DOMPurify.sanitize(term);
```

---

## ✅ Frontend XSS Testing

* Test with payloads like `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`.
* Use your browser dev tools to check **what’s rendered**.
* Use CSP headers to block inline scripts.

---

## ✅ Frontend Monitoring for Injection

* Log unexpected redirects.
* Alert on XSS reports (e.g. use `Report-To` or `Content-Security-Policy: report-uri`).

---

## ✅ Best Practices Summary

✔️ React escapes by default — don’t disable it.
✔️ Sanitize before using `dangerouslySetInnerHTML`.
✔️ Don’t use `eval()`.
✔️ Validate all redirects.
✔️ Set strong CSP headers.
✔️ Treat all URL/query/localStorage input as untrusted.
✔️ Test with common XSS payloads.
