## 🔒 Secure Coding Practices for **Next.js Frontend**

**OWASP A05:2021 – Security Misconfiguration**

---

### 📌 What does *Security Misconfiguration* mean in the frontend?

A lot!
Most frontend devs think “it’s the backend’s problem” — but many attack surfaces originate in misconfigured **frontend builds**, **runtime environments**, and **browser security policies**.

Common examples:

* Open `robots.txt` or `.env` in your build output
* Wrong Content Security Policy (CSP)
* Source maps exposed in production
* Debug endpoints left enabled
* Wrong CORS settings exposing your API
* Hardcoded secrets in the bundle
* Missing secure headers

---

## ⚡️ Common Misconfigurations in Next.js

✅ **1. Exposed `.env` files**
✅ **2. Source maps deployed publicly**
✅ **3. Weak Content Security Policy**
✅ **4. Missing or loose CORS rules**
✅ **5. Unnecessary debug pages (e.g. `/api/debug`)**
✅ **6. Verbose error pages in prod**
✅ **7. Open directory listing on `public/` files**

---

## 🧩 Step-by-Step Secure Config

---

### ✅ 1️⃣ Remove secrets from client code

**Mistake:**

```ts
// DO NOT DO THIS!
export const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
```

**Fix:**

* Never expose *server-only* secrets via `NEXT_PUBLIC_` or direct exports.
* Only expose *public* keys using `NEXT_PUBLIC_`.

---

### ✅ 2️⃣ Secure `.env` files

* Add `.env` and `.env.*` to `.gitignore`.
* Do not push `.env` to your repo or deploy them to your `public/` folder.

---

### ✅ 3️⃣ Prevent source map leaks

**By default**, Next.js won’t expose source maps publicly.
If you use `source-map` in `next.config.js` for debugging — disable for production:

```js
const nextConfig = {
  productionBrowserSourceMaps: false
};

module.exports = nextConfig;
```

---

### ✅ 4️⃣ Use a strict Content Security Policy (CSP)

Add security headers in **middleware** or your hosting config.

**Example: `next.config.js`**

```js
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: `
              default-src 'self';
              script-src 'self' 'unsafe-inline';
              style-src 'self' 'unsafe-inline';
              img-src 'self' data:;
              connect-src 'self';
              frame-ancestors 'none';
            `.replace(/\s{2,}/g, ' ').trim()
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin'
          }
        ]
      }
    ];
  }
};
```

---

### ✅ 5️⃣ Configure CORS properly (for `api/`)

If you expose `/api` routes in Next.js:

* **Allow only trusted origins**
* Use `allowedMethods`

Example using `nextjs-cors`:

```ts
import NextCors from 'nextjs-cors';

export default async function handler(req, res) {
  await NextCors(req, res, {
    methods: ['GET', 'POST'],
    origin: process.env.ALLOWED_ORIGIN,
    optionsSuccessStatus: 200
  });

  res.json({ message: 'OK' });
}
```

---

### ✅ 6️⃣ Disable debug routes in production

Remove or gate routes like `/api/debug`.

```ts
export default function handler(req, res) {
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).end();
  }

  // Debug logic here
}
```

---

### ✅ 7️⃣ Custom error page for production

Do **not** leak stack traces:

```tsx
// pages/_error.tsx
export default function Error({ statusCode }) {
  return (
    <p>
      {statusCode
        ? `An error ${statusCode} occurred`
        : 'An unexpected error occurred'}
    </p>
  );
}

Error.getInitialProps = ({ res, err }) => {
  const statusCode = res?.statusCode || err?.statusCode || 404;
  return { statusCode };
};
```

---

## ✅ 8️⃣ Harden your hosting

✔️ Use a CDN that disables directory listing
✔️ Don’t deploy your `.next/` folder with dev logs
✔️ Use `next build && next start` for production — **not `next dev`**

---

## ✅ 9️⃣ Automate configuration checks

Use:

* **ESLint**: Check for accidental `console.log` in production
* **Next.js Analytics**: Verify bundle leaks
* **npm audit**: Keep dependencies safe

---

## ✅ 10️⃣ CI checks for secrets

Add a secret scan:

```bash
# Example: git-secrets or truffleHog
npx trufflehog filesystem .
```

---

## 📌 Summary: Secure Next.js Config

| ✔️ | Best Practice                 |
| -- | ----------------------------- |
| ✅  | No secrets in `NEXT_PUBLIC_*` |
| ✅  | CSP + secure headers          |
| ✅  | No source maps in prod        |
| ✅  | Debug routes disabled         |
| ✅  | Only trusted CORS             |
| ✅  | Custom error pages            |
| ✅  | Secure CDN config             |
| ✅  | Audit and lint in CI          |

---

## Final Note

🛡️ **Security config is not “set once and forget”.**
✅ Automate it.
✅ Test your prod build with `curl -I` and security scanners (ZAP, Nuclei).
✅ Do code reviews for **.env leaks, debug flags, or open endpoints**.

---
