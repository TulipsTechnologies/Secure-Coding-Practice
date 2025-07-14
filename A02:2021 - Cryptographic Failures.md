# 🔐 Secure Coding Practices for Next.js **Frontend**

**OWASP A02:2021 — Cryptographic Failures**

---

## 📌 Why Cryptographic Failures Matter on the Frontend

While most crypto operations **should happen on the server**, the frontend can still weaken crypto by:

* Storing secrets in localStorage/sessionStorage.
* Exposing API keys in client JS bundles.
* Misusing browser crypto APIs.
* Weakly generating tokens/passwords client-side.
* Failing to validate HTTPS/TLS or doing mixed content.
* Not using `HTTPS` at all.

---

## ✅ Common Frontend Crypto Pitfalls

1️⃣ Storing secrets or JWTs in localStorage (prone to XSS).

2️⃣ Hardcoding secrets or API keys in the source code.

3️⃣ Using weak random number generation (like `Math.random()`).

4️⃣ Implementing crypto manually instead of using **`window.crypto`**.

5️⃣ Making API calls over HTTP (no TLS).

6️⃣ Accepting untrusted third-party scripts that can leak crypto material.

---

## ✅ Frontend Safe Practices & Patterns

---

### 1️⃣ Never Hardcode Secrets in Frontend

**❌ Bad:**

```js
// This secret will be visible in source maps and dev tools!
const STRIPE_SECRET = 'sk_test_...'; 
```

**✅ Good:**
Frontend should **only use public keys** (e.g. Stripe **publishable key**), never secret ones.
Keep server-side keys server-side (API routes or backend).

---

### 2️⃣ Use **window\.crypto** for Client-side Randomness

For example, if you need to generate a CSRF token client-side:

**❌ Bad:**

```js
// Predictable
const token = Math.random().toString(36).substring(2);
```

**✅ Good:**

```js
function generateCsrfToken(length = 32) {
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}
```

---

### 3️⃣ Don’t Store Sensitive Data in localStorage/sessionStorage

**❌ Bad:**

```js
localStorage.setItem('authToken', jwt);
```

**✅ Better:**

* Store tokens in **HTTP-only secure cookies**, set by the server.
* JS cannot read these cookies → protected from XSS.

---

### 4️⃣ Always Use HTTPS for All API Calls

**In `next.config.js`:**

```js
module.exports = {
  async redirects() {
    return [
      {
        source: '/(.*)',
        has: [{ type: 'host', value: 'yourdomain.com' }],
        permanent: true,
        destination: 'https://yourdomain.com/:path*',
      },
    ];
  },
};
```

Or force HTTPS at your CDN or proxy.

---

### 5️⃣ Validate Mixed Content

Never load insecure HTTP scripts or assets on an HTTPS page:

```html
<!-- ❌ Bad -->
<script src="http://example.com/script.js"></script>
<!-- ✅ Good -->
<script src="https://example.com/script.js"></script>
```

---

### 6️⃣ Don’t Roll Your Own Encryption in JS

* If you must encrypt in-browser, use **Web Crypto API** (`window.crypto.subtle`) with trusted algorithms like AES-GCM.
* Example AES-GCM encrypt (for *low-sensitivity* use cases only):

```js
// lib/clientCrypto.js
export async function encryptAESGCM(plaintext, key) {
  const enc = new TextEncoder();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    enc.encode(plaintext)
  );
  return { ciphertext, iv };
}
```

✅ *But remember: Do encryption server-side whenever possible.*

---

### 7️⃣ Always Use Trusted Libraries for Client-side Crypto

If you must hash or sign data:

* Use `crypto.subtle.digest` for hashing:

```js
const data = new TextEncoder().encode('hello');
const hashBuffer = await crypto.subtle.digest('SHA-256', data);
const hashHex = Array.from(new Uint8Array(hashBuffer))
  .map(b => b.toString(16).padStart(2, '0')).join('');
```

---

## 🛡️ Summary — Frontend Crypto Best Practices

✅ Keep ALL secrets server-side.
✅ Use `window.crypto` for any randomness.
✅ Never store JWTs in localStorage — prefer secure, HTTP-only cookies.
✅ Always force HTTPS.
✅ Don’t do custom crypto logic — use trusted, well-vetted browser APIs.
✅ Audit all third-party scripts — supply chain matters.
✅ Warn devs to keep `.env` private keys out of `NEXT_PUBLIC_*`!

---

**🔒 Frontend crypto rule:** *the less crypto you do in the browser, the safer you are.*

---

If you’d like, I can wrap this as:

* a Markdown doc (`SECURE-CRYPTO-FRONTEND.md`),
* or add example **Next.js code snippets** for auth tokens, cookies, or secure config.
