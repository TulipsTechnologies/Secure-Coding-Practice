# ✅ Secure Coding Practices for Next.js API: Addressing OWASP A01:2021 (Broken Access Control)

## 📌 Introduction to Broken Access Control

**Broken Access Control** is the top risk in modern web apps (OWASP #1).
It happens when users can perform actions or access data they shouldn’t — due to missing, weak, or bypassable authorization logic.

---

## ⚠️ Common Broken Access Control Scenarios in Next.js

1. **Insecure Direct Object References (IDOR)**
2. **Missing or Weak API Authorization**
3. **Privilege Escalation (e.g., non-admins calling admin endpoints)**
4. **CORS Misconfiguration**
5. **Public API Routes that should be protected**

---

## ✅ Step-by-Step Implementation Guide

---

### 1️⃣ Protect All API Routes with Auth Middleware

Next.js 13+ supports **Middleware** and **Route Handlers** for edge auth checks.
Example: `lib/auth.js` (using JWT).

```javascript
// lib/auth.js
import jwt from 'jsonwebtoken';

export function verifyToken(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;

  const token = authHeader.split(' ')[1];
  if (!token) return null;

  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}
```

**Use in API Route:**

```javascript
// pages/api/admin-data.js
import { verifyToken } from '@/lib/auth';

export default async function handler(req, res) {
  const user = verifyToken(req);
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ message: 'Forbidden' });
  }

  res.json({ secret: 'Sensitive admin info' });
}
```

---

### 2️⃣ Apply Role-Based Access Control (RBAC)

Add role checks to protect actions.

```javascript
if (user.role !== 'admin') {
  return res.status(403).json({ message: 'Access Denied' });
}
```

---

### 3️⃣ Validate Resource Ownership (Prevent IDOR)

**Bad:**

```javascript
// Directly using user ID from query
const order = await prisma.order.findUnique({ where: { id: req.query.id } });
```

**Good:**

```javascript
const order = await prisma.order.findFirst({
  where: {
    id: req.query.id,
    userId: user.id
  }
});
if (!order) return res.status(404).json({ message: 'Not found' });
```

---

### 4️⃣ Use UUIDs / Hash IDs in Public URLs

Never expose raw database IDs.

```javascript
// Instead of /api/user/123
// Use /api/user/6f4a2c0e-b1d7-4b9d-9c3e-xxxxxxxxxxxx
```

---

### 5️⃣ Lock Down CORS

**Only allow trusted origins** — don’t use `"*"`.

```javascript
// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          {
            key: 'Access-Control-Allow-Origin',
            value: 'https://your-frontend-domain.com',
          },
        ],
      },
    ];
  },
};
```

Or use `next-cors` package for more control.

---

### 6️⃣ Add Rate Limiting

Use libraries like **`rate-limiter-flexible`**.

```javascript
// lib/rateLimit.js
import { RateLimiterMemory } from 'rate-limiter-flexible';

const rateLimiter = new RateLimiterMemory({
  points: 10, // 10 requests
  duration: 1, // per second
});

export default async function rateLimit(req, res) {
  try {
    await rateLimiter.consume(req.headers['x-forwarded-for'] || req.socket.remoteAddress);
  } catch {
    res.status(429).json({ message: 'Too Many Requests' });
  }
}
```

---

### 7️⃣ Enforce Secure Defaults

* Require auth for all protected routes.
* Use `middleware.js` to globally enforce auth.
* Example `middleware.js` in `/pages`:

```javascript
// middleware.js (Next.js 13)
import { NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';

export async function middleware(req) {
  const user = verifyToken(req);
  if (!user) {
    return NextResponse.redirect(new URL('/login', req.url));
  }
  return NextResponse.next();
}

// Match protected routes
export const config = {
  matcher: ['/api/protected/:path*'],
};
```

---

### 8️⃣ Enforce MFA for Sensitive Operations

Add an `mfa` claim in the JWT or a flag in DB.

```javascript
if (!user.mfaVerified) {
  return res.status(403).json({ message: 'MFA required' });
}
```

---

### 9️⃣ Test Your Access Controls

Use Jest + Supertest:

```javascript
// __tests__/api/admin-data.test.js
import handler from '@/pages/api/admin-data';
import { createMocks } from 'node-mocks-http';

test('denies access for non-admins', async () => {
  const { req, res } = createMocks({
    method: 'GET',
    headers: {
      authorization: 'Bearer <regular-user-token>',
    },
  });

  await handler(req, res);
  expect(res._getStatusCode()).toBe(403);
});
```

---

### 🔟 Monitor & Log Forbidden Attempts

Add a simple logger:

```javascript
if (!user) {
  console.warn(`Unauthorized access attempt to ${req.url}`);
}
```

Use a logging service (e.g., Sentry) for critical endpoints.

---

## ✅ Next.js Broken Access Control Best Practices

✔ Always use `[Authorize]` equivalent → custom auth checks
✔ Validate resource ownership
✔ Use UUIDs for external references
✔ Lock CORS to trusted domains
✔ Rate limit all APIs
✔ Require MFA for sensitive actions
✔ Write tests for auth edge cases
✔ Log suspicious access attempts
✔ Review roles/scopes regularly

---
