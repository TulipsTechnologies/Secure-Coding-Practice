# ✅ Secure Coding Practices for Next.js API: Addressing OWASP Top 10 (A07:2021 - Identification and Authentication Failures)

---

## 📌 Comprehensive Authentication Security Implementation for Next.js

---

## 1️⃣ Multi-Factor Authentication Framework

### ✅ MFA with `next-auth` and TOTP

Use `next-auth` with **Custom Credentials** and TOTP as a second factor.

**MFA Code Example**:

```ts
// pages/api/auth/[...nextauth].ts
import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { verifyPassword, generateTOTP, validateTOTP } from "@/lib/auth";

export default NextAuth({
  providers: [
    CredentialsProvider({
      async authorize(credentials) {
        const user = await findUserByEmail(credentials.email);
        if (!user) throw new Error("Invalid credentials");

        const valid = await verifyPassword(credentials.password, user.passwordHash);
        if (!valid) throw new Error("Invalid credentials");

        // Check TOTP code
        const validTOTP = validateTOTP(credentials.totp, user.totpSecret);
        if (!validTOTP) throw new Error("Invalid MFA code");

        return { id: user.id, email: user.email };
      },
    }),
  ],
  session: { strategy: "jwt" },
});
```

```ts
// lib/auth.ts
import { authenticator } from "otplib";
import bcrypt from "bcryptjs";

export async function verifyPassword(password: string, hash: string) {
  return bcrypt.compare(password, hash);
}

export function generateTOTP(secret: string) {
  return authenticator.generate(secret);
}

export function validateTOTP(code: string, secret: string) {
  return authenticator.check(code, secret);
}
```

---

## 2️⃣ Password Security Architecture

### ✅ Strong Password Policy + Hashing

**Secure Password Service**:

```ts
// lib/password.ts
import bcrypt from "bcryptjs";
import zxcvbn from "zxcvbn";

export async function hashPassword(password: string) {
  const salt = await bcrypt.genSalt(12);
  return bcrypt.hash(password, salt);
}

export async function verifyPassword(password: string, hash: string) {
  return bcrypt.compare(password, hash);
}

export function validatePasswordStrength(password: string) {
  const result = zxcvbn(password);
  if (result.score < 3) {
    throw new Error("Password too weak");
  }
  return true;
}
```

**✅ Best Practices**

* Enforce min length (12+ chars).
* Use `zxcvbn` to check strength.
* Use `bcrypt` or `argon2` for hashing.
* Store password hashes only, never plaintext.

---

## 3️⃣ Secure Session Management

### ✅ JWT + Secure Cookies

**Using `next-auth` JWT strategy**:

```ts
// [...nextauth].ts
import NextAuth from "next-auth";

export default NextAuth({
  session: {
    strategy: "jwt",
    maxAge: 60 * 60, // 1 hour
  },
  jwt: {
    secret: process.env.JWT_SECRET,
  },
  cookies: {
    sessionToken: {
      name: `__Secure-next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        secure: process.env.NODE_ENV === "production",
      },
    },
  },
});
```

**✅ Best Practices**

* Use `Secure`, `HttpOnly` cookies.
* Set `SameSite=Lax` or `Strict` to reduce CSRF risk.
* Rotate JWT secrets periodically.
* Short token lifetime.

---

## 4️⃣ Account Protection & Brute Force Blocking

### ✅ Rate Limiting + Lockout

Use a rate limiter like **Upstash Redis**, **RateLimiter-Flexible**, or custom Redis rules.

**Example with `next-rate-limit`:**

```ts
// pages/api/login.ts
import { NextApiRequest, NextApiResponse } from "next";
import rateLimit from "@/lib/rateLimit";

const limiter = rateLimit({
  interval: 60 * 1000, // 1 minute
  uniqueTokenPerInterval: 500,
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    await limiter.check(res, 5, "CACHE_TOKEN"); // max 5 per min
  } catch {
    return res.status(429).json({ message: "Too many attempts" });
  }

  // handle login
}
```

---

## 5️⃣ Authentication Event Logging

### ✅ Audit Logs

Store login success/failure in a secure DB or log service.

```ts
// lib/audit.ts
import { db } from "@/lib/db";

export async function logAuthEvent({ userId, type, ip, userAgent }) {
  await db.auditLog.create({
    data: {
      userId,
      type,
      ip,
      userAgent,
      timestamp: new Date(),
    },
  });
}
```

Add to your login or API route:

```ts
await logAuthEvent({
  userId: user.id,
  type: "LOGIN_SUCCESS",
  ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
  userAgent: req.headers["user-agent"],
});
```

---

## 6️⃣ Secure OAuth/OpenID Connect

### ✅ Use `next-auth` with PKCE

If you use OAuth:

* Always use `PKCE` for public clients.
* Validate `id_token` and `access_token`.
* Never expose client secrets on frontend.

`next-auth` handles this internally for Google, GitHub, Auth0.

---

## 7️⃣ CSRF Protection

For custom forms:

* Use `next-auth`'s built-in CSRF protection for session APIs.
* For custom APIs: use `next-csrf` or same-origin policy.

```ts
// pages/api/secure-action.ts
import { csrf } from "@/lib/csrf";

export default csrf(async (req, res) => {
  // secure handler
});
```

---

## ✅ Best Practices Summary

| #   | Best Practice                                  |
| --- | ---------------------------------------------- |
| 1️⃣ | Use `next-auth` or trusted IdP                 |
| 2️⃣ | Hash passwords with `bcrypt` or `argon2`       |
| 3️⃣ | Enforce strong password policies with `zxcvbn` |
| 4️⃣ | Implement TOTP MFA                             |
| 5️⃣ | Store JWT in secure, HttpOnly cookies          |
| 6️⃣ | Use CSRF protection for custom routes          |
| 7️⃣ | Log all auth events                            |
| 8️⃣ | Apply brute force protection / rate limiting   |
| 9️⃣ | Use PKCE for OAuth flows                       |
| 🔟  | Review session expiry and revoke when needed   |

---
