### A01:2021 Broken Access Control — Next.js Deep Dive

---

## What is Broken Access Control?

Broken Access Control happens when an application **fails to enforce restrictions on what authenticated or unauthenticated users can do**. Attackers exploit these flaws to **access data or functions beyond their privileges**, like viewing other users' data, performing admin-only actions, or manipulating records.

---

## How Broken Access Control Manifests in Next.js Apps

### Common Vulnerabilities due to Bad Coding:

1. **Missing or Weak Authorization Checks**

   * Skipping role or permission verification in API routes or page components.
   * Relying only on UI controls (hiding buttons/links) without backend enforcement.
   * Not validating the logged-in user's rights on each request.

2. **Insecure Direct Object References (IDOR)**

   * Using identifiers (e.g., user ID, order ID) directly from the client without verifying ownership.
   * Example: `/api/orders/[orderId]` allows access to any order if the `orderId` is manipulated.

3. **Elevation of Privileges**

   * Allowing normal users to escalate their privileges by changing parameters (like `role=admin` in requests).
   * Missing checks on sensitive actions like user management or financial transactions.

4. **Bypassing Access Checks**

   * Accessing admin-only pages by directly entering URLs.
   * Accessing APIs without authentication or with forged tokens.

---

## What Should Be Done in Next.js to Prevent Broken Access Control

### 1. **Enforce Authorization on Every API Route**

* Use **middleware or utility functions** that verify the user’s session and roles on *every* API route that accesses sensitive data or functionality.

* Example with Next.js API routes using `getSession` from `next-auth`:

```js
import { getSession } from "next-auth/react";

export default async function handler(req, res) {
  const session = await getSession({ req });

  if (!session) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  // Example: Allow only admin users
  if (session.user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden: insufficient privileges" });
  }

  // Proceed with admin-only operation
  res.status(200).json({ secretData: "Admin-only content" });
}
```

### 2. **Validate Ownership of Resources**

* When a user accesses data by ID, **check the resource belongs to that user or the user has rights to access it.**

```js
const order = await db.orders.findUnique({ where: { id: orderId } });

if (order.userId !== session.user.id && session.user.role !== "admin") {
  return res.status(403).json({ error: "Forbidden" });
}
```

### 3. **Protect Client-Side Pages via Server-Side Rendering (SSR) or Middleware**

* Use Next.js middleware or SSR (`getServerSideProps`) to check permissions before rendering protected pages.

```js
// pages/admin.js
import { getSession } from "next-auth/react";

export async function getServerSideProps(context) {
  const session = await getSession(context);

  if (!session || session.user.role !== "admin") {
    return {
      redirect: { destination: "/", permanent: false }
    };
  }

  return { props: { user: session.user } };
}

export default function AdminPage({ user }) {
  return <div>Welcome, admin {user.name}!</div>;
}
```

### 4. **Avoid Relying on Client-Side Controls for Security**

* Client code (React components, buttons, links) should **only improve user experience, not enforce access control.**

* Example of *bad* practice:

```jsx
// Bad: showing admin button conditionally but not blocking API
{user.role === 'admin' && <button onClick={handleDelete}>Delete User</button>}
```

* Always enforce permission checks on server-side for the associated API request.

### 5. **Use Secure Session and Token Handling**

* Use secure session tokens (e.g., via `next-auth` or JWT with proper secret and expiry).
* Validate tokens on every request and ensure tokens can’t be forged or manipulated to escalate privileges.

---

## What Should NOT Be Done

* **Never trust any client input for access decisions.**
  Don’t trust roles or IDs sent from client without server verification.

* **Don’t rely solely on hiding UI elements** to restrict access.
  Attackers can craft direct HTTP requests bypassing the UI.

* **Don’t skip authorization checks in API routes or server-side rendering** because it "feels secure enough" on the frontend.

* **Avoid embedding sensitive information in client-side code** (e.g., hardcoded API keys or admin flags in React components).

---

## Summary: Best Practices Checklist for Next.js Broken Access Control

| Practice                            | Details                                                                   |
| ----------------------------------- | ------------------------------------------------------------------------- |
| **Authorization enforcement**       | Check user roles & permissions on *every* API call and SSR.               |
| **Resource ownership validation**   | Verify resources belong to user or user has explicit access.              |
| **Use server-side checks**          | Use API route guards and SSR protections; middleware to guard pages/APIs. |
| **No client-side-only enforcement** | UI controls are *not* security boundaries.                                |
| **Secure session management**       | Use trusted auth libraries; verify tokens on every request.               |
| **Logging & Monitoring**            | Log authorization failures for audit and anomaly detection.               |

---
