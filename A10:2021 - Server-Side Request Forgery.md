# Secure SSRF Protection in Next.js API Routes: Comprehensive Guide

---

## 1. SSRF Protection Middleware for Next.js API Routes

Next.js API routes use plain Node.js request/response objects (or `NextApiRequest` and `NextApiResponse`). We'll create a reusable middleware to detect and block SSRF vectors in incoming requests — checking query params, body fields, and headers.

### SSRF Middleware (`middleware/ssrfProtection.js`)

```js
import { logger } from '../utils/logger'; // Your custom logger

// List of URL patterns or suspicious tokens commonly used in SSRF
const suspiciousPatterns = [
  /169\.254\.169\.254/,          // Cloud metadata IP
  /127\.0\.0\.1/,                // localhost
  /localhost/,                   // localhost string
  /http:\/\/|https:\/\//i,       // URLs in parameters
  /file:\/\//i,                  // File protocol
  /\/\/\//,                     // Malformed URLs
  /\/etc\/passwd/,               // Unix passwd file (just an example)
];

export function ssrfProtectionMiddleware(handler) {
  return async (req, res) => {
    try {
      // Combine all potential SSRF input vectors into one iterable
      const inputs = [];

      // Query parameters
      if (req.query) {
        Object.values(req.query).forEach(value => {
          if (typeof value === 'string') inputs.push(value);
          else if (Array.isArray(value)) inputs.push(...value);
        });
      }

      // Body (for POST/PUT)
      if (req.body && typeof req.body === 'object') {
        Object.values(req.body).forEach(value => {
          if (typeof value === 'string') inputs.push(value);
          else if (Array.isArray(value)) inputs.push(...value);
        });
      }

      // Headers (some SSRF attacks may abuse headers)
      Object.entries(req.headers).forEach(([key, value]) => {
        if (typeof value === 'string') inputs.push(value);
        else if (Array.isArray(value)) inputs.push(...value);
      });

      // Check all inputs against suspicious patterns
      for (const input of inputs) {
        for (const pattern of suspiciousPatterns) {
          if (pattern.test(input)) {
            logger.warn(`SSRF attempt detected in input: "${input}"`);
            res.status(400).json({ error: `Potential SSRF attempt detected in input.` });
            return;
          }
        }
      }

      // Proceed to actual handler if clean
      await handler(req, res);
    } catch (err) {
      logger.error('Error in SSRF middleware:', err);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  };
}
```

---

## 2. Secure HTTP Client with Domain Whitelist & IP Checks

Use a wrapped HTTP client (e.g., Axios) that checks:

* URL scheme (only `http` and `https` allowed, with restrictions on `http` for localhost)
* Host is on an allowlist of trusted domains
* IP address is not internal/private (block RFC1918 addresses, link-local, loopback)
* No DNS rebinding (resolve IPs and re-check before request)

### Secure Fetch Wrapper (`utils/secureFetch.js`)

```js
import axios from 'axios';
import dns from 'dns/promises';
import net from 'net';

const allowedDomains = new Set([
  'api.trustedservice.com',
  'example.com',
  // add your allowed domains here
]);

// Helper to check if IP is private/internal
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    return (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      ip === '127.0.0.1'
    );
  }
  // Add IPv6 private checks if needed
  return false;
}

export async function secureFetch(url, options = {}) {
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new Error('Invalid URL format');
  }

  // Check scheme whitelist
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    throw new Error(`URL scheme ${parsedUrl.protocol} is not allowed`);
  }

  // Restrict http to localhost only
  if (parsedUrl.protocol === 'http:' && !['localhost', '127.0.0.1'].includes(parsedUrl.hostname)) {
    throw new Error('Only localhost allowed for http URLs');
  }

  // Check allowed domains whitelist
  if (!allowedDomains.has(parsedUrl.hostname)) {
    throw new Error(`Domain ${parsedUrl.hostname} is not allowed`);
  }

  // DNS resolution and private IP check
  const addresses = await dns.lookup(parsedUrl.hostname, { all: true });
  for (const addr of addresses) {
    if (isPrivateIp(addr.address)) {
      throw new Error(`Access to private IP addresses is blocked`);
    }
  }

  // TODO: Add DNS rebinding detection if multiple IPs change over time

  try {
    const response = await axios(url, options);
    if (response.status >= 400) {
      throw new Error(`Request failed with status ${response.status}`);
    }
    return response.data;
  } catch (error) {
    throw new Error(`Fetch failed: ${error.message}`);
  }
}
```

---

## 3. Usage Example in API Route with SSRF Middleware & Secure Fetch

```js
import { ssrfProtectionMiddleware } from '../../middleware/ssrfProtection';
import { secureFetch } from '../../utils/secureFetch';

async function handler(req, res) {
  const { targetUrl } = req.query;
  if (!targetUrl) {
    return res.status(400).json({ error: 'targetUrl is required' });
  }

  try {
    const data = await secureFetch(targetUrl);
    res.status(200).json({ data });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
}

export default ssrfProtectionMiddleware(handler);
```

---

## 4. Testing SSRF Protection

### 4.1 Unit Tests for Middleware (Using Jest)

```js
import { ssrfProtectionMiddleware } from '../../middleware/ssrfProtection';

describe('ssrfProtectionMiddleware', () => {
  let req, res, next, handler;

  beforeEach(() => {
    req = {
      query: {},
      body: {},
      headers: {},
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    handler = jest.fn();
  });

  it('blocks request with suspicious query parameter', async () => {
    req.query.url = 'http://169.254.169.254/latest/meta-data/';

    const middleware = ssrfProtectionMiddleware(handler);
    await middleware(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining('Potential SSRF') })
    );
    expect(handler).not.toHaveBeenCalled();
  });

  it('allows request without suspicious input', async () => {
    req.query.param = 'safe-value';

    const middleware = ssrfProtectionMiddleware(handler);
    await middleware(req, res);

    expect(handler).toHaveBeenCalledWith(req, res);
    expect(res.status).not.toHaveBeenCalledWith(400);
  });
});
```

---

## 5. Integration and Best Practices

* **Always apply SSRF middleware on any API route that consumes URLs or user-controlled network input.**
* Use **strict allowlists** for domains and IPs.
* Use **HTTPS whenever possible**, disallow unencrypted protocols.
* For external calls, use **timeout** and **connection limits** to prevent DoS.
* **Log all blocked SSRF attempts** with IP, user, and request context.
* Regularly **review and update** suspicious patterns and allowlists.
* Consider using third-party **security scanning tools** (e.g., OWASP ZAP, Burp Suite) to test SSRF attack vectors.
* Implement **rate limiting and CAPTCHA** to reduce brute force or automated SSRF attacks.
* Use **environment variables or config files** to manage allowlists and settings securely.

