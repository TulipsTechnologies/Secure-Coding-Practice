# Secure Coding Practices for Next.js API: Addressing OWASP Top 10 (A09:2021 - Security Logging and Monitoring Failures)

## Comprehensive Security Monitoring Framework

---

### 1. Centralized Security Event Logging

#### Structured Logging Service Implementation

```ts
// lib/securityEventLogger.ts
import pino from "pino";
import { NextApiRequest } from "next";

export interface SecurityEvent {
  eventType: string;
  severity: "info" | "warn" | "error";
  timestamp: string;
  correlationId: string;
  ipAddress: string;
  userAgent: string;
  userId: string;
  details: any;
}

export class SecurityEventLogger {
  private logger = pino({
    level: "info",
    formatters: {
      level(label) {
        return { level: label.toUpperCase() };
      },
    },
  });

  logSecurityEvent(event: Partial<SecurityEvent> & { details: any }, req?: NextApiRequest) {
    try {
      const enrichedEvent: SecurityEvent = {
        eventType: event.eventType,
        severity: event.severity,
        timestamp: new Date().toISOString(),
        correlationId: req?.headers["x-correlation-id"]?.toString() ?? crypto.randomUUID(),
        ipAddress: req?.headers["x-forwarded-for"]?.toString() || req?.socket.remoteAddress || "unknown",
        userAgent: req?.headers["user-agent"]?.toString() ?? "unknown",
        userId: req?.user?.id ?? "anonymous",  // req.user set by your auth middleware
        details: event.details,
      };

      this.logger.info({ securityEvent: enrichedEvent }, "Security event logged");

      // Publish to event bus or message queue if applicable
      // e.g., eventBus.publish("securityEvent", enrichedEvent);

    } catch (error) {
      this.logger.error({ err: error }, "Failed to log security event");
    }
  }

  logAuthenticationEvent(success: boolean, username: string, method: string, failureReason?: string, req?: NextApiRequest) {
    this.logSecurityEvent({
      eventType: success ? "AuthenticationSuccess" : "AuthenticationFailure",
      severity: success ? "info" : "warn",
      details: {
        username,
        authenticationMethod: method,
        failureReason,
      },
    }, req);
  }

  logAuthorizationEvent(success: boolean, userId: string, resource: string, action: string, deniedReason?: string, req?: NextApiRequest) {
    this.logSecurityEvent({
      eventType: success ? "AuthorizationSuccess" : "AuthorizationFailure",
      severity: success ? "info" : "warn",
      details: {
        userId,
        resource,
        action,
        deniedReason,
      },
    }, req);
  }
}
```

---

### 2. Real-time Security Monitoring

#### Anomaly Detection Service (Example: Brute Force Detector)

```ts
// services/anomalyDetectionService.ts
import { SecurityEvent } from "../lib/securityEventLogger";

interface SecurityAnomaly {
  type: string;
  severity: "low" | "medium" | "high";
  details: any;
}

export class BruteForceDetector {
  detect(events: SecurityEvent[]): SecurityAnomaly[] {
    // Detect >5 failed auth attempts by same username within time window
    const failedAuths = events
      .filter(e => e.eventType === "AuthenticationFailure")
      .reduce((acc, e) => {
        const user = e.details.username;
        acc[user] = acc[user] ? [...acc[user], e] : [e];
        return acc;
      }, {} as Record<string, SecurityEvent[]>);

    const anomalies: SecurityAnomaly[] = [];

    for (const [username, attempts] of Object.entries(failedAuths)) {
      if (attempts.length > 5) {
        anomalies.push({
          type: "BruteForceAttempt",
          severity: "high",
          details: {
            username,
            attemptCount: attempts.length,
            firstAttempt: attempts[0].timestamp,
            lastAttempt: attempts[attempts.length - 1].timestamp,
            ipAddresses: [...new Set(attempts.map(a => a.ipAddress))],
          },
        });
      }
    }

    return anomalies;
  }
}

// Example runner periodically processing queued events
export class AnomalyDetectionService {
  private detectors = [new BruteForceDetector()];
  private eventQueue: SecurityEvent[] = []; // Ideally from DB or message queue

  enqueue(event: SecurityEvent) {
    this.eventQueue.push(event);
  }

  processEvents() {
    if (this.eventQueue.length === 0) return;

    this.detectors.forEach(detector => {
      const anomalies = detector.detect(this.eventQueue);
      anomalies.forEach(anomaly => {
        console.warn("Security anomaly detected:", anomaly.type, anomaly.details);
        // TODO: Alert security team via email, Slack, PagerDuty, etc.
      });
    });

    this.eventQueue = []; // Clear after processing
  }
}
```

---

### 3. Audit Trail Implementation

#### Comprehensive Audit Service

```ts
// services/auditService.ts
import { PrismaClient } from "@prisma/client"; // Or your ORM/DB client
import { NextApiRequest } from "next";

interface AuditRecord {
  timestamp: string;
  action: string;
  userId: string;
  ipAddress: string;
  userAgent: string;
  targetType: string;
  targetId: string;
  description: string;
  details: string;
}

export class AuditService {
  private prisma = new PrismaClient();

  async recordAction(
    action: string,
    target: any,
    description: string,
    req?: NextApiRequest
  ) {
    try {
      const auditRecord: AuditRecord = {
        timestamp: new Date().toISOString(),
        action,
        userId: req?.user?.id ?? "system",
        ipAddress: req?.headers["x-forwarded-for"]?.toString() || req?.socket.remoteAddress || "unknown",
        userAgent: req?.headers["user-agent"]?.toString() || "unknown",
        targetType: target?.constructor?.name ?? typeof target,
        targetId: target?.id ?? JSON.stringify(target).slice(0, 100),
        description,
        details: JSON.stringify(target),
      };

      await this.prisma.auditLog.create({ data: auditRecord });

    } catch (error) {
      console.error("Failed to record audit action", error);
    }
  }

  async query(filter: Partial<AuditRecord>) {
    return this.prisma.auditLog.findMany({ where: filter });
  }
}
```

**Example usage in API route:**

```ts
// pages/api/users/[id].ts
import { AuditService } from "../../../services/auditService";

const auditService = new AuditService();

export default async function handler(req, res) {
  const userId = req.query.id;

  // Assume getUser and updateUser are implemented services
  const user = await getUser(userId);

  await auditService.recordAction("UpdateUser", user, `Update initiated by ${req.user?.id}`, req);

  const updatedUser = await updateUser(userId, req.body);

  await auditService.recordAction("UpdateUser", updatedUser, `Update completed by ${req.user?.id}`, req);

  res.status(200).json(updatedUser);
}
```

---

### 4. Security Alerting System

#### Multi-Channel Alerting Service

```ts
// services/securityAlertService.ts
export interface SecurityAlert {
  title: string;
  severity: "low" | "medium" | "high";
  timestamp: string;
  details: string;
  remediation?: string[];
}

export interface AlertNotifier {
  supportsSeverity(severity: string): boolean;
  notify(alert: SecurityAlert): Promise<void>;
}

export class SecurityAlertService {
  private notifiers: AlertNotifier[];

  constructor(notifiers: AlertNotifier[]) {
    this.notifiers = notifiers;
  }

  async raiseAlert(alert: SecurityAlert) {
    console.warn(`Security alert: ${alert.title} (Severity: ${alert.severity})`);

    await Promise.all(
      this.notifiers
        .filter(n => n.supportsSeverity(alert.severity))
        .map(n => n.notify(alert).catch(err => console.error(`Notifier failed:`, err)))
    );
  }
}
```

**Email Notifier Example**

```ts
// services/emailAlertNotifier.ts
import nodemailer from "nodemailer";
import { SecurityAlert, AlertNotifier } from "./securityAlertService";

export class EmailAlertNotifier implements AlertNotifier {
  private transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: true,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  private securityTeamEmail = process.env.SECURITY_TEAM_EMAIL!;

  supportsSeverity(severity: string) {
    return ["medium", "high"].includes(severity);
  }

  async notify(alert: SecurityAlert) {
    const htmlBody = `
      <h1>Security Alert: ${alert.title}</h1>
      <p><strong>Severity:</strong> ${alert.severity}</p>
      <p><strong>Timestamp:</strong> ${alert.timestamp}</p>
      <p><strong>Details:</strong></p>
      <pre>${alert.details}</pre>
      ${alert.remediation ? `<p><strong>Remediation:</strong></p><ul>${alert.remediation.map(r => `<li>${r}</li>`).join("")}</ul>` : ""}
    `;

    await this.transporter.sendMail({
      from: `"Security Alert" <alerts@example.com>`,
      to: this.securityTeamEmail,
      subject: `[Security Alert] ${alert.title}`,
      html: htmlBody,
    });
  }
}
```

---

### 5. Log Protection Mechanisms

#### Secure Log Management Service with Sanitization and Encryption

```ts
// lib/secureLogService.ts
import pino from "pino";
import crypto from "crypto";

export class SecureLogService {
  private logger = pino();
  private encryptionKey: Buffer;

  constructor(encryptionKeyHex: string) {
    this.encryptionKey = Buffer.from(encryptionKeyHex, "hex");
  }

  private sanitize(input: string): string {
    const patterns = [
      /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g, // Credit cards
      /\b\d{3}[- ]?\d{2}[- ]?\d{4}\b/g,           // SSN
      /password=[^&\s]+/gi,                        // password=...
      /api[_-]?key=[^&\s]+/gi                      // api_key=...
    ];
    let sanitized = input;
    for (const pattern of patterns) {
      sanitized = sanitized.replace(pattern, "[REDACTED]");
    }
    return sanitized;
  }

  logInfo(message: string, ...args: any[]) {
    this.logger.info(this.sanitize(message), ...args);
  }

  logWarning(message: string, ...args: any[]) {
    this.logger.warn(this.sanitize(message), ...args);
  }

  logError(err: Error, message: string, ...args: any[]) {
    this.logger.error({ err }, this.sanitize(message), ...args);
  }

  logSensitive(message: string) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.encryptionKey, iv);
    let encrypted = cipher.update(message, "utf8", "hex");
    encrypted += cipher.final("hex");
    const tag = cipher.getAuthTag().toString("hex");
    this.logger.info(`[ENCRYPTED_LOG] iv=${iv.toString("hex")} tag=${tag} data=${encrypted}`);
  }
}
```

---

## Implementation Checklist

| #   | Best Practice                                                                           |
| --- | --------------------------------------------------------------------------------------- |
| 1️⃣ | Log all security-relevant events with rich context (timestamps, user ID, IP, UserAgent) |
| 2️⃣ | Implement real-time anomaly detection services to catch suspicious patterns             |
| 3️⃣ | Maintain detailed audit trails for sensitive actions with secure storage                |
| 4️⃣ | Use multi-channel alerting with severity filtering and remediation instructions         |
| 5️⃣ | Sanitize logs to redact sensitive data before writing                                   |
| 6️⃣ | Encrypt sensitive logs or use protected storage mechanisms                              |
| 7️⃣ | Restrict access to logs and audit data                                                  |
| 8️⃣ | Define and enforce log retention and archival policies                                  |
| 9️⃣ | Perform regular incident response drills based on logged events                         |
| 🔟  | Monitor and audit logging pipeline for failures or tampering attempts                   |

---
