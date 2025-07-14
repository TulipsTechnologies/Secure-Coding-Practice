- **Web Application Security Overview**: Since 2003, the OWASP Top 10 list has been curated to identify the most critical security risks for web applications, combining data-driven insights and practitioner surveys to highlight emerging threats ().

- **Purpose of OWASP Top 10**: It serves as an awareness document, emphasizing the top security risks rather than a strict checklist. The list helps developers understand prevalent threats and their potential impact, enabling better security practices ().

- **Compilation Method**: The list is based on surveys of security practitioners and data from security audits. It includes the incidence rate of vulnerabilities, severity, and likelihood of exploitation, which are combined into risk assessments. The list is updated approximately every four years, with the latest from 2021 and scheduled for 2024/2025 ().

- **Key Risks in 2021**:
  1. Broken Access Control
  2. Cryptographic Failures
  3. Injection
  4. Insecure Design
  5. Security Misconfiguration
  6. Outdated Components
  7. Identification and Authentication Failures
  8. Data Integrity Failures
  9. Logging and Monitoring Failures
  10. Server-Side Request Forgery (SSRF) ().

- **Focus on Access Control**: Access control issues are prominent, including insecure direct object references and missing function-level access controls. Examples include:
  - Exploiting URL parameters to access unauthorized data
  - Manipulating client-side restrictions, e.g., Twitter's tweet length limit, which was only checked on the client side, allowing longer tweets via direct HTTP requests ().
  - Mass assignment vulnerabilities in frameworks like Laravel, where unprotected properties can be overwritten via form submissions, leading to privilege escalation or data manipulation ().

- **Common Attack Examples**:
  - **Broken Access Control**: Manipulating URL parameters or form data to access or modify unauthorized data or functions ().
  - **Mass Assignment**: Sending additional data in forms that automatically bind to models, potentially overriding protected fields like creation dates unless explicitly guarded ().
  - **Cross-Site Request Forgery (CSRF)**: Exploiting authenticated sessions by tricking users into submitting unwanted requests, mitigated by cookie flags like SameSite, Secure, and HttpOnly ().

- **Security Best Practices**:
  - Use view models to limit data binding to only necessary properties, avoiding mass assignment vulnerabilities ().
  - Implement strict access controls for data and functions, including proper authorization checks on server-side.
  - Protect cookies with flags like SameSite, Secure, and HttpOnly to prevent CSRF and session hijacking ().

- **Additional Notes**:
  - The list is not exhaustive; it reflects the most common and impactful vulnerabilities based on recent data.
  - The OWASP Top 10 is a dynamic document, updated with new data and emerging threats, emphasizing the importance of continuous security assessment and adaptation ().

This study note provides a comprehensive overview of OWASP Top 10 security risks, focusing on access control issues, common attack vectors, and recommended security practices.

