Here’s a **security-focused developer guide** tailored for **WordPress and Laravel (PHP)**, covering critical OWASP Top 10 mitigations with actionable code examples:

---

### **1. Security Mindset Shift**
- **Assume all input is malicious**: Validate/sanitize *every* input (forms, APIs, DB queries, file uploads).  
- **Principle of Least Privilege**: Restrict file permissions, database roles, and API scopes.  
- **Secure by Default**: Deny access unless explicitly allowed (e.g., whitelisting routes).  

---

### **2. Code-Level Priorities**  
#### **A. Input Validation & Output Encoding**  
- **WordPress**:  
  ```php
  // Validate email
  $email = sanitize_email($_POST['email']); 
  if (!is_email($email)) { wp_die('Invalid email'); }

  // Escape output (XSS protection)
  echo esc_html(get_user_meta($user_id, 'bio', true));
  ```

- **Laravel**:  
  ```php
  // Validation in controllers
  $request->validate(['username' => 'required|alpha_dash|max:255']);

  // Blade output encoding (auto-escaped by default)
  <div>{{ $userInput }}</div>
  ```

#### **B. Authentication & Session Management**  
- **WordPress**:  
  - Use `wp_hash_password()` and `wp_verify_password()` for custom auth.  
  - Enforce strong passwords:  
    ```php
    add_filter('password_strength_meter', function() { return 4; }); // Max strength
    ```

- **Laravel**:  
  - Use built-in Auth (`php artisan make:auth`) with `bcrypt()` hashing.  
  - Enable MFA via packages like `laravel-fortify`.  
  - Secure sessions:  
    ```php
    // .env
    SESSION_DRIVER=database
    SESSION_SECURE_COOKIE=true
    ```

#### **C. Secure Data Handling**  
- **Encryption**:  
  - Laravel: `encrypt()`/`decrypt()` helpers (uses AES-256).  
  - WordPress: Use `openssl_encrypt()` (avoid homegrown crypto).  

- **Secrets Management**:  
  - Laravel: Store in `.env` (never commit to Git).  
  - WordPress: Use constants in `wp-config.php`:  
    ```php
    define('API_KEY', 'value'); // Override in server env if possible
    ```

#### **D. Dependency Hygiene**  
- **WordPress**:  
  - Audit plugins with [WPScan](https://wpscan.com/).  
  - Update core/plugins immediately.  

- **Laravel**:  
  - Scan for vulnerabilities:  
    ```bash
    composer audit
    ```
  - Update dependencies:  
    ```bash
    composer update --dry-run # Test first
    ```

---

### **3. Defensive Coding Practices**  
#### **A. Error Handling**  
- **Never expose debug info**:  
  - Laravel: Set `APP_DEBUG=false` in production.  
  - WordPress: Disable `WP_DEBUG` in production.  

- **Secure logging**:  
  ```php
  // Laravel: Redact sensitive data
  Log::error('Login failed', ['user_id' => $user->id]); // No passwords!
  ```

#### **B. API Security**  
- **Laravel**:  
  - Rate limiting:  
    ```php
    // routes/api.php
    RateLimiter::for('api', fn ($request) => Limit::perMinute(60));
    ```
  - Sanitize API responses:  
    ```php
    return response()->json(['data' => $data], 200, [
        'Content-Type' => 'application/json',
        'X-Content-Type-Options' => 'nosniff'
    ]);
    ```

#### **C. SSRF/File Upload Mitigation**  
- **Validate file uploads**:  
  ```php
  // WordPress
  $allowed_types = ['image/jpeg', 'image/png'];
  if (!in_array($_FILES['file']['type'], $allowed_types)) {
      wp_die('Invalid file type');
  }

  // Laravel
  $request->validate(['file' => 'mimes:jpeg,png|max:2048']);
  ```

---

### **4. Automation & Tools**  
- **Static Analysis**:  
  - Laravel: [PHPStan](https://phpstan.org/), [Laravel Pint](https://laravel.com/docs/pint)  
  - WordPress: [PHPCS with WordPress standards](https://github.com/WordPress/WordPress-Coding-Standards)  

- **Dynamic Analysis**:  
  - OWASP ZAP for both platforms.  

- **Git Hooks**:  
  ```bash
  # Example pre-commit hook (Laravel)
  composer run-script lint && composer test
  ```

---

### **5. Secure Design Principles**  
1. **Zero Trust**: Validate permissions for *every* request (even in admin panels).  
2. **Immutable Deployments**: Use Docker/containerized WordPress/Laravel.  
3. **Threat Modeling**: Ask:  
   - "Can users access others’ data?" (e.g., `/profile?id=123` → force ownership checks).  

---

### **6. Must-Know Libraries/Packages**  
| Purpose              | WordPress                     | Laravel                          |
|----------------------|-------------------------------|----------------------------------|
| Hashing              | `wp_hash_password()`          | `bcrypt()`                       |
| CSRF Protection      | `wp_nonce_field()`            | `@csrf` (Blade directive)        |
| Input Sanitization   | `sanitize_text_field()`       | `$request->only(‘safe_fields’)`  |
| Rate Limiting        | Wordfence plugin              | `laravel-rate-limiter`           |

---

### **7. Pre-Commit Checklist**  
1. [ ] All inputs sanitized/validated?  
2. [ ] No raw DB queries (`$wpdb->prepare()` or Laravel Eloquent used)?  
3. [ ] Sensitive data encrypted or redacted?  
4. [ ] Dependencies scanned for CVEs?  
5. [ ] Error messages generic (no stack traces)?  

---

### **Final Advice**  
- **WordPress**: Assume plugins/themes are vulnerable—minimize use and keep updated.  
- **Laravel**: Leverage built-in security features (middleware, validators, CSRF).  
- **Both**:  
  - **Patch immediately**—attackers exploit known vulnerabilities.  

Security isn’t optional—it’s your **first responsibility** as a developer. 🔒
