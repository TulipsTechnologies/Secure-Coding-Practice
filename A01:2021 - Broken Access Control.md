# **Deep Dive: Secure Access Control in WordPress & Laravel (OWASP A01)**

Let’s dissect **Broken Access Control** vulnerabilities in both frameworks with **implementation-level details**, **edge cases**, and **advanced hardening techniques**.

---

## **1. Laravel: Advanced Access Control**
### **A. Hierarchical Role-Based Access Control (RBAC)**
**Scenario:** A SaaS app with **Admin > Manager > User** roles where Managers can edit team content but not delete users.

#### **Step 1: Database Structure**
```php
// Migration: roles with hierarchy_level
Schema::create('roles', function (Blueprint $table) {
    $table->id();
    $table->string('name')->unique(); // admin, manager, user
    $table->integer('hierarchy_level'); // 1 (highest) to 3 (lowest)
    $table->timestamps();
});

// Users table
Schema::table('users', function (Blueprint $table) {
    $table->foreignId('role_id')->constrained();
});
```

#### **Step 2: Middleware for Role Hierarchy**
```php
// app/Http/Middleware/CheckRoleHierarchy.php
public function handle($request, Closure $next, $minHierarchyLevel)
{
    $user = $request->user();
    
    if ($user->role->hierarchy_level > $minHierarchyLevel) {
        abort(403, 'Higher privileges required.');
    }
    
    return $next($request);
}

// Usage: Restrict to Admin (level 1) or Manager (level 2)
Route::put('/teams/{team}', [TeamController::class, 'update'])
     ->middleware('check.hierarchy:2');
```

#### **Step 3: Dynamic Policy Resolution**
```php
// app/Providers/AuthServiceProvider.php
protected $policies = [
    Team::class => TeamPolicy::class,
];

// app/Policies/TeamPolicy.php
public function delete(User $user, Team $team)
{
    // Admin (level 1) can delete anything
    if ($user->role->hierarchy_level === 1) return true;
    
    // Manager (level 2) can only delete their own teams
    return $user->id === $team->manager_id;
}
```

---

### **B. Row-Level Security (RLS) for Multi-Tenancy**
**Scenario:** A CRM where users **must only see their client data**.

#### **Step 1: Global Query Scope**
```php
// app/Models/Client.php
protected static function booted()
{
    static::addGlobalScope('user_clients', function (Builder $builder) {
        $builder->where('user_id', auth()->id());
    });
}

// Now, Client::all() only returns the current user's clients.
```

#### **Step 2: Database-Level Enforcement**
For **bulletproof security**, use PostgreSQL **Row-Level Security (RLS)**:
```sql
-- Enable RLS on clients table
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only access their own rows
CREATE POLICY client_access_policy ON clients
    USING (user_id = current_setting('app.current_user_id')::integer);
```

**Laravel Integration:**
```php
// Set the PostgreSQL session variable before queries
DB::statement("SET app.current_user_id = ?", [auth()->id()]);
```

---

## **2. WordPress: Hardening Access Control**
### **A. Fine-Grained Capabilities**
**Scenario:** A custom post type `project` where **Editors can publish but not delete**.

#### **Step 1: Custom Capabilities**
```php
// functions.php
add_action('init', function () {
    // Add custom capability to Editor role
    $editor = get_role('editor');
    $editor->add_cap('publish_projects');
    $editor->remove_cap('delete_published_projects');
});

// Register CPT with custom caps
register_post_type('project', [
    'capabilities' => [
        'edit_post' => 'edit_project',
        'delete_post' => 'delete_project',
        'publish_posts' => 'publish_projects',
    ],
]);
```

#### **Step 2: Restrict Admin UI**
```php
// Hide "Delete" button for Editors
add_action('admin_head', function () {
    if (current_user_can('editor') && get_post_type() === 'project') {
        echo '<style>#delete-action { display: none; }</style>';
    }
});
```

---

### **B. Securing REST API Endpoints**
**Scenario:** Prevent subscribers from accessing user data via `/wp-json/wp/v2/users`.

#### **Step 1: Remove Default User Endpoint**
```php
// Disable default user endpoint
add_filter('rest_endpoints', function ($endpoints) {
    if (isset($endpoints['/wp/v2/users'])) {
        unset($endpoints['/wp/v2/users']);
    }
    return $endpoints;
});
```

#### **Step 2: Custom Secure Endpoint**
```php
// Register a secure alternative
add_action('rest_api_init', function () {
    register_rest_route('myplugin/v1', '/users', [
        'methods' => 'GET',
        'callback' => function ($request) {
            if (!current_user_can('list_users')) {
                return new WP_Error('rest_forbidden', 'Unauthorized', ['status' => 403]);
            }
            return get_users(['role__in' => ['editor', 'author']]);
        },
        'permission_callback' => '__return_true' // Handle auth in callback
    ]);
});
```

---

## **3. Shared Advanced Techniques**
### **A. Rate Limiting Sensitive Actions**
**Laravel:**
```php
// app/Http/Kernel.php
protected $middlewareGroups = [
    'web' => [
        \App\Http\Middleware\RateLimitSensitiveActions::class,
    ],
];

// Custom Middleware
public function handle($request, Closure $next, $action)
{
    $key = 'action:' . $action . ':' . $request->ip();
    $maxAttempts = 5; // e.g., password reset attempts
    
    if (RateLimiter::tooManyAttempts($key, $maxAttempts)) {
        abort(429, 'Too many attempts.');
    }
    
    RateLimiter::hit($key);
    return $next($request);
}
```

**WordPress:**
```php
// Rate limit login attempts
add_filter('authenticate', function ($user, $username) {
    $transient_key = 'login_attempts_' . $_SERVER['REMOTE_ADDR'];
    $attempts = get_transient($transient_key) ?: 0;
    
    if ($attempts > 5) {
        wp_die('Too many login attempts. Try again later.');
    }
    
    set_transient($transient_key, $attempts + 1, 300); // 5-minute window
    return $user;
}, 30, 2);
```

---

### **B. Logging & Alerting**
**Laravel:**
```php
// Log unauthorized access attempts
public function show(Post $post)
{
    if (!Gate::allows('view', $post)) {
        Log::warning('Unauthorized post access attempt', [
            'user_id' => auth()->id(),
            'post_id' => $post->id,
            'ip' => request()->ip()
        ]);
        abort(403);
    }
}
```

**WordPress:**
```php
// Log failed admin login attempts
add_action('wp_login_failed', function ($username) {
    error_log(sprintf(
        'Failed login for %s from IP %s',
        $username,
        $_SERVER['REMOTE_ADDR']
    ));
});
```

---

## **4. Edge Cases & Hardening**
### **A. Mass Assignment Protection**
**Laravel:**
```php
// Model: Explicitly define fillable fields
protected $fillable = ['title', 'content']; // Never include 'role_id'

// Alternative: Use FormRequest validation
public function rules()
{
    return [
        'role_id' => 'prohibited', // Block role_id in requests
    ];
}
```

**WordPress:**
```php
// Sanitize user meta updates
add_filter('update_user_metadata', function ($check, $user_id, $meta_key) {
    if ($meta_key === 'wp_capabilities' && !current_user_can('promote_users')) {
        return false; // Block unauthorized role changes
    }
    return $check;
}, 10, 3);
```

---

### **B. Session Fixation Protection**
**Laravel:**
```php
// In LoginController
protected function authenticated()
{
    auth()->logoutOtherDevices(request('password')); // Invalidate other sessions
}
```

**WordPress:**
```php
// Force session regeneration on login
add_action('wp_login', function () {
    wp_session_regenerate_id(true);
});
```

---

## **5. Key Takeaways**
| **Framework** | **Critical Security Measure** |
|--------------|-------------------------------|
| **Laravel**  | Use **Policies + Middleware** for hierarchical RBAC. |
| **WordPress** | **Remove default REST endpoints** + enforce custom caps. |
| **Both**      | **Rate limit sensitive actions** + **log access violations**. |

---

### **Final Checklist**
✅ **Laravel:**  
- Implement **hierarchical RBAC** with database-backed roles.  
- Use **global scopes** or **RLS** for multi-tenancy.  
- Block **mass assignment** via `$fillable`/`FormRequest`.  

✅ **WordPress:**  
- **Disable default REST endpoints** exposing user data.  
- **Custom capabilities** > default roles for fine control.  
- **Rate limit logins** and monitor with `error_log`.  
