# policies/powershell/security.rego
# OPA policies for PowerShell script security

package powershell.security

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# ============================================================================
# HARDCODED SECRETS
# ============================================================================

# Detect hardcoded passwords
deny_hardcoded_password contains msg if {
    line := input.lines[i]
    regex.match(`(?i)(\$password|\$pwd|\$secret|\$apikey|\$api_key|\$token)\s*=\s*["'][^"']+["']`, line.content)
    msg := sprintf("Line %d: Possible hardcoded secret in variable assignment", [line.number])
}

# Detect hardcoded connection strings
deny_hardcoded_connection_string contains msg if {
    line := input.lines[i]
    regex.match(`(?i)(connectionstring|connection_string)\s*=\s*["'][^"']+["']`, line.content)
    msg := sprintf("Line %d: Possible hardcoded connection string", [line.number])
}

# Detect hardcoded API keys patterns
deny_hardcoded_api_key contains msg if {
    line := input.lines[i]
    regex.match(`(?i)(api[_-]?key|apikey|api[_-]?secret)\s*=\s*["'][a-zA-Z0-9]{16,}["']`, line.content)
    msg := sprintf("Line %d: Possible hardcoded API key", [line.number])
}

# Detect AWS keys
deny_aws_keys contains msg if {
    line := input.lines[i]
    regex.match(`(?i)(AKIA[0-9A-Z]{16}|aws[_-]?secret[_-]?access[_-]?key)`, line.content)
    msg := sprintf("Line %d: Possible AWS credentials detected", [line.number])
}

# Detect Azure keys
deny_azure_keys contains msg if {
    line := input.lines[i]
    regex.match(`(?i)(azure[_-]?client[_-]?secret|azure[_-]?tenant|AccountKey=)`, line.content)
    msg := sprintf("Line %d: Possible Azure credentials detected", [line.number])
}

# ============================================================================
# DANGEROUS FUNCTIONS
# ============================================================================

# Detect Invoke-Expression usage
deny_invoke_expression contains msg if {
    line := input.lines[i]
    regex.match(`(?i)invoke-expression|iex\s+`, line.content)
    not regex.match(`^\s*#`, line.content)  # Skip comments
    msg := sprintf("Line %d: Invoke-Expression is dangerous - avoid with untrusted input", [line.number])
}

# Detect ConvertTo-SecureString with plain text
deny_plaintext_secure_string contains msg if {
    line := input.lines[i]
    regex.match(`(?i)ConvertTo-SecureString\s+.*-AsPlainText`, line.content)
    msg := sprintf("Line %d: ConvertTo-SecureString with -AsPlainText exposes secrets", [line.number])
}

# ============================================================================
# INSECURE PROTOCOLS
# ============================================================================

# Detect HTTP (not HTTPS) in web requests
deny_insecure_http contains msg if {
    line := input.lines[i]
    regex.match(`(?i)(invoke-webrequest|invoke-restmethod|wget|curl).*["']http://`, line.content)
    not regex.match(`(?i)http://localhost|http://127\.0\.0\.1`, line.content)
    msg := sprintf("Line %d: Use HTTPS instead of HTTP for web requests", [line.number])
}

# Detect disabled certificate validation
deny_skip_cert_check contains msg if {
    line := input.lines[i]
    regex.match(`(?i)-SkipCertificateCheck|-SkipCert`, line.content)
    msg := sprintf("Line %d: Skipping certificate validation is insecure", [line.number])
}

# ============================================================================
# AGGREGATE SECURITY VIOLATIONS
# ============================================================================

security_violations := union({
    deny_hardcoded_password,
    deny_hardcoded_connection_string,
    deny_hardcoded_api_key,
    deny_aws_keys,
    deny_azure_keys,
    deny_invoke_expression,
    deny_plaintext_secure_string,
    deny_insecure_http,
    deny_skip_cert_check
})
