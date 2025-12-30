# policies/powershell/main.rego
# Main policy aggregating all PowerShell rules

package powershell.main

import data.powershell.security
import data.powershell.best_practices
import data.powershell.cicd

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# ============================================================================
# DENY - These cause build failure
# ============================================================================

deny contains msg if {
    msg := security.security_violations[_]
}

deny contains msg if {
    msg := cicd.cicd_violations[_]
}

# ============================================================================
# WARN - These are reported but don't fail build
# ============================================================================

warn contains msg if {
    msg := best_practices.best_practice_warnings[_]
}

warn contains msg if {
    msg := cicd.cicd_warnings[_]
}

# ============================================================================
# SUMMARY
# ============================================================================

summary := {
    "file": input.file,
    "total_lines": count(input.lines),
    "errors": count(deny),
    "warnings": count(warn),
    "pass": count(deny) == 0
}

# ============================================================================
# RESULT
# ============================================================================

result := {
    "summary": summary,
    "errors": deny,
    "warnings": warn
}
