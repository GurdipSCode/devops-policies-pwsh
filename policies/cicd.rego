# policies/powershell/cicd.rego
# OPA policies for CI/CD PowerShell scripts

package powershell.cicd

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# ============================================================================
# EXIT CODES
# ============================================================================

# Check for explicit exit codes
warn_no_exit_code contains msg if {
    not has_exit_statement
    input.is_script
    msg := "CI/CD script should have explicit exit codes for pass/fail"
}

has_exit_statement if {
    line := input.lines[_]
    regex.match(`(?i)\bexit\s+\d+|\bexit\s+\$`, line.content)
}

# Check for exit 0 after success (potential false positive handler)
warn_unconditional_exit_zero contains msg if {
    line := input.lines[i]
    regex.match(`(?i)^\s*exit\s+0\s*$`, line.content)
    
    # Check if it's at the end of a try block or conditional
    prev_line := input.lines[i - 1]
    not regex.match(`(?i)\}|else|success|passed|green`, prev_line.content)
    msg := sprintf("Line %d: Unconditional 'exit 0' may mask failures", [line.number])
}

# ============================================================================
# LOGGING / OUTPUT
# ============================================================================

# Detect potential secret logging
deny_potential_secret_logging contains msg if {
    line := input.lines[i]
    regex.match(`(?i)(Write-Host|Write-Output|Write-Verbose|echo).*\$(password|secret|token|apikey|api_key|credential)`, line.content)
    msg := sprintf("Line %d: Potential secret being logged to output", [line.number])
}

# Check for buildkite-agent annotate usage
info_buildkite_annotate contains msg if {
    line := input.lines[i]
    regex.match(`buildkite-agent\s+annotate`, line.content)
    not regex.match(`--context`, line.content)
    msg := sprintf("Line %d: buildkite-agent annotate should include --context", [line.number])
}

# ============================================================================
# ARTIFACTS
# ============================================================================

# Check artifact download error handling
warn_artifact_no_error_handling contains msg if {
    line := input.lines[i]
    regex.match(`buildkite-agent\s+artifact\s+download`, line.content)
    not regex.match(`2>\$null|2>null|-ErrorAction`, line.content)
    
    # Check next line for error handling
    next_line := input.lines[i + 1]
    not regex.match(`(?i)if\s*\(|Test-Path`, next_line.content)
    msg := sprintf("Line %d: Handle artifact download failures", [line.number])
}

# ============================================================================
# IDEMPOTENCY
# ============================================================================

# Check for New-Item without -Force (not idempotent)
warn_new_item_not_idempotent contains msg if {
    line := input.lines[i]
    regex.match(`(?i)New-Item\s+`, line.content)
    not regex.match(`(?i)-Force`, line.content)
    not regex.match(`(?i)if\s*\(\s*-not\s*\(Test-Path`, input.lines[i - 1].content)
    msg := sprintf("Line %d: New-Item without -Force may fail if item exists", [line.number])
}

# Check for Remove-Item without -ErrorAction
warn_remove_item_strict contains msg if {
    line := input.lines[i]
    regex.match(`(?i)Remove-Item\s+`, line.content)
    not regex.match(`(?i)-ErrorAction|if\s*\(Test-Path`, line.content)
    msg := sprintf("Line %d: Remove-Item should handle non-existent items gracefully", [line.number])
}

# ============================================================================
# EXTERNAL TOOLS
# ============================================================================

# Common CI tools that need exit code checking
warn_tool_no_exit_check contains msg if {
    line := input.lines[i]
    tools := ["terraform", "tfsec", "trivy", "checkov", "opa", "git", "az", "aws", "kubectl", "helm", "docker"]
    tool := tools[_]
    
    regex.match(sprintf(`(?i)^\s*%s\s+`, [tool]), line.content)
    not regex.match(`(?i)\$\(|try\s*\{`, line.content)
    
    # Check if next few lines check exit code
    check_lines := [input.lines[j].content | j := numbers.range(i + 1, i + 3)[_]]
    not exit_code_checked(check_lines)
    msg := sprintf("Line %d: Check exit code after '%s' command", [line.number, tool])
}

exit_code_checked(lines) if {
    line := lines[_]
    regex.match(`(?i)\$LASTEXITCODE|if\s*\(|\$\?`, line)
}

# ============================================================================
# AGGREGATE CI/CD VIOLATIONS
# ============================================================================

cicd_violations := deny_potential_secret_logging

cicd_warnings := union({
    warn_no_exit_code,
    warn_unconditional_exit_zero,
    warn_artifact_no_error_handling,
    warn_new_item_not_idempotent,
    warn_remove_item_strict,
    warn_tool_no_exit_check,
    info_buildkite_annotate
})
