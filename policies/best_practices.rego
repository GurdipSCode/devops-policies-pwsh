# policies/powershell/best_practices.rego
# OPA policies for PowerShell best practices

package powershell.best_practices

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# ============================================================================
# ERROR HANDLING
# ============================================================================

# Check for ErrorActionPreference
warn_no_error_action_preference contains msg if {
    not has_error_action_preference
    msg := "Script should set $ErrorActionPreference = 'Stop' for fail-fast behavior"
}

has_error_action_preference if {
    line := input.lines[_]
    regex.match(`(?i)\$ErrorActionPreference\s*=\s*["']Stop["']`, line.content)
}

# Check for empty catch blocks
warn_empty_catch contains msg if {
    line := input.lines[i]
    regex.match(`(?i)catch\s*\{\s*\}`, line.content)
    msg := sprintf("Line %d: Empty catch block - handle or log the error", [line.number])
}

# Check LASTEXITCODE after external commands
warn_unchecked_lastexitcode contains msg if {
    line := input.lines[i]
    next_line := input.lines[i + 1]
    
    # Common external tools
    regex.match(`(?i)(terraform|tfsec|trivy|checkov|git|az|aws|kubectl)\s+`, line.content)
    not regex.match(`(?i)\$LASTEXITCODE`, next_line.content)
    not regex.match(`(?i)if\s*\(`, next_line.content)
    msg := sprintf("Line %d: Check $LASTEXITCODE after external command", [line.number])
}

# ============================================================================
# CMDLET ALIASES
# ============================================================================

# Detect common aliases that should be full cmdlet names
warn_alias_usage contains msg if {
    line := input.lines[i]
    not regex.match(`^\s*#`, line.content)  # Skip comments
    
    aliases := {
        "cd": "Set-Location",
        "cls": "Clear-Host",
        "cp": "Copy-Item",
        "dir": "Get-ChildItem",
        "echo": "Write-Output",
        "del": "Remove-Item",
        "rm": "Remove-Item",
        "mv": "Move-Item",
        "cat": "Get-Content",
        "pwd": "Get-Location",
        "ls": "Get-ChildItem",
        "ps": "Get-Process",
        "kill": "Stop-Process",
        "curl": "Invoke-WebRequest",
        "wget": "Invoke-WebRequest",
        "%": "ForEach-Object",
        "?": "Where-Object",
        "select": "Select-Object",
        "sort": "Sort-Object",
        "ft": "Format-Table",
        "fl": "Format-List",
        "gm": "Get-Member",
        "gc": "Get-Content",
        "sc": "Set-Content",
        "ac": "Add-Content",
        "gi": "Get-Item",
        "gci": "Get-ChildItem",
        "ni": "New-Item",
        "ri": "Remove-Item",
        "mi": "Move-Item",
        "ci": "Copy-Item",
        "gl": "Get-Location",
        "sl": "Set-Location",
        "iex": "Invoke-Expression",
        "irm": "Invoke-RestMethod",
        "iwr": "Invoke-WebRequest"
    }
    
    alias := object.keys(aliases)[_]
    regex.match(sprintf(`(?i)\b%s\b`, [alias]), line.content)
    msg := sprintf("Line %d: Use '%s' instead of alias '%s'", [line.number, aliases[alias], alias])
}

# ============================================================================
# DOCUMENTATION
# ============================================================================

# Check for comment-based help
warn_no_help contains msg if {
    not has_comment_help
    input.is_script  # Only for standalone scripts, not modules
    msg := "Script should include comment-based help (.SYNOPSIS, .DESCRIPTION)"
}

has_comment_help if {
    line := input.lines[_]
    regex.match(`(?i)\.(SYNOPSIS|DESCRIPTION)`, line.content)
}

# Check for CmdletBinding in functions
warn_no_cmdlet_binding contains msg if {
    line := input.lines[i]
    regex.match(`(?i)^\s*function\s+\w+`, line.content)
    next_lines := [input.lines[j] | j := numbers.range(i, i + 3)[_]]
    not has_cmdlet_binding(next_lines)
    msg := sprintf("Line %d: Function should use [CmdletBinding()]", [line.number])
}

has_cmdlet_binding(lines) if {
    line := lines[_]
    regex.match(`(?i)\[CmdletBinding\(\)\]`, line.content)
}

# ============================================================================
# CODE QUALITY
# ============================================================================

# Check for Write-Host without color (info should use Write-Output)
warn_write_host_no_color contains msg if {
    line := input.lines[i]
    regex.match(`(?i)Write-Host\s+["'][^"']+["']\s*$`, line.content)
    not regex.match(`(?i)-ForegroundColor|-BackgroundColor`, line.content)
    msg := sprintf("Line %d: Consider Write-Output for data or add -ForegroundColor for UI output", [line.number])
}

# Check for magic numbers
warn_magic_numbers contains msg if {
    line := input.lines[i]
    not regex.match(`^\s*#`, line.content)  # Skip comments
    not regex.match(`(?i)(exit|return|\$LASTEXITCODE|Line|sleep|Start-Sleep)`, line.content)
    regex.match(`[^0-9\.]\b([2-9]\d{2,}|\d{4,})\b[^0-9\.]`, line.content)  # Numbers > 199 or 4+ digits
    msg := sprintf("Line %d: Consider using named constant instead of magic number", [line.number])
}

# Check for long lines
warn_long_lines contains msg if {
    line := input.lines[i]
    count(line.content) > 120
    msg := sprintf("Line %d: Line exceeds 120 characters (%d chars)", [line.number, count(line.content)])
}

# ============================================================================
# APPROVED VERBS
# ============================================================================

# Check for approved PowerShell verbs in function names
warn_unapproved_verb contains msg if {
    line := input.lines[i]
    regex.match(`(?i)^\s*function\s+(\w+)-`, line.content)
    
    # Extract verb
    match := regex.find_n(`(?i)function\s+(\w+)-`, line.content, 1)
    verb := lower(regex.replace(match[0], `(?i)function\s+`, ""))
    verb_clean := regex.replace(verb, `-.*`, "")
    
    approved_verbs := {
        "add", "approve", "assert", "backup", "block", "checkpoint", "clear", "close", "compare",
        "complete", "compress", "confirm", "connect", "convert", "copy", "debug", "deny", "disable",
        "disconnect", "dismount", "edit", "enable", "enter", "exit", "expand", "export", "find",
        "format", "get", "grant", "group", "hide", "import", "initialize", "install", "invoke",
        "join", "limit", "lock", "measure", "merge", "mount", "move", "new", "open", "optimize",
        "out", "ping", "pop", "protect", "publish", "push", "read", "receive", "redo", "register",
        "remove", "rename", "repair", "request", "reset", "resize", "resolve", "restart", "restore",
        "resume", "revoke", "save", "search", "select", "send", "set", "show", "skip", "split",
        "start", "step", "stop", "submit", "suspend", "switch", "sync", "test", "trace", "unblock",
        "undo", "uninstall", "unlock", "unprotect", "unpublish", "unregister", "update", "use",
        "wait", "watch", "write"
    }
    
    not verb_clean in approved_verbs
    msg := sprintf("Line %d: '%s' is not an approved PowerShell verb", [line.number, verb_clean])
}

# ============================================================================
# AGGREGATE BEST PRACTICE WARNINGS
# ============================================================================

best_practice_warnings := union({
    warn_no_error_action_preference,
    warn_empty_catch,
    warn_alias_usage,
    warn_no_help,
    warn_write_host_no_color,
    warn_long_lines,
    warn_unapproved_verb
})
