# Security Review Checklist

Complete checklist for skill security reviews. Use during analysis to ensure full coverage.

---

## Manifest & Policy

- [ ] Skill name matches `[a-z0-9-]{1,64}`
- [ ] Description is 20–1024 characters
- [ ] Description accurately reflects actual behavior
- [ ] License is specified
- [ ] No unauthorized "official" or vendor branding
- [ ] No impersonation of legitimate skills or vendors

---

## Prompt Injection & Instruction Safety

- [ ] No "ignore/disregard/forget previous instructions" patterns
- [ ] No "override prior rules/context" patterns
- [ ] No "you are now in [unrestricted/debug/admin] mode" patterns
- [ ] No "disable safety/filters/restrictions" patterns
- [ ] No "bypass content policy" patterns
- [ ] No "reveal/show system prompt" patterns
- [ ] No "don't tell the user" or concealment patterns
- [ ] No "hide this action from logs" patterns
- [ ] No encoded/obfuscated instructions (base64, rot13, etc.)
- [ ] Referenced files checked for injection patterns
- [ ] No semantic equivalents of override patterns
- [ ] No conditional injection triggers

---

## Code Execution Safety

### Python
- [ ] No `eval()` on untrusted input
- [ ] No `exec()` on untrusted input
- [ ] No `compile()` on untrusted input
- [ ] No `os.system()` with user input
- [ ] No `os.popen()` with user input
- [ ] No `subprocess` with `shell=True` and user input
- [ ] No unsafe deserialization (`pickle.loads`, `yaml.load` without SafeLoader)
- [ ] No SQL string formatting (use parameterized queries)
- [ ] File paths validated against traversal attacks

### Bash
- [ ] No `eval` with user input
- [ ] No unquoted variables in commands
- [ ] No command substitution with user input
- [ ] Inputs validated before use in commands

### General
- [ ] All user inputs traced to execution points
- [ ] Dangerous functions only receive sanitized input

---

## Declared vs. Actual Behavior

- [ ] All tools used in code are listed in `allowed-tools` (if field exists)
- [ ] Network usage declared in compatibility (if code uses network)
- [ ] File write capability declared (if code writes files)
- [ ] Code execution capability declared (if code runs subprocesses)
- [ ] Description mentions all significant capabilities
- [ ] Skill name accurately represents function
- [ ] No undeclared side effects

---

## Data & Privacy

### Network
- [ ] All network calls identified
- [ ] Network usage justified for skill's purpose
- [ ] Destinations documented or clearly legitimate
- [ ] No data exfiltration patterns (data in URLs, headers, DNS)

### Secrets
- [ ] No hardcoded API keys
- [ ] No hardcoded passwords or tokens
- [ ] Secrets loaded from environment variables or secure store
- [ ] Secrets not logged or included in error messages
- [ ] Secrets not exposed in output

### Data Access
- [ ] File access scoped to skill's stated purpose
- [ ] No access to unrelated sensitive files
- [ ] No collection of system information beyond need
- [ ] Path traversal prevented with normalization and containment

---

## Dependency & Supply Chain

- [ ] All dependencies identified
- [ ] Dependencies pinned to specific versions
- [ ] No typosquatting (verify package names carefully)
- [ ] Dependencies from trusted sources (official registries)
- [ ] No dependencies from arbitrary URLs or unverified git repos
- [ ] Dependency count justified for skill's scope
- [ ] No known vulnerable versions

---

## Resource Exhaustion

- [ ] All loops have termination conditions
- [ ] Loop bounds not solely controlled by untrusted input
- [ ] Recursion has explicit depth limits
- [ ] File creation bounded
- [ ] Memory allocation bounded
- [ ] Long-running operations have timeouts
- [ ] No patterns that could cause denial of service

---

## Files, References & Binaries

### Binaries
- [ ] All binary files identified
- [ ] Binaries are necessary and documented
- [ ] No unexpected executables (.exe, .dll, .so)
- [ ] No compiled code hiding source (.pyc without .py)

### Text Assets
- [ ] Template files checked for injection patterns
- [ ] Asset files checked for suspicious URLs
- [ ] No free phishing TLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`) without justification
- [ ] No URL shorteners hiding destinations
- [ ] No IPs where domains expected

### References
- [ ] All file references followed and checked
- [ ] No deeply nested references hiding content
- [ ] Referenced documentation doesn't contain injection

---

## Skill Integrity & Updates

- [ ] Skill source is known and trusted
- [ ] No auto-update from remote sources (or updates are verified)
- [ ] Integrity verification available (checksums, signatures) if distributed

---

## Logging & Audit

- [ ] Skill does not suppress or disable logging
- [ ] Skill does not tamper with audit mechanisms
- [ ] Sensitive data redacted from any logging
- [ ] No instructions to hide actions from the user

---

## Multi-Skill Considerations

- [ ] Description is distinct from other skills (no trigger hijacking)
- [ ] No instructions to invoke other skills with attacker-controlled input
- [ ] No privilege escalation through skill chaining
- [ ] Cross-skill interaction risks considered

---

## Novel Attack Patterns

Beyond checklist items, apply reasoning to detect:

- [ ] Semantic manipulation (benign-sounding dangerous instructions)
- [ ] Encoded or obfuscated payloads
- [ ] Indirect attacks (instructions that cause AI to generate dangerous code)
- [ ] Social engineering (content designed to manipulate reviewers)
- [ ] Time-of-check vs time-of-use vulnerabilities
- [ ] Context-dependent attacks (safe in isolation, dangerous in context)

---

## Review Completion

- [ ] All SKILL.md content reviewed
- [ ] All scripts reviewed
- [ ] All references reviewed
- [ ] All assets reviewed
- [ ] All file references followed recursively
- [ ] Findings documented with evidence
- [ ] Severity ratings assigned with justification
- [ ] Remediation guidance provided
- [ ] Overall risk assessment completed
