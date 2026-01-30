# Security Review Report Template

Use this template when producing security review reports.

---

## Report Structure

```markdown
# Skill Security Review: [skill-name]

**Review Date**: [date]
**Reviewer**: [name/identifier]
**Skill Version**: [version or commit if available]

---

## Executive Summary

[2-3 sentence overview: What is this skill? What is the overall risk level? Are there blocking issues?]

**Overall Risk Assessment**: [Critical / High / Medium / Low / Pass]

**Recommendation**: [Approve / Approve with conditions / Reject / Needs remediation]

---

## Skill Overview

**Stated Purpose**: [What the skill claims to do based on description]

**Declared Capabilities**:
- [Tool/permission 1]
- [Tool/permission 2]

**Actual Capabilities Observed**:
- [Capability 1]
- [Capability 2]

**Manifest-Behavior Alignment**: [Match / Minor gaps / Significant gaps / Misleading]

---

## Findings

### [Finding ID]: [Finding Title]

**Severity**: [Critical / High / Medium / Low / Info]

**Category**: [T1-T8 category]

**Location**: [File path and line numbers if applicable]

**Description**:
[What was found and why it's a concern]

**Evidence**:
```
[Code snippet, instruction text, or other evidence]
```

**Risk Analysis**:
[How could this be exploited? What's the impact?]

**Remediation**:
[Specific steps to fix this issue]

---

[Repeat for each finding]

---

## Checklist Results

### Manifest & Policy
- [x] Skill name valid
- [x] Description accurate
- [ ] **FAIL**: License not specified

### Prompt Injection
- [x] No instruction override patterns
- [x] No mode switching
- [x] No concealment language

[Continue for all categories...]

---

## Files Reviewed

| File | Type | Findings |
|------|------|----------|
| SKILL.md | Instructions | Finding 1, 2 |
| scripts/main.py | Python | Finding 3 |
| assets/template.html | Template | None |

---

## Recommendations

### Must Fix (Blocking)
1. [Critical/High severity items that must be addressed]

### Should Fix
1. [Medium severity items recommended for remediation]

### Consider
1. [Low severity items or best practice suggestions]

---

## Conclusion

[Final assessment paragraph: Is this skill safe to use? Under what conditions? What monitoring might be needed?]
```

---

## Severity Guidelines

| Severity | Criteria | Examples |
|----------|----------|----------|
| **Critical** | Immediate exploitation possible; high impact; no user interaction required | Remote code execution, credential theft, unrestricted prompt injection |
| **High** | Exploitable with some conditions; significant impact | SQL injection, path traversal to sensitive files, undeclared network exfiltration |
| **Medium** | Requires specific circumstances; moderate impact | Unbounded resource usage, missing input validation, undeclared capabilities |
| **Low** | Theoretical risk; minimal impact; defense in depth | Unpinned dependencies, verbose error messages, minor manifest inconsistencies |
| **Info** | Observation; not a vulnerability; best practice suggestion | Code style, documentation gaps, optimization opportunities |

---

## Writing Effective Findings

### Good Finding

```markdown
### F001: SQL Injection in User Query Handler

**Severity**: High

**Category**: T2 - Code Execution Risks

**Location**: scripts/database.py, lines 45-48

**Description**:
User-provided search terms are concatenated directly into SQL queries without sanitization or parameterization, allowing SQL injection attacks.

**Evidence**:
```python
def search_users(search_term):
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)
```

**Risk Analysis**:
An attacker could provide a search term like `'; DROP TABLE users; --` to execute arbitrary SQL commands, potentially destroying data or exfiltrating the entire database.

**Remediation**:
Use parameterized queries:
```python
def search_users(search_term):
    query = "SELECT * FROM users WHERE name LIKE ?"
    cursor.execute(query, (f'%{search_term}%',))
```
```

### Bad Finding

```markdown
### F001: SQL Issue

**Severity**: High

**Description**: The code has SQL problems.

**Remediation**: Fix the SQL.
```

The good finding includes specific location, evidence, exploitation scenario, and concrete remediation. The bad finding is vague and unactionable.

---

## Report Tone Guidelines

- **Be specific**: Point to exact files, lines, and code
- **Be objective**: Describe what is, not what you assume about intent
- **Be actionable**: Every finding should have clear remediation steps
- **Be proportionate**: Don't over-hype low-severity issues
- **Be thorough**: Better to note an info-level observation than miss something
- **Be clear**: Write for someone who will need to fix the issues
