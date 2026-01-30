# Skill Security Review: skill-creator

**Review Date**: January 30, 2026  
**Reviewer**: Claude (using skill-security-reviewer)  
**Skill Version**: Unknown (no version in manifest)

---

## Executive Summary

The `skill-creator` skill is a meta-skill that guides users in creating new skills. It includes Python scripts for initialization, validation, and packaging of skills. Overall, this is a **low-risk skill** with no critical or high-severity findings. The code follows reasonable security practices, though there are some areas for improvement around input validation and YAML parsing.

**Overall Risk Assessment**: Low

**Recommendation**: Approve with minor recommendations

---

## Skill Overview

**Stated Purpose**: Guide for creating effective skills. Used when users want to create or update skills that extend Claude's capabilities with specialized knowledge, workflows, or tool integrations.

**Declared Capabilities**:
- No explicit `allowed-tools` field declared
- License referenced: "Complete terms in LICENSE.txt"

**Actual Capabilities Observed**:
- File system operations (create directories, write files)
- File permission changes (chmod)
- ZIP file creation
- YAML parsing
- Regex-based validation

**Manifest-Behavior Alignment**: Minor gaps — The description doesn't explicitly mention that the skill includes executable scripts that perform file system operations. However, this is reasonable for a skill-creation tool.

---

## Findings

### F001: YAML Parsing Uses safe_load (Positive Finding)

**Severity**: Info (Positive)

**Category**: T2 - Code Execution Risks

**Location**: scripts/quick_validate.py, line 38

**Description**:
The skill correctly uses `yaml.safe_load()` instead of the dangerous `yaml.load()` for parsing YAML frontmatter. This prevents arbitrary code execution through malicious YAML.

**Evidence**:
```python
frontmatter = yaml.safe_load(frontmatter_text)
```

**Risk Analysis**:
No risk — this is the correct approach.

**Remediation**:
None needed. This is a positive security practice.

---

### F002: File Path Construction Without Full Normalization

**Severity**: Low

**Category**: T2 - Code Execution Risks / T3 - Data & Privacy

**Location**: scripts/init_skill.py, lines 206, 228-234, 239-258

**Description**:
The `init_skill.py` script accepts a user-provided path and skill name, then constructs paths using `Path(path).resolve() / skill_name`. While `resolve()` normalizes the path, the script doesn't validate that the resulting path is within an expected directory. A user could potentially create skills in unintended locations.

**Evidence**:
```python
def init_skill(skill_name, path):
    skill_dir = Path(path).resolve() / skill_name
    # ...
    skill_dir.mkdir(parents=True, exist_ok=False)
```

**Risk Analysis**:
Low risk in practice because:
1. The script is run by the user themselves, not automatically
2. The user explicitly provides both the path and skill name
3. Creating directories generally requires existing write permissions

However, in a multi-user or automated environment, this could be exploited to create files in unintended locations if the path input is not trusted.

**Remediation**:
Consider adding validation that the output path is within an allowed directory:
```python
ALLOWED_ROOTS = [Path.home() / "skills", Path("/mnt/skills")]
resolved = Path(path).resolve() / skill_name
if not any(resolved.is_relative_to(root) for root in ALLOWED_ROOTS):
    raise ValueError(f"Path must be within allowed directories")
```

---

### F003: No Input Sanitization on Skill Name

**Severity**: Low

**Category**: T2 - Code Execution Risks

**Location**: scripts/init_skill.py, lines 287-294

**Description**:
The `init_skill.py` script accepts a skill name from command-line arguments and uses it directly in path construction and string formatting. While the script does validate naming conventions in `quick_validate.py`, this validation happens *after* the skill is created in `init_skill.py`, not before.

**Evidence**:
```python
skill_name = sys.argv[1]
path = sys.argv[3]

# ... later used in:
skill_dir = Path(path).resolve() / skill_name
skill_content = SKILL_TEMPLATE.format(skill_name=skill_name, skill_title=skill_title)
```

**Risk Analysis**:
The `.format()` usage is safe because `skill_name` only substitutes into string templates, not into code execution contexts. The path construction could theoretically allow path traversal if `skill_name` contained `../`, but `resolve()` would normalize this away.

However, the skill name validation in `quick_validate.py` (kebab-case, no special chars) is not enforced in `init_skill.py` before directory creation.

**Remediation**:
Add name validation in `init_skill.py` before any file operations:
```python
import re
if not re.match(r'^[a-z0-9-]+$', skill_name):
    print("Error: Skill name must be kebab-case")
    sys.exit(1)
```

---

### F004: Potential Resource Exhaustion via rglob

**Severity**: Low

**Category**: T6 - Resource Exhaustion

**Location**: scripts/package_skill.py, line 70

**Description**:
The packaging script uses `rglob('*')` to recursively find all files in a skill directory. If pointed at a directory with many files (e.g., a directory containing node_modules or a large git repo), this could consume significant memory and time.

**Evidence**:
```python
for file_path in skill_path.rglob('*'):
    if file_path.is_file():
        arcname = file_path.relative_to(skill_path.parent)
        zipf.write(file_path, arcname)
```

**Risk Analysis**:
Low risk because:
1. The user controls what directory is packaged
2. Skill directories are typically small
3. This is a local operation, not a server-side one

However, accidentally packaging a large directory could cause slowdowns.

**Remediation**:
Consider adding safeguards:
```python
MAX_FILES = 1000
file_count = 0
for file_path in skill_path.rglob('*'):
    file_count += 1
    if file_count > MAX_FILES:
        print(f"Error: Too many files ({file_count}+). Is this the right directory?")
        return None
```

Or exclude known problematic directories:
```python
EXCLUDE_DIRS = {'.git', 'node_modules', '__pycache__', '.venv'}
```

---

### F005: No Integrity Verification for Created Skills

**Severity**: Info

**Category**: T5 - Supply Chain & Dependencies

**Location**: scripts/package_skill.py

**Description**:
The packaging script creates a `.skill` file (ZIP format) but doesn't generate checksums or signatures for integrity verification. Users receiving a `.skill` file cannot verify it hasn't been tampered with.

**Evidence**:
The script creates a ZIP file without any accompanying integrity information:
```python
with zipfile.ZipFile(skill_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
    # ... writes files
print(f"✅ Successfully packaged skill to: {skill_filename}")
```

**Risk Analysis**:
This is an informational finding. For skills shared publicly or across organizations, lack of integrity verification means a man-in-the-middle or compromised distribution channel could modify the skill.

**Remediation**:
Consider generating and outputting a SHA256 checksum:
```python
import hashlib
with open(skill_filename, 'rb') as f:
    checksum = hashlib.sha256(f.read()).hexdigest()
print(f"SHA256: {checksum}")
# Optionally write to .skill.sha256 file
```

---

### F006: Template Strings Don't Contain Injection Risks

**Severity**: Info (Positive)

**Category**: T1 - Prompt Injection

**Location**: scripts/init_skill.py, lines 18-186

**Description**:
The template strings (`SKILL_TEMPLATE`, `EXAMPLE_SCRIPT`, `EXAMPLE_REFERENCE`, `EXAMPLE_ASSET`) were reviewed for prompt injection patterns. None contain instruction override patterns, concealment language, or other manipulation attempts.

**Evidence**:
Templates contain benign placeholder text like:
- `[TODO: Complete and informative explanation...]`
- `# TODO: Add actual script logic here`
- Guidance about skill structure

**Risk Analysis**:
No risk. The templates are safe.

**Remediation**:
None needed.

---

## Checklist Results

### Manifest & Policy
- [x] Skill name valid (`skill-creator` matches `[a-z0-9-]+`)
- [x] Description present and accurate
- [x] License referenced
- [x] No unauthorized branding

### Prompt Injection & Instruction Safety
- [x] No instruction override patterns
- [x] No mode switching language
- [x] No concealment patterns
- [x] Templates and references checked — clean

### Code Execution Safety
- [x] No `eval()` or `exec()` on untrusted data
- [x] No `os.system()` or unsafe subprocess
- [x] YAML uses `safe_load()` ✓
- [x] No SQL (not applicable)
- [ ] **Minor**: Path validation could be stronger (F002, F003)

### Declared vs. Actual Behavior
- [x] Description matches general behavior
- [ ] **Minor**: File system operations not explicitly declared (acceptable for this skill type)

### Data & Privacy
- [x] No network calls
- [x] No hardcoded credentials
- [x] No data exfiltration patterns
- [ ] **Minor**: No path traversal prevention (F002)

### Dependency & Supply Chain
- [x] Minimal dependencies (stdlib only: sys, os, re, yaml, pathlib, zipfile)
- [x] No external package installation
- [ ] **Info**: No integrity verification for outputs (F005)

### Resource Exhaustion
- [ ] **Minor**: Unbounded file iteration (F004)
- [x] No unbounded loops otherwise
- [x] No recursive functions without limits

### Files, References & Binaries
- [x] No binary files
- [x] All text files reviewed
- [x] No suspicious URLs
- [x] Reference files contain only documentation

### Logging & Audit
- [x] No logging suppression
- [x] Operations print status messages

### Multi-Skill Considerations
- [x] Description is distinct
- [x] No cross-skill invocation patterns

---

## Files Reviewed

| File | Type | Findings |
|------|------|----------|
| SKILL.md | Instructions | None |
| scripts/init_skill.py | Python | F002, F003 |
| scripts/package_skill.py | Python | F004, F005 |
| scripts/quick_validate.py | Python | F001 (positive) |
| references/workflows.md | Documentation | None |
| references/output-patterns.md | Documentation | None |

---

## Recommendations

### Must Fix (Blocking)
None — no critical or high-severity findings.

### Should Fix
1. **F002/F003**: Add input validation for skill names in `init_skill.py` before file operations, matching the validation in `quick_validate.py`.

### Consider
1. **F004**: Add safeguards against packaging excessively large directories (file count limit or exclusion list).
2. **F005**: Generate checksums for packaged `.skill` files to enable integrity verification.

---

## Conclusion

The `skill-creator` skill is **safe to use**. It follows good security practices, including using `yaml.safe_load()` for YAML parsing and avoiding dangerous code execution patterns. The templates and documentation contain no prompt injection or malicious content.

The findings are all low-severity or informational, primarily around input validation and defense-in-depth improvements. These are reasonable to address in future iterations but do not block approval.

**Approved for use.**
