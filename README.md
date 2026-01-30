# Skill Security Reviewer

An AI skill that teaches language models how to perform intelligent security reviews of agent skills. Unlike static scanners that match patterns, this skill enables contextual threat analysis, intent reasoning, and detection of novel attacks.

## What is This?

This is a **skill** — a structured set of instructions that extends an AI assistant's capabilities. Specifically, it teaches the AI how to:

- Analyze skills for security vulnerabilities
- Reason about intent, not just syntax
- Detect prompt injection, code execution risks, data exfiltration, and more
- Produce actionable security reports

For background on what skills are and why they matter, see the companion blog posts:
- [The Complete Guide to Agent Skills: Concepts, Security, and Best Practices](https://medium.com/@oguzhantopgul/the-complete-guide-to-agent-skills-concepts-security-and-best-practices-part-1-understanding-08403fafdeeb)

## Why an AI-Powered Security Reviewer?

Traditional static analysis tools match patterns — they look for `eval()` or `shell=True` and flag them. But they miss:

- **Semantic manipulation** — Instructions that seem benign but have dangerous interpretations
- **Context-dependent risks** — A network call in a "weather" skill is fine; in a "calculator" skill, it's suspicious
- **Novel attacks** — Anything that doesn't match a pre-written rule
- **Intent analysis** — Understanding *why* code does something, not just *what* it does

An LLM guided by security expertise can reason about these issues the way a human security reviewer would — but faster and more consistently.

## Installation

Copy the `skill-security-reviewer` folder to your skills directory:

```bash
# Example for Claude's skill directory
cp -r skill-security-reviewer /path/to/your/skills/
```

Or clone this repository:

```bash
git clone https://github.com/YOUR_USERNAME/skill-security-reviewer.git
```

## Usage

Once installed, ask your AI assistant to review a skill:

```
Review the skill at /path/to/some-skill for security issues
```

Or:

```
Perform a security audit of the pdf-editor skill
```

The AI will:
1. Gather all skill components (SKILL.md, scripts, references, assets)
2. Establish baseline expectations from the manifest
3. Analyze actual behavior against threat models
4. Produce a structured security report

## Skill Structure

```
skill-security-reviewer/
├── SKILL.md                    # Core instructions and threat models
├── scripts/
│   └── gather_skill.py         # Helper to collect skill files
├── references/
│   ├── threat-deep-dive.md     # Detailed patterns for each threat category
│   ├── report-template.md      # Security report format
│   └── checklist.md            # Complete verification checklist
```

## Threat Categories Covered

| Category | Description |
|----------|-------------|
| T1 | Prompt Injection & Instruction Override |
| T2 | Code Execution Risks |
| T3 | Data Exfiltration & Privacy |
| T4 | Manifest-Behavior Mismatch |
| T5 | Supply Chain & Dependencies |
| T6 | Resource Exhaustion |
| T7 | Binary & Asset Risks |
| T8 | Multi-Skill & Privilege Escalation |

## Example Output

See [examples/sample-review.md](examples/sample-review.md) for a complete security review produced by this skill.

## Security Checklist

For quick manual reviews, see the standalone checklist: [references/checklist.md](references/checklist.md)

## Related Resources

- [The Complete Guide to Agent Skills](#) — Understanding skills, security, and best practices
- [Securing Agent Skills: A Practical Checklist](#) — The checklist that informed this skill

## Contributing

Contributions welcome! Areas that would be particularly valuable:

- Additional threat patterns for `references/threat-deep-dive.md`
- Example reviews of different skill types
- Integration with CI/CD pipelines
- Translations of the checklist

## License

MIT License — See [LICENSE](LICENSE) for details.

## Acknowledgments

The threat categories covered in this skill were inspired in part by the threat taxonomy from the [Cisco Skills Scanner Project](https://github.com/cisco-ai-defense/skill-scanner).
