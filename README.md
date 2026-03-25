# agent-infra-security

Security skills for AI coding agents — detect compromised PyPI packages, triage supply chain attacks, hunt for IOCs, and automate credential rotation. Each skill works as an installable agent skill (Claude Code, Codex, Cursor) or as standalone scripts and runbooks you can use without any agent.

Every skill in this repo works two ways: as an agent skill you can install and trigger conversationally, and as a standalone resource (shell scripts, runbooks, IOC pattern libraries) you can use directly.

## Skills

| Skill | What it does | Standalone tools |
|-------|-------------|-----------------|
| [pypi-supply-chain-response](skills/pypi-supply-chain-response/) | Triage and recover from a compromised Python package on PyPI | `check_compromise_template.sh`, IOC pattern library, manual investigation playbook |
| [supply-chain-security-check](skills/supply-chain-security-check/) | Multi-ecosystem blast radius scan for any compromised dependency | Investigation commands for Python, Node, Go, Rust, Java, Docker |

## Why this exists

AI agent infrastructure has a supply chain problem. Packages like LiteLLM sit at the center of the AI stack, routing API keys for dozens of LLM providers, and they're pulled in as transitive dependencies by frameworks most developers don't audit. When one of these packages gets compromised, the blast radius is enormous and the response playbook doesn't exist in most organizations.

This repo collects the response playbooks, detection scripts, and Claude skills that fill that gap. Each skill encodes the kind of triage process a security engineer would walk you through, except it's available to any developer at 2am when the advisory drops.

## Using the skills

### As agent skills (Claude Code, Codex, Cursor)

Each skill directory contains a `SKILL.md` with agent instructions and YAML frontmatter. For Claude Code, point your skill path at the specific skill directory. For other agents, use the skill's `README.md` and standalone tools directly.

Trigger phrases are listed in each skill's `SKILL.md` frontmatter. For example, `pypi-supply-chain-response` triggers on anything from "litellm got compromised" to "how do I check if my pip dependencies are backdoored."

### As standalone tools

Every skill ships scripts and references that work without any agent. Check each skill's README for usage. Shell scripts include `--dry-run` flags and confirmation prompts before destructive actions.

## Quick manual check (no agent needed)

If a package just got reported as compromised and you need to check right now:

```bash
# Is it installed? What version?
pip show <PACKAGE> | grep -E "^(Name|Version|Location)"

# What pulled it in? (transitive dependency check — the step most people miss)
pip install pipdeptree && pipdeptree -r -p <PACKAGE>

# Is it hiding in other environments on this machine?
find / -path "*/site-packages/<PACKAGE>" -type d 2>/dev/null

# Any malicious .pth startup hooks? (fires on every Python invocation, not just import)
SITE=$(python -c "import site; print(site.getsitepackages()[0])")
find "$SITE" -name "*.pth" -exec grep -l "base64\|subprocess\|exec\|eval\|compile" {} \;

# Cached wheels that could reinstall the bad version?
pip cache list <PACKAGE>
```

For the full investigation playbook (Windows/macOS/Linux), see [`manual-investigation-playbook.md`](skills/pypi-supply-chain-response/references/manual-investigation-playbook.md).

## Contributing

New skills are curated by the maintainer. If you have a playbook idea, [open an issue](../../issues) to discuss.

## Repo structure

```
agent-infra-security/
├── README.md                                    # This file
├── LICENSE                                      # MIT
├── CATALOG.md                                   # Skill index with descriptions
└── skills/
    ├── pypi-supply-chain-response/              # PyPI-specific deep triage
    │   ├── SKILL.md
    │   ├── README.md
    │   ├── references/
    │   │   ├── ioc-patterns.md
    │   │   └── manual-investigation-playbook.md
    │   └── scripts/
    │       └── check_compromise_template.sh
    └── supply-chain-security-check/             # Multi-ecosystem blast radius scan
        ├── SKILL.md
        └── README.md
```

## License

MIT
