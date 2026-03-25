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

## Contributing

New skills are currently curated by the maintainer. If you have a playbook idea or have been through an incident worth encoding, open an issue to discuss before building. The structure for a new skill:

```
skills/<skill-name>/
├── SKILL.md              # Required. Claude instructions + YAML frontmatter.
├── README.md             # Required. Standalone usage docs.
├── references/           # Optional. IOC libraries, pattern files, reference docs.
└── scripts/              # Optional. Standalone scripts that work without Claude.
```

The `SKILL.md` frontmatter needs a `name` and `description`. The description controls when Claude triggers the skill, so make it specific about the contexts where the skill is useful.

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
