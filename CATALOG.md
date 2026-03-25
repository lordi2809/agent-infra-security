# Skill Catalog

Index of all skills in this repo. Each skill works as an agent skill and ships standalone tools.

---

## pypi-supply-chain-response

**Path:** `skills/pypi-supply-chain-response/`

**Trigger phrases:** compromised Python package, PyPI supply chain attack, malicious dependency, credential-stealing malware in pip, "am I affected by" a package compromise, rotate credentials after Python incident, transitive dependency audit, IOC hunting for pip install

**What it does:** Walks through a six-phase incident response for any compromised PyPI package: exposure check (including transitive dependencies), version confirmation, IOC hunting, containment, credential rotation, and prevention. Produces an interactive triage checklist, a full runbook, or an automated shell script depending on what the user needs.

**Standalone tools:**
- `scripts/check_compromise_template.sh` — Automated checker with color-coded output, `--dry-run`, and confirmation prompts
- `references/ioc-patterns.md` — IOC pattern library covering .pth attacks, persistence mechanisms, credential harvesting targets, exfiltration patterns, and Kubernetes lateral movement

**Created:** March 2026, in response to the LiteLLM/TeamPCP supply chain attack.

---

## supply-chain-security-check

**Path:** `skills/supply-chain-security-check/`

**Trigger phrases:** compromised dependency, supply chain incident, "do we use this package", blast radius scan, dependency compromise investigation, transitive dependency audit, "am I affected" by a package compromise, compromised npm package, compromised crate, compromised gem

**What it does:** Multi-ecosystem blast radius scan for any compromised dependency — PyPI, npm, crates.io, RubyGems, Maven, NuGet, Go modules, Docker Hub. Seven-step workflow: confirm incident facts, search source and lockfiles across ecosystems, check installed environments for transitive use, hunt for IOCs (generic .pth detection, persistence mechanisms, K8s lateral movement), classify impact across five severity levels, recommend containment with per-class credential rotation, and prevent future incidents (SBOM, pip-audit, hashed lockfiles, Trusted Publishing). Produces a structured incident report.

**Standalone tools:**
- Investigation commands in SKILL.md work without any agent — copy the relevant sections for your ecosystem

**Created:** March 2026

---

*New skills get added here as they're built. Format: name, path, trigger phrases, what it does, standalone tools, date.*
