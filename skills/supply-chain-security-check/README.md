# supply-chain-security-check

Investigate whether a project, environment, container, or CI pipeline is affected by a dependency supply chain incident. Multi-ecosystem: works for PyPI, npm, crates.io, RubyGems, Maven, NuGet, Go modules, and Docker Hub.

## What it does

Seven-step investigation workflow: confirm incident facts, search source and lockfiles, check installed environments for transitive use, hunt for IOCs (including .pth hooks, persistence mechanisms, K8s lateral movement), classify impact across five severity levels, recommend containment and credential rotation, and prevent future incidents.

Produces a structured incident report with executive summary, per-system findings, immediate actions, and unknowns.

## Install as an agent skill

Point your agent's skill path at this directory. The `SKILL.md` contains the full instructions.

## Use standalone

The investigation commands in the SKILL.md work without any agent. Copy the relevant sections for your ecosystem and run them directly.

## Differences from pypi-supply-chain-response

| | supply-chain-security-check | pypi-supply-chain-response |
|---|---|---|
| Scope | Multi-ecosystem (Python, Node, Go, Rust, Java, Docker) | Python/PyPI only |
| Depth | Broader investigation workflow | Deeper PyPI-specific detection, IOC patterns, shell script automation |
| Output | Structured incident report | Interactive checklist, full runbook, or automated shell script |
| Best for | "Do we use this anywhere?" across the whole stack | Deep-dive triage of a specific PyPI compromise |

Use both together: `supply-chain-security-check` for the initial blast radius scan, then `pypi-supply-chain-response` for deep Python-specific investigation.
