# npm-supply-chain-response

Triage, investigate, and recover from a compromised npm package.

Built in response to the [Axios supply chain attack](https://gist.github.com/joe-desimone/36061dabd2bc2513705e0d083a9673e7) (March 31, 2026). Generic enough for any npm compromise.

## What it does

Six-phase incident response: exposure check, version confirmation, IOC hunting, containment, credential rotation (via handoff to credential-exfiltration-response), prevention.

Three output modes: interactive triage checklist (default), full incident response runbook (markdown), or automated shell script with `--dry-run` support.

## Install as a Claude skill

Point your Claude skill path at this directory.

## Use the shell script standalone

No Claude required. Edit the configuration variables at the top for your incident, then run:

```bash
export COMPROMISED_VERSIONS="1.14.1 0.30.4"
export SAFE_VERSION="1.14.0"
export C2_DOMAINS="sfrclak.com"
export MALICIOUS_DEP="plain-crypto-js"

./scripts/check_npm_compromise.sh axios
./scripts/check_npm_compromise.sh axios --dry-run
```

## IOC reference

`references/ioc-patterns.md` contains the full IOC library:
- Axios-specific IOCs: C2 domain (`sfrclak.com:8000`), campaign ID, platform-specific payloads, anti-forensics patterns
- Generic npm patterns: postinstall script abuse, typosquatted dependency injection, obfuscated payloads, credential harvesting targets
