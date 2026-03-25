# Manual Investigation Playbook for Dependency Supply Chain Incidents

This playbook is for manually investigating whether a compromised dependency exists in your source tree, local environments, CI runners, containers, or deployed hosts.

It is written to be usable during real incidents, especially when the package may be a transitive dependency and when host-level indicators of compromise matter.

You can use it for incidents like the recent LiteLLM compromise, but the process works for most package supply chain attacks.

---

## What you are trying to answer

For any reported package incident, answer these questions in order:

1. Do we reference this package directly in source or build files?
2. Was it installed anywhere indirectly through another package?
3. Which exact versions were resolved?
4. Which systems, images, runners, or developer machines had those versions?
5. Are there host-level indicators of compromise?
6. What credentials or secrets may have been exposed?
7. What must be isolated, rebuilt, blocked, or rotated?

---

## Evidence to collect first

Before running commands, note the following in a scratch file:

- package name
- ecosystem: Python, Node, Go, Rust, etc.
- known bad versions
- known safe version if available
- official indicators of compromise
- affected install time window if known
- repos, images, hosts, runners, and laptops to inspect
- who owns CI/CD, containers, developer endpoints, and secrets

---

## Investigation order

Use this order. Do not jump straight to "upgrade and move on".

1. Search source and lockfiles
2. Inspect installed environments
3. Inspect dependency tree
4. Check build logs and CI logs
5. Check containers and images
6. Hunt for indicators of compromise on hosts
7. Scope secrets exposure
8. Rebuild from known-good state
9. Block bad versions
10. Record exact evidence

---

## Cross-platform source checks

Search for the package name in:

- requirements.txt
- requirements-*.txt
- pyproject.toml
- poetry.lock
- uv.lock
- Pipfile.lock
- package.json
- package-lock.json
- pnpm-lock.yaml
- yarn.lock
- go.mod
- go.sum
- Cargo.toml
- Cargo.lock
- Dockerfile
- docker-compose files
- CI workflows
- install scripts
- bootstrap scripts
- internal docs with install commands

### Package names to search
Replace `litellm` below with the affected package when handling another incident.

---

# Windows Playbook

## 1. Search source files

### PowerShell
```powershell
Get-ChildItem -Recurse -File | Select-String -Pattern "litellm"
Get-ChildItem -Recurse -Include requirements*.txt,pyproject.toml,poetry.lock,uv.lock,Pipfile.lock,setup.py,setup.cfg,Dockerfile,package.json,package-lock.json,pnpm-lock.yaml,yarn.lock,go.mod,go.sum,Cargo.toml,Cargo.lock
```

### If rg is installed
```powershell
rg -n "litellm" .
rg -n "pip install .*litellm|google-adk|browser-use" .
```

## 2. Check installed Python environments

### Current environment
```powershell
python -m pip list
python -m pip freeze | Select-String -Pattern "litellm"
python -m pip show litellm
python -m pip inspect > pip-inspect.json
```

### All virtualenvs you know about
Repeat the above inside:
- `.venv`
- `venv`
- Poetry environments
- Conda environments
- per-project virtualenvs
- CI cache copies if accessible

### Conda
```powershell
conda env list
conda list | Select-String -Pattern "litellm"
```

## 3. Find which package pulled it in

### If pipdeptree is installed
```powershell
pipdeptree | Select-String -Pattern "litellm" -Context 5,5
```

This tells you whether the dependency is direct or transitive.

## 4. Hunt for startup hook or artifact indicators

Some Python package attacks drop files that execute at interpreter startup.

### Search site-packages for suspicious files
```powershell
python - <<'PY'
import os
import site

for p in site.getsitepackages():
    for root, _, files in os.walk(p):
        for f in files:
            if "litellm" in f.lower() or f.endswith(".pth"):
                print(os.path.join(root, f))
PY
```

### Search broadly for a known malicious file
```powershell
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Force | Where-Object { $_.Name -eq "litellm_init.pth" }
```

## 5. Check logs and command history

### PowerShell history
```powershell
Get-Content (Get-PSReadLineOption).HistorySavePath | Select-String -Pattern "pip install|litellm"
```

### CI or build logs
Search for:
- `litellm==`
- `Collecting litellm`
- `Installing collected packages`
- the incident date window
- packages known to pull LiteLLM transitively

## 6. Check outbound indicator domains or strings

```powershell
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | Select-String -Pattern "models.litellm.cloud" -ErrorAction SilentlyContinue
```

Also inspect:
- EDR telemetry
- proxy logs
- DNS logs
- firewall logs
- cloud egress logs

## 7. Check containers

### Local Docker images
```powershell
docker images
docker history <image>
docker run --rm <image> python -m pip freeze
docker run --rm <image> python -m pip show litellm
```

## 8. Immediate response if found

If a bad version or indicator is found:
- isolate the laptop, host, or runner if possible
- preserve logs if you need forensics
- assume secrets on that system may be compromised
- revoke and rotate credentials
- delete and rebuild the environment from a known-good base
- pin or block the bad version

---

# macOS Playbook

## 1. Search source files

### Terminal
```bash
rg -n "litellm" .
rg -n "pip install .*litellm|google-adk|browser-use" .
find . -iname "requirements*.txt" -o -iname "pyproject.toml" -o -iname "poetry.lock" -o -iname "uv.lock" -o -iname "Pipfile.lock" -o -iname "Dockerfile"
```

## 2. Check installed Python environments

### Current environment
```bash
python3 -m pip list
python3 -m pip freeze | grep -i litellm
python3 -m pip show litellm
python3 -m pip inspect > pip-inspect.json
```

### Known environments
Repeat in:
- `.venv`
- `venv`
- Poetry environments
- pyenv environments
- Conda environments
- local development containers

### Conda
```bash
conda env list
conda list | grep -i litellm
```

## 3. Find who pulled it in
```bash
pipdeptree | grep -i -A 5 -B 5 litellm
```

## 4. Hunt for suspicious startup hooks and artifacts

```bash
python3 - <<'PY'
import os
import site

for p in site.getsitepackages():
    for root, _, files in os.walk(p):
        for f in files:
            if "litellm" in f.lower() or f.endswith(".pth"):
                print(os.path.join(root, f))
PY
```

### Direct file hunt
```bash
find / -name "litellm_init.pth" 2>/dev/null
find ~/ -name "*.pth" 2>/dev/null
```

## 5. Check shell history and logs

### Shell history
```bash
grep -i "litellm\|pip install" ~/.zsh_history ~/.bash_history 2>/dev/null
```

### Local logs and temp areas
```bash
grep -R "models.litellm.cloud" /tmp /var/log "$HOME" 2>/dev/null
```

Also inspect:
- MDM or EDR telemetry
- outbound proxy logs
- DNS logs
- CI logs
- cloud audit logs for credential use after install time

## 6. Check containers
```bash
docker images
docker history <image>
docker run --rm <image> python3 -m pip freeze
docker run --rm <image> python3 -m pip show litellm
```

## 7. Immediate response if found

If a bad version or indicator is found:
- disconnect or isolate the machine or runner
- preserve evidence if needed
- treat credentials on that system as compromised
- rotate API keys, cloud credentials, SSH keys, tokens, and cookies if they may have been present
- rebuild environments instead of trying to clean them in place
- pin and block the compromised versions

---

# Linux Playbook

## 1. Search source files
```bash
rg -n "litellm" .
rg -n "pip install .*litellm|google-adk|browser-use" .
find . -iname "requirements*.txt" -o -iname "pyproject.toml" -o -iname "poetry.lock" -o -iname "uv.lock" -o -iname "Pipfile.lock" -o -iname "Dockerfile"
```

## 2. Check installed Python environments

### Current environment
```bash
python3 -m pip list
python3 -m pip freeze | grep -i litellm
python3 -m pip show litellm
python3 -m pip inspect > pip-inspect.json
```

### Other Python locations
Inspect:
- project virtualenvs
- system Python if used in CI or automation
- pyenv environments
- Conda environments
- build worker images
- ephemeral runner caches

### Conda
```bash
conda env list
conda list | grep -i litellm
```

## 3. Find which package pulled it in
```bash
pipdeptree | grep -i -A 5 -B 5 litellm
```

## 4. Hunt for malicious artifacts and hooks

```bash
python3 - <<'PY'
import os
import site

for p in site.getsitepackages():
    for root, _, files in os.walk(p):
        for f in files:
            if "litellm" in f.lower() or f.endswith(".pth"):
                print(os.path.join(root, f))
PY
```

### Direct filesystem hunt
```bash
find / -name "litellm_init.pth" 2>/dev/null
find / -name "*.pth" 2>/dev/null
```

## 5. Check logs and history

### Shell history
```bash
grep -i "litellm\|pip install" ~/.bash_history ~/.zsh_history 2>/dev/null
```

### Local logs
```bash
grep -R "models.litellm.cloud" /var/log /tmp "$HOME" 2>/dev/null
```

### Network and process clues
Inspect:
- egress firewall logs
- DNS resolver logs
- proxy logs
- systemd journal
- EDR alerts
- suspicious Python process launches during or after install

## 6. Check containers and runners
```bash
docker images
docker history <image>
docker run --rm <image> python3 -m pip freeze
docker run --rm <image> python3 -m pip show litellm
```

For Kubernetes:
- inspect image tags and digests used during the affected period
- inspect CI logs that built those images
- inspect init containers and build jobs
- check secret use from affected workloads after suspect install times

## 7. Immediate response if found

If a bad version or indicator is found:
- isolate the host, pod node, or runner
- revoke and rotate secrets
- destroy and rebuild workloads from known-good images
- flush package caches if needed
- block bad versions in dependency policy
- monitor for reuse of compromised credentials

---

# CI/CD Investigation

This is often where real exposure happened.

## What to search in CI
Search for:
- install lines showing the affected package
- dependency resolution logs
- cached wheels
- pip cache restores
- Docker build layers
- environment variables exposed to builds
- OIDC or cloud tokens used during affected jobs

## Common places
- GitHub Actions logs and caches
- GitLab CI logs and caches
- Jenkins agents
- CircleCI workspaces
- Buildkite agents
- Azure DevOps agents

## Questions to answer
- Did the runner resolve a bad version?
- Was the runner persistent or ephemeral?
- What secrets were present in the job?
- Did the job publish images, packages, or releases after compromise?
- Were those downstream artifacts promoted to production?

---

# Container and Image Investigation

A repo can look clean while images are infected.

## Check these
- image build timestamps
- base image digest
- dependency install layers
- pip freeze inside the image
- runtime site-packages contents
- whether the image was pushed onward to registries or clusters

## Commands
```bash
docker history <image>
docker run --rm <image> python3 -m pip freeze
docker run --rm <image> find / -name "litellm_init.pth" 2>/dev/null
```

---

# How to interpret results

## Case 1: Package absent everywhere
Good result, but still verify:
- CI logs during the incident window
- images built during that window
- developer machines that may have installed optional extras manually

## Case 2: Package present, safe version only
Still record:
- where found
- version
- why you believe it was safe
- whether install time overlapped the incident window

## Case 3: Package present, bad version found
Treat as likely compromise unless you can prove otherwise.

## Case 4: Bad version not found, but malicious indicator found
Treat as confirmed compromise on that host or image.

## Case 5: Incomplete evidence
If logs are missing or environments were deleted:
- assume a wider blast radius
- rotate secrets conservatively
- rebuild from known-good state

---

# Secret rotation scope

If you find a compromised dependency on a machine, runner, or image, assume secrets present there may be burned.

## Rotate at minimum
- cloud credentials
- API keys
- GitHub tokens
- package registry tokens
- CI secrets
- Kubernetes service account tokens
- SSH keys
- database credentials
- session cookies if developer browsers were in scope
- any `.env` values present on the system

## Also check
- what those credentials accessed after the suspected install time
- whether they were used from unusual source IPs or regions
- whether they created new tokens, users, or persistence

---

# Rebuild and containment guidance

Do not rely on uninstalling the package and moving on.

## Preferred response
1. isolate affected systems
2. preserve evidence if needed
3. revoke and rotate secrets
4. delete affected virtualenvs, images, or runners
5. rebuild from a known-good base
6. pin safe versions
7. add dependency blocking rules
8. review logs for follow-on activity

---

# Lightweight reporting template

Copy this into your incident notes.

## Summary
- incident:
- package:
- ecosystem:
- known bad versions:
- systems reviewed:
- result:

## Findings by system
- system name:
- source reference found:
- installed version:
- direct or transitive:
- indicator found:
- risk level:
- evidence:

## Secret exposure
- secrets likely present:
- secrets rotated:
- audit logs checked:

## Actions taken
- isolated:
- rebuilt:
- blocked versions:
- monitoring added:

## Unknowns
- missing logs:
- deleted environments:
- confidence level:

---

# LiteLLM-specific quick checks

Use these when the incident is specifically about LiteLLM.

## Search source
```bash
rg -n "litellm|google-adk|browser-use" .
```

## Check install state
```bash
python3 -m pip freeze | grep -i litellm
python3 -m pip show litellm
pipdeptree | grep -i -A 5 -B 5 litellm
```

## Check for the known startup hook artifact
```bash
find / -name "litellm_init.pth" 2>/dev/null
```

## Check for known suspicious domain string
```bash
grep -R "models.litellm.cloud" /var/log /tmp "$HOME" 2>/dev/null
```

On Windows, use the equivalent PowerShell commands from the Windows section above.

---

# Final rule

Do not ask only:
"Do we import the package?"

Ask:
"Did any repo, environment, runner, image, or developer machine resolve the bad version, and do we have any host-level evidence that it executed?"
