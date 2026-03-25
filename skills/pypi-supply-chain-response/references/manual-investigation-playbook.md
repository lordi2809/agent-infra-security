# Manual Investigation Playbook for Dependency Supply Chain Incidents

This playbook is for manually investigating whether a compromised dependency exists in your source tree, local environments, CI runners, containers, or deployed hosts.

It is written to be usable during real incidents, especially when the package may be a transitive dependency and when host-level indicators of compromise matter.

**How to read this playbook:**
- **Commands come first.** Follow them top to bottom. A developer at 2am during an incident should be able to run every command without reading background text first.
- **Blockquotes (`>`) contain background, context, and advanced techniques.** Regular developers can skip them. Security experts should read everything.

Replace `PACKAGE` throughout with the actual compromised package name (e.g., `litellm`).

---

## What you are trying to answer

For any reported package incident, answer these questions in order:

1. Do we reference this package directly in source or build files?
2. Was it installed anywhere indirectly through another package?
3. Which exact versions were resolved?
4. Which systems, images, runners, or developer machines had those versions?
5. Are there host-level indicators of compromise?
6. Were persistence mechanisms installed?
7. Was data exfiltrated or were credentials harvested?
8. What credentials or secrets may have been exposed?
9. What must be isolated, rebuilt, blocked, or rotated?

---

## Evidence to collect first

Before running commands, note the following in a scratch file:

- package name
- ecosystem: Python, Node, Go, Rust, etc.
- known bad versions
- known safe version if available
- official indicators of compromise (IOC domains, filenames, hashes)
- affected install time window if known
- repos, images, hosts, runners, and laptops to inspect
- who owns CI/CD, containers, developer endpoints, and secrets

---

## Evidence preservation

**Before any destructive action (uninstall, rebuild, wipe), preserve evidence.**

### All platforms
```bash
# Snapshot the pip environment
python3 -m pip freeze > evidence-pip-freeze-$(hostname)-$(date +%Y%m%d%H%M%S).txt
python3 -m pip inspect > evidence-pip-inspect-$(hostname)-$(date +%Y%m%d%H%M%S).json

# Copy site-packages for offline analysis
python3 -c "import site; print('\n'.join(site.getsitepackages()))"
# Then tar the relevant directory:
tar czf evidence-site-packages-$(hostname)-$(date +%Y%m%d%H%M%S).tar.gz /path/to/site-packages/

# Snapshot running processes
ps auxww > evidence-processes-$(hostname)-$(date +%Y%m%d%H%M%S).txt

# Snapshot network connections
ss -tunap > evidence-network-$(hostname)-$(date +%Y%m%d%H%M%S).txt 2>/dev/null || netstat -tunap > evidence-network-$(hostname)-$(date +%Y%m%d%H%M%S).txt 2>/dev/null

# Copy shell history
cp ~/.bash_history evidence-bash-history-$(hostname)-$(date +%Y%m%d%H%M%S).txt 2>/dev/null
cp ~/.zsh_history evidence-zsh-history-$(hostname)-$(date +%Y%m%d%H%M%S).txt 2>/dev/null

# Snapshot cron
crontab -l > evidence-crontab-$(hostname)-$(date +%Y%m%d%H%M%S).txt 2>/dev/null
```

### Windows (PowerShell)
```powershell
python -m pip freeze > "evidence-pip-freeze-$env:COMPUTERNAME-$(Get-Date -Format yyyyMMddHHmmss).txt"
python -m pip inspect > "evidence-pip-inspect-$env:COMPUTERNAME-$(Get-Date -Format yyyyMMddHHmmss).json"
Get-Process | Out-File "evidence-processes-$env:COMPUTERNAME-$(Get-Date -Format yyyyMMddHHmmss).txt"
Get-NetTCPConnection | Out-File "evidence-network-$env:COMPUTERNAME-$(Get-Date -Format yyyyMMddHHmmss).txt"
```

> **Why preserve evidence first?**
> Once you uninstall a package or wipe an environment, forensic artifacts are gone. If your organization needs to understand the full scope of compromise, file an IR ticket, or report to a CISO, you need the raw data. Store evidence files in a secure location (not on the potentially compromised host if possible).

---

## Investigation order

Use this order. Do not jump straight to "upgrade and move on".

1. Preserve evidence
2. Search source and lockfiles
3. Inspect installed environments
4. Inspect dependency tree
5. Hunt for malicious artifacts and persistence
6. Check network IOCs
7. Check for credential harvesting and exfiltration
8. Check build logs and CI logs
9. Check containers, images, and Kubernetes
10. Scope secrets exposure
11. Rotate credentials
12. Rebuild from known-good state
13. Block bad versions
14. Record exact evidence

---

## Cross-platform source checks

Search for the package name in:

- requirements.txt, requirements-*.txt
- pyproject.toml
- poetry.lock, uv.lock, Pipfile.lock
- setup.py, setup.cfg
- package.json, package-lock.json, pnpm-lock.yaml, yarn.lock
- go.mod, go.sum
- Cargo.toml, Cargo.lock
- Dockerfile, docker-compose*.yml
- CI workflows (.github/workflows/, .gitlab-ci.yml, Jenkinsfile, .circleci/, buildkite/)
- install scripts, bootstrap scripts
- internal docs with install commands
- Makefile, Taskfile, justfile

---

# Windows Playbook

## 1. Search source files

### PowerShell
```powershell
Get-ChildItem -Recurse -File | Select-String -Pattern "PACKAGE"
Get-ChildItem -Recurse -Include requirements*.txt,pyproject.toml,poetry.lock,uv.lock,Pipfile.lock,setup.py,setup.cfg,Dockerfile,package.json,package-lock.json,pnpm-lock.yaml,yarn.lock,go.mod,go.sum,Cargo.toml,Cargo.lock
```

### If rg (ripgrep) is installed
```powershell
rg -n "PACKAGE" .
rg -n "pip install .*PACKAGE" .
rg -n "PACKAGE" --type-add "lock:*.lock" --type lock .
```

> **Why search broadly?**
> The package might appear in documentation, scripts, or CI files that are not standard dependency manifests. A broad text search catches references that targeted file searches miss.

## 2. Check installed Python environments

### Current environment
```powershell
python -m pip list
python -m pip freeze | Select-String -Pattern "PACKAGE"
python -m pip show PACKAGE
python -m pip show -f PACKAGE          # shows installed files
python -m pip inspect > pip-inspect.json
```

### Find all Python interpreters on the system
```powershell
Get-Command python* | Select-Object Source
where.exe python
where.exe python3
```

### All virtualenvs you know about
Repeat the above inside:
- `.venv`, `venv`
- Poetry environments: `poetry env info --path`
- Conda environments: `conda env list`
- pyenv environments
- per-project virtualenvs
- CI cache copies if accessible

### Conda
```powershell
conda env list
conda list | Select-String -Pattern "PACKAGE"
# Check all conda envs
foreach ($env in (conda env list --json | ConvertFrom-Json).envs) {
    Write-Host "=== $env ==="
    conda list -p $env | Select-String -Pattern "PACKAGE"
}
```

> **Transitive dependencies hide.** The package may not appear in your requirements.txt but could be pulled in by another package you depend on. Always check the actual installed environment, not just your manifest files.

## 3. Find which package pulled it in

### If pipdeptree is installed
```powershell
pipdeptree | Select-String -Pattern "PACKAGE" -Context 5,5
pipdeptree -r -p PACKAGE      # reverse tree: shows what depends on PACKAGE
```

### If pipdeptree is not installed
```powershell
python -m pip install pipdeptree
pipdeptree -r -p PACKAGE
```

> **Direct vs. transitive matters.** If the package is a direct dependency, you control the pin. If it is transitive, you need to know which parent pulled it in so you can evaluate whether the parent is also compromised or just needs a version constraint update.

## 4. Hunt for malicious artifacts and startup hooks

### Search site-packages for suspicious files
```powershell
python -c "import site; [print(p) for p in site.getsitepackages()]"
```

### Search for .pth files with code execution patterns
```powershell
python - <<'PY'
import os, site

for p in site.getsitepackages():
    for root, _, files in os.walk(p):
        for f in files:
            if f.endswith(".pth"):
                full = os.path.join(root, f)
                with open(full) as fh:
                    content = fh.read()
                # .pth files that contain import statements execute code at startup
                if "import " in content and not content.strip().startswith("#"):
                    print(f"[SUSPICIOUS .pth] {full}")
                    print(f"  Content: {content[:200]}")
                else:
                    print(f"[benign .pth] {full}")
PY
```

### Search broadly for known malicious filenames
```powershell
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Force | Where-Object { $_.Name -match "\.pth$" }
```

> **Why .pth files matter:**
> Python's site-packages mechanism processes `.pth` files at interpreter startup. A `.pth` file containing an `import` statement will execute arbitrary code every time Python starts. This is a common persistence mechanism in supply chain attacks. Legitimate `.pth` files usually contain only directory paths. Any `.pth` file with `import` statements is suspicious and should be inspected.

> **Deeper inspection:**
> ```powershell
> # Search for .pth files that import modules (code execution)
> Get-ChildItem -Path C:\ -Recurse -Filter "*.pth" -ErrorAction SilentlyContinue | ForEach-Object {
>     $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
>     if ($content -match "import ") {
>         Write-Host "[SUSPICIOUS] $($_.FullName): $($content.Substring(0, [Math]::Min(200, $content.Length)))"
>     }
> }
> ```

## 5. Check persistence mechanisms

### Scheduled Tasks
```powershell
Get-ScheduledTask | Where-Object { $_.Actions.Execute -match "python|pip|PACKAGE" }
schtasks /query /fo LIST /v | Select-String -Pattern "python|PACKAGE" -Context 3,3
```

### Startup folders
```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

### Registry Run keys
```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```

> **Supply chain malware often installs persistence** so it survives environment rebuilds. Check for scheduled tasks, startup entries, and registry modifications that reference Python, pip, or the package name.

## 6. Check network IOCs

### Active connections from Python processes
```powershell
Get-NetTCPConnection | Where-Object { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName -match "python" }
```

### DNS cache
```powershell
Get-DnsClientCache | Where-Object { $_.Entry -match "PACKAGE|suspicious-domain" }
```

### Search for IOC domains/IPs in files
```powershell
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | Select-String -Pattern "models.litellm.cloud|SUSPICIOUS_DOMAIN" -ErrorAction SilentlyContinue
```

> **Also inspect:**
> - EDR telemetry for outbound connections from Python
> - Proxy logs for connections to IOC domains
> - DNS logs for resolution of IOC domains
> - Firewall logs for unusual outbound traffic
> - Cloud egress logs (CloudTrail, GCP audit logs, Azure Activity Log)

## 7. Check for credential harvesting targets

```powershell
# Files that malware commonly sweeps for credentials
$targets = @(
    "$env:USERPROFILE\.aws\credentials",
    "$env:USERPROFILE\.aws\config",
    "$env:USERPROFILE\.azure\accessTokens.json",
    "$env:USERPROFILE\.azure\azureProfile.json",
    "$env:USERPROFILE\.config\gcloud\credentials.db",
    "$env:USERPROFILE\.config\gcloud\application_default_credentials.json",
    "$env:USERPROFILE\.kube\config",
    "$env:USERPROFILE\.ssh\id_rsa",
    "$env:USERPROFILE\.ssh\id_ed25519",
    "$env:USERPROFILE\.ssh\config",
    "$env:USERPROFILE\.gitconfig",
    "$env:USERPROFILE\.git-credentials",
    "$env:USERPROFILE\.npmrc",
    "$env:USERPROFILE\.pypirc",
    "$env:USERPROFILE\.docker\config.json",
    "$env:USERPROFILE\.env",
    "$env:USERPROFILE\.netrc"
)
foreach ($f in $targets) {
    if (Test-Path $f) {
        $lastAccess = (Get-Item $f).LastAccessTime
        Write-Host "[EXISTS] $f  (last accessed: $lastAccess)"
    }
}
```

> **Why check access times?**
> If a credential file was accessed during the compromise window but the user did not access it themselves, it may indicate the malware read those credentials. Compare access times against the known compromise window.

> **Cloud metadata endpoints:**
> If the compromised code ran on a cloud instance (EC2, GCE, Azure VM), it may have queried the instance metadata service to steal temporary credentials:
> - AWS IMDS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
> - GCP metadata: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
> - Azure IMDS: `http://169.254.169.254/metadata/identity/oauth2/token`
>
> Check cloud audit logs for metadata endpoint access and for any use of the temporary credentials from unexpected IPs.

## 8. Check for exfiltration patterns

```powershell
# Look for archive files in temp directories (staging for exfiltration)
Get-ChildItem -Path $env:TEMP, "C:\Temp", "$env:USERPROFILE\AppData\Local\Temp" -Recurse -Include *.zip,*.tar,*.tar.gz,*.7z -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-30) }

# Check for recent outbound HTTPS from Python
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5156} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match "python" -and $_.Message -match "443" } | Select-Object -First 20
```

## 9. Check logs and command history

### PowerShell history
```powershell
Get-Content (Get-PSReadLineOption).HistorySavePath | Select-String -Pattern "pip install|PACKAGE"
```

### Expected output (example)
```
pip install litellm==4.97.0
pip install google-adk
```

> **What to look for in history:**
> - Direct installs of the compromised package
> - Installs of packages known to depend on the compromised package
> - Any install commands during the compromise time window
> - Unusual pip install commands with `--index-url` pointing to non-standard registries

## 10. Check containers

### Local Docker images
```powershell
docker images
docker history <image>
docker run --rm <image> python -m pip freeze
docker run --rm <image> python -m pip show PACKAGE
docker run --rm <image> python -c "import site; print('\n'.join(site.getsitepackages()))"
docker run --rm <image> find / -name "*.pth" -exec grep -l "import " {} \; 2>/dev/null
```

## 11. Immediate response if found

If a bad version or indicator is found:
1. Preserve evidence (see Evidence Preservation section above)
2. Isolate the laptop, host, or runner if possible
3. Assume secrets on that system may be compromised
4. Revoke and rotate credentials (see Credential Rotation section)
5. Delete and rebuild the environment from a known-good base
6. Pin or block the bad version

---

# macOS Playbook

## 1. Search source files

```bash
rg -n "PACKAGE" .
rg -n "pip install .*PACKAGE" .
rg -n "PACKAGE" --type-add "lock:*.lock" --type lock .
find . -iname "requirements*.txt" -o -iname "pyproject.toml" -o -iname "poetry.lock" \
       -o -iname "uv.lock" -o -iname "Pipfile.lock" -o -iname "Dockerfile" \
       -o -iname "docker-compose*.yml" -o -iname "Makefile" -o -iname "justfile"
```

### If rg is not installed
```bash
grep -rn "PACKAGE" . --include="*.txt" --include="*.toml" --include="*.lock" \
    --include="*.yaml" --include="*.yml" --include="*.cfg" --include="*.py" \
    --include="Dockerfile" --include="Makefile"
```

## 2. Check installed Python environments

### Current environment
```bash
python3 -m pip list
python3 -m pip freeze | grep -i PACKAGE
python3 -m pip show PACKAGE
python3 -m pip show -f PACKAGE
python3 -m pip inspect > pip-inspect.json
```

### Find all Python interpreters
```bash
which -a python python3
find /usr/local /opt/homebrew ~/.pyenv -name "python3" -type f 2>/dev/null
mdfind "kMDItemFSName == 'python3'"
```

### Known environments
Repeat in:
- `.venv`, `venv`
- Poetry environments: `poetry env info --path`
- pyenv environments: `ls ~/.pyenv/versions/`
- Conda environments: `conda env list`
- local development containers

### Conda
```bash
conda env list
conda list | grep -i PACKAGE
# Check all conda envs
for env in $(conda env list --json | python3 -c "import sys,json; [print(e) for e in json.load(sys.stdin)['envs']]"); do
    echo "=== $env ==="
    conda list -p "$env" 2>/dev/null | grep -i PACKAGE
done
```

## 3. Find who pulled it in

```bash
pipdeptree | grep -i -A 5 -B 5 PACKAGE
pipdeptree -r -p PACKAGE
```

### If pipdeptree is not available
```bash
python3 -m pip install pipdeptree
pipdeptree -r -p PACKAGE
```

> **Reverse tree** (`-r -p PACKAGE`) shows all packages that depend on PACKAGE. This is the fastest way to identify the parent dependency that pulled in the compromised package.

## 4. Hunt for malicious artifacts and startup hooks

### Search for .pth files with code execution
```bash
python3 - <<'PY'
import os, site

for p in site.getsitepackages():
    for root, _, files in os.walk(p):
        for f in files:
            if f.endswith(".pth"):
                full = os.path.join(root, f)
                try:
                    with open(full) as fh:
                        content = fh.read()
                    if "import " in content and not content.strip().startswith("#"):
                        print(f"[SUSPICIOUS .pth] {full}")
                        print(f"  Content: {content[:200]}")
                    else:
                        print(f"[benign .pth] {full}")
                except Exception as e:
                    print(f"[ERROR] {full}: {e}")
PY
```

### Direct file hunt
```bash
find / -name "*.pth" 2>/dev/null | while read f; do
    if grep -q "import " "$f" 2>/dev/null; then
        echo "[SUSPICIOUS] $f"
        head -5 "$f"
    fi
done
```

> **Beyond .pth files:**
> Also check for modifications to `sitecustomize.py` and `usercustomize.py`, which Python executes at startup:
> ```bash
> python3 -c "import site; print(site.ENABLE_USER_SITE); import sysconfig; print(sysconfig.get_path('purelib'))"
> find $(python3 -c "import site; print('\n'.join(site.getsitepackages()))") -name "sitecustomize.py" -o -name "usercustomize.py" 2>/dev/null
> ```

## 5. Check persistence mechanisms

### LaunchAgents and LaunchDaemons
```bash
ls -la ~/Library/LaunchAgents/ 2>/dev/null
ls -la /Library/LaunchAgents/ 2>/dev/null
ls -la /Library/LaunchDaemons/ 2>/dev/null

# Search for references to python or the package in launch plists
grep -rl "python\|PACKAGE" ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/ 2>/dev/null
```

### Cron jobs
```bash
crontab -l 2>/dev/null
for user in $(dscl . list /Users | grep -v '^_'); do
    echo "=== $user ==="
    sudo crontab -u "$user" -l 2>/dev/null
done
```

### Login items
```bash
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null
```

### XDG autostart (if using Linux-style desktop on macOS)
```bash
ls -la ~/.config/autostart/ 2>/dev/null
```

> **macOS-specific persistence vectors:**
> - LaunchAgents/LaunchDaemons are the primary persistence mechanism on macOS
> - Check `/tmp` and `/var/tmp` for scripts that may have been dropped
> - Check `at` jobs: `atq`
> - Check for modified shell profiles: `ls -la ~/.zshrc ~/.zprofile ~/.bash_profile ~/.bashrc` and diff against known-good versions

## 6. Check network IOCs

### Active connections from Python processes
```bash
lsof -i -n -P | grep -i python
lsof -i :443 | grep -i python
```

### Check for active connections to IOC domains
```bash
# Current connections
netstat -an | grep ESTABLISHED
lsof -i TCP -n -P | grep ESTABLISHED | grep python

# DNS cache (macOS)
sudo dscacheutil -cachedump 2>/dev/null
# Or check DNS resolution logs
log show --predicate 'process == "mDNSResponder"' --last 24h 2>/dev/null | grep -i "PACKAGE\|SUSPICIOUS_DOMAIN"
```

> **For deeper network analysis:**
> ```bash
> # Check for Python processes making outbound HTTPS connections
> lsof -i :443 -n -P 2>/dev/null | grep python
>
> # If tcpdump is available and you suspect active exfiltration
> sudo tcpdump -i any -n 'port 443 and (host SUSPICIOUS_IP)' -c 100
>
> # Check Little Snitch or other firewall logs if available
> ```

## 7. Check for credential harvesting targets

```bash
# Files that malware commonly sweeps for credentials
credential_files=(
    "$HOME/.aws/credentials"
    "$HOME/.aws/config"
    "$HOME/.azure/accessTokens.json"
    "$HOME/.azure/azureProfile.json"
    "$HOME/.config/gcloud/credentials.db"
    "$HOME/.config/gcloud/application_default_credentials.json"
    "$HOME/.kube/config"
    "$HOME/.ssh/id_rsa"
    "$HOME/.ssh/id_ed25519"
    "$HOME/.ssh/id_ecdsa"
    "$HOME/.ssh/config"
    "$HOME/.ssh/known_hosts"
    "$HOME/.gitconfig"
    "$HOME/.git-credentials"
    "$HOME/.npmrc"
    "$HOME/.pypirc"
    "$HOME/.docker/config.json"
    "$HOME/.env"
    "$HOME/.netrc"
    "$HOME/.config/gh/hosts.yml"
    "$HOME/Library/Keychains/login.keychain-db"
    "$HOME/.bash_history"
    "$HOME/.zsh_history"
)

echo "=== Credential files present on this system ==="
for f in "${credential_files[@]}"; do
    if [ -f "$f" ]; then
        access_time=$(stat -f "%Sa" -t "%Y-%m-%d %H:%M:%S" "$f" 2>/dev/null)
        echo "[EXISTS] $f  (last accessed: $access_time)"
    fi
done
```

> **Cloud metadata endpoints:**
> If the compromised code ran on a cloud VM, it may have queried instance metadata to steal temporary credentials without touching any files on disk:
> - **AWS IMDS:** `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
> - **GCP metadata:** `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
> - **Azure IMDS:** `http://169.254.169.254/metadata/identity/oauth2/token`
>
> Check CloudTrail / GCP audit logs / Azure Activity Log for metadata API calls and for any use of instance role credentials from unexpected source IPs.

## 8. Check for exfiltration patterns

```bash
# Archive files in temp directories (common staging area for exfiltration)
find /tmp /var/tmp "$TMPDIR" -name "*.zip" -o -name "*.tar" -o -name "*.tar.gz" -o -name "*.7z" -o -name "*.tgz" 2>/dev/null | while read f; do
    echo "$f  (modified: $(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$f" 2>/dev/null))"
done

# Recent outbound HTTPS connections from Python (check log)
log show --predicate 'process CONTAINS "python" AND message CONTAINS "443"' --last 24h 2>/dev/null | head -50
```

> **Signs of exfiltration:**
> - Newly created archive files in /tmp or writable directories
> - Python processes with outbound HTTPS connections to unknown hosts
> - Encoded data in environment variables or temp files
> - Unexpected DNS queries (DNS exfiltration uses TXT or CNAME records)

## 9. Check shell history and logs

```bash
grep -i "PACKAGE\|pip install" ~/.zsh_history ~/.bash_history 2>/dev/null
```

### System logs
```bash
# Check console logs for Python activity
log show --predicate 'process CONTAINS "python"' --last 48h 2>/dev/null | head -100

# Search for IOC domains
grep -R "SUSPICIOUS_DOMAIN" /tmp /var/log "$HOME" 2>/dev/null
```

> **Also inspect:**
> - MDM or EDR telemetry
> - Outbound proxy logs
> - DNS logs
> - CI logs
> - Cloud audit logs for credential use after the install timestamp

## 10. Check containers
```bash
docker images
docker history <image>
docker run --rm <image> python3 -m pip freeze
docker run --rm <image> python3 -m pip show PACKAGE
docker run --rm <image> find / -name "*.pth" -exec grep -l "import " {} \; 2>/dev/null
```

## 11. Immediate response if found

If a bad version or indicator is found:
1. Preserve evidence (see Evidence Preservation section above)
2. Disconnect or isolate the machine or runner
3. Treat credentials on that system as compromised
4. Rotate API keys, cloud credentials, SSH keys, tokens, and cookies if they may have been present
5. Rebuild environments instead of trying to clean them in place
6. Pin and block the compromised versions

---

# Linux Playbook

## 1. Search source files
```bash
rg -n "PACKAGE" .
rg -n "pip install .*PACKAGE" .
rg -n "PACKAGE" --type-add "lock:*.lock" --type lock .
find . -iname "requirements*.txt" -o -iname "pyproject.toml" -o -iname "poetry.lock" \
       -o -iname "uv.lock" -o -iname "Pipfile.lock" -o -iname "Dockerfile" \
       -o -iname "docker-compose*.yml" -o -iname "Makefile" -o -iname "justfile"
```

### If rg is not installed
```bash
grep -rn "PACKAGE" . --include="*.txt" --include="*.toml" --include="*.lock" \
    --include="*.yaml" --include="*.yml" --include="*.cfg" --include="*.py" \
    --include="Dockerfile" --include="Makefile"
```

## 2. Check installed Python environments

### Current environment
```bash
python3 -m pip list
python3 -m pip freeze | grep -i PACKAGE
python3 -m pip show PACKAGE
python3 -m pip show -f PACKAGE
python3 -m pip inspect > pip-inspect.json
```

### Find all Python interpreters
```bash
which -a python python3
find / -name "python3" -type f 2>/dev/null
find / -name "python3.*" -type f 2>/dev/null
update-alternatives --list python 2>/dev/null
update-alternatives --list python3 2>/dev/null
```

### Other Python locations
Inspect:
- project virtualenvs
- system Python if used in CI or automation
- pyenv environments: `ls ~/.pyenv/versions/`
- Conda environments: `conda env list`
- build worker images
- ephemeral runner caches

### Conda
```bash
conda env list
conda list | grep -i PACKAGE
for env in $(conda env list --json | python3 -c "import sys,json; [print(e) for e in json.load(sys.stdin)['envs']]"); do
    echo "=== $env ==="
    conda list -p "$env" 2>/dev/null | grep -i PACKAGE
done
```

## 3. Find which package pulled it in
```bash
pipdeptree | grep -i -A 5 -B 5 PACKAGE
pipdeptree -r -p PACKAGE
```

## 4. Hunt for malicious artifacts and hooks

### Search for .pth files with code execution
```bash
python3 - <<'PY'
import os, site

for p in site.getsitepackages():
    for root, _, files in os.walk(p):
        for f in files:
            if f.endswith(".pth"):
                full = os.path.join(root, f)
                try:
                    with open(full) as fh:
                        content = fh.read()
                    if "import " in content and not content.strip().startswith("#"):
                        print(f"[SUSPICIOUS .pth] {full}")
                        print(f"  Content: {content[:200]}")
                    else:
                        print(f"[benign .pth] {full}")
                except Exception as e:
                    print(f"[ERROR] {full}: {e}")
PY
```

### Direct filesystem hunt
```bash
find / -name "*.pth" 2>/dev/null | while read f; do
    if grep -q "import " "$f" 2>/dev/null; then
        echo "[SUSPICIOUS] $f"
        head -5 "$f"
    fi
done
```

### Check for modified startup files
```bash
find $(python3 -c "import site; print('\n'.join(site.getsitepackages()))") \
    -name "sitecustomize.py" -o -name "usercustomize.py" 2>/dev/null | while read f; do
    echo "=== $f ==="
    cat "$f"
done
```

## 5. Check persistence mechanisms

### Systemd services and timers
```bash
# User-level systemd
systemctl --user list-units --type=service --all 2>/dev/null | grep -i "python\|PACKAGE"
systemctl --user list-timers --all 2>/dev/null
ls -la ~/.config/systemd/user/ 2>/dev/null

# System-level systemd
systemctl list-units --type=service --all 2>/dev/null | grep -i "python\|PACKAGE"
systemctl list-timers --all 2>/dev/null

# Recently created/modified service files
find /etc/systemd /usr/lib/systemd ~/.config/systemd -name "*.service" -newer /tmp -mtime -30 2>/dev/null
```

### Cron jobs
```bash
crontab -l 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null
for user in $(cut -f1 -d: /etc/passwd); do
    cron=$(sudo crontab -u "$user" -l 2>/dev/null)
    if [ -n "$cron" ]; then
        echo "=== $user ==="
        echo "$cron"
    fi
done

# Search all cron entries for references to python or the package
grep -r "python\|PACKAGE" /etc/cron* /var/spool/cron 2>/dev/null
```

### XDG autostart
```bash
ls -la ~/.config/autostart/ 2>/dev/null
grep -rl "python\|PACKAGE" ~/.config/autostart/ /etc/xdg/autostart/ 2>/dev/null
```

### At jobs
```bash
atq 2>/dev/null
```

### Shell profile modifications
```bash
# Check if shell profiles were recently modified
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile 2>/dev/null
# Look for suspicious additions
grep -n "python\|curl\|wget\|base64\|eval" ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile 2>/dev/null
```

> **Linux persistence is diverse.** Attackers can use systemd services, cron jobs, at jobs, shell profiles, XDG autostart entries, or even kernel modules. A thorough check should cover all of these. Pay special attention to anything created or modified during the compromise time window.

> **Advanced persistence checks:**
> ```bash
> # Check for LD_PRELOAD hijacking
> echo $LD_PRELOAD
> cat /etc/ld.so.preload 2>/dev/null
>
> # Check for modified shared libraries
> ldconfig -p | grep -i python
>
> # Check for unusual SUID binaries
> find / -perm -4000 -type f -newer /tmp -mtime -30 2>/dev/null
> ```

## 6. Check network IOCs

### Active connections from Python processes
```bash
ss -tunap | grep python
ss -tunap | grep -i ESTABLISHED | grep python
lsof -i -n -P | grep python
```

### Outbound HTTPS connections from Python
```bash
ss -tunap state established '( dport = :443 )' | grep python
lsof -i :443 | grep python
```

### Check for connections to IOC domains/IPs
```bash
# Current connections
ss -tunap | grep "SUSPICIOUS_IP\|IOC_PORT"

# DNS resolution checks
dig SUSPICIOUS_DOMAIN 2>/dev/null
host SUSPICIOUS_DOMAIN 2>/dev/null

# Recent DNS queries (if systemd-resolved)
resolvectl query SUSPICIOUS_DOMAIN 2>/dev/null
journalctl -u systemd-resolved --since "48 hours ago" 2>/dev/null | grep -i "SUSPICIOUS_DOMAIN"
```

### Expected output (example, no IOCs found)
```
$ ss -tunap | grep python
(no output = good, no active Python network connections)

$ lsof -i -n -P | grep python
(no output = good)
```

> **What suspicious output looks like:**
> ```
> $ ss -tunap | grep python
> ESTAB  0  0  10.0.1.5:48832  203.0.113.50:443  users:(("python3",pid=12345,fd=5))
> ```
> If you see Python holding connections to unknown IPs, investigate the process:
> ```bash
> ls -la /proc/12345/exe
> cat /proc/12345/cmdline | tr '\0' ' '
> ls -la /proc/12345/fd/
> cat /proc/12345/environ | tr '\0' '\n' | grep -i key\|token\|secret\|pass
> ```

## 7. Check for credential harvesting targets

```bash
credential_files=(
    "$HOME/.aws/credentials"
    "$HOME/.aws/config"
    "$HOME/.azure/accessTokens.json"
    "$HOME/.azure/azureProfile.json"
    "$HOME/.config/gcloud/credentials.db"
    "$HOME/.config/gcloud/application_default_credentials.json"
    "$HOME/.kube/config"
    "$HOME/.ssh/id_rsa"
    "$HOME/.ssh/id_ed25519"
    "$HOME/.ssh/id_ecdsa"
    "$HOME/.ssh/config"
    "$HOME/.ssh/known_hosts"
    "$HOME/.gitconfig"
    "$HOME/.git-credentials"
    "$HOME/.npmrc"
    "$HOME/.pypirc"
    "$HOME/.docker/config.json"
    "$HOME/.env"
    "$HOME/.netrc"
    "$HOME/.config/gh/hosts.yml"
    "$HOME/.bash_history"
    "$HOME/.zsh_history"
    "$HOME/.local/share/python_keyring/"
    "/etc/shadow"
    "/etc/kubernetes/admin.conf"
)

echo "=== Credential files present on this system ==="
for f in "${credential_files[@]}"; do
    if [ -f "$f" ]; then
        access_time=$(stat -c "%x" "$f" 2>/dev/null || stat -f "%Sa" "$f" 2>/dev/null)
        echo "[EXISTS] $f  (last accessed: $access_time)"
    fi
done
```

### Find .env files across the filesystem
```bash
find / -name ".env" -o -name "*.env" -o -name ".env.*" 2>/dev/null | head -50
```

> **Cloud metadata endpoints:**
> If the compromised code ran on a cloud VM, container, or serverless function, it may have queried the instance metadata service to steal temporary credentials without touching any files on disk:
> - **AWS IMDS:** `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
> - **GCP metadata:** `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
> - **Azure IMDS:** `http://169.254.169.254/metadata/identity/oauth2/token`
>
> Check cloud audit logs (CloudTrail, GCP Audit Logs, Azure Activity Log) for:
> - Metadata API calls during the compromise window
> - Use of instance role credentials from unexpected IPs or regions
> - AssumeRole calls, credential creation, or privilege escalation events

## 8. Check for exfiltration patterns

```bash
# Archive files in temp directories (common staging for exfiltration)
find /tmp /var/tmp /dev/shm -name "*.zip" -o -name "*.tar" -o -name "*.tar.gz" \
    -o -name "*.7z" -o -name "*.tgz" -o -name "*.bz2" 2>/dev/null | while read f; do
    echo "$f  (modified: $(stat -c '%y' "$f" 2>/dev/null))"
done

# Large recently-created files in /tmp
find /tmp /var/tmp -size +1M -mtime -7 -type f 2>/dev/null

# Encoded data files (base64-encoded exfiltration staging)
find /tmp /var/tmp -name "*.b64" -o -name "*.encoded" 2>/dev/null

# Check for Python processes with open network connections
lsof -i TCP -n -P 2>/dev/null | grep python | grep -v LISTEN
```

> **Signs of active exfiltration:**
> - Newly created tar/zip archives in /tmp containing credential files or source code
> - Python processes with persistent outbound HTTPS connections
> - Unusual DNS query patterns (long subdomain strings = DNS exfiltration)
> - Data written to world-writable directories (/tmp, /dev/shm)
> - curl/wget invocations in process list that were not initiated by the user

## 9. Check logs and history

### Shell history
```bash
grep -i "PACKAGE\|pip install" ~/.bash_history ~/.zsh_history 2>/dev/null
```

### System logs
```bash
# Systemd journal
journalctl --since "7 days ago" | grep -i "PACKAGE\|python.*install" | head -50

# Traditional syslogs
grep -R "SUSPICIOUS_DOMAIN" /var/log /tmp "$HOME" 2>/dev/null

# Audit logs
ausearch -k python 2>/dev/null | head -50
```

### Network and process clues
```bash
# Recent Python process executions (systemd journal)
journalctl --since "48 hours ago" | grep -i "python" | head -50

# Last logins (check for unusual access)
last -50
lastlog 2>/dev/null
```

> **What to look for:**
> - pip install commands during the compromise window
> - Python process launches with unusual arguments
> - Outbound network connections to IOC domains
> - Suspicious cron or systemd activity
> - Logins from unusual IPs near the compromise time

## 10. Check containers, images, and Kubernetes

### Docker
```bash
docker images
docker history <image>
docker run --rm <image> python3 -m pip freeze
docker run --rm <image> python3 -m pip show PACKAGE
docker run --rm <image> find / -name "*.pth" -exec grep -l "import " {} \; 2>/dev/null
```

### Kubernetes investigation

```bash
# List all pods and their images
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{range .spec.containers[*]}{.image}{"\t"}{end}{"\n"}{end}'

# Check for pods using the affected image
kubectl get pods --all-namespaces -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for pod in data['items']:
    for c in pod['spec'].get('containers', []):
        if 'PACKAGE' in c.get('image', '').lower():
            print(f\"{pod['metadata']['namespace']}/{pod['metadata']['name']}: {c['image']}\")
"

# Check for privileged pods (lateral movement risk)
kubectl get pods --all-namespaces -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for pod in data['items']:
    for c in pod['spec'].get('containers', []):
        sc = c.get('securityContext', {})
        if sc.get('privileged') or sc.get('runAsUser') == 0:
            print(f\"[PRIVILEGED] {pod['metadata']['namespace']}/{pod['metadata']['name']}: {c['name']}\")
"

# Check RBAC bindings for over-permissioned service accounts
kubectl get clusterrolebindings -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for b in data['items']:
    for s in b.get('subjects', []):
        if s.get('kind') == 'ServiceAccount':
            role = b.get('roleRef', {}).get('name', '')
            if role in ('cluster-admin', 'admin', 'edit'):
                print(f\"[HIGH-PRIV] {s.get('namespace','')}/{s.get('name','')} -> {role}\")
"

# Check secret access timestamps (when were secrets last updated?)
kubectl get secrets --all-namespaces -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for s in data['items']:
    meta = s.get('metadata', {})
    ts = meta.get('creationTimestamp', '')
    annotations = meta.get('annotations', {})
    last_update = annotations.get('kubectl.kubernetes.io/last-applied-configuration', '')
    print(f\"{meta.get('namespace','')}/{meta.get('name','')}: created={ts}\")
"

# Check for pods with host filesystem mounts
kubectl get pods --all-namespaces -o json | python3 -c "
import sys, json
data = json.load(sys.stdin)
for pod in data['items']:
    for v in pod['spec'].get('volumes', []):
        if v.get('hostPath'):
            print(f\"[HOST-MOUNT] {pod['metadata']['namespace']}/{pod['metadata']['name']}: {v['hostPath']['path']}\")
"
```

> **Kubernetes lateral movement risks:**
> - Compromised pods with privileged security contexts can escape to the node
> - Service account tokens mounted in pods can be used to access the K8s API
> - Pods with hostPath mounts can read/write to the node filesystem
> - Over-permissioned RBAC bindings allow compromised workloads to access secrets
> - Check if any secrets were accessed or modified during the compromise window
> - Review the audit log if enabled: `kubectl logs -n kube-system -l component=kube-apiserver`

## 11. Immediate response if found

If a bad version or indicator is found:
1. Preserve evidence (see Evidence Preservation section above)
2. Isolate the host, pod node, or runner
3. Revoke and rotate secrets (see Credential Rotation section)
4. Destroy and rebuild workloads from known-good images
5. Flush package caches if needed
6. Block bad versions in dependency policy
7. Monitor for reuse of compromised credentials

---

# CI/CD Investigation

This is often where real exposure happened.

## What to search in CI

Search CI logs for:
- `pip install.*PACKAGE`
- `Collecting PACKAGE`
- `Downloading PACKAGE`
- `Installing collected packages`
- `Successfully installed.*PACKAGE`
- `PACKAGE==BAD_VERSION`
- the incident date window

## Provider-specific log search patterns

### GitHub Actions
```bash
# List recent workflow runs
gh run list --limit 50

# View logs for a specific run
gh run view <run-id> --log | grep -i "PACKAGE"

# Search across workflow files
rg -n "PACKAGE" .github/workflows/

# Check cached dependencies
gh cache list | grep -i pip
```

> **GitHub Actions specifics:**
> - Cached pip wheels persist across runs. If the cache was populated during the compromise window, subsequent runs also used the bad version.
> - Check `actions/cache` and `actions/setup-python` configurations.
> - OIDC tokens (`ACTIONS_ID_TOKEN_REQUEST_URL`) may have been exfiltrated.
> - `GITHUB_TOKEN` has write access by default in many configurations.

### GitLab CI
```bash
# Search pipeline logs via API
# Replace PROJECT_ID and PIPELINE_ID
curl --header "PRIVATE-TOKEN: $GITLAB_TOKEN" "https://gitlab.com/api/v4/projects/PROJECT_ID/pipelines/PIPELINE_ID/jobs" | python3 -m json.tool

# Search job logs
curl --header "PRIVATE-TOKEN: $GITLAB_TOKEN" "https://gitlab.com/api/v4/projects/PROJECT_ID/jobs/JOB_ID/trace" | grep -i "PACKAGE"
```

> **GitLab CI specifics:**
> - Check CI/CD variables: Settings > CI/CD > Variables
> - Check runner registration tokens if runners are shared
> - Review artifact storage for compromised build outputs

### Jenkins
```bash
# Search Jenkins build logs (on the Jenkins server)
find /var/lib/jenkins/jobs/*/builds/*/log -newer /tmp -mtime -30 2>/dev/null | xargs grep -l "PACKAGE" 2>/dev/null

# Or via API
curl -s "https://jenkins.example.com/job/JOB_NAME/lastBuild/consoleText" | grep -i "PACKAGE"
```

### CircleCI, Buildkite, Azure DevOps

> **CircleCI:** Use the API to fetch job logs: `GET /api/v2/project/{project-slug}/pipeline` then trace through workflows to job logs.
>
> **Buildkite:** Use `buildkite-agent artifact download` or the API to search build logs.
>
> **Azure DevOps:** Search pipeline run logs via the REST API or in the web UI under Pipelines > Runs.

## Questions to answer for every CI system
- Did the runner resolve a bad version? (Check pip install output in logs)
- Was the runner persistent or ephemeral? (Persistent runners are higher risk)
- What secrets were present in the job? (Environment variables, vault integrations, OIDC)
- Did the job publish images, packages, or releases after compromise?
- Were those downstream artifacts promoted to production?
- Was the pip cache poisoned and reused by later builds?

---

# Container and Image Investigation

A repo can look clean while images are infected.

## Check these
- Image build timestamps vs. compromise window
- Base image digest
- Dependency install layers
- pip freeze inside the image
- Runtime site-packages contents
- Whether the image was pushed to registries or deployed to clusters

## Commands
```bash
# Inspect image layers
docker history <image>
docker inspect <image> | python3 -c "import sys,json; d=json.load(sys.stdin)[0]; print('Created:', d['Created']); [print(f'  {k}: {v}') for k,v in d.get('Config',{}).get('Labels',{}).items()]"

# Check pip state inside the image
docker run --rm <image> python3 -m pip freeze
docker run --rm <image> python3 -m pip show PACKAGE

# Hunt for malicious .pth files inside the image
docker run --rm <image> find / -name "*.pth" -exec grep -l "import " {} \; 2>/dev/null

# Check for persistence inside the image
docker run --rm <image> crontab -l 2>/dev/null
docker run --rm <image> ls /etc/cron.d/ 2>/dev/null

# Export image filesystem for offline analysis
docker save <image> -o image-evidence.tar
```

> **Registry investigation:**
> - Check your container registry for images built during the compromise window
> - Compare image digests before and after the incident
> - If using a tag like `latest`, the same tag may have been pushed with different contents
> - Review image scanning results if you have a scanner (Trivy, Grype, Snyk Container)

---

# How to interpret results

## Case 1: Package absent everywhere
Good result, but still verify:
- CI logs during the incident window
- Images built during that window
- Developer machines that may have installed optional extras manually
- Ephemeral environments (Lambda, Cloud Functions, Cloud Run) that may have installed the package and are now gone

> **Even if the package is absent now**, it may have been installed and removed. Check shell history for `pip uninstall PACKAGE` or `pip install PACKAGE`. Check pip log files: `~/.pip/pip.log` or `~/.cache/pip/log/`.

## Case 2: Package present, safe version only
Still record:
- Where found
- Version number
- Why you believe it was safe (version number outside the affected range, hash verification)
- Whether install time overlapped the incident window
- Whether the safe version was installed before or after the compromise window

> **Version alone may not be sufficient.** If an attacker compromised the package's build pipeline, even "safe" version numbers could have been rebuilt with malicious code. Verify package hashes against known-good values from official advisories if available.

## Case 3: Package present, bad version found
Treat as likely compromise unless you can prove otherwise.
- Immediately preserve evidence
- Isolate the system
- Begin credential rotation
- Check for persistence mechanisms and IOCs
- Assume any secrets on the system are burned

> **Proof of non-compromise is hard.** The malicious code may have executed during install (via setup.py or post-install hooks) even if the package was later upgraded. The only safe assumption is that if the bad version was ever resolved, the system should be treated as compromised.

## Case 4: Bad version not found, but malicious indicator found
Treat as confirmed compromise on that host or image.
- This is worse than Case 3: the malware actively executed and left artifacts
- Full incident response is required
- Evidence preservation is critical
- All secrets on the system are burned

## Case 5: Incomplete evidence
If logs are missing or environments were deleted:
- Assume a wider blast radius
- Rotate secrets conservatively (rotate everything that could have been in scope)
- Rebuild from known-good state
- Document what evidence was unavailable and why
- Consider this a gap in your observability and address it

> **Missing evidence is not evidence of absence.** If a CI runner was ephemeral and logs were not retained, you cannot confirm or deny compromise. Default to assuming compromise and rotate accordingly.

---

# Credential Rotation

If you find a compromised dependency on a machine, runner, or image, assume secrets present there may be burned.

## SSH Keys
```bash
# List existing keys
ls -la ~/.ssh/id_* 2>/dev/null

# Generate new SSH keys
ssh-keygen -t ed25519 -C "rotated-$(date +%Y%m%d)" -f ~/.ssh/id_ed25519_new

# Update authorized_keys on remote servers
# Remove the OLD public key and add the new one

# On GitHub/GitLab
# Go to Settings > SSH Keys, remove old, add new

# Revoke old key from all servers
# Then rename new key:
# mv ~/.ssh/id_ed25519_new ~/.ssh/id_ed25519
# mv ~/.ssh/id_ed25519_new.pub ~/.ssh/id_ed25519.pub
```

## AWS Credentials
```bash
# List current access keys
aws iam list-access-keys --user-name YOUR_USER

# Create new access key
aws iam create-access-key --user-name YOUR_USER

# Update ~/.aws/credentials with new key

# Deactivate old key (do not delete yet until you confirm new key works)
aws iam update-access-key --user-name YOUR_USER --access-key-id OLD_KEY_ID --status Inactive

# Delete old key after confirming new key works
aws iam delete-access-key --user-name YOUR_USER --access-key-id OLD_KEY_ID

# Invalidate temporary credentials (STS)
# If an IAM role was compromised, revoke all active sessions:
aws iam put-role-policy --role-name ROLE_NAME --policy-name DenyAll --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"COMPROMISE_TIME"}}}]}'

# Check CloudTrail for use of compromised credentials
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=OLD_KEY_ID --start-time "2026-03-20T00:00:00Z"
```

## GCP Credentials
```bash
# List service account keys
gcloud iam service-accounts keys list --iam-account SA_EMAIL

# Create new key
gcloud iam service-accounts keys create new-key.json --iam-account SA_EMAIL

# Delete old key
gcloud iam service-accounts keys delete OLD_KEY_ID --iam-account SA_EMAIL

# Revoke application default credentials
gcloud auth application-default revoke

# Re-authenticate
gcloud auth application-default login

# Check audit logs
gcloud logging read 'resource.type="service_account" AND protoPayload.authenticationInfo.principalEmail="SA_EMAIL"' --freshness=7d
```

## Azure Credentials
```bash
# List service principal credentials
az ad sp credential list --id SP_ID

# Reset service principal credentials
az ad sp credential reset --id SP_ID

# Revoke user sessions
az account clear

# Re-authenticate
az login

# Check sign-in logs
az monitor activity-log list --start-time "2026-03-20" --caller SP_ID
```

## Kubernetes Secrets and Service Accounts
```bash
# Rotate a specific secret
kubectl delete secret SECRET_NAME -n NAMESPACE
kubectl create secret generic SECRET_NAME -n NAMESPACE --from-literal=key=new-value

# Rotate service account tokens
kubectl delete serviceaccount SA_NAME -n NAMESPACE
kubectl create serviceaccount SA_NAME -n NAMESPACE

# Delete and recreate token secrets
kubectl get secrets -n NAMESPACE | grep SA_NAME

# Bounce pods to pick up new credentials
kubectl rollout restart deployment DEPLOYMENT_NAME -n NAMESPACE
```

## .env and Application Secrets
```bash
# Find all .env files
find / -name ".env" -o -name "*.env" -o -name ".env.*" 2>/dev/null

# For each .env file: regenerate every secret value it contains
# Track which services each secret is for and rotate them at the source:
# - Database passwords: ALTER USER ... PASSWORD '...'
# - API keys: regenerate in the provider's dashboard
# - JWT secrets: generate new random value, invalidate existing tokens
# - Encryption keys: rotate with care (you need to re-encrypt data)
```

## Git Credentials
```bash
# Clear cached git credentials
git credential reject <<EOF
protocol=https
host=github.com
EOF

# Revoke GitHub personal access tokens
# Go to https://github.com/settings/tokens and delete compromised tokens

# If using credential helper store
cat ~/.git-credentials  # review stored credentials
# Delete and re-authenticate
rm ~/.git-credentials
git credential approve <<EOF
protocol=https
host=github.com
username=YOUR_USER
password=NEW_TOKEN
EOF
```

## Database Credentials
```bash
# PostgreSQL
psql -c "ALTER USER username WITH PASSWORD 'new_password';"

# MySQL
mysql -e "ALTER USER 'username'@'host' IDENTIFIED BY 'new_password';"

# MongoDB
mongosh --eval 'db.changeUserPassword("username", "new_password")'

# Redis
redis-cli CONFIG SET requirepass "new_password"
```

## Package Registry Tokens
```bash
# PyPI: go to https://pypi.org/manage/account/token/ and regenerate
# Update ~/.pypirc with new token

# npm: regenerate at https://www.npmjs.com/settings/tokens
npm token revoke TOKEN_ID
npm login

# GitHub Packages: regenerate PAT with packages scope
```

## Post-Rotation Audit

After rotating credentials, verify that the compromised credentials were not used maliciously:

```bash
# AWS: Check CloudTrail for unusual activity with the old key
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=OLD_KEY_ID \
    --start-time "COMPROMISE_START" --end-time "ROTATION_TIME"

# Check for unusual source IPs
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=OLD_KEY_ID \
    --start-time "COMPROMISE_START" | python3 -c "
import sys, json
events = json.load(sys.stdin)
ips = set()
for e in events.get('Events', []):
    detail = json.loads(e.get('CloudTrailEvent', '{}'))
    ip = detail.get('sourceIPAddress', 'unknown')
    ips.add(ip)
print('Source IPs that used this credential:')
for ip in sorted(ips):
    print(f'  {ip}')
"

# GCP: Check audit logs for the service account
gcloud logging read 'protoPayload.authenticationInfo.principalEmail="SA_EMAIL"' --freshness=7d --format=json | python3 -c "
import sys, json
entries = json.load(sys.stdin)
ips = set()
for e in entries:
    ip = e.get('protoPayload', {}).get('requestMetadata', {}).get('callerIp', 'unknown')
    ips.add(ip)
print('Source IPs:')
for ip in sorted(ips):
    print(f'  {ip}')
"
```

> **What to look for in post-rotation audit:**
> - Credential use from IPs outside your organization's known ranges
> - Credential use from cloud regions you do not operate in
> - API calls that create new users, roles, access keys, or tokens (persistence)
> - API calls that modify security groups, IAM policies, or bucket policies
> - API calls that access secrets managers, parameter stores, or key vaults
> - Data access patterns that differ from normal usage (bulk reads, unusual S3 buckets)

---

# Rebuild and containment guidance

Do not rely on uninstalling the package and moving on.

## Preferred response
1. Isolate affected systems
2. Preserve evidence if needed
3. Revoke and rotate secrets
4. Delete affected virtualenvs, images, or runners
5. Rebuild from a known-good base
6. Pin safe versions explicitly
7. Add dependency blocking rules
8. Review logs for follow-on activity (persistence, lateral movement, data access)
9. Verify clean state after rebuild

---

# Prevention recommendations

## Use hashed lockfiles
```bash
# pip: generate requirements with hashes
pip-compile --generate-hashes requirements.in -o requirements.txt
pip install --require-hashes -r requirements.txt

# uv: hashes are included in uv.lock by default
uv lock
uv sync
```

## Pin with time boundaries
```bash
# uv: only resolve packages published before a specific date
uv pip install PACKAGE --exclude-newer "2026-03-20T00:00:00Z"
```

## Run dependency audits regularly
```bash
# pip-audit: scan for known vulnerabilities
pip-audit
pip-audit -r requirements.txt

# Safety
safety check -r requirements.txt

# uv
uv pip audit
```

## Generate and maintain SBOMs
```bash
# Generate SBOM in CycloneDX format
pip install cyclonedx-bom
cyclonedx-py environment -o sbom.json --format json

# Generate SBOM in SPDX format
pip install spdx-tools
# Or use syft
syft dir:. -o spdx-json > sbom-spdx.json
```

## Use Trusted Publishing (PyPI)
> Configure your CI to publish packages to PyPI using OIDC-based Trusted Publishing instead of long-lived API tokens. This prevents token theft from being sufficient to publish malicious versions.
>
> - GitHub Actions: https://docs.pypi.org/trusted-publishers/using-a-publisher/
> - GitLab CI: Also supported via OIDC

## Use dependency review in CI
```bash
# GitHub: enable dependency review action
# In .github/workflows/dependency-review.yml:
# - uses: actions/dependency-review-action@v4

# GitLab: enable dependency scanning
# In .gitlab-ci.yml:
# include:
#   - template: Security/Dependency-Scanning.gitlab-ci.yml
```

## Monitor for compromised packages
> Subscribe to security advisories for your ecosystem:
> - PyPI: https://github.com/pypa/advisory-database
> - GitHub Advisory Database: https://github.com/advisories
> - OSV: https://osv.dev
> - Phylum, Socket, Snyk for real-time supply chain monitoring

---

# Reporting template

Copy this into your incident notes.

## Summary
- Incident name:
- Date discovered:
- Date investigation started:
- Investigator(s):
- Package:
- Ecosystem:
- Known bad versions:
- Known safe versions:
- Official advisory URL:
- Compromise time window:
- Systems reviewed:
- Overall result: [CLEAN | EXPOSED | COMPROMISED | UNKNOWN]

## Findings by system

### System 1
- System name/identifier:
- System type: [developer laptop | CI runner | production host | container image | K8s pod]
- Source reference found: [yes/no, where]
- Installed version:
- Direct or transitive dependency:
- Parent package (if transitive):
- Malicious indicator found: [yes/no, which]
- Persistence mechanism found: [yes/no, which]
- Network IOC found: [yes/no, which]
- Risk level: [none | low | medium | high | critical]
- Evidence files:

(Repeat for each system)

## Secret exposure assessment
- Secrets likely present on compromised systems:
- Secrets confirmed rotated:
- Secrets rotation pending:
- Cloud audit logs checked: [yes/no]
- Unusual credential usage found: [yes/no, details]
- Source IPs of suspicious credential usage:

## Actions taken
- Systems isolated: [list]
- Systems rebuilt: [list]
- Credentials rotated: [list]
- Versions blocked: [list]
- Package pinned to safe version: [version]
- Monitoring added: [what]
- SBOM updated: [yes/no]
- Dependency audit run: [yes/no, tool used]

## Timeline
- Compromise window: [start] to [end]
- Our first install of bad version: [timestamp, if known]
- Detection time: [timestamp]
- Investigation start: [timestamp]
- Containment complete: [timestamp]
- Rotation complete: [timestamp]
- Rebuild complete: [timestamp]

## Unknowns and gaps
- Missing logs: [what, why]
- Deleted environments: [what]
- Systems not inspected: [what, why]
- Confidence level: [high | medium | low]
- Follow-up items:

## Lessons learned
- How did the compromised version enter our environment?
- Could we have detected this sooner?
- What prevention measures should we adopt?
- What monitoring gaps did this expose?

---

# Incident-specific quick checks

Use these templates when investigating a specific package. Replace values as needed.

## Search source
```bash
rg -n "PACKAGE" .
```

## Check install state
```bash
python3 -m pip freeze | grep -i PACKAGE
python3 -m pip show PACKAGE
pipdeptree -r -p PACKAGE
```

## Check for startup hook artifacts
```bash
find / -name "*.pth" 2>/dev/null | xargs grep -l "import " 2>/dev/null
```

## Check for known IOC domain
```bash
grep -R "SUSPICIOUS_DOMAIN" /var/log /tmp "$HOME" 2>/dev/null
```

## Check network connections
```bash
ss -tunap | grep python
lsof -i -n -P | grep python
```

## Check persistence
```bash
crontab -l 2>/dev/null
systemctl --user list-units --type=service 2>/dev/null | grep python
ls ~/.config/autostart/ 2>/dev/null
```

On Windows, use the equivalent PowerShell commands from the Windows section above.

---

# Final rule

Do not ask only:
"Do we import the package?"

Ask:
"Did any repo, environment, runner, image, or developer machine resolve the bad version, and do we have any host-level evidence that it executed, persisted, exfiltrated data, or harvested credentials?"
