# IOC Pattern Library for npm Supply Chain Attacks

This reference contains indicators of compromise from the Axios supply chain attack (March 31, 2026) and generic patterns seen across npm supply chain attacks.

## Axios Compromise (March 31, 2026)

### Attack overview

The npm maintainer account `jasonsaayman` was compromised. The attacker published malicious versions of axios and created a typosquatted dependency `plain-crypto-js` to deliver the payload. The malicious axios versions added `plain-crypto-js` as a dependency, which executed an obfuscated postinstall script.

Source: Elastic Security — https://gist.github.com/joe-desimone/36061dabd2bc2513705e0d083a9673e7

### Compromised packages and versions

| Package | Version | Tag | Status |
|---------|---------|-----|--------|
| axios | 1.14.1 | latest | Malicious |
| axios | 0.30.4 | legacy | Malicious |
| plain-crypto-js | 4.2.0 | — | Malicious payload |
| plain-crypto-js | 4.2.1 | — | Malicious payload |

**Safe versions:**
- axios 1.14.0 (last legitimate 1.x — published via GitHub Actions OIDC with SLSA provenance)
- axios 0.30.3 (last legitimate 0.30.x)

### Timeline

| Time (UTC) | Event |
|------------|-------|
| 2026-03-27T19:01:40Z | axios@1.14.0 published legitimately via GitHub Actions OIDC |
| 2026-03-31 | plain-crypto-js@4.2.0 and 4.2.1 published |
| 2026-03-31T00:21:58Z | axios@1.14.1 published (tagged `latest`) |
| 2026-03-31T01:00:57Z | axios@0.30.4 published (tagged `legacy`) |

### Network IOCs

| Indicator | Type | Context |
|-----------|------|---------|
| `sfrclak.com` | C2 domain | Payload delivery and exfiltration |
| `http://sfrclak.com:8000/` | C2 URL | Stage-2 download endpoint |
| `http://sfrclak.com:8000/6202033` | C2 URL (with campaign ID) | Full callback URL |

Campaign ID: `6202033`

### Account IOCs

| Indicator | Type | Context |
|-----------|------|---------|
| `jasonsaayman` | npm username | Compromised maintainer account |
| `ifstap@proton.me` | Email | Attacker changed account email to this |
| `nrwise@proton.me` | Email | Secondary attacker email |

### Payload delivery

The attack uses a multi-layer obfuscation chain:
- **Layer 1:** String reversal + base64 decoding
- **Layer 2:** XOR cipher using key `OrDeR_7077` with position-dependent index `7 * i² % 10`

The deobfuscated payload imports: `child_process`, `os`, `fs`, `http`

### Filesystem IOCs — macOS (darwin)

| Path | Description |
|------|-------------|
| `/Library/Caches/com.apple.act.mond` | Stage-2 binary disguised as Apple daemon |
| `$TMPDIR/<campaign_id>` | AppleScript payload written before execution |

**Execution chain:** Writes AppleScript → downloads binary via `curl` → `chmod 770` → executes via `/bin/zsh` through `osascript` for process-tree evasion.

### Filesystem IOCs — Windows (win32)

| Path | Description |
|------|-------------|
| `%PROGRAMDATA%\wt.exe` | Renamed copy of PowerShell (Windows Terminal masquerade) |
| `%TEMP%\6202033.vbs` | Transient VBScript loader (self-deletes) |
| `%TEMP%\6202033.ps1` | Transient PowerShell payload |

**Execution chain:** Locates PowerShell via `where powershell` → copies to `wt.exe` → writes VBScript that downloads `.ps1` payload → executes hidden: `wt.exe -w hidden -ep bypass -file <payload>.ps1` via `cscript //nologo` → self-deletes VBScript.

### Filesystem IOCs — Linux

| Path | Description |
|------|-------------|
| `/tmp/ld.py` | Stage-2 Python script |

**Execution chain:** Downloads Python script via `curl` → `python3 /tmp/ld.py` in background via `nohup`.

### Anti-forensics

| Technique | Detection |
|-----------|-----------|
| `setup.js` self-deletion via `fs.unlink(__filename)` | File will be missing from `node_modules/<MALICIOUS_DEP>/` |
| `package.md` → `package.json` swap | Presence of `package.md` alongside `package.json` in malicious dep |
| Transient VBScript/PowerShell files (Windows) | Files created and deleted during execution |

**Critical detection:** If `node_modules/plain-crypto-js/package.md` exists, the attack already executed and cleaned up after itself.

### Detection commands

```bash
# Check for compromised axios versions
cat node_modules/axios/package.json 2>/dev/null | grep '"version"'

# Check for malicious dependency
ls node_modules/plain-crypto-js/ 2>/dev/null

# Check for anti-forensics evidence
ls node_modules/plain-crypto-js/package.md 2>/dev/null

# Check npm cache for cached malicious packages
grep -r 'plain-crypto-js' ~/.npm/_cacache/index-v5/ 2>/dev/null

# Platform-specific IOC checks
ls -la /Library/Caches/com.apple.act.mond 2>/dev/null    # macOS
ls -la /tmp/ld.py 2>/dev/null                              # Linux
# Windows: dir %PROGRAMDATA%\wt.exe 2>nul

# Network — check for C2 connections
ss -tnp 2>/dev/null | grep "sfrclak"
grep -rF "sfrclak" /var/log/ 2>/dev/null

# Process check
ps aux 2>/dev/null | grep -E "ld\.py|com\.apple\.act|wt\.exe" | grep -v grep
```

---

## Generic npm Supply Chain Attack Patterns

### Payload delivery mechanisms

**postinstall scripts** — The primary vector for npm attacks. Runs automatically during `npm install` with the user's full permissions. Detection:
```bash
# Scan all installed packages for lifecycle scripts
npm query ':attr(scripts, [postinstall])' 2>/dev/null | jq '.[].name'

# Fallback for older npm versions
find node_modules -maxdepth 2 -name package.json \
  -exec grep -l '"preinstall\|postinstall\|preuninstall"' {} \;
```

**Typosquatted dependency injection** — The compromised package adds a new dependency with a name similar to a legitimate package (e.g., `plain-crypto-js` mimicking `crypto-js`). The dependency carries the actual payload.

Detection:
```bash
# Compare current lockfile against a known-good version
git diff HEAD~1 package-lock.json | grep "plain-crypto-js\|new-dependency"

# List all new dependencies added since last known-good state
diff <(git show HEAD~1:package-lock.json | jq -r '.packages | keys[]' 2>/dev/null | sort) \
     <(jq -r '.packages | keys[]' package-lock.json 2>/dev/null | sort) | grep "^>"
```

**Obfuscated payloads** — Base64-encoded strings, XOR ciphers, `eval()`/`Buffer.from()` calls buried in minified code.

Detection:
```bash
# Search for obfuscation patterns in installed packages
grep -rn "eval(\|Buffer\.from(\|atob(\|String\.fromCharCode" node_modules/<PACKAGE>/ --include="*.js" | head -20
```

### Environment-gated execution

Some payloads only fire in CI environments:
```bash
# Check if payload gates on CI environment variables
grep -rn "CI\|GITHUB_ACTIONS\|GITLAB_CI\|JENKINS" node_modules/<PACKAGE>/ --include="*.js" 2>/dev/null
```

### Persistence mechanisms (post-exploitation)

After the initial postinstall execution, payloads may install persistence:

**macOS:**
```bash
find ~/Library/LaunchAgents -name "*.plist" -mtime -7 2>/dev/null
```

**Linux:**
```bash
find ~/.config/systemd/user/ -name "*.service" -mtime -7 2>/dev/null
crontab -l 2>/dev/null
find /tmp -name "*.py" -mtime -3 2>/dev/null
```

**Cross-platform:**
```bash
# Node.js global hooks
ls ~/.node_modules/ 2>/dev/null
cat ~/.npmrc 2>/dev/null | grep -v "_authToken"
```

### Credential harvesting targets

npm attacks commonly target these credential locations:

| Target | Path | Detection |
|--------|------|-----------|
| npm tokens | `~/.npmrc` | `stat ~/.npmrc` — check access time |
| SSH keys | `~/.ssh/id_*` | `find ~/.ssh -name "id_*" -atime -1` |
| AWS credentials | `~/.aws/credentials` | `stat ~/.aws/credentials` — check access time |
| GCP credentials | `~/.config/gcloud/application_default_credentials.json` | Check access time |
| Docker config | `~/.docker/config.json` | May contain registry auth tokens |
| Git credentials | `~/.git-credentials` | Plaintext credentials |
| .env files | `.env`, `.env.local`, `.env.production` | `find . -name ".env*"` |
| Kubernetes config | `~/.kube/config` | May contain multiple cluster creds |

### Kubernetes lateral movement

Sophisticated payloads may use in-cluster service account tokens:
```bash
# Check for unexpected pods
kubectl get pods -n kube-system --sort-by=.metadata.creationTimestamp

# Look for privileged pods across all namespaces
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name'

# Recently created secrets
kubectl get secrets --all-namespaces --sort-by=.metadata.creationTimestamp | tail -20

# Audit RBAC for unexpected bindings
kubectl get clusterrolebindings -o json | jq '.items[] | select(.metadata.creationTimestamp > "<ATTACK_DATE>") | .metadata.name'
```
