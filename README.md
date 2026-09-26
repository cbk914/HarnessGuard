# HarnessGuard

**Security and privacy auditing for AI coding IDEs, agents, extensions, and orchestration harnesses.**

HarnessGuard is a vendor-neutral security auditing toolkit designed to detect potentially dangerous data-handling behavior in AI-assisted development tools.

Modern AI coding environments routinely receive extremely broad access to developer workstations. Depending on the product, an AI IDE, coding agent, extension, or orchestration framework may be able to:

- read entire repositories;
- access Git history;
- inspect environment files;
- discover credentials and API tokens;
- execute commands;
- create temporary archives;
- maintain persistent indexes;
- collect telemetry;
- communicate with external APIs;
- upload files or snapshots to cloud storage;
- retry failed uploads in the background.

That creates a security boundary that deserves the same scrutiny as any other privileged developer tool.

HarnessGuard helps investigate that boundary.

It combines **static analysis**, **runtime network observation**, and **synthetic canary repositories** to identify behaviors that may expose source code, credentials, proprietary information, or repository history to unintended destinations.

---

## Why HarnessGuard exists

AI development tools increasingly operate with access equivalent to a highly privileged local user.

A typical coding agent may legitimately need to:

```text
read files
    ↓
understand the repository
    ↓
generate context
    ↓
send selected information to an LLM
```

But implementations can sometimes evolve into something closer to:

```text
enumerate workspace
    ↓
collect repository
    ↓
include Git metadata/history
    ↓
create snapshot/archive
    ↓
encrypt/compress payload
    ↓
queue upload
    ↓
send to cloud infrastructure
    ↓
retry silently on failure
```

Those two architectures have very different privacy and security implications.

HarnessGuard is intended to help determine which one you are dealing with.

---

# Core goals

HarnessGuard focuses on four questions:

1. **What can the tool read?**
2. **What does the tool stage or persist locally?**
3. **What leaves the machine?**
4. **Can sensitive data cross that boundary without explicit user intent?**

It does not assume that cloud communication is malicious.

It looks for **behavioral chains**.

For example:

```text
recursive repository enumeration
+
snapshot creation
+
sensitive file access
+
archive/encryption
+
upload
```

is much more meaningful than simply discovering:

```text
fetch()
```

or:

```text
api.example.com
```

somewhere in an application bundle.

---

# Features

HarnessGuard currently provides four primary workflows:

```text
harnessguard audit
harnessguard runtime
harnessguard canary
harnessguard hunt
```

Each one covers a different stage of the data lifecycle.

---

# Installation

HarnessGuard requires **Python 3.9 or newer**.

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/harnessguard.git
cd harnessguard
```

Check your Python version:

```bash
python3 --version
```

or on Windows:

```powershell
python --version
```

HarnessGuard is designed to work with the Python standard library.

For improved runtime process and network inspection, install the optional `psutil` dependency:

```bash
python3 -m pip install psutil
```

On Windows:

```powershell
python -m pip install psutil
```

---

# Running on Linux

HarnessGuard works on modern Linux distributions with Python 3.9+.

Tested or expected to work on distributions such as:

```text
Ubuntu
Debian
Kali Linux
Parrot OS
Fedora
Arch Linux
Rocky Linux
AlmaLinux
```

## Install

On Debian, Ubuntu, Kali, or related systems:

```bash
sudo apt update
sudo apt install -y python3 python3-pip git
```

Optional but recommended:

```bash
python3 -m pip install --user psutil
```

If your distribution enforces externally managed Python environments, create a virtual environment instead:

```bash
sudo apt install -y python3-venv

python3 -m venv .venv
source .venv/bin/activate

pip install psutil
```

Run HarnessGuard:

```bash
python3 harnessguard.py --help
```

---

## Linux static audit

Audit a cloned or installed coding agent:

```bash
python3 harnessguard.py audit ~/tools/some-agent
```

Scan multiple locations:

```bash
python3 harnessguard.py audit \
    ~/tools/some-agent \
    --app-data ~/.config/some-agent \
    --app-data ~/.cache/some-agent
```

Common application data locations worth checking include:

```text
~/.config/
~/.cache/
~/.local/share/
~/.local/state/
~/
```

For Electron-based applications, useful locations often include:

```text
~/.config/<application>
~/.cache/<application>
~/.local/share/<application>
```

Example:

```bash
python3 harnessguard.py audit \
    /opt/some-ai-ide \
    --app-data ~/.config/SomeAIIDE \
    --app-data ~/.cache/SomeAIIDE
```

---

## Linux canary test

Create a synthetic repository:

```bash
python3 harnessguard.py canary ~/harness-canary
```

Open:

```text
~/harness-canary
```

with the application under test.

Trigger features such as:

```text
repository indexing
AI chat
autocomplete
repository summary
project documentation
code search
background analysis
```

Then hunt for copied markers:

```bash
python3 harnessguard.py hunt \
    --token-file ~/harness-canary/.privacy-canary.json \
    --root ~/.config/some-agent \
    --root ~/.cache/some-agent \
    --root ~/.local/share/some-agent
```

---

## Linux runtime monitoring

Find the process first if necessary:

```bash
ps aux | grep -i some-agent
```

or:

```bash
pgrep -af some-agent
```

Then:

```bash
python3 harnessguard.py runtime \
    --pid 12345 \
    --watch 120
```

Alternatively:

```bash
python3 harnessguard.py runtime \
    --process-name some-agent \
    --watch 120
```

When `psutil` is not installed, HarnessGuard may fall back to Linux utilities such as:

```text
ps
ss
```

Installing `psutil` is strongly recommended for better process-tree visibility.

---

## Linux permissions

Some operating-system information may only be available with elevated privileges.

For deeper runtime visibility:

```bash
sudo python3 harnessguard.py runtime \
    --pid 12345 \
    --watch 120
```

Do **not** run HarnessGuard as root unnecessarily.

Use elevated privileges only when required to inspect a process you are authorized to test.

---

## Linux advanced tracing

For deeper investigations, combine HarnessGuard with:

```text
strace
lsof
ss
tcpdump
Wireshark
auditd
eBPF
bpftrace
Falco
mitmproxy
```

Example:

```bash
sudo strace -f \
    -e trace=openat,read,write,connect,sendto,recvfrom \
    -p 12345
```

Monitor open files:

```bash
lsof -p 12345
```

Monitor network connections:

```bash
ss -ntp
```

Capture network traffic:

```bash
sudo tcpdump -i any -nn -w harnessguard-session.pcap
```

A useful investigation correlation is:

```text
open repository file
    ↓
read .git object
    ↓
create temporary snapshot
    ↓
write encrypted archive
    ↓
DNS lookup
    ↓
connect to external endpoint
    ↓
transfer data
```

---

# Running on macOS

HarnessGuard works on macOS with Python 3.9 or newer.

Apple Silicon and Intel systems are both supported by the Python implementation.

---

## Install Python and Git

macOS includes several developer utilities, but using a current Python installation is recommended.

With Homebrew:

```bash
brew install python git
```

Check:

```bash
python3 --version
git --version
```

Clone HarnessGuard:

```bash
git clone https://github.com/YOUR_USERNAME/harnessguard.git
cd harnessguard
```

Install optional runtime support:

```bash
python3 -m pip install psutil
```

Or use a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install psutil
```

Run:

```bash
python3 harnessguard.py --help
```

---

## macOS static audit

Audit an application:

```bash
python3 harnessguard.py audit \
    "/Applications/SomeIDE.app"
```

macOS applications are bundles, so HarnessGuard can inspect files inside:

```text
/Applications/SomeIDE.app/
```

Electron applications frequently store important resources under paths similar to:

```text
SomeIDE.app/Contents/Resources/
SomeIDE.app/Contents/Resources/app/
SomeIDE.app/Contents/Resources/app.asar
```

Application data commonly lives under:

```text
~/Library/Application Support/
~/Library/Caches/
~/Library/Preferences/
~/Library/Logs/
```

Example:

```bash
python3 harnessguard.py audit \
    "/Applications/SomeIDE.app" \
    --app-data "$HOME/Library/Application Support/SomeIDE" \
    --app-data "$HOME/Library/Caches/SomeIDE"
```

Remember to quote paths containing spaces.

---

## macOS canary test

Create a synthetic workspace:

```bash
python3 harnessguard.py canary ~/harness-canary
```

Open it in the target IDE.

Exercise:

```text
repository indexing
chat
autocomplete
workspace search
code explanation
repository summarization
documentation generation
background indexing
```

Then search application data:

```bash
python3 harnessguard.py hunt \
    --token-file ~/harness-canary/.privacy-canary.json \
    --root "$HOME/Library/Application Support/SomeIDE" \
    --root "$HOME/Library/Caches/SomeIDE"
```

Additional directories may be worth testing:

```text
~/Library/Logs/
~/Library/Preferences/
~/Library/Saved Application State/
```

---

## macOS runtime monitoring

Find the process:

```bash
ps aux | grep -i someide
```

or:

```bash
pgrep -af SomeIDE
```

Then:

```bash
python3 harnessguard.py runtime \
    --pid 12345 \
    --watch 120
```

Or:

```bash
python3 harnessguard.py runtime \
    --process-name SomeIDE \
    --watch 120
```

For best results:

```bash
python3 -m pip install psutil
```

---

## macOS privacy permissions

macOS privacy controls may limit access to application data or process information.

Depending on what you are auditing, you may need to grant your terminal application:

```text
Full Disk Access
Developer Tools permissions
Files and Folders permissions
```

These settings are available under:

```text
System Settings
    → Privacy & Security
```

For example, Full Disk Access may be required to inspect some files under:

```text
~/Library/
```

or application sandboxes.

Only grant additional permissions when needed for an authorized investigation.

---

## macOS application sandboxes

Sandboxed applications may store data under:

```text
~/Library/Containers/
```

and:

```text
~/Library/Group Containers/
```

You can search for likely application directories with:

```bash
find "$HOME/Library/Containers" \
    -maxdepth 1 \
    -iname '*someide*' \
    2>/dev/null
```

or:

```bash
find "$HOME/Library/Group Containers" \
    -maxdepth 1 \
    -iname '*someide*' \
    2>/dev/null
```

These paths can then be supplied to:

```bash
python3 harnessguard.py hunt \
    --token-file ~/harness-canary/.privacy-canary.json \
    --root "$HOME/Library/Containers/<application>"
```

---

## macOS advanced tracing

Useful native tools include:

```text
fs_usage
opensnoop
nettop
lsof
tcpdump
log stream
```

Monitor filesystem activity:

```bash
sudo fs_usage -w -f filesystem
```

Filter approximately by process name:

```bash
sudo fs_usage -w -f filesystem | grep -i SomeIDE
```

Inspect open files:

```bash
lsof -p 12345
```

Inspect network activity:

```bash
nettop -p 12345
```

Capture traffic:

```bash
sudo tcpdump -i any -nn -w harnessguard-session.pcap
```

For deeper application security research, additional options include:

```text
Wireshark
mitmproxy
Burp Suite
Endpoint Security API
DTrace-derived tooling where available
Frida
```

---

# Running on Windows

Clone:

```powershell
git clone https://github.com/YOUR_USERNAME/harnessguard.git
cd harnessguard
```

Check Python:

```powershell
python --version
```

Optional runtime dependency:

```powershell
python -m pip install psutil
```

Run:

```powershell
python .\harnessguard.py --help
```

---

## Windows static audit

```powershell
python .\harnessguard.py audit `
    "C:\Program Files\SomeIDE"
```

Include application data:

```powershell
python .\harnessguard.py audit `
    "C:\Program Files\SomeIDE" `
    --app-data "$env:APPDATA\SomeIDE" `
    --app-data "$env:LOCALAPPDATA\SomeIDE"
```

Common locations include:

```text
%APPDATA%
%LOCALAPPDATA%
%USERPROFILE%
%PROGRAMFILES%
%PROGRAMFILES(X86)%
```

---

## Windows canary test

```powershell
python .\harnessguard.py canary C:\Temp\harness-canary
```

Use that repository with the target application.

Then:

```powershell
python .\harnessguard.py hunt `
    --token-file C:\Temp\harness-canary\.privacy-canary.json `
    --root "$env:APPDATA\SomeIDE" `
    --root "$env:LOCALAPPDATA\SomeIDE"
```

---

## Windows runtime monitoring

Find the process:

```powershell
Get-Process | Where-Object {
    $_.ProcessName -like "*SomeIDE*"
}
```

Then:

```powershell
python .\harnessguard.py runtime `
    --pid 12345 `
    --watch 120
```

Or:

```powershell
python .\harnessguard.py runtime `
    --process-name SomeIDE `
    --watch 120
```

Without `psutil`, HarnessGuard may use:

```text
tasklist
netstat
```

as fallback mechanisms.

---

# 1. Static audit

The `audit` command analyzes source code, application bundles, extensions, installation directories, and application data.

Example:

```bash
python3 harnessguard.py audit ./some-agent
```

HarnessGuard searches for combinations of behaviors such as:

## Repository enumeration

```text
readdir
readdirSync
os.walk
walkDir
glob
fast-glob
**/*
git ls-files
git rev-list
git reflog
.git/objects
.git/logs
.git/lfs
```

## Snapshot and indexing mechanisms

```text
snapshot
checkpoint
baseline
repository snapshot
workspace snapshot
repo index
repo wiki
manifest
```

## Archive creation

```text
zip
tar
gzip
deflate
archiver
compression
```

## Cryptography

```text
AES
RSA
RSA-OAEP
createCipheriv
crypto.subtle
wrappedKey
encrypt
```

## Upload mechanisms

```text
putObject
uploadObject
multipartUpload
presigned URL
signed URL
FormData
axios.post
axios.put
fetch()
requests.post
httpx.post
```

## Object-storage services

HarnessGuard recognizes common storage backends including:

```text
Alibaba Cloud OSS
Amazon S3
Google Cloud Storage
Azure Blob Storage
Cloudflare R2
Backblaze B2
DigitalOcean Spaces
MinIO
```

Use of these services is not considered malicious by itself.

The important signal is **what is being uploaded**.

---

# 2. Runtime network inspection

Static analysis can show that upload functionality exists.

Runtime analysis can show whether a process actually establishes outbound connections.

Example:

```bash
python3 harnessguard.py runtime --pid 12345
```

Or:

```bash
python3 harnessguard.py runtime \
    --process-name someide \
    --watch 120
```

HarnessGuard attempts to inspect the selected process and its child processes.

During the observation window, exercise the application normally.

For example:

```text
launch application
login
open repository
trigger indexing
use autocomplete
send chat request
generate project summary
activate repository documentation
leave application idle
```

---

# 3. Synthetic canary repository

The canary workflow creates a completely synthetic test project instead of requiring real repositories containing real secrets.

Create one with:

```bash
python3 harnessguard.py canary ./harness-canary
```

The generated repository contains fake sensitive information such as:

```text
.env
config/private-config.json
docs/internal-only.txt
synthetic API tokens
synthetic bearer tokens
unique canary identifiers
```

None of these credentials are real.

---

# Git history canary

If Git is available, HarnessGuard creates an additional secret that exists only in repository history.

Conceptually:

```text
Commit A
    |
    +-- normal repository

Commit B
    |
    +-- historic-secret.txt
        GIT_HISTORY_CANARY_xxxxx

Commit C
    |
    +-- historic-secret.txt deleted
```

At the end:

```text
working tree:
    secret does NOT exist

Git history:
    secret DOES exist
```

This makes it possible to determine whether a development tool accesses or snapshots Git history beyond the current working tree.

---

# 4. Canary hunt

After using the synthetic repository with the target application, HarnessGuard can search application caches and data directories for copied canaries.

Example:

```bash
python3 harnessguard.py hunt \
    --token-file ./harness-canary/.privacy-canary.json \
    --root ~/.some-agent \
    --root ~/.cache
```

If HarnessGuard discovers a Git-history-only canary outside the original repository, this indicates that repository history was copied or staged somewhere by the tested environment.

A finding should still be investigated to determine exactly which component produced it and why.

---

# Recommended testing methodology

For a meaningful audit, combine all detection layers.

## Phase 1 — Static analysis

Inspect:

```text
application installation
extensions
bundled JavaScript
Electron resources
Python packages
Node modules
configuration
cache directories
application data
```

Run:

```bash
python3 harnessguard.py audit /path/to/application
```

---

## Phase 2 — Canary testing

Create:

```bash
python3 harnessguard.py canary ./harness-canary
```

Open the repository with the application.

Trigger repository-aware functionality.

Then:

```bash
python3 harnessguard.py hunt \
    --token-file ./harness-canary/.privacy-canary.json \
    --root /path/to/application/data
```

---

## Phase 3 — Runtime analysis

At the same time:

```bash
python3 harnessguard.py runtime \
    --process-name target-application \
    --watch 120
```

Compare destinations with documented:

```text
LLM APIs
authentication endpoints
telemetry services
update infrastructure
cloud storage
repository services
```

---

# Finding severity model

HarnessGuard deliberately avoids treating isolated strings as proof of malicious behavior.

## INFO

Examples:

```text
sensitive-looking files exist
telemetry configuration exists
repository index feature exists
```

## LOW

Examples:

```text
privacy-related configuration detected
workspace indexing options discovered
telemetry-related settings discovered
```

## MEDIUM

Examples:

```text
upload-capable component found
cloud object-storage endpoint discovered
large archive or encrypted blob in application data
runtime network destination observed
```

## HIGH

Examples:

```text
workspace snapshot + upload

snapshot + encryption + upload

snapshot + retry queue

snapshot + cloud storage
```

## CRITICAL

Examples:

```text
recursive repository enumeration
+
sensitive file references
+
archive generation
+
upload functionality
```

or:

```text
synthetic secret copied outside test repository
```

or:

```text
Git-history-only canary copied into application staging/cache
```

A CRITICAL finding should still be investigated before concluding that actual exfiltration occurred.

---

# Exit codes

HarnessGuard can be used in scripts and CI environments.

```text
0  No HIGH or CRITICAL findings
1  HIGH finding detected
2  CRITICAL finding detected
3  Execution or configuration error
```

Example:

```bash
python3 harnessguard.py audit ./candidate-agent

STATUS=$?

if [ "$STATUS" -ge 2 ]; then
    echo "HarnessGuard detected a critical privacy/security condition."
    exit 1
fi
```

---

# JSON reporting

Generate machine-readable output:

```bash
python3 harnessguard.py audit ./some-agent \
    --json harnessguard-report.json
```

JSON output can later be integrated with:

```text
CI/CD
security dashboards
SIEM pipelines
automated research environments
vulnerability research workflows
```

---

# Threat model

HarnessGuard assumes that an AI development tool may have legitimate reasons to communicate externally.

Potential legitimate destinations include:

```text
LLM inference APIs
authentication services
update infrastructure
telemetry platforms
extension marketplaces
cloud storage
repository hosting services
```

The threat model focuses instead on unintended or excessive data exposure.

Examples include:

- excessive repository collection;
- Git history exposure;
- secret leakage;
- silent local staging;
- persistent upload queues;
- privacy configuration mismatches;
- undocumented cloud storage;
- excessive telemetry.

---

# What HarnessGuard does NOT prove

HarnessGuard findings must be interpreted carefully.

For example:

```text
upload code exists
```

does not prove:

```text
source code was uploaded
```

Likewise:

```text
outbound HTTPS connection observed
```

does not prove:

```text
repository contents were transmitted
```

And:

```text
no canary found
```

does not prove:

```text
no data left the machine
```

Encrypted, compressed, or memory-only transfers may not leave searchable plaintext artifacts.

HarnessGuard is therefore best considered an **evidence-generation and investigation framework**, not an automatic verdict engine.

---

# TLS and encrypted traffic

Most modern applications use TLS.

HarnessGuard can normally observe information such as:

```text
process
destination IP
destination port
connection timing
sometimes hostname
```

but not HTTPS payload contents.

For authorized testing environments, deeper inspection may require:

```text
Burp Suite
mitmproxy
Wireshark
TLS key logging
application instrumentation
OS-level tracing
```

Certificate pinning may prevent conventional proxy interception.

---

# Project architecture

The intended project structure is:

```text
harnessguard/
├── harnessguard/
│   ├── __init__.py
│   ├── cli.py
│   ├── models.py
│   ├── reporting.py
│   │
│   ├── static/
│   │   ├── scanner.py
│   │   ├── rules.py
│   │   ├── secrets.py
│   │   └── endpoints.py
│   │
│   ├── runtime/
│   │   ├── processes.py
│   │   ├── network.py
│   │   └── dns.py
│   │
│   ├── canary/
│   │   ├── generator.py
│   │   ├── hunter.py
│   │   └── git_history.py
│   │
│   └── rules/
│       └── default_rules.yaml
│
├── tests/
├── examples/
├── docs/
├── .github/
│   └── workflows/
├── pyproject.toml
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
└── README.md
```

---

# Roadmap

Planned areas include:

## Static analysis

- configurable YAML rules;
- entropy-based secret detection;
- AST-aware JavaScript analysis;
- Electron application inspection;
- VS Code extension inspection;
- source-map recovery;
- Webpack bundle analysis;
- Semgrep integration;
- YARA support.

## Runtime analysis

- process tree tracking;
- connection timelines;
- DNS correlation;
- TLS SNI extraction;
- filesystem event correlation;
- Windows ETW backend;
- Linux eBPF backend;
- macOS Endpoint Security integration.

## Network analysis

- PCAP integration;
- proxy integration;
- Burp Suite integration;
- mitmproxy addon;
- endpoint ownership resolution.

## Canary framework

- multiple fake secret types;
- per-file unique markers;
- clipboard canaries;
- prompt canaries;
- repository-history canaries;
- dependency canaries;
- binary canaries;
- automatic staging-directory discovery.

## Reporting

- HTML reports;
- SARIF;
- Markdown;
- evidence bundles;
- timeline visualization;
- CI integration.

---

# Responsible use

HarnessGuard is intended for:

```text
defensive security research
application security testing
privacy auditing
software supply-chain analysis
authorized penetration testing
internal security reviews
academic research
```

Only inspect systems and applications that you are authorized to test.

---

# Responsible disclosure

If HarnessGuard reveals a credible vulnerability in a third-party product:

1. reproduce the behavior carefully;
2. preserve evidence;
3. avoid exposing real user secrets;
4. use synthetic canaries where possible;
5. contact the vendor through their security process;
6. allow reasonable remediation time;
7. disclose findings responsibly.

A suspicious code path is not necessarily a vulnerability.

Always verify actual behavior.

---

# Contributing

Contributions are welcome.

Particularly useful contributions include:

```text
new static detection rules
runtime backends
platform support
test fixtures
false-positive reductions
new canary strategies
AI IDE profiles
documentation
research methodology
```

HarnessGuard intentionally prioritizes **correlated evidence over keyword panic**.

---

# Design principles

### Vendor neutral

Security behavior should be evaluated independently of vendor nationality or brand.

### Evidence first

Findings should describe observable technical behavior.

### Correlation over signatures

Multiple weak signals can form strong evidence.

### Synthetic secrets over real secrets

Whenever possible, test using canaries instead of production credentials.

### Reproducibility

Findings should be independently reproducible.

### Transparency

The scanner should explain why it generated a finding.

### Low assumptions

Absence of evidence must not be reported as evidence of absence.

---

# Project status

HarnessGuard is currently an early-stage security research project.

Interfaces, detection rules, severity classifications, and report formats may change significantly between versions.

Do not treat the current scoring system as an authoritative security certification.

---

# License

HarnessGuard is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

You are free to:

- use the software;
- study and modify the source code;
- redistribute copies;
- distribute modified versions.

If you distribute HarnessGuard or a derivative work, the corresponding source code must remain available under the terms of the GPL-3.0.

See the [`LICENSE`](LICENSE) file for the full license text.

---

# Disclaimer

HarnessGuard identifies indicators and behavioral patterns that may warrant security investigation.

A finding does not automatically prove:

```text
malicious intent
unauthorized exfiltration
regulatory violation
vendor misconduct
```

Likewise, a clean report does not prove that an application is secure or privacy-preserving.

Results must be interpreted alongside:

```text
application architecture
documented functionality
runtime evidence
network captures
privacy policies
user configuration
vendor documentation
```

HarnessGuard is an investigation tool, not a trust certificate.
