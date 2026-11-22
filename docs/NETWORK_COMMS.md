# Communication detection and endpoint attribution

This document describes the `harnessguard network` workflow: how observed
destinations are attributed, what the findings mean, and where the evidence
stops.

The goal is narrow and technical: given a harness running on a machine, answer
three questions with reproducible evidence.

1. Which external destinations does it contact?
2. Who operates those destinations, and does the harness declare them?
3. What does the harness actually send?

---

## 1. Observation model

### 1.1 Target selection

A target is one of:

| Selector | Meaning |
|---|---|
| `--pid` | A single process id. Repeatable. |
| `--process-name` | Substring match against process name, executable path and command line. Repeatable. |
| `--profile` | A JSON profile that declares `process_patterns`. |

Process matching is deliberately permissive: name, executable path and full
command line are all searched, so helper processes such as `nxnode.bin`,
`helper.exe` or `python3 harness.py` are found from the parent process name.

### 1.2 Process tree and connection scope

Each endpoint records whether the owning process is the harness itself or a
descendant (`scope`). A descendant-only destination is reported at lower
severity: harnesses routinely spawn shells, language servers and helper
binaries whose traffic is not the harness' own telemetry, and separating the two
keeps the findings actionable.

The observation follows the target into its children. A harness that spawns a
runtime, a helper or a language server is audited as a whole, because those
children are frequently the components that actually talk to the network.

### 1.3 Sampling

Connections are sampled every `--interval` seconds (default 1.0) for
`--watch` seconds (default 60). Each sample collapses into one record per
(pid, address, port, protocol) with `first_seen`, `last_seen` and a sample
counter.

Both TCP and UDP are collected. UDP matters: Chromium-based clients can use
QUIC, and a UDP-only egress is invisible to a TCP-only collector.

Backends, in order of preference:

| Platform | Primary | Fallback |
|---|---|---|
| any | `psutil` (optional extra) | platform specific |
| Windows | `Get-CimInstance Win32_Process`, `Get-NetTCPConnection`, `Get-NetUDPEndpoint` | `netstat -ano` |
| Linux / macOS | `ps`, `ss -antp` | `ss` without process column |

### 1.4 The sampling window is evidence of a bounded kind

A quiet window proves nothing on its own. Beacons are often tied to user
activity (a turn, a route change, an error) rather than to a timer, so a scan
of an idle application can look clean while the same scan during a real
session does not. Run the audit twice: once idle, once while exercising the
harness.

---

## 2. Attribution model

Every observed remote address is classified as one of:

| Attribution | Meaning |
|---|---|
| `self_declared` | The address is served by a hostname declared in the harness profile. |
| `referenced` | The address is served by a hostname found in the harness' own files (configuration, state, bundle) but absent from the profile. |
| `unattributed` | No such link was found. The destination is unexplained by the harness' own artefacts. |

The three classes exist because "the harness mentions this hostname" and "the
harness is configured to talk to this service" are different claims. A
third-party SDK bundled with the harness shows up as `referenced`; an endpoint
nobody can explain shows up as `unattributed`.

Attribution sources, all optional and combined:

1. **Profile declarations** — `declared_hosts` in the harness profile.
2. **Harvested hosts** — hostnames extracted from URLs found in files under
   `--app-data`. These are the harness' own declarations, discovered from
   its data directory instead of being typed by hand.
3. **DNS answers** — each candidate hostname is resolved and the result is
   inverted into an address-to-hostname index. This is what recovers the real
   service name when a shared CDN edge answers for dozens of hosts.
4. **Reverse DNS** — the PTR record, used as a weaker signal and as a hint.
5. **TLS certificate names** (`--tls-names`) — a plain TLS handshake against
   the address returns a certificate whose DNS names usually identify the
   service. No elevated privileges and no interception required.

### 2.1 Why reverse DNS alone is not enough

CDN edges answer for many unrelated hostnames. A PTR record such as
`a104-90-205-224.deploy.static.akamaitechnologies.com` identifies the
operator of the edge, not the service the harness asked for. Forward
resolution of candidate hostnames is what recovers the service name, and the
certificate names are the fallback when the candidate list is incomplete.

### 2.2 Jurisdiction

`--geoip` resolves the country, network operator and autonomous system of
each address. It is **opt-in**, because it is the only step that contacts a
third party, and the endpoint and cache location are configurable:

```bash
harnessguard network --pid 1234 --geoip --geo-cache ~/.harnessguard/geoip-cache.json
```

Jurisdiction is reported as context. It is never a verdict on its own: a
vendor may legitimately operate edges in several countries, and an address
registered in one jurisdiction may serve users in another.

---

## 3. Payload evidence

Connection metadata does not reveal content. `--app-data` adds a second,
independent evidence source: many harnesses serialize the request they send
(model, system prompt, tool schemas, conversation) into their session
directory before sending it.

The scanner looks for JSON and JSONL records shaped like an LLM request and
reports, per record:

| Field | Meaning |
|---|---|
| `path` | Where the artefact lives. |
| `model` | Model identifier in the payload. |
| `api` | Protocol family, when declared. |
| `endpoint` / `endpoint_host` | Base URL the request targets. |
| `max_tokens` | Output limit requested. |
| `tool_count` | Number of tool schemas transmitted. |
| `carries_user_text` | Whether conversation or prompt content is present. |
| `context_bytes` | Approximate size of that content. |
| `record_bytes` / `file_bytes` | Size of the record and of the file. |

This is the cheapest way to answer "what exactly is sent", and it works
without touching TLS.

---

## 4. Findings

| Category | Default severity | Raised when |
|---|---|---|
| `network-third-party-egress` | MEDIUM / LOW | A destination is contacted that the harness configuration does not declare. Downgraded to LOW when only a descendant process owns the connection, because harnesses commonly shell out to tools with their own traffic. |
| `network-referenced-third-party` | LOW | A destination referenced by the harness' own files is outside the declared endpoint set. |
| `network-beacon-pattern` | LOW | The same unattributed destination is contacted repeatedly inside the window. |
| `network-cross-jurisdiction-egress` | MEDIUM | The destination is registered outside the jurisdictions declared for the harness. |
| `network-payload-evidence` | INFO | The harness stores the serialized outbound request on disk. |
| `network-egress` | INFO | No public destination was observed. |

### 4.1 Rule design

The rules describe behaviour, never nationality, vendor reputation or
geography as a judgement. The wording is deliberately behavioural:

- good: "Outbound connection to an endpoint not declared by the harness configuration";
- bad: "Connection to a Chinese server".

Jurisdiction appears as evidence and as a declared-expectation mismatch, and
always with a confidence marker and a suggested next step.

### 4.2 Confidence

| Confidence | Meaning |
|---|---|
| HIGH | Directly observed and mechanically verifiable (a file on disk, a recorded field). |
| MEDIUM | Observed during the window, attribution inferred from DNS or configuration. |
| LOW | Pattern-based inference from recurrence, or jurisdiction mismatch without corroboration. |

---

## 5. Profiles

A profile is a JSON document describing what the operator expects a harness to
do. Profiles live in `profiles/` in the repository and in
`~/.harnessguard/profiles/` on the machine.

```json
{
  "name": "example-harness",
  "process_patterns": ["example-harness"],
  "regex": false,
  "declared_hosts": ["api.example.com"],
  "essential_hosts": ["api.example.com"],
  "declared_jurisdictions": ["US"],
  "app_data_paths": ["~/.config/example-harness"],
  "notes": "Free text for the auditor."
}
```

| Key | Meaning |
|---|---|
| `process_patterns` | How to find the harness. Plain substrings, or regular expressions when `regex` is true. |
| `declared_hosts` | Hostnames the harness is expected to contact. A hostname matches a destination when it is equal to it or a suffix of it. |
| `essential_hosts` | Hostnames the harness cannot work without. They are classified as `core` and are never offered for blocking. |
| `declared_jurisdictions` | ISO country codes the harness is expected to operate in. Advisory. |
| `app_data_paths` | Directories holding the harness' state and configuration. Used for host harvesting and payload evidence. |

A profile is evidence, not a whitelist. Declaring a host silences the
"undeclared" finding for it; it does not prove the traffic is safe.

---

## 6. Necessity classification and blocking options

Knowing *that* a destination is contacted does not answer whether it should
be. Every observed endpoint is therefore classified twice.

**Role** — what the destination does:

| Role | What it does |
|---|---|
| `model_api` | The model endpoint: prompts, tool schemas and conversation content are sent here. |
| `streaming` | The response stream: the model answer is delivered here. |
| `authentication` | Account sign-in, session tokens and identity. |
| `storage` | Uploaded files, generated artefacts and attachments. |
| `update` | Application updates and release metadata. |
| `platform` | Harness configuration, entitlements, agents and extensions. |
| `cdn_asset` | Static assets and downloads. |
| `telemetry` | Diagnostics: errors, crashes, performance and health signals. |
| `analytics` | Product analytics: navigation, session and interaction events. |
| `unknown` | Unclassified destination. |

**Necessity** — whether the harness can work without it:

| Necessity | Meaning |
|---|---|
| `core` | The harness cannot work without it. |
| `feature` | Only one capability depends on it. Blocking it disables that capability. |
| `optional` | Telemetry or analytics. Blocking it removes no capability. |

### 6.1 Evidence order

The classification prefers evidence over name matching, in this order:

1. **`essential_hosts` in the profile** — the operator declared the
   destination as required, so it is `core`.
2. **The endpoint observed in a persisted request payload** — the destination
   that actually receives the prompt is the model endpoint, so it is `core`.
3. **Hostname heuristics** — a hostname label or a known provider table
   assigns the role.
4. **`declared_hosts`** — a destination the harness declares is not reported
   as strictly unnecessary.

Heuristic classification is weaker evidence, and the `reason` field of every
destination states which rule produced its classification.

### 6.2 The operator decides

The tool never blocks anything by itself. `--interactive` presents every
destination that is not strictly necessary, with its role, what it does and
what data it receives, and asks for a scope:

| Scope | Effect |
|---|---|
| `l` | Add the hostname to the local hosts file. |
| `d` | Write the hostname to a DNS blocklist. |
| `n` | Write an outbound firewall rule for the address. |
| `s` | Leave the destination alone. |

Only the destinations chosen for a scope reach the artifact for that scope.
A destination skipped for DNS is not written into the DNS list, and a
destination assigned to DNS is not written into the hosts file.

### 6.3 Hostname scopes and address scopes differ

The scope determines the blast radius:

- **Hostname scopes** (hosts file, DNS filters) stop the name from resolving
  and leave every other name untouched. Two names served from the same
  address remain independent.
- **The address scope** rejects the address itself. A shared origin or a
  shared CDN edge can serve a destination the harness needs, so an address
  rule can break a capability that looks unrelated to the blocked
  destination.

Before writing an address rule, resolve the address and check what else
answers on it. The tool reports the address next to every destination for
exactly this reason.

### 6.4 Known limits of the classification

- A destination that serves several roles behind one address cannot be
  separated by an address rule.
- The provider tables classify by name. A hostname that matches no table and
  carries no role label stays `unknown`, and unknown destinations are not
  offered for blocking.
- A role describes the purpose of a destination, not the legitimacy of the
  operator behind it.

---

## 7. Reports

`--markdown` writes a standalone report containing the endpoint table, the
findings and the limitations. `--json` writes the machine-readable form used
by the rest of HarnessGuard.

```text
| Endpoint | Attribution | Hosts | Owner | Jurisdiction | First seen | Last seen | Samples |
|---|---|---|---|---|---|---|---|
| 203.0.113.9:443/tcp | self_declared | api.example.com | Example Net | US | ... | ... | 42 |
```

---

## 8. Limits

- TLS prevents payload inspection without authorized interception. The tool
  does not decrypt traffic and does not install certificates.
- Connection observation is not proof of content.
- A quiet window does not prove the absence of egress.
- Address attribution is heuristic: shared CDN edges answer for many hosts.
- Jurisdiction of an address is context, not a verdict.
- Data on the local disk is not automatically data that leaves the machine; the
  payload evidence shows what is prepared for sending.

## 9. Responsible use

- The scan is read-only and observes the harness it is pointed at.
- `--geoip` is the only outbound call HarnessGuard makes on its own, and only
  when explicitly requested. It discloses the audited addresses, not the
  machine's traffic.
- Do not point the tool at processes you are not authorised to audit.
