# Changelog

## [0.2.0] - 2026-11-21

### Communication detection
- New `harnessguard network` workflow: samples TCP and UDP sockets of a target
  process and every descendant over a configurable window.
- Cross-platform process and socket collection without mandatory dependencies
  (`psutil` remains optional; Windows uses `Get-CimInstance`/`Get-NetTCPConnection`,
  Linux and macOS use `ps`/`ss`, with `netstat` fallback).
- Endpoint attribution: remote addresses are mapped back to the hostnames that
  serve them using harness-declared hosts, hostnames harvested from the
  harness' own configuration and state files, and reverse DNS.
- Self-declared vs unattributed classification of every observed destination.
- Optional TLS certificate name extraction for unattributed destinations
  (`--tls-names`), implemented as a plain handshake that needs no elevated
  privileges.
- Optional jurisdiction and network owner resolution (`--geoip`, opt-in, cached
  on disk, overridable endpoint).
- Payload evidence: locates outbound request payloads that the harness
  persisted on disk (model, system prompt, tool schemas, conversation) so the
  exact content leaving the machine can be reviewed.
- New findings: `network-third-party-egress`, `network-beacon-pattern`,
  `network-cross-jurisdiction-egress`, `network-payload-evidence`,
  `network-egress`.
- Markdown report output (`--markdown`) with an endpoint table, findings and
  limitations.
- Harness profiles (`profiles/*.json`, `~/.harnessguard/profiles/`) describing
  expected processes, endpoints and jurisdictions, with two examples.

### Documentation
- New `docs/NETWORK_COMMS.md` describing the attribution model, the profile
  format, the finding semantics and the limits of the evidence.
- README updated with the new workflow and with the roadmap entries that are
  now delivered.

### Packaging
- Bumped version to `0.2.0`.

## [0.1.1] - 2026-09-26

### False-positive reduction
- Local line/character correlation instead of whole-file behavioral correlation.
- Byte-offset correlation for binaries.
- Strong vs weak static indicators.
- Authentication/status negative context for generic `snapshot` identifiers.
- Source classification: first-party, third-party, localization, browser cache, user state, binary.
- Behavioral suppression for localization resources.
- Browser-cache endpoint findings downgraded to informational observations.
- Third-party dependency findings reduced in severity/confidence.
- Component-scoped cross-file correlation.
- Separate evidence confidence from severity.
- User-state JWTs/tokens treated as stored session state rather than automatically as hard-coded secrets.
- Risk scoring deduplicated by category/component and weighted by confidence.
- Regression tests derived from real Electron AI-tool false positives.

### Packaging
- Bumped version to `0.1.1`.
- Updated repository URLs to `cbk914/HarnessGuard`.
