# Changelog

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
