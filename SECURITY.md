# Security Policy

## Supported Versions

HarnessGuard is currently an early-stage project.

Security fixes are applied to the latest development version and, when releases are published, to the most recent supported release.

| Version | Supported |
| --- | --- |
| Latest | Yes |
| Older development snapshots | No guarantee |

## Reporting a Vulnerability

Please do not open a public GitHub issue for a vulnerability that could place users at risk.

Use GitHub private vulnerability reporting if enabled for this repository.

Please include:

- affected version or commit;
- operating system and Python version;
- clear vulnerability description;
- reproduction steps;
- proof-of-concept material when appropriate;
- potential impact;
- suggested remediation if known.

## Scope

Examples of issues that should be reported privately include:

- arbitrary code execution;
- unsafe handling of real secrets;
- unintended outbound transmission caused by HarnessGuard itself;
- path traversal or unsafe file creation;
- privilege escalation;
- command injection;
- insecure temporary-file handling;
- sensitive report data disclosure.

False positives in detection rules are generally not security vulnerabilities and may be reported through normal GitHub issues.

## Responsible Disclosure

Please allow reasonable time for triage and remediation before public disclosure.
