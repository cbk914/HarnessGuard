# HarnessGuard Threat Model

## Protected Assets

HarnessGuard is primarily concerned with protecting:

- source code;
- proprietary repository contents;
- environment files;
- API credentials;
- authentication tokens;
- private keys;
- Git history;
- deleted historical secrets;
- prompts and developer context;
- local configuration;
- customer information embedded in development workspaces.

## Trust Boundary

AI coding tools often sit at the intersection of:

```text
filesystem
+
developer credentials
+
Git repositories
+
shell / tool execution
+
network access
+
cloud inference
```

HarnessGuard treats that intersection as a privileged security boundary.

## Threat Classes

- Excessive workspace collection
- Historical repository exposure
- Secret exposure
- Silent staging
- Persistent background transmission
- Privacy control mismatch
- Undocumented destinations
- Excessive telemetry

## Non-goals

HarnessGuard does not assume:

- all cloud communication is malicious;
- all telemetry is unsafe;
- a destination is dangerous because of geography;
- static upload code proves exfiltration;
- absence of findings proves safety.
