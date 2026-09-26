# Detection Philosophy

HarnessGuard is intentionally conservative about isolated indicators.

The following should generally not create severe findings by themselves:

```text
fetch()
upload
snapshot
token
telemetry
S3 endpoint
AES usage
```

Severity increases when multiple behaviors form a meaningful chain:

```text
recursive workspace enumeration
+
sensitive file access
+
snapshot creation
+
archive/encryption
+
external upload
+
retry queue
```

The objective is not to classify vendors as good or bad. The objective is to generate reproducible evidence.
