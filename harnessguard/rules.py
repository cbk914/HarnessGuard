from __future__ import annotations

import re

SENSITIVE_FILE_PATTERNS = [
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.kdbx",
    "id_rsa", "id_ed25519", "credentials", "credentials.*",
    "secrets.*", "secret.*", "*.tfstate", "*.tfvars",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials",
    "application.properties", "application.yml", "application.yaml",
]

RULES = {
    "enumeration": [
        r"\breaddir(?:Sync)?\b",
        r"\bwalk(?:Dir)?\b",
        r"\bos\.walk\b",
        r"\bglob(?:Sync)?\b",
        r"\bfast[-_]?glob\b",
        r"\brecursive\s*[:=]\s*true\b",
        r"\*\*/\*",
        r"\bgit\s+(?:ls-files|rev-list|reflog)\b",
        r"\.git[/\\](?:objects|logs|lfs)",
    ],
    "snapshot": [
        r"\bsnapshot\b",
        r"\bcheckpoint\b",
        r"\bbaseline\b",
        r"\brepo(?:sitory)?[-_ ]?(?:snapshot|index|wiki)\b",
        r"\bworkspace[-_ ]?(?:snapshot|archive|index)\b",
        r"\bmanifest\b",
    ],
    "archive": [
        r"\bzipfile\b",
        r"\btarfile\b",
        r"\barchiver\b",
        r"\bcreateGzip\b",
        r"\bgzip\b",
        r"\bdeflate\b",
        r"\bcompress(?:ion|ed)?\b",
        r"\b7z\b",
        r"\btar\b",
        r"\bzip\b",
    ],
    "crypto": [
        r"\bAES[-_ ]?(?:128|192|256)?\b",
        r"\bRSA[-_ ]?(?:OAEP)?\b",
        r"\bpublicKey\b",
        r"\bwrap(?:ped)?Key\b",
        r"\bcreateCipheriv\b",
        r"\bencrypt(?:ion|ed)?\b",
        r"\bcrypto\.subtle\b",
    ],
    "upload": [
        r"\bputObject\b",
        r"\buploadObject\b",
        r"\bmultipartUpload\b",
        r"\bpresigned?\s*url\b",
        r"\bsignedUrl\b",
        r"\bformData\b",
        r"\baxios\.(?:put|post)\b",
        r"\bfetch\s*\(",
        r"\brequests\.(?:put|post)\b",
        r"\bhttpx\.(?:put|post)\b",
        r"\bcurl\b.*\b(?:PUT|POST)\b",
        r"\bupload(?:File|Blob|Stream|Data)?\b",
    ],
    "object_storage": [
        r"\baliyun\b",
        r"\balibaba(?:cloud)?\b",
        r"\boss[-_.a-z0-9]*\.aliyuncs\.com\b",
        r"\bamazonaws\.com\b",
        r"\bs3[.-][a-z0-9-]+\.amazonaws\.com\b",
        r"\bstorage\.googleapis\.com\b",
        r"\bblob\.core\.windows\.net\b",
        r"\br2\.cloudflarestorage\.com\b",
        r"\bbackblazeb2\.com\b",
        r"\bdigitaloceanspaces\.com\b",
        r"\bminio\b",
    ],
    "retry_queue": [
        r"\bpending[-_ ]?(?:upload|snapshot|queue)\b",
        r"\bretry\b",
        r"\bfailureCount\b",
        r"\bbackoff\b",
        r"\bmarkAccepted\b",
        r"\blastAccepted\b",
        r"\bqueue(?:Upload|Snapshot)?\b",
    ],
    "sensitive_mentions": [
        r"\.env\b",
        r"\.git[/\\](?:objects|logs|lfs|config)",
        r"\bid_rsa\b",
        r"\bid_ed25519\b",
        r"\bcredentials\b",
        r"\bapi[-_]?key\b",
        r"\bauthorization\b",
        r"\bbearer\b",
        r"\bsecret\b",
        r"\btoken\b",
    ],
    "telemetry": [
        r"\btelemetry\b",
        r"\banalytics\b",
        r"\bmetrics\b",
        r"\bsentry\b",
        r"\bposthog\b",
        r"\bsegment\b",
        r"\bamplitude\b",
        r"\bmixpanel\b",
        r"\bdatadog\b",
    ],
}

COMPILED_RULES = {
    category: [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns]
    for category, patterns in RULES.items()
}

COMBINATION_RULES = [
    (
        {"enumeration", "snapshot", "upload"},
        "HIGH",
        "snapshot-upload",
        "Broad workspace snapshot + upload logic in the same file",
        "Review whether the code can package more than the minimum prompt context and whether the user explicitly opts in.",
    ),
    (
        {"snapshot", "crypto", "upload"},
        "HIGH",
        "encrypted-upload",
        "Encrypted snapshot + upload pipeline in the same file",
        "Verify key ownership, retention, deletion controls, destination, and explicit user consent.",
    ),
    (
        {"snapshot", "retry_queue", "upload"},
        "HIGH",
        "retry-upload",
        "Snapshot upload with pending/retry semantics",
        "Inspect pending queues and ensure failed transfers cannot retry indefinitely without visible user control.",
    ),
    (
        {"object_storage", "upload", "snapshot"},
        "HIGH",
        "cloud-upload",
        "Workspace snapshot appears to target object storage",
        "Confirm destination account/region, retention, and whether whole-workspace upload is necessary.",
    ),
    (
        {"sensitive_mentions", "snapshot", "upload"},
        "CRITICAL",
        "sensitive-upload",
        "Sensitive-file indicators occur in snapshot/upload code path",
        "Treat as potential secret/code exfiltration until scope and exclusions are proven.",
    ),
    (
        {"enumeration", "sensitive_mentions", "archive", "upload"},
        "CRITICAL",
        "archive-exfil",
        "Recursive collection + sensitive content + archive + upload indicators",
        "Perform a controlled canary test and packet/process trace before trusting the tool with real repositories.",
    ),
    (
        {"telemetry", "sensitive_mentions", "upload"},
        "HIGH",
        "telemetry-sensitive",
        "Telemetry/upload code references sensitive material",
        "Verify telemetry payload schemas and disable data collection by default for code/secrets.",
    ),
]

SECRET_VALUE_PATTERNS = [
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("Bearer/JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b")),
    ("Private key header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]
