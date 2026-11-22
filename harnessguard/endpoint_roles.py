from __future__ import annotations

import re
from collections.abc import Sequence

CORE = "core"
FEATURE = "feature"
OPTIONAL = "optional"

ROLE_MODEL_API = "model_api"
ROLE_STREAMING = "streaming"
ROLE_AUTHENTICATION = "authentication"
ROLE_STORAGE = "storage"
ROLE_UPDATE = "update"
ROLE_PLATFORM = "platform"
ROLE_CDN = "cdn_asset"
ROLE_EDGE = "edge"
ROLE_TELEMETRY = "telemetry"
ROLE_ANALYTICS = "analytics"
ROLE_UNKNOWN = "unknown"

ROLE_ORDER = [
    ROLE_MODEL_API,
    ROLE_STREAMING,
    ROLE_AUTHENTICATION,
    ROLE_STORAGE,
    ROLE_UPDATE,
    ROLE_PLATFORM,
    ROLE_CDN,
    ROLE_EDGE,
    ROLE_TELEMETRY,
    ROLE_ANALYTICS,
    ROLE_UNKNOWN,
]

# role -> (necessity, what it does, blockable by default)
ROLE_PROFILE: dict[str, tuple[str, str, bool]] = {
    ROLE_MODEL_API: (
        CORE,
        "the model endpoint: prompts, tool schemas and conversation content are sent here",
        False,
    ),
    ROLE_STREAMING: (
        CORE,
        "the response stream: the model answer is delivered here",
        False,
    ),
    ROLE_AUTHENTICATION: (
        FEATURE,
        "account sign-in, session tokens and identity",
        True,
    ),
    ROLE_STORAGE: (
        FEATURE,
        "uploaded files, generated artefacts and attachments",
        True,
    ),
    ROLE_UPDATE: (
        FEATURE,
        "application updates and release metadata",
        True,
    ),
    ROLE_PLATFORM: (
        FEATURE,
        "harness configuration, entitlements, agents and extensions",
        True,
    ),
    ROLE_CDN: (
        FEATURE,
        "static assets and downloads",
        True,
    ),
    ROLE_EDGE: (
        FEATURE,
        "shared delivery edge: the address answers for many unrelated hostnames",
        False,
    ),
    ROLE_TELEMETRY: (
        OPTIONAL,
        "diagnostics: errors, crashes, performance and health signals",
        True,
    ),
    ROLE_ANALYTICS: (
        OPTIONAL,
        "product analytics: navigation, session and interaction events",
        True,
    ),
    ROLE_UNKNOWN: (
        FEATURE,
        "unclassified destination",
        False,
    ),
}

# Hostnames of well known telemetry and analytics providers. This is a list of
# providers, not a judgement: matching one only changes how a destination is
# described, never whether it is allowed.
TELEMETRY_SUFFIXES = (
    "rum-openway.guance.com",
    "sentry.io",
    "ingest.sentry.io",
    "datadoghq.com",
    "newrelic.com",
    "bugsnag.com",
    "rollbar.com",
    "logrocket.com",
    "statsig.com",
    "appcenter.ms",
)
ANALYTICS_SUFFIXES = (
    "doubleclick.net",
    "google-analytics.com",
    "googletagmanager.com",
    "sensorsdata.cn",
    "sensorsdata.com",
    "guance.com",
    "growingio.com",
    "mixpanel.com",
    "amplitude.com",
    "segment.io",
    "matomo.cloud",
)

# Hostnames served by a shared delivery edge. A reverse DNS name such as
# "a104-90-205-224.deploy.static.akamaitechnologies.com" identifies the
# operator of the edge, not the service that was requested: the same address
# answers for unrelated services. Such a name is never a service hostname, so
# it is never offered for blocking and never used to guess a role.
EDGE_SUFFIXES = (
    "akamaitechnologies.com",
    "akamaihd.net",
    "akamaiedge.net",
    "akadns.net",
    "edgesuite.net",
    "edgekey.net",
    "cloudfront.net",
    "fastly.net",
    "fastlylb.net",
    "llnwd.net",
    "cdn77.org",
    "cachefly.net",
    "edgecastcdn.net",
    "edgecastdns.net",
    "footprint.net",
    "cdngc.net",
)

# Hostname labels that indicate a role. Matched against the labels of a
# hostname, so a label has to match exactly.
ROLE_TOKENS: dict[str, set[str]] = {
    ROLE_TELEMETRY: {
        "telemetry",
        "rum",
        "beacon",
        "collect",
        "ingest",
        "metrics",
        "metric",
        "sentry",
        "datadog",
        "newrelic",
        "bugsnag",
        "rollbar",
        "logrocket",
        "statsig",
    },
    ROLE_ANALYTICS: {
        "analytics",
        "sensorsdata",
        "guance",
        "growingio",
        "amplitude",
        "mixpanel",
        "segment",
        "doubleclick",
        "adservice",
        "adsystem",
        "heatmap",
    },
    ROLE_MODEL_API: {
        "llm",
        "anthropic",
        "openai",
        "completions",
        "inference",
        "inference-api",
        "models",
    },
    ROLE_STREAMING: {"stream", "streaming", "sse", "eventsource"},
    ROLE_AUTHENTICATION: {
        "auth",
        "login",
        "oauth",
        "token",
        "passport",
        "account",
        "accounts",
        "identity",
        "session",
    },
    ROLE_STORAGE: {
        "storage",
        "upload",
        "uploads",
        "files",
        "blob",
        "oss",
        "s3",
        "bucket",
        "attachments",
    },
    ROLE_UPDATE: {"update", "updates", "release", "releases", "upgrade", "download", "version"},
    ROLE_PLATFORM: {"platform", "console", "admin", "manage", "management", "portal"},
    ROLE_CDN: {"cdn", "static", "assets", "img", "images", "fonts"},
}

LABEL_SPLIT = re.compile(r"[.\-_]+")


def _labels(host: str) -> set[str]:
    return {part.lower() for part in LABEL_SPLIT.split(host.lower()) if part}


def _matches_suffix(host: str, suffixes: Sequence[str]) -> bool:
    host = host.lower().strip(".")
    return any(host == suffix or host.endswith("." + suffix) for suffix in suffixes)


def is_edge_host(host: str) -> bool:
    """True when the hostname belongs to a shared delivery edge."""
    return _matches_suffix(host.lower().strip("."), EDGE_SUFFIXES)


def classify_host(host: str) -> tuple[str, str]:
    """Return (role, reason) for a single hostname."""
    host = host.lower().strip(".")
    if not host:
        return ROLE_UNKNOWN, "no hostname"

    if _matches_suffix(host, EDGE_SUFFIXES):
        return (
            ROLE_EDGE,
            "hostname belongs to a shared delivery edge and does not identify the service",
        )

    if _matches_suffix(host, TELEMETRY_SUFFIXES):
        return ROLE_TELEMETRY, "hostname belongs to a known telemetry provider"
    if _matches_suffix(host, ANALYTICS_SUFFIXES):
        return ROLE_ANALYTICS, "hostname belongs to a known analytics provider"

    labels = _labels(host)
    for role in (ROLE_TELEMETRY, ROLE_ANALYTICS, ROLE_MODEL_API, ROLE_STREAMING,
                 ROLE_AUTHENTICATION, ROLE_STORAGE, ROLE_UPDATE, ROLE_PLATFORM, ROLE_CDN):
        matched = labels & ROLE_TOKENS[role]
        if matched:
            token = sorted(matched)[0]
            return role, f"hostname label '{token}' indicates a {role.replace('_', ' ')} destination"

    return ROLE_UNKNOWN, "no role indicator found in the hostname"


def classify_endpoint(
    hosts: Sequence[str],
    tls_names: Sequence[str] = (),
    essential_hosts: Sequence[str] = (),
    declared_hosts: Sequence[str] = (),
    model_hosts: Sequence[str] = (),
) -> tuple[str, str, str]:
    """Return (role, necessity, reason) for an endpoint.

    Explicit operator declarations win over name heuristics. The model hosts
    observed in persisted request payloads are treated as the core endpoint.
    """
    candidates = [h for h in list(hosts) + list(tls_names) if h]
    essential = {h.lower().strip(".") for h in essential_hosts if h}
    declared = {h.lower().strip(".") for h in declared_hosts if h}
    model = {h.lower().strip(".") for h in model_hosts if h}

    def _overlap(pool: set[str]) -> str | None:
        for host in candidates:
            low = host.lower().strip(".")
            for candidate in pool:
                if low == candidate or low.endswith("." + candidate):
                    return host
        return None

    hit = _overlap(essential)
    if hit:
        return ROLE_MODEL_API, CORE, f"declared essential in the harness profile ({hit})"

    hit = _overlap(model)
    if hit:
        return ROLE_MODEL_API, CORE, f"observed as the model endpoint in persisted request payloads ({hit})"

    # A hostname the harness declares is a service hostname, even when the
    # same address also answers with a shared edge name. The edge name never
    # replaces it, because the edge name says nothing about the service.
    def _declared(host: str) -> bool:
        low = host.lower().strip(".")
        return any(low == candidate or low.endswith("." + candidate) for candidate in declared)

    declared_candidates = [host for host in candidates if _declared(host)]
    usable = declared_candidates or candidates

    best_role = ROLE_UNKNOWN
    best_reason = "no role indicator found in the hostname"
    edge_result: tuple[str, str] | None = None
    for host in usable:
        role, reason = classify_host(host)
        if role == ROLE_EDGE:
            if edge_result is None:
                edge_result = (role, reason)
            continue
        if role != ROLE_UNKNOWN:
            best_role = role
            best_reason = reason
            break
    if best_role == ROLE_UNKNOWN and edge_result is not None:
        return ROLE_EDGE, FEATURE, edge_result[1]

    necessity = ROLE_PROFILE[best_role][0]

    hit = _overlap(declared)
    if hit and necessity == OPTIONAL:
        necessity = FEATURE
        best_reason += f"; the harness declares {hit}, so it may be expected"
    elif hit:
        best_reason += f"; the harness declares {hit}"

    return best_role, necessity, best_reason


def describe(role: str) -> str:
    """Human readable description of what a role does."""
    return ROLE_PROFILE.get(role, ROLE_PROFILE[ROLE_UNKNOWN])[1]
