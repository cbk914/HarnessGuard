from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.request import Request, urlopen

DEFAULT_BATCH_ENDPOINT = "http://ip-api.com/batch"


@dataclass
class GeoRecord:
    ip: str
    country_code: str | None = None
    country: str | None = None
    region: str | None = None
    city: str | None = None
    org: str | None = None
    asn: str | None = None
    source: str = "none"

    def as_dict(self) -> dict:
        return asdict(self)


def scope_of(ip: str) -> str:
    """Classify an address without contacting any external service."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if obj.is_loopback:
        return "loopback"
    if obj.is_link_local:
        return "link_local"
    if obj.is_private:
        return "private"
    if obj.is_multicast:
        return "multicast"
    if obj.is_unspecified:
        return "unspecified"
    if obj.is_reserved:
        return "reserved"
    return "public"


def load_cache(path: Path) -> dict[str, dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_cache(path: Path, data: dict[str, dict]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def lookup(
    ips: list[str],
    endpoint: str = DEFAULT_BATCH_ENDPOINT,
    timeout: float = 20.0,
    cache: dict[str, dict] | None = None,
) -> dict[str, GeoRecord]:
    """Resolve jurisdiction and network ownership for the given addresses.

    The lookup is opt-in: HarnessGuard never contacts a third party unless the
    caller asks for it. Results are advisory context, never a verdict.
    """
    records: dict[str, GeoRecord] = {}
    if cache is None:
        cache = {}
    pending = []

    for ip in ips:
        cached = cache.get(ip)
        if cached:
            records[ip] = GeoRecord(**cached)
        else:
            pending.append(ip)

    if pending:
        payload = [
            {
                "query": ip,
                "fields": "query,country,countryCode,regionName,city,isp,org,as",
            }
            for ip in pending
        ]
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            endpoint,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "harnessguard"},
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw)
        except Exception:
            parsed = []

        if isinstance(parsed, dict):
            parsed = [parsed]
        for item in parsed if isinstance(parsed, list) else []:
            ip = str(item.get("query") or "")
            if not ip:
                continue
            record = GeoRecord(
                ip=ip,
                country_code=str(item.get("countryCode") or "") or None,
                country=str(item.get("country") or "") or None,
                region=str(item.get("regionName") or "") or None,
                city=str(item.get("city") or "") or None,
                org=str(item.get("org") or item.get("isp") or "") or None,
                asn=str(item.get("as") or "") or None,
                source="geoip",
            )
            records[ip] = record
            cache[ip] = record.as_dict()

    for ip in ips:
        records.setdefault(ip, GeoRecord(ip=ip, source="unresolved"))
    return records
