from __future__ import annotations

import json

from harnessguard import geo


class _FakeResponse:
    def __init__(self, payload: str):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_scope_of_classifies_addresses():
    assert geo.scope_of("127.0.0.1") == "loopback"
    assert geo.scope_of("10.1.2.3") == "private"
    assert geo.scope_of("169.254.1.1") == "link_local"
    assert geo.scope_of("8.8.8.8") == "public"
    assert geo.scope_of("not-an-ip") == "invalid"


def test_lookup_returns_records_and_fills_cache(monkeypatch):
    payload = json.dumps(
        [
            {
                "query": "203.0.113.9",
                "country": "Exampleland",
                "countryCode": "EX",
                "regionName": "Region",
                "city": "City",
                "isp": "Example ISP",
                "org": "Example Org",
                "as": "AS64500 Example",
            }
        ]
    )

    def fake_urlopen(request, timeout=None):
        return _FakeResponse(payload)

    monkeypatch.setattr(geo, "urlopen", fake_urlopen)
    cache: dict = {}
    records = geo.lookup(["203.0.113.9"], cache=cache)
    record = records["203.0.113.9"]
    assert record.country_code == "EX"
    assert record.org == "Example Org"
    assert "203.0.113.9" in cache


def test_lookup_uses_cache_without_network(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("network must not be used when the cache has the address")

    monkeypatch.setattr(geo, "urlopen", fail)
    cache = {"203.0.113.9": {"ip": "203.0.113.9", "country_code": "EX", "country": "Exampleland"}}
    records = geo.lookup(["203.0.113.9"], cache=cache)
    assert records["203.0.113.9"].country_code == "EX"
