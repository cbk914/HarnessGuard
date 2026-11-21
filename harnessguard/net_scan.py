from __future__ import annotations

import json
import os
import re
import socket
import ssl
import subprocess
import time
from collections.abc import Iterable, Sequence
from pathlib import Path

from .utils import is_public_ip, now_iso

URL_HOST_RE = re.compile(
    r"(?i)\b(?:https?|wss?)://([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{2,63})+)"
)

CERT_NAME_RE = re.compile(rb"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{2,63})+")

SCANNABLE_SUFFIXES = {".json", ".jsonl", ".ndjson", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".js",
                      ".mjs", ".cjs", ".ts", ".txt", ".env", ".properties", ".conf"}


def _psutil_module():
    try:
        import psutil  # type: ignore

        return psutil
    except Exception:
        return None


def _as_records(raw: str) -> list[dict]:
    raw = (raw or "").strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    return []


def _windows_process_table() -> dict[int, dict]:
    script = (
        "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
        "Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | "
        "ConvertTo-Json -Compress"
    )
    try:
        raw = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", script],
            text=True,
            errors="replace",
            timeout=45,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return {}

    table: dict[int, dict] = {}
    for record in _as_records(raw):
        try:
            pid = int(record.get("ProcessId"))
        except (TypeError, ValueError):
            continue
        table[pid] = {
            "pid": pid,
            "ppid": int(record.get("ParentProcessId") or 0),
            "name": str(record.get("Name") or ""),
            "exe": str(record.get("ExecutablePath") or ""),
            "cmdline": str(record.get("CommandLine") or ""),
        }
    return table


def _posix_process_table() -> dict[int, dict]:
    try:
        raw = subprocess.check_output(
            ["ps", "-eo", "pid=,ppid=,comm=,args="],
            text=True,
            errors="replace",
            timeout=30,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return {}

    table: dict[int, dict] = {}
    for line in raw.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
        except ValueError:
            continue
        table[pid] = {
            "pid": pid,
            "ppid": ppid,
            "name": parts[2],
            "exe": parts[2],
            "cmdline": parts[3] if len(parts) > 3 else "",
        }
    return table


def process_table() -> dict[int, dict]:
    """Return {pid: {name, ppid, exe, cmdline}} for every visible process."""
    psutil = _psutil_module()
    if psutil:
        table: dict[int, dict] = {}
        for process in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline"]):
            try:
                info = process.info
                table[int(info["pid"])] = {
                    "pid": int(info["pid"]),
                    "ppid": int(info.get("ppid") or 0),
                    "name": str(info.get("name") or ""),
                    "exe": str(info.get("exe") or ""),
                    "cmdline": " ".join(info.get("cmdline") or []),
                }
            except Exception:
                continue
        if table:
            return table
    if os.name == "nt":
        return _windows_process_table()
    return _posix_process_table()


def find_pids(patterns: Sequence[str], regex: bool = False) -> list[int]:
    """Match processes whose name, executable or command line contains a pattern."""
    if not patterns:
        return []
    table = process_table()
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns] if regex else None
    needles = [p.lower() for p in patterns] if not regex else []

    hits = []
    for pid, info in table.items():
        fields = [info.get("name") or "", info.get("exe") or "", info.get("cmdline") or ""]
        haystack = " ".join(fields)
        matched = False
        if compiled:
            # A regular expression is applied to each attribute on its own, so
            # anchors such as ^srv\b match the command line and not the prefix
            # contributed by the process name.
            matched = any(rx.search(field) for rx in compiled for field in fields if field)
            if not matched:
                matched = any(rx.search(haystack) for rx in compiled)
        else:
            lowered = haystack.lower()
            matched = any(needle in lowered for needle in needles)
        if matched:
            hits.append(pid)
    return sorted(set(hits))


def process_tree(root_pids: Iterable[int]) -> set[int]:
    """Expand a pid set with every descendant process."""
    table = process_table()
    children: dict[int, list[int]] = {}
    for pid, info in table.items():
        ppid = int(info.get("ppid") or 0)
        if ppid:
            children.setdefault(ppid, []).append(pid)

    resolved = set(int(p) for p in root_pids)
    queue = list(resolved)
    while queue:
        current = queue.pop()
        for child in children.get(current, []):
            if child not in resolved:
                resolved.add(child)
                queue.append(child)
    return resolved


def _psutil_connections(pids: set[int]) -> list[dict]:
    psutil = _psutil_module()
    if not psutil:
        return []
    results = []
    for pid in pids:
        try:
            process = psutil.Process(pid)
            for connection in process.net_connections(kind="inet"):
                if not connection.raddr:
                    continue
                local = getattr(connection.laddr, "ip", None)
                local_port = getattr(connection.laddr, "port", None)
                remote = getattr(connection.raddr, "ip", None)
                remote_port = getattr(connection.raddr, "port", None)
                results.append(
                    {
                        "pid": pid,
                        "protocol": "udp" if connection.type == socket.SOCK_DGRAM else "tcp",
                        "local_ip": local,
                        "local_port": local_port,
                        "remote_ip": remote,
                        "remote_port": remote_port,
                        "status": str(connection.status),
                    }
                )
        except Exception:
            continue
    return results


def _windows_connections() -> list[dict]:
    script = (
        "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
        "Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort,State | "
        "ConvertTo-Json -Compress; "
        "Get-NetUDPEndpoint -ErrorAction SilentlyContinue | "
        "Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort,@{n='State';e={'UDP'}} | "
        "ConvertTo-Json -Compress"
    )
    try:
        raw = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", script],
            text=True,
            errors="replace",
            timeout=45,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return []

    rows = []
    for chunk in raw.split("}{"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if not chunk.startswith("{"):
            chunk = "{" + chunk
        if not chunk.endswith("}"):
            chunk = chunk + "}"
        rows.extend(_as_records(chunk))

    results = []
    for row in rows:
        try:
            pid = int(row.get("OwningProcess"))
        except (TypeError, ValueError):
            continue
        results.append(
            {
                "pid": pid,
                "protocol": "udp" if str(row.get("State")) == "UDP" else "tcp",
                "local_ip": row.get("LocalAddress"),
                "local_port": row.get("LocalPort"),
                "remote_ip": row.get("RemoteAddress"),
                "remote_port": row.get("RemotePort"),
                "status": str(row.get("State") or ""),
            }
        )
    return results


def _netstat_connections(pids: set[int]) -> list[dict]:
    results = []
    try:
        raw = subprocess.check_output(
            ["netstat", "-ano"], text=True, errors="replace", timeout=45, stderr=subprocess.DEVNULL
        )
    except Exception:
        return results

    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].upper()
        if proto not in ("TCP", "UDP"):
            continue
        try:
            pid = int(parts[-1])
        except ValueError:
            continue
        if pid not in pids:
            continue
        remote_field = parts[2]
        local_field = parts[1]
        status = parts[3] if proto == "TCP" else "UDP"

        def _split(value: str) -> tuple[str, int | None]:
            if value.startswith("["):
                host, _, port = value.rpartition(":")
                return host.strip("[]"), int(port) if port.isdigit() else None
            if ":" in value:
                host, _, port = value.rpartition(":")
                return host, int(port) if port.isdigit() else None
            return value, None

        remote_ip, remote_port = _split(remote_field)
        local_ip, local_port = _split(local_field)
        results.append(
            {
                "pid": pid,
                "protocol": "udp" if proto == "UDP" else "tcp",
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "status": status,
            }
        )
    return results


def _ss_connections(pids: set[int]) -> list[dict]:
    results = []
    try:
        raw = subprocess.check_output(
            ["ss", "-antp"],
            text=True,
            errors="replace",
            timeout=45,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return results

    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in ("tcp", "udp"):
            continue
        match = re.search(r"pid=(\d+)", line)
        if not match:
            continue
        pid = int(match.group(1))
        if pid not in pids:
            continue
        local_field = parts[3]
        remote_field = parts[4]
        results.append(
            {
                "pid": pid,
                "protocol": proto,
                "local_ip": local_field.rsplit(":", 1)[0],
                "local_port": local_field.rsplit(":", 1)[-1],
                "remote_ip": remote_field.rsplit(":", 1)[0],
                "remote_port": remote_field.rsplit(":", 1)[-1],
                "status": parts[1] if proto == "tcp" else "UDP",
            }
        )
    return results


def collect_connections(pids: set[int]) -> list[dict]:
    """Return every connection owned by the given pids (TCP and UDP)."""
    rows = _psutil_connections(pids)
    if rows:
        return rows
    if os.name == "nt":
        rows = [r for r in _windows_connections() if r["pid"] in pids]
        if rows:
            return rows
        return _netstat_connections(pids)
    return _ss_connections(pids)


def sample_connections(
    pids: Iterable[int], watch: int = 60, interval: float = 1.0
) -> list[dict]:
    """Sample connections over a time window and collapse them per endpoint."""
    roots = set(int(p) for p in pids)
    observed: dict[tuple, dict] = {}
    end = time.time() + max(0, watch)

    while True:
        tree = process_tree(roots) if roots else set()
        for connection in collect_connections(tree):
            remote_ip = str(connection.get("remote_ip") or "")
            remote_port = connection.get("remote_port")
            if not remote_ip or remote_port is None:
                continue
            if int(remote_port) <= 0:
                continue
            if remote_ip in ("0.0.0.0", "::", "*"):
                continue
            if str(connection.get("status") or "").upper() in ("LISTEN", "BOUND"):
                continue
            key = (
                int(connection["pid"]),
                remote_ip,
                int(remote_port),
                str(connection.get("protocol") or "tcp"),
            )
            record = observed.get(key)
            if record is None:
                record = dict(connection)
                record["first_seen"] = now_iso()
                record["samples"] = 0
                observed[key] = record
            record["last_seen"] = now_iso()
            record["samples"] = int(record.get("samples") or 0) + 1
            record["status"] = connection.get("status")

        if watch <= 0 or time.time() >= end:
            break
        time.sleep(max(0.1, interval))

    return list(observed.values())


def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def resolve_hosts(hosts: Iterable[str]) -> dict[str, list[str]]:
    """Resolve hostnames to their current A/AAAA addresses."""
    from concurrent.futures import ThreadPoolExecutor

    unique = sorted({h.strip().lower() for h in hosts if h and h.strip()})

    def _resolve(host: str) -> tuple[str, list[str]]:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except Exception:
            return host, []
        addresses = []
        for info in infos:
            address = info[4][0]
            if address not in addresses:
                addresses.append(address)
        return host, addresses

    with ThreadPoolExecutor(max_workers=16) as pool:
        return dict(pool.map(_resolve, unique))


def build_host_index(hosts: Iterable[str], ips: Iterable[str]) -> dict[str, list[str]]:
    """Map each observed IP to the hostnames that resolve to it."""
    resolved = resolve_hosts(hosts)
    index: dict[str, list[str]] = {}
    for host, addresses in resolved.items():
        for address in addresses:
            index.setdefault(address, [])
            if host not in index[address]:
                index[address].append(host)

    for ip in ips:
        ptr = reverse_dns(ip)
        if ptr:
            index.setdefault(ip, [])
            if ptr not in index[ip]:
                index[ip].append(ptr)
    return index


def tls_certificate_names(ip: str, port: int = 443, timeout: float = 2.0) -> list[str]:
    """Read the TLS certificate served by an IP and extract DNS names.

    A plain TLS handshake is used, so this works without elevated privileges.
    Certificate names are indicative attribution, not proof of the served site.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=None) as tls:
                der = tls.getpeercert(binary_form=True)
    except Exception:
        return []

    names = []
    for match in CERT_NAME_RE.findall(der or b""):
        try:
            name = match.decode("ascii")
        except UnicodeDecodeError:
            continue
        name = name.strip(".").lower()
        if "." in name and name not in names and not name.endswith(".arpa"):
            names.append(name)
    return names


def harvest_hosts(
    paths: Sequence[Path], max_file_bytes: int = 8 * 1024 * 1024, max_files: int = 5000
) -> dict[str, list[str]]:
    """Extract hostnames referenced by configuration or state files.

    Returns {host: [source files]}. Hosts harvested from the harness' own data
    directory are treated as "declared by the harness" for attribution.
    """
    hosts: dict[str, list[str]] = {}
    seen_files = 0

    for root in paths:
        root = Path(root)
        candidates: list[Path] = []
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in {"node_modules", ".git", "__pycache__"}]
                for filename in filenames:
                    candidates.append(Path(dirpath) / filename)
                    if len(candidates) >= max_files:
                        break
                if len(candidates) >= max_files:
                    break

        for path in candidates:
            if seen_files >= max_files:
                break
            if path.suffix.lower() not in SCANNABLE_SUFFIXES:
                continue
            try:
                if path.stat().st_size > max_file_bytes:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            seen_files += 1
            if b"://" not in data:
                continue
            text = data.decode("utf-8", errors="replace")
            for match in URL_HOST_RE.finditer(text):
                host = match.group(1).lower().rstrip(".")
                if host not in hosts:
                    hosts[host] = []
                source = str(path)
                if source not in hosts[host]:
                    hosts[host].append(source)
    return hosts


def public_endpoints(connections: Sequence[dict]) -> list[dict]:
    """Filter connections down to externally routable destinations."""
    endpoints = []
    for connection in connections:
        ip = str(connection.get("remote_ip") or "")
        if not ip or not is_public_ip(ip):
            continue
        endpoints.append(connection)
    return endpoints
