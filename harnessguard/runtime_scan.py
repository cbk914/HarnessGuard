from __future__ import annotations

import os
import re
import socket
import subprocess
import time

from .models import Finding
from .static_scan import dedupe_findings
from .utils import is_public_ip, now_iso


def _psutil_module():
    try:
        import psutil  # type: ignore

        return psutil
    except Exception:
        return None


def find_pids_by_name(name: str) -> list[int]:
    name_lower = name.lower()
    psutil = _psutil_module()
    pids = []

    if psutil:
        for process in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                haystack = " ".join(
                    [
                        str(process.info.get("name") or ""),
                        str(process.info.get("exe") or ""),
                        " ".join(process.info.get("cmdline") or []),
                    ]
                ).lower()
                if name_lower in haystack:
                    pids.append(int(process.info["pid"]))
            except Exception:
                continue
        return sorted(set(pids))

    try:
        if os.name == "nt":
            import csv
            import io

            output = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"], text=True, errors="replace"
            )
            for row in csv.reader(io.StringIO(output)):
                if len(row) >= 2 and name_lower in row[0].lower():
                    try:
                        pids.append(int(row[1]))
                    except ValueError:
                        pass
        else:
            output = subprocess.check_output(
                ["ps", "-eo", "pid=,comm=,args="], text=True, errors="replace"
            )
            for line in output.splitlines():
                if name_lower in line.lower():
                    match = re.match(r"\s*(\d+)", line)
                    if match:
                        pids.append(int(match.group(1)))
    except Exception:
        pass

    return sorted(set(pids))


def children_of(pid: int) -> set[int]:
    pids = {pid}
    psutil = _psutil_module()
    if psutil:
        try:
            process = psutil.Process(pid)
            pids.update(child.pid for child in process.children(recursive=True))
        except Exception:
            pass
    return pids


def process_info(pid: int) -> dict:
    info = {"pid": pid}
    psutil = _psutil_module()
    if psutil:
        try:
            process = psutil.Process(pid)
            info.update(
                {
                    "name": process.name(),
                    "exe": process.exe(),
                    "cmdline": process.cmdline(),
                    "cwd": process.cwd(),
                    "username": process.username(),
                }
            )
        except Exception as exc:
            info["error"] = str(exc)
    return info


def split_host_port(value: str) -> tuple[str, int | None]:
    value = value.strip()
    if value.startswith("[") and "]:" in value:
        host, port = value.rsplit(":", 1)
        host = host.strip("[]")
    elif ":" in value:
        host, port = value.rsplit(":", 1)
    else:
        return value, None
    try:
        return host, int(port)
    except ValueError:
        return host, None


def connections_for_pids(pids: set[int]) -> list[dict]:
    psutil = _psutil_module()
    results = []

    if psutil:
        for pid in pids:
            try:
                process = psutil.Process(pid)
                for connection in process.net_connections(kind="inet"):
                    if not connection.raddr:
                        continue
                    local_ip = getattr(
                        connection.laddr, "ip", connection.laddr[0] if connection.laddr else None
                    )
                    local_port = getattr(
                        connection.laddr, "port", connection.laddr[1] if connection.laddr else None
                    )
                    remote_ip = getattr(connection.raddr, "ip", connection.raddr[0])
                    remote_port = getattr(connection.raddr, "port", connection.raddr[1])
                    results.append(
                        {
                            "pid": pid,
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "status": str(connection.status),
                        }
                    )
            except Exception:
                continue
        return results

    try:
        if os.name == "nt":
            output = subprocess.check_output(
                ["netstat", "-ano", "-p", "tcp"], text=True, errors="replace"
            )
            for line in output.splitlines():
                cols = line.split()
                if len(cols) < 5 or cols[0].upper() != "TCP":
                    continue
                try:
                    pid = int(cols[-1])
                except ValueError:
                    continue
                if pid not in pids:
                    continue
                remote_ip, remote_port = split_host_port(cols[2])
                local_ip, local_port = split_host_port(cols[1])
                results.append(
                    {
                        "pid": pid,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "status": cols[3],
                    }
                )
        else:
            output = subprocess.check_output(
                ["ss", "-ntp"], text=True, errors="replace", stderr=subprocess.DEVNULL
            )
            for line in output.splitlines():
                pid_match = re.search(r"pid=(\d+)", line)
                if not pid_match:
                    continue
                pid = int(pid_match.group(1))
                if pid not in pids:
                    continue
                cols = line.split()
                if len(cols) < 5:
                    continue
                local_ip, local_port = split_host_port(cols[3])
                remote_ip, remote_port = split_host_port(cols[4])
                results.append(
                    {
                        "pid": pid,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "status": cols[0],
                    }
                )
    except Exception:
        pass

    return results


def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def runtime_audit(pid: int, watch: int, interval: float = 1.0):
    findings = []
    info = process_info(pid)
    observed: dict[tuple[int, str, int], dict] = {}
    end = time.time() + max(0, watch)

    while True:
        pids = children_of(pid)
        for connection in connections_for_pids(pids):
            remote_ip = str(connection.get("remote_ip") or "")
            remote_port = int(connection.get("remote_port") or 0)
            if not remote_ip or not remote_port:
                continue
            key = (int(connection["pid"]), remote_ip, remote_port)
            if key not in observed:
                connection["first_seen"] = now_iso()
                if is_public_ip(remote_ip):
                    connection["reverse_dns"] = reverse_dns(remote_ip)
                observed[key] = connection

        if watch <= 0 or time.time() >= end:
            break
        time.sleep(max(0.25, interval))

    public = [c for c in observed.values() if is_public_ip(str(c["remote_ip"]))]
    local = [c for c in observed.values() if not is_public_ip(str(c["remote_ip"]))]

    for connection in public:
        host = connection.get("reverse_dns")
        destination = f"{connection['remote_ip']}:{connection['remote_port']}"
        if host:
            destination += f" ({host})"
        severity = "MEDIUM" if connection["remote_port"] in (80, 443, 8080, 8443) else "LOW"
        findings.append(
            Finding(
                severity,
                "runtime-egress",
                "Observed outbound connection from target process",
                destination,
                metadata={"pid": connection["pid"], "connection": connection},
                recommendation="Correlate this destination with documented model/API/telemetry endpoints and capture DNS/TLS metadata or proxy traffic if deeper inspection is authorized.",
            )
        )

    if not public:
        findings.append(
            Finding(
                "INFO",
                "runtime-egress",
                "No public outbound connection observed during the sampling window",
                f"PID {pid}; watch={watch}s. This does NOT prove the process never sends data.",
                recommendation="Exercise code-indexing, chat, autocomplete, repo-wiki, login, and telemetry paths while running a longer watch.",
            )
        )

    metadata = {
        "process": info,
        "observed_connections": list(observed.values()),
        "public_connection_count": len(public),
        "local_connection_count": len(local),
        "psutil_available": _psutil_module() is not None,
    }
    return dedupe_findings(findings), metadata
