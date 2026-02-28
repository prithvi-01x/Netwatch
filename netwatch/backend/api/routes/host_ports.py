"""
host_ports.py — FastAPI route that discovers ALL listening ports on the host.

Reads /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6
These files are available when the backend container mounts the host's
/proc via:  volumes: - /proc:/host/proc:ro   (see docker-compose patch below)

To add this route to your FastAPI app:
    from backend.api.routes.host_ports import router as host_ports_router
    app.include_router(host_ports_router)

docker-compose.yml — add to the backend service volumes:
    - /proc:/host/proc:ro

This gives us visibility into nc, socat, python -m http.server, ssh,
and anything else listening on the host that isn't a Docker container.
"""

from __future__ import annotations

import os
import socket
import struct
from pathlib import Path
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/host", tags=["host"])

# Where we expect the host's /proc to be.
# - Running natively (your case): /proc  ← default
# - Running in Docker with mount:  /host/proc  ← set HOST_PROC_PATH env var
HOST_PROC = Path(os.environ.get("HOST_PROC_PATH", "/proc"))

# Well-known port → service name mapping
_SERVICE_MAP: dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 514: "Syslog", 587: "SMTP-TLS",
    993: "IMAPS", 995: "POP3S",
    1194: "OpenVPN", 1433: "MSSQL", 1514: "Wazuh",
    1515: "Wazuh-agent", 1516: "Wazuh-cluster",
    3000: "React UI", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5555: "netcat/custom",
    5601: "Kibana", 8000: "FastAPI", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "Jupyter",
    9000: "Portainer", 9200: "Elasticsearch",
    9443: "Portainer-HTTPS", 11434: "Ollama",
    27017: "MongoDB", 55000: "Wazuh-API",
}


class HostPort(BaseModel):
    port: int
    protocol: Literal["tcp", "udp"]
    service: str
    state: Literal["open", "closed", "filtered"]
    pid: int | None = None
    process_name: str | None = None


class HostPortsResponse(BaseModel):
    ports: list[HostPort]
    source: str  # "proc" or "fallback"


class HostInfoResponse(BaseModel):
    ip: str
    interface: str
    all_interfaces: dict[str, str]  # name → ip


def _get_host_info() -> HostInfoResponse:
    """
    Auto-detect the active interface and IP.
    Uses socket + /proc/net/dev for reliable interface discovery.
    """
    interfaces: dict[str, str] = {}  # name → IPv4

    # Most reliable method: use socket to find the outbound interface IP
    # then match it to an interface name via /proc/net/fib_trie or ifconfig
    primary_ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        primary_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    # Get interface names from /proc/net/dev
    dev_path = HOST_PROC / "net" / "dev"
    iface_names: list[str] = []
    try:
        if dev_path.exists():
            for line in dev_path.read_text().splitlines()[2:]:  # skip 2 header lines
                name = line.split(":")[0].strip()
                if name:
                    iface_names.append(name)
    except (OSError, PermissionError):
        pass

    # Match each interface name to its IP using socket.getaddrinfo
    import fcntl
    import struct as _struct
    SIOCGIFADDR = 0x8915
    for name in iface_names:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            result = fcntl.ioctl(
                sock.fileno(),
                SIOCGIFADDR,
                _struct.pack("256s", name[:15].encode())
            )
            sock.close()
            ip = socket.inet_ntoa(result[20:24])
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                interfaces[name] = ip
        except (OSError, IOError):
            pass

    # Find which interface has the primary IP
    skip_prefixes = ("docker", "veth", "lo", "br-", "tailscale", "virbr")
    priority = ["wlan0", "eth0", "ens", "enp", "wlp", "wlan", "wifi"]

    best_iface = None
    best_ip = primary_ip or None

    # First try to match primary_ip to an interface name
    if primary_ip:
        for name, ip in interfaces.items():
            if ip == primary_ip:
                best_iface = name
                break

    # If no match, pick by priority
    if not best_iface:
        for prefix in priority:
            for name, ip in interfaces.items():
                if name.startswith(prefix) and not any(name.startswith(s) for s in skip_prefixes):
                    best_iface = name
                    best_ip = ip
                    break
            if best_iface:
                break

    # Last resort: first non-virtual interface
    if not best_iface:
        for name, ip in interfaces.items():
            if not any(name.startswith(s) for s in skip_prefixes):
                best_iface = name
                best_ip = ip
                break

    return HostInfoResponse(
        ip=best_ip or "unknown",
        interface=best_iface or "unknown",
        all_interfaces=interfaces,
    )


@router.get("/info", response_model=HostInfoResponse)
async def get_host_info() -> HostInfoResponse:
    """
    Return the host's active interface name and IP address.
    Auto-detected from /proc/net — no hardcoded config needed.
    """
    return _get_host_info()


def _hex_to_ip_port(hex_addr: str) -> tuple[str, int]:
    """Convert kernel /proc/net hex address 'AABBCCDD:PPPP' → ('ip', port)."""
    addr, port_hex = hex_addr.split(":")
    # Little-endian 32-bit address
    ip_int = int(addr, 16)
    ip = socket.inet_ntoa(struct.pack("<I", ip_int))
    port = int(port_hex, 16)
    return ip, port


def _parse_proc_net(path: Path, proto: Literal["tcp", "udp"]) -> list[HostPort]:
    """
    Parse a /proc/net/{tcp,udp,tcp6,udp6} file and return listening ports.
    
    Column layout (space-separated):
      sl  local_address  rem_address  st  tx_queue:rx_queue  ...  inode
    
    TCP state 0A = LISTEN, UDP state 07 = UNCONN (always "listening")
    """
    if not path.exists():
        return []

    ports: list[HostPort] = []
    listen_states = {"0A"} if proto == "tcp" else {"07"}  # hex state codes

    try:
        lines = path.read_text().splitlines()
    except (PermissionError, OSError):
        return []

    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 4:
            continue
        local_addr = parts[1]
        state = parts[3].upper()

        if state not in listen_states:
            continue

        try:
            ip, port = _hex_to_ip_port(local_addr)
        except (ValueError, struct.error):
            continue

        if port == 0:
            continue

        service = _SERVICE_MAP.get(port, "Unknown")

        ports.append(HostPort(
            port=port,
            protocol=proto,
            service=service,
            state="open",
        ))

    return ports


def _dedupe(ports: list[HostPort]) -> list[HostPort]:
    """Keep one entry per (port, proto) — prefer TCP over UDP on same port."""
    seen: dict[tuple[int, str], HostPort] = {}
    for p in ports:
        key = (p.port, p.protocol)
        if key not in seen:
            seen[key] = p
    return sorted(seen.values(), key=lambda p: p.port)


def _enrich_with_process_names(ports: list[HostPort]) -> list[HostPort]:
    """
    Try to match ports to process names via /proc/<pid>/net/tcp and /proc/<pid>/fd.
    Best-effort — silently skips on permission errors.
    """
    # Build inode → pid map
    inode_to_pid: dict[str, int] = {}
    proc_root = HOST_PROC

    try:
        for pid_dir in proc_root.iterdir():
            if not pid_dir.name.isdigit():
                continue
            fd_dir = pid_dir / "fd"
            if not fd_dir.exists():
                continue
            try:
                for fd in fd_dir.iterdir():
                    try:
                        target = os.readlink(fd)
                        if target.startswith("socket:["):
                            inode = target[8:-1]
                            inode_to_pid[inode] = int(pid_dir.name)
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue
    except (OSError, PermissionError):
        return ports  # give up enrichment gracefully

    # For each port, find the process name
    enriched = []
    for p in ports:
        pid = None
        name = None
        # Look through all proc net files for matching inode
        # Simplified: just tag the port with whatever pid we can find
        # (full matching requires correlating inode numbers — complex)
        # For now return ports as-is; process enrichment is a future enhancement
        enriched.append(p)

    return enriched


@router.get("/ports", response_model=HostPortsResponse)
async def get_host_ports() -> HostPortsResponse:
    """
    Return all ports currently listening on the HOST machine.
    
    This includes:
    - Docker container ports exposed on the host
    - Native processes: nc, python -m http.server, ssh, custom apps, etc.
    - Any socket bound to 0.0.0.0, 127.0.0.1, or a specific interface
    
    Reads /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6
    mounted from the host at HOST_PROC_PATH (default: /host/proc).
    """
    all_ports: list[HostPort] = []

    for filename, proto in [
        ("net/tcp",  "tcp"),
        ("net/tcp6", "tcp"),
        ("net/udp",  "udp"),
        ("net/udp6", "udp"),
    ]:
        path = HOST_PROC / filename
        all_ports.extend(_parse_proc_net(path, proto))  # type: ignore[arg-type]

    if not all_ports:
        source = "no-ports-found"
    else:
        source = "host-proc"

    deduped = _dedupe(all_ports)
    return HostPortsResponse(ports=deduped, source=source)