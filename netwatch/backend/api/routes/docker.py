"""
api/routes/docker.py

GET /api/docker/topology — Dynamic Docker container discovery

Fixes vs original:
- Docker client is lazy-initialized on first request, not at import time.
  If the socket isn't mounted yet, the process no longer permanently fails.
- All Docker SDK I/O runs in a ThreadPoolExecutor (never blocks the event loop).
- Container stats are fetched concurrently, not sequentially.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import docker
from fastapi import APIRouter, HTTPException

from ..serializers import TopologyResponse, ContainerInfo, PortInfo

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/docker", tags=["docker"])

# Dedicated thread pool — Docker SDK calls are blocking HTTP over a Unix socket
_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="docker-io")

# Lazy client — initialized on first successful request, not at import time
_client: docker.DockerClient | None = None
_client_lock = asyncio.Lock()

_SERVICE_MAP: dict[str, str] = {
    "8000": "FastAPI",
    "3000": "UI",
    "5173": "UI (Vite)",
    "11434": "Ollama",
    "22":   "SSH",
    "5432": "Postgres",
    "6379": "Redis",
    "27017":"MongoDB",
}


def _format_bytes(b: float) -> str:
    if b >= 1024 ** 3: return f"{b / 1024 ** 3:.1f}GB"
    if b >= 1024 ** 2: return f"{b / 1024 ** 2:.1f}MB"
    if b >= 1024:      return f"{b / 1024:.1f}KB"
    return f"{b:.0f}B"


# ---------------------------------------------------------------------------
# Sync helpers — run inside the thread pool
# ---------------------------------------------------------------------------

def _get_or_create_client() -> docker.DockerClient:
    """
    Create the Docker client if not already done.
    Raises on failure — caller turns this into a 503.
    This runs in a thread, so it can block freely.
    """
    global _client
    if _client is not None:
        return _client
    _client = docker.from_env()   # connects to /var/run/docker.sock
    logger.info("Docker client initialized")
    return _client


def _fetch_stats_for_container(container) -> tuple[str | None, str | None]:
    """Fetch CPU + memory for one container. Called concurrently per container."""
    try:
        raw = container.stats(stream=False)

        # Memory: subtract page cache (cgroup v1) to get real RSS
        mem_usage = raw.get("memory_stats", {}).get("usage", 0)
        cache     = raw.get("memory_stats", {}).get("stats", {}).get("cache", 0)
        real_mem  = max(mem_usage - cache, 0)
        mem_str   = _format_bytes(real_mem) if real_mem else None

        # CPU %
        cpu_now  = raw["cpu_stats"]["cpu_usage"]["total_usage"]
        cpu_prev = raw["precpu_stats"]["cpu_usage"]["total_usage"]
        sys_now  = raw["cpu_stats"].get("system_cpu_usage", 0)
        sys_prev = raw["precpu_stats"].get("system_cpu_usage", 0)
        cpus     = raw["cpu_stats"].get("online_cpus") or len(
            raw["cpu_stats"]["cpu_usage"].get("percpu_usage", [1])
        )

        cpu_delta = cpu_now - cpu_prev
        sys_delta = sys_now - sys_prev
        cpu_str   = None
        if sys_delta > 0 and cpu_delta > 0:
            cpu_str = f"{(cpu_delta / sys_delta) * cpus * 100:.1f}%"

        return cpu_str, mem_str
    except Exception as exc:
        logger.debug("Stats failed for %s: %s", getattr(container, "name", "?"), exc)
        return None, None


def _parse_one_container(c) -> ContainerInfo:
    """Parse metadata for a single container. No stats — those are concurrent."""
    # Networks + primary IP
    networks: list[str] = []
    ip_addr = ""
    try:
        net_dict = c.attrs.get("NetworkSettings", {}).get("Networks", {}) or {}
        for net_name, net_info in net_dict.items():
            if net_name != "bridge":
                networks.append(net_name)
                if not ip_addr:
                    ip_addr = net_info.get("IPAddress", "")
        if not ip_addr and "bridge" in net_dict:
            ip_addr = net_dict["bridge"].get("IPAddress", "")
            networks.append("bridge")
    except Exception:
        pass

    internal = "sqlite" in c.name.lower() or "db" in c.name.lower()

    # Ports
    ports_list: list[PortInfo] = []
    try:
        ports = c.attrs.get("NetworkSettings", {}).get("Ports", {}) or {}
        for port_proto, host_bindings in ports.items():
            if not port_proto:
                continue
            parts    = port_proto.split("/")
            port_str = parts[0]
            proto    = parts[1] if len(parts) > 1 else "tcp"
            state    = "open" if host_bindings else "filtered"
            ports_list.append(PortInfo(
                port=int(port_str),
                protocol=proto,
                service=_SERVICE_MAP.get(port_str, "Unknown"),
                state=state,
            ))
    except Exception as exc:
        logger.debug("Port parse failed for %s: %s", c.name, exc)

    return ContainerInfo(
        name=c.name,
        image=c.image.tags[0] if c.image and c.image.tags else "unknown",
        status=c.status,
        ports=ports_list,
        networks=networks,
        ip=ip_addr,
        cpu=None,
        memory=None,
        internal=internal,
    )


def _build_topology() -> list[ContainerInfo]:
    """
    Full topology fetch — runs in a single thread, but spawns concurrent
    sub-tasks for stats using the same executor pool.
    """
    client     = _get_or_create_client()
    containers = client.containers.list(all=True)

    # Parse metadata (fast — just dict access)
    infos: list[ContainerInfo] = [_parse_one_container(c) for c in containers]

    # Fetch stats concurrently for running containers
    running_pairs = [
        (i, containers[i])
        for i, info in enumerate(infos)
        if info.status == "running"
    ]

    if running_pairs:
        futures = {
            _executor.submit(_fetch_stats_for_container, c): idx
            for idx, c in running_pairs
        }
        for future in as_completed(futures, timeout=5):
            idx = futures[future]
            try:
                cpu_str, mem_str   = future.result()
                infos[idx].cpu     = cpu_str
                infos[idx].memory  = mem_str
            except Exception as exc:
                logger.debug("Stats future failed for index %d: %s", idx, exc)

    return infos


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.get("/topology", response_model=TopologyResponse)
async def get_topology() -> TopologyResponse:
    """
    Return all container metadata.
    All Docker SDK I/O runs off the event loop in a thread pool.
    """
    global _client

    loop = asyncio.get_running_loop()
    try:
        container_infos = await loop.run_in_executor(_executor, _build_topology)
    except docker.errors.DockerException as exc:
        # Socket missing, permissions wrong, daemon not running, etc.
        # Reset client so the next request retries instead of staying broken.
        _client = None
        logger.error("Docker error: %s", exc)
        raise HTTPException(
            status_code=503,
            detail=f"Docker unavailable: {exc}. Is /var/run/docker.sock mounted?",
        )
    except Exception as exc:
        _client = None
        logger.exception("Unexpected error fetching Docker topology")
        raise HTTPException(status_code=500, detail=str(exc))

    return TopologyResponse(containers=container_infos)