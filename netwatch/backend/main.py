
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import signal
import sys
import time
from typing import NoReturn

import uvicorn

from .aggregation import Aggregator
from .aggregation.models import AggregatedWindow
from .api.main import create_app, set_pipeline_stats, set_repository
from .api.ws_manager import ws_manager
from .capture import PacketCapture
from .config import settings
from .engine import Alert, DetectionEngine
from .llm import LLMClient
from .metrics import METRICS
from . import pipeline
from .pipeline import init_queues
from .storage import AlertRepository, Database
from .storage.migrations import apply_migrations

logger = logging.getLogger("netwatch.main")

_ANSI = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[96m",
    "LOW":      "\033[97m",
    "RESET":    "\033[0m",
}


def _colour(severity: str, text: str) -> str:
    return f"{_ANSI.get(severity, '')}{text}{_ANSI['RESET']}"


def _alert_to_dict(alert: Alert) -> dict:
    return {
        "alert_id":            alert.alert_id,
        "timestamp":           alert.timestamp,
        "rule_name":           alert.rule_name,
        "severity":            alert.severity.value,
        "confidence":          alert.confidence,
        "src_ip":              alert.src_ip,
        "dst_ip":              alert.dst_ip,
        "description":         alert.description,
        "evidence":            alert.evidence,
        "window_start":        alert.window_start,
        "window_end":          alert.window_end,
        "window_size_seconds": alert.window_size_seconds,
    }


# ---------------------------------------------------------------------------
# Detection consumer — AggregatedWindow → raw alert_queue
# ---------------------------------------------------------------------------

async def detection_consumer(
    engine: DetectionEngine,
    shutdown_event: asyncio.Event,
) -> None:
    """Analyze windows and put raw alert dicts on alert_queue."""
    logger.info("Detection consumer started")
    while not shutdown_event.is_set():
        try:
            window: AggregatedWindow = await asyncio.wait_for(
                pipeline.detection_queue.get(), timeout=0.5
            )
            pipeline.detection_queue.task_done()

            alerts = engine.analyze(window)
            for alert in alerts:
                d = _alert_to_dict(alert)
                # Attach window context for LLM prompt enrichment
                d["_window_context"] = {
                    "total_packets":         window.total_packets,
                    "unique_src_count":      len(window.unique_src_ips),
                    "unique_dst_ports_count": len(window.unique_dst_ports),
                    "protocol_counts":       window.protocol_counts,
                }
                await pipeline.safe_put(pipeline.alert_queue, d)

        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            break
    logger.info("Detection consumer exiting")


# ---------------------------------------------------------------------------
# LLM consumer — alert_queue → LLM → enriched_queue → DB + WS
# ---------------------------------------------------------------------------

async def llm_consumer(
    llm_client: LLMClient,
    repo: AlertRepository,
    shutdown_event: asyncio.Event,
) -> None:
    """
    Pull raw alerts from alert_queue, enrich with LLM, persist and broadcast.

    The LLM call is fully async and non-blocking. If Ollama is unavailable,
    a static fallback is used instantly so alerts are never delayed.
    """
    logger.info(
        "LLM consumer started (enabled=%s model=%r url=%s)",
        settings.LLM_ENABLED, settings.OLLAMA_MODEL, settings.OLLAMA_URL,
    )

    while not shutdown_event.is_set():
        try:
            alert_dict: dict = await asyncio.wait_for(
                pipeline.alert_queue.get(), timeout=0.5
            )
            pipeline.alert_queue.task_done()

            # Extract and remove the window context (not stored in DB)
            window_context = alert_dict.pop("_window_context", None)

            # LLM enrichment
            if settings.LLM_ENABLED:
                explanation = await llm_client.explain(alert_dict, window_context)
            else:
                from .llm.fallbacks import get_fallback
                explanation = get_fallback(alert_dict.get("rule_name", ""))

            llm_dict = explanation.to_dict()

            # Save to DB (base alert first, then attach LLM column)
            repo.save_alert(alert_dict)
            repo.update_alert_llm(alert_dict["alert_id"], llm_dict)

            # Broadcast enriched alert over WebSocket
            broadcast_payload = {**alert_dict, "llm_explanation": llm_dict}
            await ws_manager.broadcast("alerts", broadcast_payload)

            # Console print
            _print_alert_dict(alert_dict, explanation)

        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            break

    logger.info("LLM consumer exiting")


def _print_alert_dict(alert_dict: dict, explanation=None) -> None:
    sev = alert_dict.get("severity", "LOW")
    header = _colour(sev, f"[ALERT ★ {sev}]")
    llm_line = ""
    if explanation and not explanation.fallback_used:
        llm_line = f"\n  {_colour(sev, '🤖 ' + explanation.summary[:100])}"
    print(
        f"\n{header} rule={alert_dict.get('rule_name')!r} "
        f"conf={alert_dict.get('confidence', 0):.2f} "
        f"src={alert_dict.get('src_ip')!r}\n"
        f"  {_colour(sev, alert_dict.get('description', ''))}"
        f"{llm_line}\n"
        f"  id={alert_dict.get('alert_id', '')[:8]}\n",
        flush=True,
    )


# ---------------------------------------------------------------------------
# Periodic broadcasters
# ---------------------------------------------------------------------------

async def flows_broadcaster(
    aggregator: Aggregator,
    shutdown_event: asyncio.Event,
) -> None:
    while not shutdown_event.is_set():
        await asyncio.sleep(1.0)
        if ws_manager.connection_count("flows") == 0:
            continue
        top_flows = aggregator._tracker.get_top_flows(n=10)
        flows_data = [
            {
                "src_ip":   f.flow_key.src_ip,
                "dst_ip":   f.flow_key.dst_ip,
                "src_port": f.flow_key.src_port,
                "dst_port": f.flow_key.dst_port,
                "protocol": f.flow_key.protocol,
                "packets":  f.packet_count,
                "bytes":    f.byte_count,
                "pps":      round(f.packets_per_second, 2),
            }
            for f in top_flows
        ]
        await ws_manager.broadcast("flows", {"flows": flows_data, "timestamp": time.time()})


async def stats_broadcaster(
    aggregator: Aggregator,
    engine: DetectionEngine,
    repo: AlertRepository,
    shutdown_event: asyncio.Event,
    interval: float = 5.0,
) -> None:
    while not shutdown_event.is_set():
        await asyncio.sleep(interval)
        capture_stats = METRICS.as_dict()
        snapshot = {
            "timestamp":        time.time(),
            "packets_seen":     capture_stats.get("packets_received", 0),
            "packets_dropped":  capture_stats.get("packets_dropped", 0),
            "flows_active":     aggregator.stats.get("flows_active", 0),
            "alerts_fired":     engine.stats.get("alerts_fired", 0),
            "windows_analyzed": engine.stats.get("windows_analyzed", 0),
        }
        repo.save_stats_snapshot(snapshot)
        await ws_manager.broadcast("stats", snapshot)
        logger.info(
            "METRICS capture=%s aggregator=%s engine=%s ws=%s",
            capture_stats, aggregator.stats, engine.stats, ws_manager.all_counts(),
        )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run(iface: str, bpf_filter: str, local_net: str) -> None:
    shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    init_queues(
        capture_size=settings.CAPTURE_QUEUE_SIZE,
        detection_size=settings.DETECTION_QUEUE_SIZE,
        alert_size=settings.ALERT_QUEUE_SIZE,
        enriched_size=settings.ENRICHED_QUEUE_SIZE,
    )

    def _signal_handler(_signum, _frame) -> None:
        logger.info("Shutdown signal received")
        loop.call_soon_threadsafe(shutdown_event.set)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Storage
    db = Database(settings.DB_PATH)
    db.init_schema()
    apply_migrations(db)
    repo = AlertRepository(db)

    # Capture
    capture = PacketCapture(
        queue=pipeline.capture_queue,
        loop=loop,
        iface=iface,
        bpf_filter=bpf_filter,
        local_net=local_net,
    )
    capture.start()

    # Aggregator
    aggregator = Aggregator(
        input_queue=pipeline.capture_queue,
        output_queue=pipeline.detection_queue,
        flow_ttl=settings.FLOW_TTL_SECONDS,
    )

    # Detection engine
    engine = DetectionEngine(
        confidence_threshold=settings.DETECTION_CONFIDENCE_THRESHOLD
    )

    # LLM client
    llm_client = LLMClient(
        base_url=settings.OLLAMA_URL,
        model=settings.OLLAMA_MODEL,
    )

    # Wire API state
    set_repository(repo)
    combined_stats: dict = {
        "capture":    METRICS.as_dict(),
        "aggregator": aggregator.stats,
        "engine":     engine.stats,
        "llm":        llm_client.stats,
    }
    set_pipeline_stats(combined_stats)

    # Register LLM routes onto the app (passes llm_client reference)
    from .api.routes import llm as llm_routes
    llm_routes.set_llm_client(llm_client)

    # FastAPI + uvicorn
    app = create_app()
    uv_config = uvicorn.Config(
        app,
        host=settings.API_HOST,
        port=settings.API_PORT,
        log_level="warning",
        loop="none",
    )
    uv_server = uvicorn.Server(uv_config)

    # Check Ollama at startup (non-blocking — just logs)
    asyncio.create_task(llm_client.health_check())

    tasks = [
        asyncio.create_task(aggregator.run(),                             name="aggregator"),
        asyncio.create_task(detection_consumer(engine, shutdown_event),   name="detection"),
        asyncio.create_task(llm_consumer(llm_client, repo, shutdown_event), name="llm"),
        asyncio.create_task(flows_broadcaster(aggregator, shutdown_event), name="flows_ws"),
        asyncio.create_task(
            stats_broadcaster(aggregator, engine, repo, shutdown_event),  name="stats_ws"
        ),
        asyncio.create_task(uv_server.serve(),                            name="api"),
    ]

    logger.info(
        "NetWatch Phase 5 — iface=%r filter=%r  API=http://%s:%d  LLM=%s@%s",
        iface, bpf_filter, settings.API_HOST, settings.API_PORT,
        settings.OLLAMA_MODEL, settings.OLLAMA_URL,
    )
    logger.info("Detection rules: %s", [r.name for r in engine.rules])

    await shutdown_event.wait()

    uv_server.should_exit = True
    for t in tasks[:-1]:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    capture.stop()
    db.close()
    logger.info("Final stats — engine=%s llm=%s", engine.stats, llm_client.stats)
    logger.info("NetWatch stopped cleanly")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NetWatch Phase 5")
    parser.add_argument("--iface",     default=settings.INTERFACE)
    parser.add_argument("--filter",    default=settings.BPF_FILTER, dest="bpf")
    parser.add_argument("--local-net", default=settings.LOCAL_NETWORK)
    parser.add_argument(
        "--log-level", default=settings.LOG_LEVEL,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser.parse_args()


def main() -> NoReturn:
    args = _parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    try:
        ipaddress.ip_network(args.local_net, strict=False)
    except ValueError as e:
        print(f"ERROR: invalid --local-net: {e}", file=sys.stderr)
        sys.exit(1)

    asyncio.run(run(iface=args.iface, bpf_filter=args.bpf, local_net=args.local_net))
    sys.exit(0)


if __name__ == "__main__":
    main()
