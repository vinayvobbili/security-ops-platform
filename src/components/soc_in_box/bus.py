"""Redis Streams wrapper — the internal message bus for SOC-in-a-Box.

Streams (flat namespace, role-agnostic):
    soc.alerts   — every AlertReceived (XSOAR ticket landed)
    soc.triage   — AlertTriaged emitted by triage tiers
    soc.cases    — handoffs (CaseEscalated, InvestigationComplete, ...)
    soc.audit    — fan-out mirror of every event for the timeline UI / backtest

Consumer groups: one per agent role (e.g. ``tier1``). Each agent process is a
unique consumer within its group; in-flight messages live in the Pending
Entries List until ``ack()``. Failures leave the message unacked so Redis
re-delivers on the next XREADGROUP cycle (or via XAUTOCLAIM on long stalls).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Iterator, Optional

import redis
from pydantic import BaseModel

logger = logging.getLogger(__name__)


STREAM_ALERTS = "soc.alerts"
STREAM_TRIAGE = "soc.triage"
STREAM_CASES = "soc.cases"
STREAM_AUDIT = "soc.audit"
ALL_STREAMS = [STREAM_ALERTS, STREAM_TRIAGE, STREAM_CASES, STREAM_AUDIT]


def get_redis_client() -> redis.Redis:
    """Return a Redis client. Honors ``REDIS_URL`` env var.

    Falls back to ``redis://localhost:6379/0`` (the docker-compose default).
    ``decode_responses=True`` so payloads come back as ``str``.
    """
    url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    return redis.Redis.from_url(url, decode_responses=True)


def publish(client: redis.Redis, stream: str, event: BaseModel) -> str:
    """XADD a Pydantic event onto ``stream``, mirror to ``soc.audit``.

    Returns the new stream entry id.
    """
    payload = event.model_dump_json()
    msg_id = client.xadd(stream, {"payload": payload})
    if stream != STREAM_AUDIT:
        client.xadd(STREAM_AUDIT, {"payload": payload, "source_stream": stream})
    logger.debug("bus.publish stream=%s id=%s type=%s",
                 stream, msg_id, getattr(event, "event_type", "?"))
    return msg_id


def ensure_group(client: redis.Redis, stream: str, group: str) -> None:
    """Idempotently create the consumer group for ``stream`` at ``0``.

    Starting at ``0`` (not ``$``) so a brand-new role consumes any backlog
    already in the stream — if Tier 1 is restarted after an alert burst,
    we don't want those alerts silently dropped.
    """
    try:
        client.xgroup_create(stream, group, id="0", mkstream=True)
        logger.info("bus.ensure_group created stream=%s group=%s", stream, group)
    except redis.ResponseError as exc:
        if "BUSYGROUP" in str(exc):
            return
        raise


def consume_batch(
    client: redis.Redis,
    streams: list[str],
    group: str,
    consumer: str,
    batch_size: int = 10,
    block_ms: int = 5000,
) -> list[tuple[str, str, dict[str, Any]]]:
    """Single XREADGROUP across multiple streams.

    Returns ``[(stream, msg_id, event_dict), ...]``. Caller must
    :func:`ack` after successful processing. Empty list on timeout.
    """
    for s in streams:
        ensure_group(client, s, group)
    stream_map = {s: ">" for s in streams}
    resp = client.xreadgroup(
        groupname=group, consumername=consumer,
        streams=stream_map, count=batch_size, block=block_ms,
    )
    if not resp:
        return []
    out: list[tuple[str, str, dict[str, Any]]] = []
    for stream, msgs in resp:
        for msg_id, fields in msgs:
            try:
                event = json.loads(fields["payload"])
            except (json.JSONDecodeError, KeyError) as exc:
                logger.exception("bus.consume_batch bad payload msg=%s: %s", msg_id, exc)
                # Ack-and-skip — don't let a poison pill wedge the group.
                client.xack(stream, group, msg_id)
                continue
            out.append((stream, msg_id, event))
    return out


def consume(
    client: redis.Redis,
    stream: str,
    group: str,
    consumer: str,
    batch_size: int = 10,
    block_ms: int = 5000,
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Single-stream generator. Useful for scripts; agent loop uses ``consume_batch``."""
    ensure_group(client, stream, group)
    while True:
        batch = consume_batch(client, [stream], group, consumer, batch_size, block_ms)
        for _stream, msg_id, event in batch:
            yield msg_id, event


def ack(client: redis.Redis, stream: str, group: str, msg_id: str) -> None:
    client.xack(stream, group, msg_id)


def replay(
    client: redis.Redis,
    stream: str = STREAM_AUDIT,
    start: str = "-",
    end: str = "+",
    count: Optional[int] = None,
) -> list[dict[str, Any]]:
    """XRANGE-based historical replay for the audit UI / backtest harness."""
    entries = client.xrange(stream, min=start, max=end, count=count)
    out = []
    for msg_id, fields in entries:
        try:
            event = json.loads(fields["payload"])
            event["_msg_id"] = msg_id
            event["_source_stream"] = fields.get("source_stream", stream)
            out.append(event)
        except (json.JSONDecodeError, KeyError):
            logger.warning("bus.replay bad payload msg=%s", msg_id)
    return out
