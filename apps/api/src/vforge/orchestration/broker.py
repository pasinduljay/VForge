"""RabbitMQ topology and persistent outbox message broker for Phase 3."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

import aio_pika
from aio_pika import DeliveryMode, ExchangeType, Message
from aio_pika.abc import AbstractIncomingMessage

logger = logging.getLogger("vforge.orchestration.broker")

EVENTS_EXCHANGE = "vforge.events"
DLX_EXCHANGE = "vforge.dlx"
DISPATCH_QUEUE = "vforge.orchestration.dispatch"
DLQ_QUEUE = "vforge.orchestration.dlq"
DISPATCH_ROUTING_KEY = "scan.job.dispatch"
DLQ_ROUTING_KEY = "orchestration.dlq"


class OrchestrationBroker(Protocol):
    """Abstract broker interface for transactional outbox publishing."""

    async def publish(
        self,
        *,
        routing_key: str,
        payload: dict[str, Any],
        message_id: str,
        correlation_id: str | None = None,
    ) -> None: ...


class RabbitMqOrchestrationBroker:
    """Durable RabbitMQ publisher/consumer respecting Phase 3 least-privilege vhost ACLs.

    Every exchange and queue uses the ``vforge.`` prefix and ``durable=True``
    required by RabbitMQ 4.x and the ``vforge_app`` permission regex.
    """

    def __init__(self, amqp_url: str, *, prefetch_count: int = 8) -> None:
        self._amqp_url = amqp_url
        self._prefetch_count = prefetch_count
        self._connection: aio_pika.abc.AbstractRobustConnection | None = None
        self._pub_channel: aio_pika.abc.AbstractChannel | None = None
        self._sub_channel: aio_pika.abc.AbstractChannel | None = None
        self._exchange: aio_pika.abc.AbstractExchange | None = None
        self._dispatch_queue: aio_pika.abc.AbstractQueue | None = None

    async def _ensure_connection(self) -> aio_pika.abc.AbstractRobustConnection:
        if self._connection is None or self._connection.is_closed:
            self._connection = await aio_pika.connect_robust(self._amqp_url, timeout=10)
            self._pub_channel = None
            self._sub_channel = None
            self._exchange = None
            self._dispatch_queue = None
        return self._connection

    async def _declare_topology(self, channel: aio_pika.abc.AbstractChannel) -> None:
        dlx = await channel.declare_exchange(
            DLX_EXCHANGE,
            ExchangeType.DIRECT,
            durable=True,
        )
        dlq = await channel.declare_queue(DLQ_QUEUE, durable=True)
        await dlq.bind(dlx, routing_key=DLQ_ROUTING_KEY)

        self._exchange = await channel.declare_exchange(
            EVENTS_EXCHANGE,
            ExchangeType.TOPIC,
            durable=True,
        )
        self._dispatch_queue = await channel.declare_queue(
            DISPATCH_QUEUE,
            durable=True,
            arguments={
                "x-dead-letter-exchange": DLX_EXCHANGE,
                "x-dead-letter-routing-key": DLQ_ROUTING_KEY,
            },
        )
        await self._dispatch_queue.bind(self._exchange, routing_key="scan.job.#")

    async def _ensure_pub_channel(self) -> aio_pika.abc.AbstractExchange:
        conn = await self._ensure_connection()
        if self._pub_channel is None or self._pub_channel.is_closed or self._exchange is None:
            self._pub_channel = await conn.channel(publisher_confirms=True)
            await self._declare_topology(self._pub_channel)
        if self._exchange is None:
            raise RuntimeError("RabbitMQ events exchange is not initialized")
        return self._exchange

    async def _ensure_sub_queue(self) -> aio_pika.abc.AbstractQueue:
        conn = await self._ensure_connection()
        if self._sub_channel is None or self._sub_channel.is_closed or self._dispatch_queue is None:
            self._sub_channel = await conn.channel(publisher_confirms=False)
            await self._sub_channel.set_qos(prefetch_count=self._prefetch_count)
            await self._declare_topology(self._sub_channel)
        if self._dispatch_queue is None:
            raise RuntimeError("RabbitMQ dispatch queue is not initialized")
        return self._dispatch_queue

    async def connect(self) -> None:
        await self._ensure_pub_channel()

    async def ensure_topology(self) -> None:
        await self._ensure_pub_channel()

    async def close(self) -> None:
        if self._sub_channel is not None and not self._sub_channel.is_closed:
            await self._sub_channel.close()
        if self._pub_channel is not None and not self._pub_channel.is_closed:
            await self._pub_channel.close()
        if self._connection is not None and not self._connection.is_closed:
            await self._connection.close()
        self._sub_channel = None
        self._pub_channel = None
        self._connection = None
        self._exchange = None
        self._dispatch_queue = None

    async def publish(
        self,
        *,
        routing_key: str,
        payload: dict[str, Any],
        message_id: str,
        correlation_id: str | None = None,
    ) -> None:
        exchange = await self._ensure_pub_channel()
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        message = Message(
            body=body,
            content_type="application/json",
            delivery_mode=DeliveryMode.PERSISTENT,
            message_id=message_id,
            correlation_id=correlation_id or "",
        )
        await exchange.publish(message, routing_key=routing_key, mandatory=True)

    async def consume_dispatch(
        self,
        handler: Callable[[dict[str, Any]], Awaitable[bool]],
    ) -> str:
        """Start consuming dispatch messages and ack/nack based on handler result."""
        dispatch_queue = await self._ensure_sub_queue()

        async def _on_message(msg: AbstractIncomingMessage) -> None:
            try:
                payload = json.loads(msg.body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                logger.warning("rejecting_malformed_broker_message type=%s", type(exc).__name__)
                await msg.reject(requeue=False)
                return

            if not isinstance(payload, dict):
                logger.warning("rejecting_non_object_broker_message")
                await msg.reject(requeue=False)
                return

            try:
                ok = await handler(payload)
                if ok:
                    await msg.ack()
                else:
                    await asyncio.sleep(0.1)
                    await msg.nack(requeue=True)
            except Exception as exc:  # noqa: BLE001
                logger.error("broker_message_transient_error type=%s", type(exc).__name__)
                await asyncio.sleep(0.1)
                await msg.nack(requeue=True)

        return await dispatch_queue.consume(_on_message)
