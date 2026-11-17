---
name: viper-kafka-rabbitmq-queue
description: Event Streaming & Message Queue Security Auditor (Kafka, RabbitMQ, Celery, BullMQ, SQS). Reviews SASL/mTLS broker auth, topic ACLs, poison messages, and task serialization.
---

# ViperClaw Skill 53: Kafka, RabbitMQ & Background Queue Security Auditor (`viper-kafka-rabbitmq-queue`)

## 1. Standards & Open-Source Reference
- **Standards:** Apache Kafka Security Guide, RabbitMQ Production Checklist, Celery Security Advisory (Pickle RCE).
- **Focus:** Auditing asynchronous message brokers, event-driven schemas, and background worker consumers.

## 2. Rapid Discovery Patterns
- Search for `CELERY_ACCEPT_CONTENT`, `task_serializer`, `security.protocol=PLAINTEXT`, `auto.offset.reset`, `ack(`, `nack(requeue=True)`.

## 3. Technical Audit Checklist
1. **Celery / Worker Safe Serialization (`json` Only):** In Celery, verify `task_serializer = "json"`, `result_serializer = "json"`, and `accept_content = ["json"]`—never allow `"pickle"`, `"yaml"`, or `"marshal"` on broker queues.
2. **Broker Transport Encryption & SASL/mTLS Auth:** Reject `security.protocol=PLAINTEXT` in Kafka and default `guest:guest` credentials in RabbitMQ; enforce `SASL_SSL` / `mTLS` and per-service topic/vhost ACLs (producers can only write to their topic; consumers can only read).
3. **Poison-Pill Message & Infinite Requeue Loop Defense:** Consumers that call `channel.basic_nack(requeue=True)` on malformed messages without a retry counter cause instant infinite-loop DoS. Enforce schema validation + max retries (e.g., `x-delivery-count <= 3`) routing to a Dead-Letter Queue (DLQ).
4. **Consumer Idempotency & Replay Deduplication:** Because message queues guarantee at-least-once delivery, consumers executing financial/email/state actions must record `event_id` in an atomic idempotency table.
5. **Event Payload Envelope Signing / Tenant Binding:** Never trust an unverified `tenant_id` or `user_id` field inside a shared queue message without validating its producer identity or HMAC/JWS envelope.

## 4. Vulnerable vs. Hardened Pattern
```python
# ❌ VULNERABLE: Celery accepts pickle payloads & retries poison messages infinitely
app.conf.accept_content = ["pickle", "json"]

# ✅ HARDENED: Strict JSON-only serialization & bounded retry with DLQ
app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)
```
