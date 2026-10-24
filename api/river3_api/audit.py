"""Tamper-evident audit log.

hash_n = SHA-256( prev_hash | seq | ts | actor | action | target | canonical-json(detail) )

Appends lock the single audit_head row (SELECT ... FOR UPDATE on PostgreSQL), so two
concurrent writers can't fork the chain. On SQLite, writes are serialized by the database
and by a process lock.
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import AuditHead, AuditLog, now

GENESIS = "0" * 64
_lock = threading.Lock()


def _canon_ts(ts: datetime) -> str:
    if ts.tzinfo is None:  # SQLite returns naive datetimes; values are stored as UTC
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _digest(prev: str, seq: int, ts: datetime, actor: str, action: str, target: str, detail: dict) -> str:
    parts = [prev, str(seq), _canon_ts(ts), actor, action, target,
             json.dumps(detail, sort_keys=True, separators=(",", ":"), default=str)]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def append(db: Session, actor: str, action: str, target: str, **detail: Any) -> AuditLog:
    """Adds an audit row to the current transaction. Caller commits."""
    with _lock:
        head = db.get(AuditHead, 1, with_for_update=True)
        if head is None:
            head = AuditHead(id=1, seq=0, hash=GENESIS)
            db.add(head)
            db.flush()
        seq = head.seq + 1
        ts = now()
        clean = json.loads(json.dumps(detail, default=str))
        h = _digest(head.hash, seq, ts, actor, action, target, clean)
        row = AuditLog(seq=seq, ts=ts, actor=actor, action=action, target=target,
                       detail=clean, prev_hash=head.hash, hash=h)
        db.add(row)
        head.seq, head.hash = seq, h
        db.flush()
        return row


def verify_chain(db: Session) -> dict[str, Any]:
    prev, count = GENESIS, 0
    for row in db.scalars(select(AuditLog).order_by(AuditLog.seq)):
        count += 1
        if row.seq != count:
            return {"ok": False, "checked": count, "broken_at": row.seq, "problem": "missing or reordered row"}
        if row.prev_hash != prev:
            return {"ok": False, "checked": count, "broken_at": row.seq, "problem": "previous hash mismatch"}
        if _digest(prev, row.seq, row.ts, row.actor, row.action, row.target, row.detail) != row.hash:
            return {"ok": False, "checked": count, "broken_at": row.seq, "problem": "row contents changed"}
        prev = row.hash
    head = db.get(AuditHead, 1)
    if head and (head.seq != count or head.hash != prev):
        return {"ok": False, "checked": count, "broken_at": count, "problem": "rows deleted from the end"}
    return {"ok": True, "checked": count, "head": prev}
