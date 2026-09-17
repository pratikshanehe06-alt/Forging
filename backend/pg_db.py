"""
Postgres/TimescaleDB-backed replacement for Motor (MongoDB async driver).

Goal: let server.py keep calling `db.assets.find_one(...)`, `db.users.insert_one(...)`,
`db.telemetry.find(...).sort(...).to_list(...)` etc. almost unchanged, while the
actual storage is PostgreSQL (generic collections as JSONB tables) and
TimescaleDB (telemetry as a real hypertable).

Covers the query patterns actually used in server.py:
  - equality filters:      {"tenant_id": "abc"}
  - $gte / $lte:            {"ts": {"$gte": cutoff}}
  - $in:                    {"id": {"$in": [...]}}
  - $ne:                    {"active": {"$ne": True}}
  - $regex (case-insens.):  {"name": {"$regex": q, "$options": "i"}}
  - $set updates:           {"$set": {"status": "RUNNING"}}
  - projections (find_one(filter, {"_id": 0, "password": 0})) — "_id" is a
    no-op (Postgres has no such field); other excluded keys are stripped
    from the returned dict.
  - .sort(field, 1|-1).to_list(n)
  - .count_documents(filter)

Install: pip install asyncpg
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import asyncpg

# Collections stored as generic JSONB tables (everything except telemetry)
JSON_COLLECTIONS = {
    "tenants", "users", "plants", "areas", "lines", "assets", "alarms",
    "maintenance_records", "downtime_events", "energy_records",
    "production_log", "escalations", "audit_logs", "report_templates",
    "tenant_modules",
}


def _build_where(filter: Dict[str, Any], params: List[Any]) -> str:
    """Translate a Mongo-style filter dict into a SQL WHERE clause on `data`."""
    if not filter:
        return "TRUE"
    clauses = []
    for key, value in filter.items():
        if isinstance(value, dict):
            for op, opval in value.items():
                if op == "$gte":
                    params.append(str(opval))
                    clauses.append(f"(data->>'{key}') >= ${len(params)}")
                elif op == "$lte":
                    params.append(str(opval))
                    clauses.append(f"(data->>'{key}') <= ${len(params)}")
                elif op == "$in":
                    params.append([str(v) for v in opval])
                    clauses.append(f"(data->>'{key}') = ANY(${len(params)})")
                elif op == "$ne":
                    params.append(str(opval))
                    clauses.append(
                        f"(data->>'{key}' IS DISTINCT FROM ${len(params)})"
                    )
                elif op == "$regex":
                    params.append(f"%{opval}%")
                    clauses.append(f"(data->>'{key}') ILIKE ${len(params)}")
                elif op == "$options":
                    continue  # handled alongside $regex
                else:
                    raise NotImplementedError(f"Unsupported operator: {op}")
        else:
            params.append(json.dumps(value) if isinstance(value, bool) else str(value))
            if isinstance(value, bool):
                clauses.append(f"(data->'{key}') = ${len(params)}::jsonb")
            else:
                clauses.append(f"(data->>'{key}') = ${len(params)}")
    return " AND ".join(clauses)


def _apply_projection(doc: Dict[str, Any], projection: Optional[Dict[str, int]]) -> Dict[str, Any]:
    if not projection:
        return doc
    excluded = {k for k, v in projection.items() if v == 0 and k != "_id"}
    return {k: v for k, v in doc.items() if k not in excluded}


class _Cursor:
    """Mimics motor's cursor: supports .sort(field, direction).to_list(n)."""

    def __init__(self, pool: asyncpg.Pool, table: str, filter: Dict[str, Any], projection: Optional[Dict[str, int]] = None):
        self.pool = pool
        self.table = table
        self.filter = filter
        self.projection = projection
        self._sort_field: Optional[str] = None
        self._sort_dir: int = 1

    def sort(self, field: str, direction: int = 1) -> "_Cursor":
        self._sort_field = field
        self._sort_dir = direction
        return self

    async def to_list(self, length: Optional[int] = None) -> List[Dict[str, Any]]:
        params: List[Any] = []
        where = _build_where(self.filter, params)
        sql = f"SELECT data FROM {self.table} WHERE {where}"
        if self._sort_field:
            direction = "DESC" if self._sort_dir == -1 else "ASC"
            sql += f" ORDER BY (data->>'{self._sort_field}') {direction}"
        if length:
            sql += f" LIMIT {int(length)}"
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
        return [_apply_projection(json.loads(r["data"]), self.projection) for r in rows]

    def __aiter__(self):
        # Support `async for doc in db.collection.find(...)`
        self._iter_cache: Optional[List[Dict[str, Any]]] = None
        return self

    async def __anext__(self):
        if self._iter_cache is None:
            self._iter_cache = await self.to_list()
            self._idx = 0
        if self._idx >= len(self._iter_cache):
            raise StopAsyncIteration
        doc = self._iter_cache[self._idx]
        self._idx += 1
        return doc


class _Result:
    def __init__(self, matched: int = 0, deleted: int = 0):
        self.matched_count = matched
        self.modified_count = matched
        self.deleted_count = deleted


class Collection:
    def __init__(self, pool: asyncpg.Pool, name: str):
        self.pool = pool
        self.name = name

    async def find_one(
        self, filter: Dict[str, Any] = None, projection: Optional[Dict[str, int]] = None, sort=None
    ) -> Optional[Dict[str, Any]]:
        filter = filter or {}
        params: List[Any] = []
        where = _build_where(filter, params)
        sql = f"SELECT data FROM {self.name} WHERE {where}"
        if sort:
            field, direction = sort[0]
            order = "DESC" if direction == -1 else "ASC"
            sql += f" ORDER BY (data->>'{field}') {order}"
        sql += " LIMIT 1"
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(sql, *params)
        if not row:
            return None
        return _apply_projection(json.loads(row["data"]), projection)

    def find(self, filter: Dict[str, Any] = None, projection: Optional[Dict[str, int]] = None) -> _Cursor:
        return _Cursor(self.pool, self.name, filter or {}, projection)

    async def insert_one(self, doc: Dict[str, Any]) -> None:
        doc_id = str(doc.get("id"))
        async with self.pool.acquire() as conn:
            await conn.execute(
                f"INSERT INTO {self.name} (id, data) VALUES ($1, $2::jsonb) "
                f"ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data",
                doc_id, json.dumps(doc),
            )

    async def insert_many(self, docs: List[Dict[str, Any]]) -> None:
        for doc in docs:
            await self.insert_one(doc)

    async def update_one(self, filter: Dict[str, Any], update: Dict[str, Any], upsert: bool = False) -> _Result:
        set_values = update.get("$set", {})
        unset_keys = update.get("$unset", {})
        params: List[Any] = []
        where = _build_where(filter, params)
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                f"SELECT id, data FROM {self.name} WHERE {where} LIMIT 1", *params
            )
            if not row:
                if upsert:
                    doc = {k: v for k, v in filter.items() if not isinstance(v, dict)}
                    doc.update(set_values)
                    if "id" not in doc:
                        import uuid as _uuid
                        doc["id"] = str(_uuid.uuid4())
                    await self.insert_one(doc)
                return _Result(matched=0)
            doc = json.loads(row["data"])
            doc.update(set_values)
            for k in unset_keys:
                doc.pop(k, None)
            await conn.execute(
                f"UPDATE {self.name} SET data = $1::jsonb WHERE id = $2",
                json.dumps(doc), row["id"],
            )
            return _Result(matched=1)

    async def delete_one(self, filter: Dict[str, Any]) -> _Result:
        params: List[Any] = []
        where = _build_where(filter, params)
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(f"SELECT id FROM {self.name} WHERE {where} LIMIT 1", *params)
            if row:
                await conn.execute(f"DELETE FROM {self.name} WHERE id = $1", row["id"])
                return _Result(deleted=1)
            return _Result(deleted=0)

    async def delete_many(self, filter: Dict[str, Any]) -> _Result:
        params: List[Any] = []
        where = _build_where(filter, params)
        async with self.pool.acquire() as conn:
            result = await conn.execute(f"DELETE FROM {self.name} WHERE {where}", *params)
        try:
            count = int(result.split()[-1])
        except Exception:
            count = 0
        return _Result(deleted=count)

    async def count_documents(self, filter: Dict[str, Any] = None) -> int:
        filter = filter or {}
        params: List[Any] = []
        where = _build_where(filter, params)
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(f"SELECT COUNT(*) AS c FROM {self.name} WHERE {where}", *params)
        return row["c"]


class TelemetryCollection:
    """Special-cased: telemetry is a real hypertable with typed columns,
    not a JSONB blob table, for query performance on high-volume writes."""

    COLUMNS = [
        "ts", "asset_id", "tenant_id", "asset_code", "machine_status",
        "temperature", "vibration", "pressure", "rpm", "voltage", "current",
        "flow", "power", "energy", "production_count", "good_count",
        "reject_count", "alarm", "alarm_message",
    ]

    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def insert_one(self, doc: Dict[str, Any]) -> None:
        cols = [c for c in self.COLUMNS if c in doc]
        placeholders = ", ".join(f"${i+1}" for i in range(len(cols)))
        values = [doc[c] for c in cols]
        async with self.pool.acquire() as conn:
            await conn.execute(
                f"INSERT INTO telemetry ({', '.join(cols)}) VALUES ({placeholders})",
                *values,
            )

    async def find_one(
        self, filter: Dict[str, Any] = None, projection: Optional[Dict[str, int]] = None, sort=None
    ) -> Optional[Dict[str, Any]]:
        filter = filter or {}
        conds, params = [], []
        for k, v in filter.items():
            params.append(v)
            conds.append(f"{k} = ${len(params)}")
        where = " AND ".join(conds) if conds else "TRUE"
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                f"SELECT * FROM telemetry WHERE {where} ORDER BY ts DESC LIMIT 1", *params
            )
        if not row:
            return None
        doc = dict(row)
        doc["ts"] = doc["ts"].isoformat()
        return doc

    def find(self, filter: Dict[str, Any] = None, projection: Optional[Dict[str, int]] = None) -> "_TelemetryCursor":
        return _TelemetryCursor(self.pool, filter or {}, projection)

    async def count_documents(self, filter: Dict[str, Any] = None) -> int:
        filter = filter or {}
        conds, params = [], []
        for k, v in filter.items():
            if isinstance(v, dict):
                continue  # rarely used on telemetry; extend if needed
            params.append(v)
            conds.append(f"{k} = ${len(params)}")
        where = " AND ".join(conds) if conds else "TRUE"
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(f"SELECT COUNT(*) AS c FROM telemetry WHERE {where}", *params)
        return row["c"]


class _TelemetryCursor:
    def __init__(self, pool: asyncpg.Pool, filter: Dict[str, Any], projection: Optional[Dict[str, int]] = None):
        self.pool = pool
        self.filter = filter
        self.projection = projection
        self._sort_field = None
        self._sort_dir = 1

    def sort(self, field: str, direction: int = 1) -> "_TelemetryCursor":
        self._sort_field = field
        self._sort_dir = direction
        return self

    async def to_list(self, length: Optional[int] = None) -> List[Dict[str, Any]]:
        conds, params = [], []
        for k, v in self.filter.items():
            if isinstance(v, dict):
                for op, opval in v.items():
                    params.append(opval)
                    if op == "$gte":
                        conds.append(f"{k} >= ${len(params)}")
                    elif op == "$lte":
                        conds.append(f"{k} <= ${len(params)}")
            else:
                params.append(v)
                conds.append(f"{k} = ${len(params)}")
        where = " AND ".join(conds) if conds else "TRUE"
        sql = f"SELECT * FROM telemetry WHERE {where}"
        if self._sort_field:
            direction = "DESC" if self._sort_dir == -1 else "ASC"
            sql += f" ORDER BY {self._sort_field} {direction}"
        if length:
            sql += f" LIMIT {int(length)}"
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
        out = []
        for r in rows:
            d = dict(r)
            d["ts"] = d["ts"].isoformat()
            d = _apply_projection(d, self.projection)
            out.append(d)
        return out


class PostgresDB:
    """Drop-in replacement for `db = client[DB_NAME]` (Motor database object)."""

    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool
        self.telemetry = TelemetryCollection(pool)
        for name in JSON_COLLECTIONS:
            setattr(self, name, Collection(pool, name))

    def __getitem__(self, name: str):
        return getattr(self, name)


async def create_pool(dsn: str) -> asyncpg.Pool:
    return await asyncpg.create_pool(dsn, min_size=1, max_size=10)