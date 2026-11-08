"""
Stigmergic Attack Surface Knowledge Graph (`viperclaw.core.graph`).

Synthesizes the best graph & swarm memory ideas from modern AI pentesting research:
- Zero-setup SQLite persistence (no mandatory Neo4j/Postgres container overhead).
- Stigmergic Pheromone Weighting: anomalies, high-value parameters, dangerous sinks,
  and unauthenticated differentials automatically boost node pheromone scores so
  parallel subagents converge on the highest-impact attack paths first.
- Native export to Mermaid flowcharts and JSON for agent context injection.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


VALID_NODE_TYPES = {
    "host",
    "endpoint",
    "parameter",
    "js_bundle",
    "lazy_chunk",
    "auth_role",
    "taint_sink",
    "hypothesis",
    "finding",
}

VALID_EDGE_TYPES = {
    "HOSTS",
    "LOADS_BUNDLE",
    "LOADS_CHUNK",
    "CALLS_ENDPOINT",
    "ACCEPTS_PARAM",
    "FLOWS_TO_SINK",
    "ACCESSED_BY_ROLE",
    "TRIGGERS_HYPOTHESIS",
    "PROVES_FINDING",
    "CHAINS_TO",
}

BASE_PHEROMONE_BY_TYPE: Dict[str, float] = {
    "finding": 10.0,
    "hypothesis": 7.5,
    "taint_sink": 7.0,
    "endpoint": 5.0,
    "parameter": 4.5,
    "lazy_chunk": 4.0,
    "js_bundle": 3.0,
    "auth_role": 3.5,
    "host": 2.0,
}


@dataclass
class GraphNode:
    node_id: str
    node_type: str
    label: str
    pheromone: float = 1.0
    status: str = "untested"
    metadata: Dict[str, Any] = field(default_factory=dict)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relation: str
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AttackGraph:
    """SQLite-backed Stigmergic Attack Surface Knowledge Graph."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id TEXT PRIMARY KEY,
                    node_type TEXT NOT NULL,
                    label TEXT NOT NULL,
                    pheromone REAL NOT NULL DEFAULT 1.0,
                    status TEXT NOT NULL DEFAULT 'untested',
                    metadata TEXT NOT NULL DEFAULT '{}',
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS edges (
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    weight REAL NOT NULL DEFAULT 1.0,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY (source_id, target_id, relation)
                );
                CREATE INDEX IF NOT EXISTS idx_nodes_pheromone ON nodes(pheromone DESC);
                CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(node_type);
                """
            )

    @staticmethod
    def make_id(node_type: str, label: str) -> str:
        digest = hashlib.sha256(f"{node_type}:{label}".encode("utf-8")).hexdigest()[:12]
        return f"{node_type}_{digest}"

    def upsert_node(
        self,
        node_type: str,
        label: str,
        pheromone_boost: float = 0.0,
        status: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        node_id: Optional[str] = None,
    ) -> GraphNode:
        if node_type not in VALID_NODE_TYPES:
            raise ValueError(f"Invalid node_type '{node_type}'. Expected one of {sorted(VALID_NODE_TYPES)}")

        nid = node_id or self.make_id(node_type, label)
        now = time.time()
        existing = self.get_node(nid)

        if existing:
            new_pheromone = round(min(100.0, existing.pheromone + pheromone_boost), 3)
            new_status = status if status is not None else existing.status
            merged_meta = {**existing.metadata, **(metadata or {})}
        else:
            base = BASE_PHEROMONE_BY_TYPE.get(node_type, 1.0)
            new_pheromone = round(min(100.0, base + pheromone_boost), 3)
            new_status = status or "untested"
            merged_meta = metadata or {}

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO nodes (node_id, node_type, label, pheromone, status, metadata, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    pheromone = excluded.pheromone,
                    status = excluded.status,
                    metadata = excluded.metadata,
                    updated_at = excluded.updated_at
                """,
                (nid, node_type, label, new_pheromone, new_status, json.dumps(merged_meta), now),
            )

        return GraphNode(
            node_id=nid,
            node_type=node_type,
            label=label,
            pheromone=new_pheromone,
            status=new_status,
            metadata=merged_meta,
            updated_at=now,
        )

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str = "CALLS_ENDPOINT",
        weight: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GraphEdge:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO edges (source_id, target_id, relation, weight, metadata)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source_id, target_id, relation) DO UPDATE SET
                    weight = excluded.weight,
                    metadata = excluded.metadata
                """,
                (source_id, target_id, relation, weight, json.dumps(metadata or {})),
            )
        return GraphEdge(
            source_id=source_id,
            target_id=target_id,
            relation=relation,
            weight=weight,
            metadata=metadata or {},
        )

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        row = self._conn.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
        if not row:
            return None
        return GraphNode(
            node_id=row["node_id"],
            node_type=row["node_type"],
            label=row["label"],
            pheromone=row["pheromone"],
            status=row["status"],
            metadata=json.loads(row["metadata"]),
            updated_at=row["updated_at"],
        )

    def top_leads(
        self,
        limit: int = 15,
        node_type: Optional[str] = None,
        only_untested: bool = False,
    ) -> List[GraphNode]:
        query = "SELECT * FROM nodes WHERE 1=1"
        params: List[Any] = []
        if node_type:
            query += " AND node_type = ?"
            params.append(node_type)
        if only_untested:
            query += " AND status = 'untested'"
        query += " ORDER BY pheromone DESC, updated_at DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [
            GraphNode(
                node_id=r["node_id"],
                node_type=r["node_type"],
                label=r["label"],
                pheromone=r["pheromone"],
                status=r["status"],
                metadata=json.loads(r["metadata"]),
                updated_at=r["updated_at"],
            )
            for r in rows
        ]

    def decay_pheromones(self, factor: float = 0.9) -> int:
        """Apply stigmergic evaporation so stale false leads decay over time."""
        clamped = max(0.01, min(1.0, float(factor)))
        with self._conn:
            cur = self._conn.execute(
                "UPDATE nodes SET pheromone = ROUND(MAX(0.5, pheromone * ?), 3) WHERE status != 'verified'",
                (clamped,),
            )
            return cur.rowcount

    def summary(self) -> Dict[str, Any]:
        counts = {}
        for row in self._conn.execute("SELECT node_type, COUNT(*) as cnt FROM nodes GROUP BY node_type"):
            counts[row["node_type"]] = row["cnt"]
        edge_count = self._conn.execute("SELECT COUNT(*) as cnt FROM edges").fetchone()["cnt"]
        return {
            "total_nodes": sum(counts.values()),
            "total_edges": edge_count,
            "counts_by_type": counts,
            "top_leads": [n.to_dict() for n in self.top_leads(limit=10)],
        }

    def export_mermaid(self, max_nodes: int = 40) -> str:
        """Render the attack surface graph as a GitHub-compatible Mermaid flowchart."""
        nodes = self.top_leads(limit=max_nodes)
        node_ids = {n.node_id for n in nodes}
        lines = ["flowchart LR"]
        for n in nodes:
            safe_label = n.label.replace('"', "'").replace("\n", " ").replace("\r", " ").replace("`", "'")
            lines.append(f'    {n.node_id}["[{n.node_type.upper()}] {safe_label} (p={n.pheromone})"]')

        edges = self._conn.execute("SELECT * FROM edges").fetchall()
        for e in edges:
            if e["source_id"] in node_ids and e["target_id"] in node_ids:
                safe_rel = str(e["relation"]).replace('"', "'").replace("\n", " ").replace("\r", " ")
                lines.append(f'    {e["source_id"]} -->|"{safe_rel}"| {e["target_id"]}')
        return "\n".join(lines)

    def to_json(self) -> Dict[str, Any]:
        nodes = [n.to_dict() for n in self.top_leads(limit=500)]
        edges = [
            {
                "source_id": r["source_id"],
                "target_id": r["target_id"],
                "relation": r["relation"],
                "weight": r["weight"],
                "metadata": json.loads(r["metadata"]),
            }
            for r in self._conn.execute("SELECT * FROM edges").fetchall()
        ]
        return {"summary": self.summary(), "nodes": nodes, "edges": edges}

    def close(self) -> None:
        self._conn.close()
