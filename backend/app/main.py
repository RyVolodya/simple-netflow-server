import asyncio
import json
import os
import re
import subprocess
import ipaddress
import hashlib
import secrets
import time
import socket
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import psycopg
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
from psycopg.rows import dict_row
from psycopg import sql

DB = os.getenv("DATABASE_URL", "postgresql://netflow:netflow@postgres:5432/netflow")
FLOW_FILE = os.getenv("FLOW_FILE", "/data/flows.jsonl")
DEFAULT_RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))
DEFAULT_RAW_RETENTION_HOURS = int(os.getenv("RAW_RETENTION_HOURS", "12"))
DEFAULT_STATS_RETENTION_HOURS = int(os.getenv("STATS_RETENTION_HOURS", "720"))
VERSION = os.getenv("APP_VERSION", "0.6.2")
DEFAULT_ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "netflow")
SESSION_HOURS = int(os.getenv("SESSION_HOURS", "24"))
IDLE_SECONDS = 300


LIVE_SUBSCRIBERS: set[asyncio.Queue] = set()
SUMMARY_CACHE = {'ts': 0.0, 'hours': None, 'data': None}
EXPORTER_DELETE_JOBS = {}
EXPORTER_DELETE_TASKS = {}

def _job_snapshot(job_id):
    job = EXPORTER_DELETE_JOBS.get(job_id)
    return dict(job) if job else None

def _job_update(job_id, **fields):
    job = EXPORTER_DELETE_JOBS.get(job_id)
    if not job:
        return
    job.update(fields)
    job['updated_at'] = datetime.now(timezone.utc).isoformat()

def _job_fail(job_id, exc):
    detail = getattr(exc, 'detail', None) or str(exc) or exc.__class__.__name__
    _job_update(job_id, status='failed', stage='Failed', error=str(detail), progress=100)


def publish_live_event(payload: dict):
    """Broadcast a lightweight event to all connected SSE clients.

    Queues are intentionally small: the browser refreshes aggregate data from
    PostgreSQL and does not need one UI refresh per flow during bursts.
    """
    dead = []
    for q in list(LIVE_SUBSCRIBERS):
        try:
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(payload)
        except Exception:
            dead.append(q)
    for q in dead:
        LIVE_SUBSCRIBERS.discard(q)

SCHEMA = r"""
CREATE TABLE IF NOT EXISTS exporters (
  ip INET PRIMARY KEY,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  hostname TEXT,
  sys_descr TEXT,
  snmp_enabled BOOLEAN NOT NULL DEFAULT false,
  snmp_version TEXT NOT NULL DEFAULT '2c',
  snmp_community TEXT,
  snmp_port INTEGER NOT NULL DEFAULT 161,
  snmp_last_poll TIMESTAMPTZ,
  snmp_last_error TEXT
);

CREATE TABLE IF NOT EXISTS interfaces (
  id BIGSERIAL PRIMARY KEY,
  exporter INET NOT NULL REFERENCES exporters(ip) ON DELETE CASCADE,
  if_index INTEGER NOT NULL,
  if_name TEXT,
  if_descr TEXT,
  if_alias TEXT,
  if_speed BIGINT,
  admin_status INTEGER,
  oper_status INTEGER,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(exporter, if_index)
);
CREATE INDEX IF NOT EXISTS idx_interfaces_exporter ON interfaces(exporter);

CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


CREATE TABLE IF NOT EXISTS flow_agg_total_1m (
  bucket TIMESTAMPTZ PRIMARY KEY,
  bytes BIGINT NOT NULL DEFAULT 0, packets BIGINT NOT NULL DEFAULT 0, flows BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS flow_agg_src_1m (
  bucket TIMESTAMPTZ NOT NULL, src_addr INET NOT NULL, bytes BIGINT NOT NULL DEFAULT 0, packets BIGINT NOT NULL DEFAULT 0, flows BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY(bucket, src_addr)
);
CREATE INDEX IF NOT EXISTS idx_agg_src_bucket ON flow_agg_src_1m(bucket DESC);
CREATE TABLE IF NOT EXISTS flow_agg_dst_1m (
  bucket TIMESTAMPTZ NOT NULL, dst_addr INET NOT NULL, bytes BIGINT NOT NULL DEFAULT 0, packets BIGINT NOT NULL DEFAULT 0, flows BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY(bucket, dst_addr)
);
CREATE INDEX IF NOT EXISTS idx_agg_dst_bucket ON flow_agg_dst_1m(bucket DESC);
CREATE TABLE IF NOT EXISTS flow_agg_exporter_1m (
  bucket TIMESTAMPTZ NOT NULL, exporter INET NOT NULL, bytes BIGINT NOT NULL DEFAULT 0, packets BIGINT NOT NULL DEFAULT 0, flows BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY(bucket, exporter)
);
CREATE INDEX IF NOT EXISTS idx_agg_exporter_bucket ON flow_agg_exporter_1m(bucket DESC);
CREATE TABLE IF NOT EXISTS flow_agg_app_1m (
  bucket TIMESTAMPTZ NOT NULL, proto INTEGER NOT NULL, port INTEGER NOT NULL, bytes BIGINT NOT NULL DEFAULT 0, packets BIGINT NOT NULL DEFAULT 0, flows BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY(bucket, proto, port)
);
CREATE INDEX IF NOT EXISTS idx_agg_app_bucket ON flow_agg_app_1m(bucket DESC);
CREATE TABLE IF NOT EXISTS flow_agg_interface_1m (
  bucket TIMESTAMPTZ NOT NULL, exporter INET NOT NULL, if_index INTEGER NOT NULL, bytes BIGINT NOT NULL DEFAULT 0, packets BIGINT NOT NULL DEFAULT 0, flows BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY(bucket, exporter, if_index)
);
CREATE INDEX IF NOT EXISTS idx_agg_interface_bucket ON flow_agg_interface_1m(bucket DESC);

CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('administrator','user')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), enabled BOOLEAN NOT NULL DEFAULT true,
  must_change_password BOOLEAN NOT NULL DEFAULT false
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
"""


FLOW_COLUMNS_SQL = """
  id BIGINT NOT NULL DEFAULT nextval('flows_id_seq'),
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  flow_time TIMESTAMPTZ,
  exporter INET,
  flow_type TEXT,
  src_addr INET,
  dst_addr INET,
  src_port INTEGER,
  dst_port INTEGER,
  proto INTEGER,
  bytes BIGINT NOT NULL DEFAULT 0,
  packets BIGINT NOT NULL DEFAULT 0,
  in_if INTEGER,
  out_if INTEGER,
  src_as BIGINT,
  dst_as BIGINT,
  src_country TEXT,
  dst_country TEXT,
  sampling_rate INTEGER,
  tcp_flags INTEGER
"""

OPTIMIZED_FLOW_INDEXES = [
    ("idx_flows_received_at", "received_at DESC"),
    ("idx_flows_exporter", "exporter"),
    ("idx_flows_src", "src_addr"),
    ("idx_flows_dst", "dst_addr"),
    ("idx_flows_proto", "proto"),
    ("idx_flows_exporter_inif", "exporter, in_if"),
    ("idx_flows_exporter_outif", "exporter, out_if"),
]


def _is_partitioned_flows(cur):
    cur.execute("""SELECT EXISTS(
        SELECT 1 FROM pg_partitioned_table pt
        JOIN pg_class c ON c.oid=pt.partrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relname='flows') AS yes""")
    return bool(cur.fetchone()['yes'])


def _partition_name(day):
    return 'flows_' + day.strftime('%Y%m%d')


def ensure_daily_partition(cur, day):
    from datetime import timedelta
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    name = _partition_name(start)
    cur.execute(f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF flows FOR VALUES FROM ('{start.isoformat()}') TO ('{end.isoformat()}')")
    return name


def ensure_future_flow_partitions(days_ahead=2):
    from datetime import timedelta
    with conn() as c, c.cursor() as cur:
        today=datetime.now(timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0)
        for i in range(days_ahead+1):
            ensure_daily_partition(cur, today + timedelta(days=i))


def ensure_partitioned_flows():
    """Create v0.5.2 partitioned raw-flow storage or migrate the legacy table once."""
    from datetime import timedelta
    with psycopg.connect(DB, row_factory=dict_row) as c, c.cursor() as cur:
        cur.execute("CREATE SEQUENCE IF NOT EXISTS flows_id_seq")
        cur.execute("SELECT to_regclass('public.flows') AS reg")
        exists = cur.fetchone()['reg'] is not None
        if exists and _is_partitioned_flows(cur):
            today=datetime.now(timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0)
            for i in range(3): ensure_daily_partition(cur, today+timedelta(days=i))
            for name,cols in OPTIMIZED_FLOW_INDEXES:
                cur.execute(f"CREATE INDEX IF NOT EXISTS {name} ON flows ({cols})")
            c.commit(); return

        if not exists:
            cur.execute(f"CREATE TABLE flows ({FLOW_COLUMNS_SQL}) PARTITION BY RANGE (received_at)")
            today=datetime.now(timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0)
            for i in range(3): ensure_daily_partition(cur, today+timedelta(days=i))
            cur.execute("ALTER SEQUENCE flows_id_seq OWNED BY flows.id")
            for name,cols in OPTIMIZED_FLOW_INDEXES:
                cur.execute(f"CREATE INDEX {name} ON flows ({cols})")
            c.commit(); return

        print('[v0.6.2] Migrating raw flows to daily partitions. This is a one-time operation...', flush=True)
        cur.execute("SELECT count(*)::bigint n,min(received_at) mn,max(received_at) mx FROM flows")
        meta=cur.fetchone(); old_count=int(meta['n'])
        cur.execute("ALTER TABLE flows RENAME TO flows_legacy_052")
        cur.execute("ALTER SEQUENCE flows_id_seq OWNED BY NONE")
        cur.execute(f"CREATE TABLE flows ({FLOW_COLUMNS_SQL}) PARTITION BY RANGE (received_at)")
        if meta['mn'] is not None:
            d=meta['mn'].astimezone(timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0)
            last=meta['mx'].astimezone(timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0)
            while d <= last + timedelta(days=2):
                ensure_daily_partition(cur,d); d += timedelta(days=1)
        else:
            today=datetime.now(timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0)
            for i in range(3): ensure_daily_partition(cur,today+timedelta(days=i))
        cols='id,received_at,flow_time,exporter,flow_type,src_addr,dst_addr,src_port,dst_port,proto,bytes,packets,in_if,out_if,src_as,dst_as,src_country,dst_country,sampling_rate,tcp_flags'
        cur.execute(f"INSERT INTO flows({cols}) SELECT {cols} FROM flows_legacy_052 ORDER BY received_at")
        cur.execute("SELECT count(*)::bigint n FROM flows"); new_count=int(cur.fetchone()['n'])
        if new_count != old_count:
            raise RuntimeError(f'flows migration count mismatch: old={old_count}, new={new_count}')
        cur.execute("SELECT setval('flows_id_seq', GREATEST((SELECT coalesce(max(id),0) FROM flows),1), true)")
        cur.execute("DROP TABLE flows_legacy_052")
        cur.execute("ALTER SEQUENCE flows_id_seq OWNED BY flows.id")
        for name,cols in OPTIMIZED_FLOW_INDEXES:
            cur.execute(f"CREATE INDEX {name} ON flows ({cols})")
        c.commit()
        print(f'[v0.6.2] Partition migration complete: {new_count} flows preserved.', flush=True)


def drop_expired_flow_partitions(cur, raw_hours):
    from datetime import timedelta
    cutoff=datetime.now(timezone.utc)-timedelta(hours=max(1,int(raw_hours)))
    cur.execute("""SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid
                   JOIN pg_class p ON p.oid=i.inhparent
                   WHERE p.relname='flows' ORDER BY c.relname""")
    for row in cur.fetchall():
        name=row['relname']
        m=re.fullmatch(r'flows_(\d{8})',name)
        if not m: continue
        day=datetime.strptime(m.group(1),'%Y%m%d').replace(tzinfo=timezone.utc)
        if day + timedelta(days=1) <= cutoff:
            cur.execute(f'DROP TABLE IF EXISTS {name}')
    cur.execute("DELETE FROM flows WHERE received_at < %s", (cutoff,))


def storage_breakdown():
    agg_tables=['flow_agg_total_1m','flow_agg_src_1m','flow_agg_dst_1m','flow_agg_exporter_1m','flow_agg_app_1m','flow_agg_interface_1m']
    with conn() as c,c.cursor() as cur:
        cur.execute("""SELECT coalesce(sum(pg_relation_size(c.oid)),0)::bigint raw_data,
                              coalesce(sum(pg_indexes_size(c.oid)),0)::bigint raw_indexes,
                              coalesce(sum(pg_total_relation_size(c.oid)),0)::bigint raw_total
                       FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid
                       JOIN pg_class p ON p.oid=i.inhparent WHERE p.relname='flows'""")
        r=cur.fetchone()
        cur.execute("SELECT coalesce(sum(pg_total_relation_size(to_regclass(x))),0)::bigint bytes FROM unnest(%s::text[]) x", (agg_tables,))
        aggs=int(cur.fetchone()['bytes'] or 0)
        cur.execute("SELECT pg_database_size(current_database())::bigint bytes")
        total=int(cur.fetchone()['bytes'])
        return {'raw_data_bytes':int(r['raw_data'] or 0),'raw_index_bytes':int(r['raw_indexes'] or 0),
                'raw_total_bytes':int(r['raw_total'] or 0),'aggregates_bytes':aggs,'database_bytes':total}

COMMON_APPS = {
    (6, 20): "FTP Data", (6, 21): "FTP", (6, 22): "SSH", (6, 23): "Telnet",
    (6, 25): "SMTP", (17, 53): "DNS", (6, 53): "DNS", (17, 67): "DHCP",
    (17, 68): "DHCP", (6, 80): "HTTP", (17, 123): "NTP", (6, 110): "POP3",
    (6, 143): "IMAP", (17, 161): "SNMP", (17, 162): "SNMP Trap", (6, 443): "HTTPS",
    (17, 500): "IKE", (6, 445): "SMB", (17, 514): "Syslog", (6, 993): "IMAPS",
    (6, 995): "POP3S", (17, 1194): "OpenVPN", (6, 1433): "MSSQL", (6, 3306): "MySQL",
    (6, 3389): "RDP", (6, 5432): "PostgreSQL", (6, 6379): "Redis", (6, 8000): "HTTP-alt",
    (6, 8080): "HTTP-alt", (6, 8443): "HTTPS-alt", (17, 51820): "WireGuard"
}


def conn():
    return psycopg.connect(DB, row_factory=dict_row, autocommit=True)


def ip_from(v):
    if v in (None, "", "AAAAAA=="):
        return None
    text = str(v).strip()
    try:
        # GoFlow/PostgreSQL may represent host addresses as IPv4/32 or IPv6/128.
        # Store and expose only the host address so SNMP receives a valid target.
        return str(ipaddress.ip_interface(text).ip) if "/" in text else str(ipaddress.ip_address(text))
    except ValueError:
        return text.split("/", 1)[0]


def normalize_host(v):
    if v is None:
        return None
    text = str(v).strip()
    try:
        return str(ipaddress.ip_interface(text).ip) if "/" in text else str(ipaddress.ip_address(text))
    except ValueError:
        return text.split("/", 1)[0]


def as_int(v):
    try:
        return int(v)
    except Exception:
        return None


def ns_to_dt(v):
    try:
        n = int(v or 0)
        if n <= 0:
            return None
        return datetime.fromtimestamp(n / 1_000_000_000, tz=timezone.utc)
    except Exception:
        return None


PROTOCOL_NUMBERS = {
    "ICMP": 1,
    "IGMP": 2,
    "IPIP": 4,
    "TCP": 6,
    "EGP": 8,
    "IGP": 9,
    "UDP": 17,
    "IPv6": 41,
    "IPV6": 41,
    "IPv6-Route": 43,
    "IPV6-ROUTE": 43,
    "IPv6-Frag": 44,
    "IPV6-FRAG": 44,
    "GRE": 47,
    "ESP": 50,
    "AH": 51,
    "ICMPv6": 58,
    "ICMPV6": 58,
    "IPv6-ICMP": 58,
    "IPV6-ICMP": 58,
    "OSPF": 89,
    "SCTP": 132,
}


def parse_protocol(value):
    """Normalize GoFlow2 JSON protocol values to the IANA IP protocol number.

    GoFlow2 JSON normally serializes the protobuf enum as a protocol name
    (for example "TCP"), while older/other producers may emit 6.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 10)
    except ValueError:
        pass
    # Accept canonical GoFlow2 names as well as common spelling variants.
    if text in PROTOCOL_NUMBERS:
        return PROTOCOL_NUMBERS[text]
    upper = text.upper().replace("_", "-")
    aliases = {k.upper().replace("_", "-"): v for k, v in PROTOCOL_NUMBERS.items()}
    return aliases.get(upper)


def protocol_name(proto):
    proto = parse_protocol(proto)
    return {1: "ICMP", 2: "IGMP", 4: "IPIP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"}.get(proto, f"IP/{proto}" if proto is not None else "Unknown")


def app_name(proto, port):
    proto = parse_protocol(proto)
    port = as_int(port)
    if not port:
        return f"Other · {protocol_name(proto)}"
    p = protocol_name(proto)
    name = COMMON_APPS.get((proto, port))
    if name:
        return f"{name} · {p}/{port}"
    return f"{p}/{port}"


def ensure_exporter(cur, exporter):
    if not exporter:
        return
    cur.execute(
        """INSERT INTO exporters(ip, first_seen, last_seen) VALUES (%s, now(), now())
           ON CONFLICT (ip) DO UPDATE SET last_seen=excluded.last_seen""",
        (exporter,),
    )


def normalize_flow(d):
    now = datetime.now(timezone.utc)
    return {
        "received_at": now,
        "flow_time": ns_to_dt(d.get("time_flow_start_ns") or d.get("time_received_ns")),
        "exporter": ip_from(d.get("sampler_address")),
        "flow_type": str(d.get("type", "")),
        "src_addr": ip_from(d.get("src_addr")),
        "dst_addr": ip_from(d.get("dst_addr")),
        "src_port": as_int(d.get("src_port")),
        "dst_port": as_int(d.get("dst_port")),
        "proto": parse_protocol(d.get("proto")),
        "bytes": as_int(d.get("bytes")) or 0,
        "packets": as_int(d.get("packets")) or 0,
        "in_if": as_int(d.get("in_if")),
        "out_if": as_int(d.get("out_if")),
        "src_as": as_int(d.get("src_as")),
        "dst_as": as_int(d.get("dst_as")),
        "src_country": d.get("src_country"),
        "dst_country": d.get("dst_country"),
        "sampling_rate": as_int(d.get("sampling_rate")),
        "tcp_flags": as_int(d.get("tcp_flags")),
    }


def _bucket_minute(dt):
    return dt.replace(second=0, microsecond=0)


def insert_flow_batch(rows):
    if not rows:
        return 0
    total = defaultdict(lambda: [0,0,0])
    src = defaultdict(lambda: [0,0,0])
    dst = defaultdict(lambda: [0,0,0])
    exp = defaultdict(lambda: [0,0,0])
    appagg = defaultdict(lambda: [0,0,0])
    iface = defaultdict(lambda: [0,0,0])
    exporters_seen = set()
    for r in rows:
        b=_bucket_minute(r["received_at"]); vals=(r["bytes"],r["packets"],1)
        for store,key in [(total,b)]:
            a=store[key]; a[0]+=vals[0]; a[1]+=vals[1]; a[2]+=1
        if r["src_addr"]:
            a=src[(b,r["src_addr"])]; a[0]+=vals[0]; a[1]+=vals[1]; a[2]+=1
        if r["dst_addr"]:
            a=dst[(b,r["dst_addr"])]; a[0]+=vals[0]; a[1]+=vals[1]; a[2]+=1
        if r["exporter"]:
            exporters_seen.add(r["exporter"]); a=exp[(b,r["exporter"])]; a[0]+=vals[0]; a[1]+=vals[1]; a[2]+=1
            for idx in {r.get("in_if"), r.get("out_if")} - {None}:
                a=iface[(b,r["exporter"],idx)]; a[0]+=vals[0]; a[1]+=vals[1]; a[2]+=1
        proto=r.get("proto")
        port=r.get("dst_port") if (r.get("dst_port") or 0) in range(1,49152) else r.get("src_port")
        if proto is not None and port is not None:
            a=appagg[(b,proto,int(port))]; a[0]+=vals[0]; a[1]+=vals[1]; a[2]+=1
    copy_cols = ("received_at","flow_time","exporter","flow_type","src_addr","dst_addr","src_port","dst_port","proto","bytes","packets","in_if","out_if","src_as","dst_as","src_country","dst_country","sampling_rate","tcp_flags")
    with psycopg.connect(DB, row_factory=dict_row) as c, c.cursor() as cur:
        with cur.copy("COPY flows(received_at,flow_time,exporter,flow_type,src_addr,dst_addr,src_port,dst_port,proto,bytes,packets,in_if,out_if,src_as,dst_as,src_country,dst_country,sampling_rate,tcp_flags) FROM STDIN") as cp:
            for r in rows:
                cp.write_row(tuple(r.get(k) for k in copy_cols))
        if exporters_seen:
            cur.executemany("""INSERT INTO exporters(ip,first_seen,last_seen) VALUES(%s::inet,now(),now())
                               ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen""", [(x,) for x in exporters_seen])
        def upsert(table, cols, data):
            if not data: return
            keys=list(data.keys())
            vals=[]
            for k in keys:
                kt=k if isinstance(k,tuple) else (k,)
                v=data[k]; vals.append((*kt,*v))
            keycols=','.join(cols); placeholders=','.join(['%s']*(len(cols)+3))
            conflict=','.join(cols)
            cur.executemany(f"INSERT INTO {table}({keycols},bytes,packets,flows) VALUES({placeholders}) ON CONFLICT({conflict}) DO UPDATE SET bytes={table}.bytes+excluded.bytes, packets={table}.packets+excluded.packets, flows={table}.flows+excluded.flows", vals)
        upsert('flow_agg_total_1m',['bucket'],total)
        upsert('flow_agg_src_1m',['bucket','src_addr'],src)
        upsert('flow_agg_dst_1m',['bucket','dst_addr'],dst)
        upsert('flow_agg_exporter_1m',['bucket','exporter'],exp)
        upsert('flow_agg_app_1m',['bucket','proto','port'],appagg)
        upsert('flow_agg_interface_1m',['bucket','exporter','if_index'],iface)
        c.commit()
    return len(rows)


def get_setting(key, default=None):
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT value FROM app_settings WHERE key=%s", (key,))
        row = cur.fetchone()
        return row["value"] if row else default


def set_setting(key, value):
    with conn() as c, c.cursor() as cur:
        cur.execute(
            """INSERT INTO app_settings(key,value) VALUES(%s,%s)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=now()""",
            (key, str(value)),
        )


async def spool_ingester():
    path = FLOW_FILE
    while not os.path.exists(path):
        await asyncio.sleep(1)
    try:
        pos = max(0, int(get_setting("flow_spool_offset", 0)))
    except Exception:
        pos = 0
    batch=[]
    last_flush=asyncio.get_running_loop().time()

    async def flush_batch(end_pos):
        nonlocal batch, last_flush, pos
        if batch:
            flushed=batch; batch=[]
            n=await asyncio.to_thread(insert_flow_batch,flushed)
            if n:
                publish_live_event({"type":"flow","count":n,"ts":datetime.now(timezone.utc).isoformat()})
        # Persist the byte offset only after the batch has been committed.
        await asyncio.to_thread(set_setting, "flow_spool_offset", int(end_pos))
        pos=int(end_pos)
        last_flush=asyncio.get_running_loop().time()

    while True:
        try:
            size=os.path.getsize(path)
            if size < pos:
                pos=0
                await asyncio.to_thread(set_setting, "flow_spool_offset", 0)
            with open(path,'r',encoding='utf-8',errors='ignore') as f:
                f.seek(pos)
                while True:
                    line=f.readline()
                    if not line: break
                    line_end=f.tell()
                    try:
                        batch.append(normalize_flow(json.loads(line)))
                    except Exception:
                        # Malformed lines are considered consumed so a restart does not loop forever.
                        await asyncio.to_thread(set_setting, "flow_spool_offset", int(line_end))
                        pos=line_end
                        continue
                    now=asyncio.get_running_loop().time()
                    if len(batch)>=500 or now-last_flush>=0.5:
                        await flush_batch(line_end)
                # Commit any tail batch at EOF. This keeps the persisted offset and DB contents
                # in sync and prevents re-reading uncommitted lines on the next loop.
                if batch:
                    await flush_batch(f.tell())
        except Exception:
            pass
        await asyncio.sleep(0.2)


async def retention_worker():
    while True:
        try:
            old=int(get_setting('retention_hours', int(get_setting('retention_days', DEFAULT_RETENTION_DAYS))*24))
            raw_hours=max(1,int(get_setting('raw_retention_hours', DEFAULT_RAW_RETENTION_HOURS)))
            stats_hours=max(6,int(get_setting('stats_retention_hours', DEFAULT_STATS_RETENTION_HOURS)))
            await asyncio.to_thread(ensure_future_flow_partitions, 2)
            with conn() as c, c.cursor() as cur:
                drop_expired_flow_partitions(cur, raw_hours)
                for table in ['flow_agg_total_1m','flow_agg_src_1m','flow_agg_dst_1m','flow_agg_exporter_1m','flow_agg_app_1m','flow_agg_interface_1m']:
                    cur.execute(f"DELETE FROM {table} WHERE bucket < now() - (%s || ' hours')::interval", (stats_hours,))
                cur.execute("DELETE FROM sessions WHERE expires_at < now()")
                SUMMARY_CACHE['data']=None
        except Exception as e:
            print(f'[v0.6.2] retention error: {e}', flush=True)
        await asyncio.sleep(3600)


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    iterations = 200_000
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations).hex()
    return f"pbkdf2_sha256${iterations}${salt}${digest}"


def verify_password(password, stored):
    try:
        algo,it,salt,digest=stored.split('$',3)
        calc=hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), int(it)).hex()
        return secrets.compare_digest(calc,digest)
    except Exception:
        return False


def session_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def authenticate_session(token):
    if not token: return None
    with conn() as c, c.cursor() as cur:
        cur.execute("""SELECT u.id,u.username,u.role,u.must_change_password FROM sessions s JOIN users u ON u.id=s.user_id
                       WHERE s.token_hash=%s AND s.expires_at>now() AND u.enabled=true""", (session_hash(token),))
        return cur.fetchone()


def rebuild_aggregates(force=False):
    with psycopg.connect(DB, row_factory=dict_row) as c, c.cursor() as cur:
        cur.execute("SELECT EXISTS(SELECT 1 FROM flow_agg_total_1m) has")
        if cur.fetchone()['has'] and not force: return
        if force:
            cur.execute("TRUNCATE flow_agg_total_1m,flow_agg_src_1m,flow_agg_dst_1m,flow_agg_exporter_1m,flow_agg_app_1m,flow_agg_interface_1m")
        print('[v0.6.2] Building 1-minute dashboard aggregates from existing flows...', flush=True)
        cur.execute("SELECT EXISTS(SELECT 1 FROM flows) has")
        if not cur.fetchone()['has']: return
        cur.execute("""INSERT INTO flow_agg_total_1m(bucket,bytes,packets,flows)
                       SELECT date_trunc('minute',received_at),sum(bytes),sum(packets),count(*) FROM flows GROUP BY 1""")
        cur.execute("""INSERT INTO flow_agg_src_1m(bucket,src_addr,bytes,packets,flows)
                       SELECT date_trunc('minute',received_at),src_addr,sum(bytes),sum(packets),count(*) FROM flows WHERE src_addr IS NOT NULL GROUP BY 1,2""")
        cur.execute("""INSERT INTO flow_agg_dst_1m(bucket,dst_addr,bytes,packets,flows)
                       SELECT date_trunc('minute',received_at),dst_addr,sum(bytes),sum(packets),count(*) FROM flows WHERE dst_addr IS NOT NULL GROUP BY 1,2""")
        cur.execute("""INSERT INTO flow_agg_exporter_1m(bucket,exporter,bytes,packets,flows)
                       SELECT date_trunc('minute',received_at),exporter,sum(bytes),sum(packets),count(*) FROM flows WHERE exporter IS NOT NULL GROUP BY 1,2""")
        cur.execute("""INSERT INTO flow_agg_app_1m(bucket,proto,port,bytes,packets,flows)
                       SELECT date_trunc('minute',received_at),proto,CASE WHEN dst_port BETWEEN 1 AND 49151 THEN dst_port WHEN src_port BETWEEN 1 AND 49151 THEN src_port ELSE dst_port END,
                              sum(bytes),sum(packets),count(*) FROM flows
                       WHERE proto IS NOT NULL AND (CASE WHEN dst_port BETWEEN 1 AND 49151 THEN dst_port WHEN src_port BETWEEN 1 AND 49151 THEN src_port ELSE dst_port END) IS NOT NULL GROUP BY 1,2,3""")
        cur.execute("""INSERT INTO flow_agg_interface_1m(bucket,exporter,if_index,bytes,packets,flows)
                       SELECT bucket,exporter,if_index,sum(bytes),sum(packets),sum(flows) FROM (
                         SELECT date_trunc('minute',received_at) bucket,exporter,in_if if_index,sum(bytes) bytes,sum(packets) packets,count(*) flows FROM flows WHERE exporter IS NOT NULL AND in_if IS NOT NULL GROUP BY 1,2,3
                         UNION ALL
                         SELECT date_trunc('minute',received_at),exporter,out_if,sum(bytes),sum(packets),count(*) FROM flows WHERE exporter IS NOT NULL AND out_if IS NOT NULL GROUP BY 1,2,3
                       ) x GROUP BY 1,2,3""")
        c.commit()
        print('[v0.6.2] Dashboard aggregates ready.', flush=True)

def bootstrap_metadata():
    with conn() as c, c.cursor() as cur:
        cur.execute(
            """INSERT INTO exporters(ip, first_seen, last_seen)
               SELECT exporter, min(received_at), max(received_at)
               FROM flows WHERE exporter IS NOT NULL GROUP BY exporter
               ON CONFLICT(ip) DO UPDATE SET
                 first_seen=LEAST(exporters.first_seen, excluded.first_seen),
                 last_seen=GREATEST(exporters.last_seen, excluded.last_seen)"""
        )
        cur.execute(
            "INSERT INTO app_settings(key,value) VALUES('retention_days',%s) ON CONFLICT(key) DO NOTHING",
            (str(DEFAULT_RETENTION_DAYS),),
        )
        cur.execute("SELECT value FROM app_settings WHERE key='retention_days'")
        retention_days_row=cur.fetchone()
        existing_days=int(retention_days_row['value']) if retention_days_row else DEFAULT_RETENTION_DAYS
        cur.execute("INSERT INTO app_settings(key,value) VALUES('retention_hours',%s) ON CONFLICT(key) DO NOTHING", (str(existing_days * 24),))
        cur.execute("SELECT value FROM app_settings WHERE key='retention_hours'"); rh=cur.fetchone(); existing_hours=int(rh['value']) if rh else existing_days*24
        # v0.6.2 defaults for fresh installations. Existing installations keep
        # their saved values because ON CONFLICT does not overwrite them.
        cur.execute("INSERT INTO app_settings(key,value) VALUES('raw_retention_hours',%s) ON CONFLICT(key) DO NOTHING", (str(DEFAULT_RAW_RETENTION_HOURS),))
        cur.execute("INSERT INTO app_settings(key,value) VALUES('stats_retention_hours',%s) ON CONFLICT(key) DO NOTHING", (str(DEFAULT_STATS_RETENTION_HOURS),))
        cur.execute("SELECT 1 FROM users LIMIT 1")
        if not cur.fetchone():
            cur.execute("INSERT INTO users(username,password_hash,role,must_change_password) VALUES(%s,%s,'administrator',true)", (DEFAULT_ADMIN_USER, hash_password(DEFAULT_ADMIN_PASSWORD)))


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialized=False
    last_error=None
    for attempt in range(30):
        try:
            await asyncio.to_thread(ensure_partitioned_flows)
            with conn() as c:
                c.execute(SCHEMA)
            bootstrap_metadata()
            await asyncio.to_thread(rebuild_aggregates, False)
            initialized=True
            break
        except Exception as e:
            last_error=e
            print(f'[v0.6.2] startup attempt {attempt+1}/30 failed: {e}', flush=True)
            await asyncio.sleep(1)
    if not initialized:
        raise RuntimeError(f'v0.6.2 storage initialization failed: {last_error}')
    t1 = asyncio.create_task(spool_ingester())
    t2 = asyncio.create_task(retention_worker())
    yield
    t1.cancel()
    t2.cancel()


app = FastAPI(title="Simple NetFlow Server", version=VERSION, lifespan=lifespan)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path=request.url.path
    if path.startswith('/api/') and path not in ('/api/health','/api/system-status','/api/auth/login'):
        user=authenticate_session(request.cookies.get('snf_session'))
        if not user:
            return JSONResponse({"detail":"Authentication required"}, status_code=401)
        request.state.user=user
        # A first-login password change is mandatory before the rest of the API can be used.
        password_paths=('/api/auth/change-password', '/api/auth/logout', '/api/auth/me')
        if user.get('must_change_password') and path not in password_paths:
            return JSONResponse({"detail":"Password change required", "must_change_password": True}, status_code=428)
        if path.startswith('/api/auth/users') and user['role']!='administrator':
            return JSONResponse({"detail":"Administrator access required"}, status_code=403)
        # Read-only users may change only their own password and log out.
        write_exceptions=('/api/auth/logout','/api/auth/change-password')
        if request.method in ('POST','PUT','PATCH','DELETE') and path not in write_exceptions and user['role']!='administrator':
            return JSONResponse({"detail":"Read-only user"}, status_code=403)
    return await call_next(request)


class LoginRequest(BaseModel):
    username: str
    password: str

class ExporterDeleteRequest(BaseModel):
    exporter: str

class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=6, max_length=128)
    role: str = Field(pattern='^(administrator|user)$')


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=6, max_length=128)

class AdminPasswordReset(BaseModel):
    new_password: str = Field(min_length=6, max_length=128)

class RetentionUpdate(BaseModel):
    days: int = Field(ge=0, le=3650)
    hours: int = Field(ge=0, le=23)

    def total_hours(self):
        total = self.days * 24 + self.hours
        if total < 1:
            raise ValueError('Retention must be at least 1 hour')
        return total


class SnmpUpdate(BaseModel):
    enabled: bool = True
    version: str = "2c"
    community: Optional[str] = Field(default=None, max_length=128)
    port: int = Field(default=161, ge=1, le=65535)


class SnmpConfigRequest(SnmpUpdate):
    exporter: str


class SnmpPollRequest(BaseModel):
    exporter: str


def time_where(hours: Optional[int], date_from: Optional[datetime], date_to: Optional[datetime]):
    clauses = []
    params = []
    if date_from:
        clauses.append("f.received_at >= %s")
        params.append(date_from)
    if date_to:
        clauses.append("f.received_at <= %s")
        params.append(date_to)
    if not date_from and not date_to:
        h = min(max(hours or 24, 1), 24 * 365)
        clauses.append("f.received_at >= now() - (%s || ' hours')::interval")
        params.append(h)
    return clauses, params


@app.post("/api/auth/login")
def login(payload: LoginRequest, response: Response):
    with psycopg.connect(DB, row_factory=dict_row) as c, c.cursor() as cur:
        cur.execute("SELECT id,username,password_hash,role,enabled,must_change_password FROM users WHERE username=%s", (payload.username,))
        u=cur.fetchone()
        if not u or not u['enabled'] or not verify_password(payload.password,u['password_hash']):
            raise HTTPException(401,'Invalid username or password')
        token=secrets.token_urlsafe(32)
        cur.execute("DELETE FROM sessions WHERE user_id=%s OR expires_at<now()", (u['id'],))
        cur.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(%s,%s,now() + (%s || ' hours')::interval)", (session_hash(token),u['id'],SESSION_HOURS))
        c.commit()
    response.set_cookie('snf_session',token,max_age=SESSION_HOURS*3600,httponly=True,samesite='lax',secure=False,path='/')
    return {'id':u['id'],'username':u['username'],'role':u['role'],'must_change_password':u['must_change_password']}

@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token=request.cookies.get('snf_session')
    if token:
        with conn() as c, c.cursor() as cur: cur.execute("DELETE FROM sessions WHERE token_hash=%s", (session_hash(token),))
    response.delete_cookie('snf_session',path='/')
    return {'status':'ok'}

@app.get("/api/auth/me")
def auth_me(request: Request):
    return dict(request.state.user)

@app.get("/api/auth/users")
def list_users():
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT id,username,role,enabled,must_change_password,created_at FROM users ORDER BY username")
        return cur.fetchall()

@app.post("/api/auth/users")
def create_user(payload: UserCreate):
    try:
        with conn() as c, c.cursor() as cur:
            cur.execute("INSERT INTO users(username,password_hash,role,must_change_password) VALUES(%s,%s,%s,false) RETURNING id,username,role,enabled,must_change_password,created_at", (payload.username.strip(),hash_password(payload.password),payload.role))
            return cur.fetchone()
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409,'Username already exists')

@app.delete("/api/auth/users/{user_id}")
def delete_user(user_id: int, request: Request):
    if int(request.state.user['id'])==user_id: raise HTTPException(409,'You cannot delete your own account')
    with conn() as c, c.cursor() as cur:
        cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
        if cur.rowcount==0: raise HTTPException(404,'User not found')
    return {'status':'deleted'}


@app.post("/api/auth/change-password")
def change_own_password(payload: PasswordChange, request: Request):
    user_id=int(request.state.user['id'])
    with psycopg.connect(DB, row_factory=dict_row) as c, c.cursor() as cur:
        cur.execute("SELECT password_hash FROM users WHERE id=%s FOR UPDATE", (user_id,))
        row=cur.fetchone()
        if not row or not verify_password(payload.current_password,row['password_hash']):
            raise HTTPException(400,'Current password is incorrect')
        cur.execute("UPDATE users SET password_hash=%s,must_change_password=false WHERE id=%s", (hash_password(payload.new_password),user_id))
        c.commit()
    return {'status':'ok'}

@app.post("/api/auth/users/{user_id}/password")
def admin_reset_password(user_id: int, payload: AdminPasswordReset):
    with conn() as c, c.cursor() as cur:
        cur.execute("UPDATE users SET password_hash=%s,must_change_password=false WHERE id=%s", (hash_password(payload.new_password),user_id))
        if cur.rowcount==0: raise HTTPException(404,'User not found')
        # Keep the current browser session valid; invalidate only other sessions for this user.
        current_token=request.cookies.get('snf_session')
        if current_token:
            cur.execute("DELETE FROM sessions WHERE user_id=%s AND token_hash<>%s", (user_id,session_hash(current_token)))
        else:
            cur.execute("DELETE FROM sessions WHERE user_id=%s", (user_id,))
    return {'status':'ok','must_change_password':False}

@app.get("/api/system-status")
def system_status():
    db_online=False
    try:
        with conn() as c, c.cursor() as cur:
            cur.execute("SELECT 1")
            db_online = cur.fetchone() is not None
    except Exception:
        db_online=False
    collector_online=False
    try:
        # Docker DNS publishes the service while the collector container is reachable.
        socket.getaddrinfo('collector', 2055, type=socket.SOCK_DGRAM)
        collector_online = os.path.exists(FLOW_FILE)
    except Exception:
        collector_online=False
    return {
        'backend': {'online': True},
        'database': {'online': db_online},
        'collector': {'online': collector_online},
        'version': VERSION,
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "version": VERSION}


@app.get("/api/events")
async def live_events():
    """Server-Sent Events stream used by the GUI for near-real-time refresh."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=1)
    LIVE_SUBSCRIBERS.add(queue)

    async def event_stream():
        try:
            yield "event: ready\ndata: {\"status\":\"connected\"}\n\n"
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"event: flow\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"
                except asyncio.TimeoutError:
                    # Comment frame keeps proxies/connections alive without UI work.
                    yield ": keepalive\n\n"
        finally:
            LIVE_SUBSCRIBERS.discard(queue)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/summary")
def summary(hours: int = 24):
    h=min(max(hours,1),24*365)
    now=time.monotonic()
    if SUMMARY_CACHE['data'] is not None and SUMMARY_CACHE['hours']==h and now-SUMMARY_CACHE['ts']<1.0:
        return SUMMARY_CACHE['data']
    with conn() as c, c.cursor() as cur:
        cur.execute("""SELECT coalesce(sum(flows),0)::bigint flows,coalesce(sum(bytes),0)::bigint bytes,coalesce(sum(packets),0)::bigint packets
                       FROM flow_agg_total_1m WHERE bucket>=now()-(%s || ' hours')::interval""", (h,))
        r=cur.fetchone()
        cur.execute("SELECT count(DISTINCT exporter)::bigint n FROM flow_agg_exporter_1m WHERE bucket>=now()-(%s || ' hours')::interval",(h,)); r['exporters']=cur.fetchone()['n']
        cur.execute("SELECT count(*)::bigint n FROM interfaces"); r['interfaces']=cur.fetchone()['n']
        cur.execute("SELECT count(DISTINCT src_addr)::bigint n FROM flow_agg_src_1m WHERE bucket>=now()-(%s || ' hours')::interval",(h,)); r['sources']=cur.fetchone()['n']
        cur.execute("SELECT count(DISTINCT dst_addr)::bigint n FROM flow_agg_dst_1m WHERE bucket>=now()-(%s || ' hours')::interval",(h,)); r['destinations']=cur.fetchone()['n']
        cur.execute("SELECT pg_database_size(current_database())::bigint bytes"); r['database_bytes']=cur.fetchone()['bytes']
        data=dict(r)
        SUMMARY_CACHE.update({'ts':now,'hours':h,'data':data})
        return data


@app.get("/api/top")
def top(kind: str = Query("src", pattern="^(src|dst|port|exporter|proto|app)$"), hours: int = 24, limit: int = 10):
    h=min(max(hours,1),24*365); limit=min(max(limit,1),50)
    table_map={'src':('flow_agg_src_1m','host(src_addr)'),'dst':('flow_agg_dst_1m','host(dst_addr)')}
    with conn() as c, c.cursor() as cur:
        if kind=='app':
            cur.execute("""SELECT proto,port,sum(bytes)::bigint bytes,sum(flows)::bigint flows FROM flow_agg_app_1m
                           WHERE bucket>=now()-(%s || ' hours')::interval GROUP BY proto,port ORDER BY bytes DESC LIMIT %s""",(h,limit))
            rows=cur.fetchall()
            for r in rows:r['label']=app_name(r['proto'],r['port'])
            return rows
        if kind=='exporter':
            cur.execute("""SELECT host(a.exporter) exporter,
                                  CASE WHEN nullif(e.hostname,'') IS NOT NULL
                                       THEN e.hostname || ' (' || host(a.exporter) || ')'
                                       ELSE host(a.exporter) END AS label,
                                  sum(a.bytes)::bigint bytes,sum(a.flows)::bigint flows
                           FROM flow_agg_exporter_1m a
                           LEFT JOIN exporters e ON e.ip=a.exporter
                           WHERE a.bucket>=now()-(%s || ' hours')::interval
                           GROUP BY a.exporter,e.hostname ORDER BY bytes DESC LIMIT %s""",(h,limit))
            return cur.fetchall()
        if kind in table_map:
            table,col=table_map[kind]
            cur.execute(f"SELECT {col} label,sum(bytes)::bigint bytes,sum(flows)::bigint flows FROM {table} WHERE bucket>=now()-(%s || ' hours')::interval GROUP BY 1 ORDER BY bytes DESC LIMIT %s",(h,limit))
            return cur.fetchall()
        if kind=='proto':
            cur.execute("SELECT proto::text label,sum(bytes)::bigint bytes,sum(flows)::bigint flows FROM flow_agg_app_1m WHERE bucket>=now()-(%s || ' hours')::interval GROUP BY proto ORDER BY bytes DESC LIMIT %s",(h,limit));return cur.fetchall()
        cur.execute("SELECT port::text label,sum(bytes)::bigint bytes,sum(flows)::bigint flows FROM flow_agg_app_1m WHERE bucket>=now()-(%s || ' hours')::interval GROUP BY port ORDER BY bytes DESC LIMIT %s",(h,limit));return cur.fetchall()


@app.get("/api/top-interfaces")
def top_interfaces(hours: int = 1, limit: int = 10):
    h=min(max(hours,1),24*30);limit=min(max(limit,1),50)
    with conn() as c,c.cursor() as cur:
        cur.execute("""WITH s AS (SELECT exporter,if_index,sum(bytes)::bigint bytes,sum(flows)::bigint flows FROM flow_agg_interface_1m
                                  WHERE bucket>=now()-(%s || ' hours')::interval GROUP BY exporter,if_index)
                       SELECT host(s.exporter) exporter,s.if_index,coalesce(nullif(i.if_name,''),nullif(i.if_descr,''),'ifIndex '||s.if_index::text) interface_name,
                              coalesce(nullif(e.hostname,''),host(s.exporter)) device_name,
                              coalesce(nullif(i.if_name,''),nullif(i.if_descr,''),'ifIndex '||s.if_index::text)||' ('||coalesce(nullif(e.hostname,''),host(s.exporter))||')' label,
                              s.bytes,s.flows FROM s LEFT JOIN interfaces i ON i.exporter=s.exporter AND i.if_index=s.if_index
                              LEFT JOIN exporters e ON e.ip=s.exporter ORDER BY s.bytes DESC LIMIT %s""",(h,limit))
        return cur.fetchall()


@app.get("/api/device-timeseries")
def device_timeseries(hours: int = 24, limit: int = 10):
    limit = min(max(limit, 1), 10)
    with conn() as c, c.cursor() as cur:
        cur.execute(
            """WITH top_devices AS (
                 SELECT exporter, sum(bytes) b FROM flows
                 WHERE received_at >= now() - (%s || ' hours')::interval AND exporter IS NOT NULL
                 GROUP BY exporter ORDER BY b DESC LIMIT %s
               )
               SELECT date_trunc('hour', f.received_at) bucket, host(f.exporter) exporter, sum(f.bytes)::bigint bytes
               FROM flows f JOIN top_devices t ON t.exporter=f.exporter
               WHERE f.received_at >= now() - (%s || ' hours')::interval
               GROUP BY 1,2 ORDER BY 1,2""",
            (hours, limit, hours),
        )
        return cur.fetchall()


@app.get("/api/traffic-timeseries")
def traffic_timeseries(hours: int = 24):
    h=min(max(hours,1),24*30)
    with conn() as c,c.cursor() as cur:
        cur.execute("""SELECT date_trunc('hour',bucket)+floor(date_part('minute',bucket)/10)*interval '10 minutes' bucket,
                              sum(bytes)::bigint bytes,sum(packets)::bigint packets,sum(flows)::bigint flows
                       FROM flow_agg_total_1m WHERE bucket>=now()-(%s || ' hours')::interval GROUP BY 1 ORDER BY 1""",(h,))
        return cur.fetchall()


def build_flow_filter(
    hours: Optional[int] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    exporter: Optional[str] = None,
    q: Optional[str] = None,
    src: Optional[str] = None,
    dst: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    port: Optional[int] = None,
    proto: Optional[int] = None,
    interface: Optional[str] = None,
    interface_exporter: Optional[str] = None,
    interface_index: Optional[int] = None,
):
    clauses, params = [], []
    if date_from:
        clauses.append("f.received_at >= %s")
        params.append(date_from)
    if date_to:
        clauses.append("f.received_at <= %s")
        params.append(date_to)
    if not date_from and not date_to and hours is not None:
        h = min(max(hours, 1), 24 * 365)
        clauses.append("f.received_at >= now() - (%s || ' hours')::interval")
        params.append(h)
    if q:
        clauses.append("(host(f.src_addr) ILIKE %s OR host(f.dst_addr) ILIKE %s OR host(f.exporter) ILIKE %s OR f.src_port::text ILIKE %s OR f.dst_port::text ILIKE %s)")
        v = f"%{q}%"
        params += [v, v, v, v, v]
    if exporter:
        clauses.append("f.exporter = %s::inet")
        params.append(normalize_host(exporter))
    if src:
        try:
            src_host=normalize_host(src); ipaddress.ip_address(src_host)
            clauses.append("f.src_addr=%s::inet"); params.append(src_host)
        except Exception:
            clauses.append("host(f.src_addr) ILIKE %s"); params.append(f"%{src}%")
    if dst:
        try:
            dst_host=normalize_host(dst); ipaddress.ip_address(dst_host)
            clauses.append("f.dst_addr=%s::inet"); params.append(dst_host)
        except Exception:
            clauses.append("host(f.dst_addr) ILIKE %s"); params.append(f"%{dst}%")
    if src_port is not None:
        clauses.append("f.src_port=%s")
        params.append(src_port)
    if dst_port is not None:
        clauses.append("f.dst_port=%s")
        params.append(dst_port)
    if port is not None:
        clauses.append("(f.src_port=%s OR f.dst_port=%s)")
        params += [port, port]
    if proto is not None:
        clauses.append("f.proto=%s")
        params.append(proto)
    if interface_index is not None:
        clauses.append("(f.in_if=%s OR f.out_if=%s)")
        params += [interface_index, interface_index]
        if interface_exporter:
            clauses.append("f.exporter=%s::inet")
            params.append(normalize_host(interface_exporter))
    elif interface:
        clauses.append("(f.in_if::text=%s OR f.out_if::text=%s OR ii.if_name ILIKE %s OR oi.if_name ILIKE %s OR ii.if_descr ILIKE %s OR oi.if_descr ILIKE %s)")
        params += [interface, interface, f"%{interface}%", f"%{interface}%", f"%{interface}%", f"%{interface}%"]
    return clauses, params


FLOW_SORT_COLUMNS = {
    "received_at": "f.received_at",
    "exporter": "COALESCE(e.hostname, host(f.exporter))",
    "src": "f.src_addr",
    "dst": "f.dst_addr",
    "proto": "f.proto",
    "in_if": "f.in_if",
    "out_if": "f.out_if",
    "bytes": "f.bytes",
    "packets": "f.packets",
}


@app.get("/api/flows")
def flows(
    limit: int = 10,
    offset: int = 0,
    q: Optional[str] = None,
    hours: Optional[int] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    exporter: Optional[str] = None,
    src: Optional[str] = None,
    dst: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    port: Optional[int] = None,
    proto: Optional[int] = None,
    interface: Optional[str] = None,
    interface_exporter: Optional[str] = None,
    interface_index: Optional[int] = None,
    sort: Optional[str] = None,
    order: Optional[str] = None,
):
    clauses, params = build_flow_filter(hours=hours, date_from=date_from, date_to=date_to, exporter=exporter, q=q, src=src, dst=dst, src_port=src_port, dst_port=dst_port, port=port, proto=proto, interface=interface, interface_exporter=interface_exporter, interface_index=interface_index)
    where = " AND ".join(clauses) if clauses else "TRUE"
    sort_col = FLOW_SORT_COLUMNS.get(sort or "received_at", "f.received_at")
    sort_dir = "ASC" if str(order).lower() == "asc" else "DESC"
    params += [min(max(limit, 1), 100), max(offset, 0)]
    with conn() as c, c.cursor() as cur:
        cur.execute(
            f"""SELECT f.id,f.received_at,f.flow_time,host(f.exporter) exporter,e.hostname exporter_hostname,f.flow_type,
                       host(f.src_addr) src_addr,host(f.dst_addr) dst_addr,f.src_port,f.dst_port,f.proto,f.bytes,f.packets,
                       f.in_if,f.out_if,
                       COALESCE(ii.if_name,ii.if_descr) in_if_name, COALESCE(oi.if_name,oi.if_descr) out_if_name,
                       f.sampling_rate
                FROM flows f
                LEFT JOIN exporters e ON e.ip=f.exporter
                LEFT JOIN interfaces ii ON ii.exporter=f.exporter AND ii.if_index=f.in_if
                LEFT JOIN interfaces oi ON oi.exporter=f.exporter AND oi.if_index=f.out_if
                WHERE {where} ORDER BY {sort_col} {sort_dir}, f.id DESC LIMIT %s OFFSET %s""",
            params,
        )
        return cur.fetchall()


@app.get("/api/flows/count")
def flows_count(
    q: Optional[str] = None,
    hours: Optional[int] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    exporter: Optional[str] = None,
    src: Optional[str] = None,
    dst: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    port: Optional[int] = None,
    proto: Optional[int] = None,
    interface: Optional[str] = None,
    interface_exporter: Optional[str] = None,
    interface_index: Optional[int] = None,
):
    clauses, params = build_flow_filter(hours=hours, date_from=date_from, date_to=date_to, exporter=exporter, q=q, src=src, dst=dst, src_port=src_port, dst_port=dst_port, port=port, proto=proto, interface=interface, interface_exporter=interface_exporter, interface_index=interface_index)
    where = " AND ".join(clauses) if clauses else "TRUE"
    with conn() as c, c.cursor() as cur:
        cur.execute(
            f"""SELECT count(*)::bigint total
                FROM flows f
                LEFT JOIN interfaces ii ON ii.exporter=f.exporter AND ii.if_index=f.in_if
                LEFT JOIN interfaces oi ON oi.exporter=f.exporter AND oi.if_index=f.out_if
                WHERE {where}""",
            params,
        )
        return cur.fetchone()



SUMMARY_SORT_COLUMNS = {
    "src": "src_addr",
    "dst": "dst_addr",
    "peer": "peer_addr",
    "proto": "proto",
    "port": "port",
    "bytes": "bytes",
    "packets": "packets",
    "flows": "flows",
}


def _summary_shape(src: Optional[str], dst: Optional[str]):
    """Return SELECT/GROUP expressions for context-aware flow summaries."""
    if src and not dst:
        return (
            "source",
            "host(f.dst_addr) AS peer_addr, NULL::text AS src_addr, host(f.dst_addr) AS dst_addr, f.proto, f.dst_port AS port",
            "f.dst_addr, f.proto, f.dst_port",
        )
    if dst and not src:
        return (
            "destination",
            "host(f.src_addr) AS peer_addr, host(f.src_addr) AS src_addr, NULL::text AS dst_addr, f.proto, f.src_port AS port",
            "f.src_addr, f.proto, f.src_port",
        )
    return (
        "pair",
        "NULL::text AS peer_addr, host(f.src_addr) AS src_addr, host(f.dst_addr) AS dst_addr, f.proto, f.dst_port AS port",
        "f.src_addr, f.dst_addr, f.proto, f.dst_port",
    )


@app.get("/api/flows/summary")
def flows_summary(
    limit: int = 10,
    offset: int = 0,
    q: Optional[str] = None,
    hours: Optional[int] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    exporter: Optional[str] = None,
    src: Optional[str] = None,
    dst: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    port: Optional[int] = None,
    proto: Optional[int] = None,
    interface: Optional[str] = None,
    interface_exporter: Optional[str] = None,
    interface_index: Optional[int] = None,
    sort: Optional[str] = None,
    order: Optional[str] = None,
):
    clauses, params = build_flow_filter(hours=hours, date_from=date_from, date_to=date_to, exporter=exporter, q=q, src=src, dst=dst, src_port=src_port, dst_port=dst_port, port=port, proto=proto, interface=interface, interface_exporter=interface_exporter, interface_index=interface_index)
    where = " AND ".join(clauses) if clauses else "TRUE"
    mode, select_cols, group_cols = _summary_shape(src, dst)
    sort_col = SUMMARY_SORT_COLUMNS.get(sort or "bytes", "bytes")
    sort_dir = "ASC" if str(order).lower() == "asc" else "DESC"
    params += [min(max(limit, 1), 100), max(offset, 0)]
    with conn() as c, c.cursor() as cur:
        cur.execute(
            f"""SELECT {select_cols},
                       coalesce(sum(f.bytes),0)::bigint AS bytes,
                       coalesce(sum(f.packets),0)::bigint AS packets,
                       count(*)::bigint AS flows
                FROM flows f
                LEFT JOIN interfaces ii ON ii.exporter=f.exporter AND ii.if_index=f.in_if
                LEFT JOIN interfaces oi ON oi.exporter=f.exporter AND oi.if_index=f.out_if
                WHERE {where}
                GROUP BY {group_cols}
                ORDER BY {sort_col} {sort_dir} NULLS LAST
                LIMIT %s OFFSET %s""",
            params,
        )
        return {"mode": mode, "rows": cur.fetchall()}


@app.get("/api/flows/summary/count")
def flows_summary_count(
    q: Optional[str] = None,
    hours: Optional[int] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    exporter: Optional[str] = None,
    src: Optional[str] = None,
    dst: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    port: Optional[int] = None,
    proto: Optional[int] = None,
    interface: Optional[str] = None,
    interface_exporter: Optional[str] = None,
    interface_index: Optional[int] = None,
):
    clauses, params = build_flow_filter(hours=hours, date_from=date_from, date_to=date_to, exporter=exporter, q=q, src=src, dst=dst, src_port=src_port, dst_port=dst_port, port=port, proto=proto, interface=interface, interface_exporter=interface_exporter, interface_index=interface_index)
    where = " AND ".join(clauses) if clauses else "TRUE"
    mode, _, group_cols = _summary_shape(src, dst)
    with conn() as c, c.cursor() as cur:
        cur.execute(
            f"""SELECT count(*)::bigint AS total FROM (
                   SELECT 1
                   FROM flows f
                   LEFT JOIN interfaces ii ON ii.exporter=f.exporter AND ii.if_index=f.in_if
                   LEFT JOIN interfaces oi ON oi.exporter=f.exporter AND oi.if_index=f.out_if
                   WHERE {where}
                   GROUP BY {group_cols}
                ) s""",
            params,
        )
        row=cur.fetchone()
        return {"mode": mode, "total": row["total"]}




@app.get("/api/conversations")
def conversations(
    limit: int = 10,
    offset: int = 0,
    q: Optional[str] = None,
    hours: Optional[int] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    exporter: Optional[str] = None,
    src: Optional[str] = None,
    dst: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    port: Optional[int] = None,
    proto: Optional[int] = None,
    interface: Optional[str] = None,
    interface_exporter: Optional[str] = None,
    interface_index: Optional[int] = None,
):
    """Aggregate directional conversations by Source IP -> Destination IP."""
    clauses, params = build_flow_filter(
        hours=hours, date_from=date_from, date_to=date_to, exporter=exporter,
        q=q, src=src, dst=dst, src_port=src_port, dst_port=dst_port,
        port=port, proto=proto, interface=interface,
        interface_exporter=interface_exporter, interface_index=interface_index,
    )
    where = " AND ".join(clauses) if clauses else "TRUE"
    params += [min(max(limit, 1), 100), max(offset, 0)]
    with conn() as c, c.cursor() as cur:
        cur.execute(
            f"""SELECT host(f.src_addr) AS src_addr,
                       host(f.dst_addr) AS dst_addr,
                       coalesce(sum(f.bytes),0)::bigint AS bytes,
                       coalesce(sum(f.packets),0)::bigint AS packets,
                       count(*)::bigint AS flows
                FROM flows f
                LEFT JOIN interfaces ii ON ii.exporter=f.exporter AND ii.if_index=f.in_if
                LEFT JOIN interfaces oi ON oi.exporter=f.exporter AND oi.if_index=f.out_if
                WHERE {where}
                GROUP BY f.src_addr, f.dst_addr
                ORDER BY bytes DESC, f.src_addr ASC, f.dst_addr ASC
                LIMIT %s OFFSET %s""",
            params,
        )
        return cur.fetchall()


@app.get("/api/conversations/count")
def conversations_count(
    q: Optional[str] = None,
    hours: Optional[int] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    exporter: Optional[str] = None,
    src: Optional[str] = None,
    dst: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    port: Optional[int] = None,
    proto: Optional[int] = None,
    interface: Optional[str] = None,
    interface_exporter: Optional[str] = None,
    interface_index: Optional[int] = None,
):
    clauses, params = build_flow_filter(
        hours=hours, date_from=date_from, date_to=date_to, exporter=exporter,
        q=q, src=src, dst=dst, src_port=src_port, dst_port=dst_port,
        port=port, proto=proto, interface=interface,
        interface_exporter=interface_exporter, interface_index=interface_index,
    )
    where = " AND ".join(clauses) if clauses else "TRUE"
    with conn() as c, c.cursor() as cur:
        cur.execute(
            f"""SELECT count(*)::bigint AS total FROM (
                   SELECT 1
                   FROM flows f
                   LEFT JOIN interfaces ii ON ii.exporter=f.exporter AND ii.if_index=f.in_if
                   LEFT JOIN interfaces oi ON oi.exporter=f.exporter AND oi.if_index=f.out_if
                   WHERE {where}
                   GROUP BY f.src_addr, f.dst_addr
                ) c""",
            params,
        )
        return cur.fetchone()


@app.get("/api/flows/series")
def flows_series(
    q: Optional[str] = None,
    hours: Optional[int] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    exporter: Optional[str] = None,
    src: Optional[str] = None,
    dst: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    port: Optional[int] = None,
    proto: Optional[int] = None,
    interface: Optional[str] = None,
    interface_exporter: Optional[str] = None,
    interface_index: Optional[int] = None,
):
    clauses, params = build_flow_filter(hours=hours, date_from=date_from, date_to=date_to, exporter=exporter, q=q, src=src, dst=dst, src_port=src_port, dst_port=dst_port, port=port, proto=proto, interface=interface, interface_exporter=interface_exporter, interface_index=interface_index)
    where = " AND ".join(clauses) if clauses else "TRUE"
    with conn() as c, c.cursor() as cur:
        cur.execute(
            f"""SELECT date_trunc('hour', f.received_at)
                         + floor(date_part('minute', f.received_at) / 10) * interval '10 minutes' AS bucket,
                      coalesce(sum(f.bytes),0)::bigint bytes,
                      coalesce(sum(f.packets),0)::bigint packets,
                      count(*)::bigint flows
                FROM flows f
                LEFT JOIN interfaces ii ON ii.exporter=f.exporter AND ii.if_index=f.in_if
                LEFT JOIN interfaces oi ON oi.exporter=f.exporter AND oi.if_index=f.out_if
                WHERE {where}
                GROUP BY 1 ORDER BY 1""",
            params,
        )
        return cur.fetchall()


@app.get("/api/exporters")
def exporters():
    with conn() as c, c.cursor() as cur:
        cur.execute(
            """SELECT host(e.ip) exporter,e.hostname,e.sys_descr,e.first_seen,e.last_seen,e.snmp_enabled,e.snmp_version,e.snmp_port,
                      e.snmp_last_poll,e.snmp_last_error,e.snmp_community,(e.snmp_community IS NOT NULL) community_set,
                      coalesce(fs.flows,0)::bigint flows,coalesce(fs.bytes,0)::bigint bytes,
                      coalesce(ic.interfaces,0)::bigint interfaces,
                      (e.last_seen >= now() - interval '5 minutes') active
               FROM exporters e
               LEFT JOIN (SELECT exporter,sum(flows) flows,sum(bytes) bytes FROM flow_agg_exporter_1m GROUP BY exporter) fs ON fs.exporter=e.ip
               LEFT JOIN (SELECT exporter,count(*) interfaces FROM interfaces GROUP BY exporter) ic ON ic.exporter=e.ip
               ORDER BY e.ip ASC"""
        )
        return cur.fetchall()


@app.delete("/api/exporters/{exporter}")
async def delete_exporter(exporter: str):
    """Compatibility endpoint: starts an asynchronous purge job."""
    return await _start_exporter_delete_job(exporter)


@app.post("/api/exporters/{exporter}/delete")
async def delete_exporter_post(exporter: str):
    """Compatibility endpoint: starts an asynchronous purge job."""
    return await _start_exporter_delete_job(exporter)


@app.post("/api/exporters/delete")
async def delete_exporter_stable(payload: ExporterDeleteRequest):
    return await _start_exporter_delete_job(payload.exporter)


@app.get("/api/exporters/delete-jobs/{job_id}")
def exporter_delete_job_status(job_id: str, request: Request):
    if getattr(request.state, 'user', {}).get('role') != 'administrator':
        raise HTTPException(403, "Administrator access required")
    job = _job_snapshot(job_id)
    if not job:
        raise HTTPException(404, "Delete job not found")
    return job


async def _start_exporter_delete_job(exporter: str):
    exporter = normalize_host(exporter)
    # Refuse duplicate jobs for the same exporter while one is in progress.
    for existing in EXPORTER_DELETE_JOBS.values():
        if existing.get('exporter') == exporter and existing.get('status') in ('queued', 'running'):
            return existing

    # Validate existence/Idle state before showing a progress dialog in the GUI.
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT last_seen FROM exporters WHERE ip=%s::inet", (exporter,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Exporter not found")
        cur.execute("SELECT (last_seen < now() - interval '5 minutes') idle FROM exporters WHERE ip=%s::inet", (exporter,))
        if not cur.fetchone()['idle']:
            raise HTTPException(409, "Exporter is Active. Stop NetFlow export and wait until it becomes Idle before deleting it.")

    job_id = secrets.token_urlsafe(12)
    now = datetime.now(timezone.utc).isoformat()
    EXPORTER_DELETE_JOBS[job_id] = {
        'job_id': job_id,
        'exporter': exporter,
        'status': 'queued',
        'stage': 'Queued',
        'progress': 0,
        'message': 'Delete job queued',
        'created_at': now,
        'updated_at': now,
        'deleted_flows': 0,
    }
    task = asyncio.create_task(_run_exporter_delete_job(job_id, exporter))
    EXPORTER_DELETE_TASKS[job_id] = task
    task.add_done_callback(lambda _t, jid=job_id: EXPORTER_DELETE_TASKS.pop(jid, None))
    return _job_snapshot(job_id)


async def _run_exporter_delete_job(job_id: str, exporter: str):
    try:
        _job_update(job_id, status='running', stage='Checking exporter', progress=3,
                    message='Checking exporter state')
        result = await asyncio.to_thread(_purge_exporter_with_progress, exporter, job_id)
        _job_update(job_id, status='running', stage='Rebuilding statistics', progress=90,
                    message='Rebuilding dashboard statistics')
        await asyncio.to_thread(rebuild_aggregates, True)
        SUMMARY_CACHE['data'] = None
        _job_update(job_id, status='done', stage='Completed', progress=100,
                    message='Exporter and all related data were deleted', result=result,
                    deleted_flows=result.get('deleted_flows', 0))
        print(f"[v0.6.2] Exporter purge completed: {exporter}, {result.get('deleted_flows', 0)} flows removed.", flush=True)
    except Exception as exc:
        _job_fail(job_id, exc)
        print(f"[v0.6.2] Exporter purge failed for {exporter}: {getattr(exc, 'detail', exc)}", flush=True)


def _purge_exporter_with_progress(exporter: str, job_id: str):
    """Delete an Idle exporter in observable, bounded batches.

    Raw rows are deleted partition-by-partition in small commits so the GUI can
    report real progress instead of waiting on one long HTTP request. Once raw
    data is gone, exporter-scoped metadata is removed. Global aggregates are
    rebuilt by the async job after this function returns.
    """
    exporter = normalize_host(exporter)
    batch_size = 10000

    with psycopg.connect(DB, row_factory=dict_row) as c, c.cursor() as cur:
        cur.execute("SELECT last_seen FROM exporters WHERE ip=%s::inet FOR UPDATE", (exporter,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Exporter not found")
        cur.execute("SELECT (last_seen < now() - interval '5 minutes') idle FROM exporters WHERE ip=%s::inet", (exporter,))
        if not cur.fetchone()['idle']:
            raise HTTPException(409, "Exporter became Active. Stop NetFlow export and try again after it becomes Idle.")
        cur.execute("SELECT count(*)::bigint total FROM flows WHERE exporter=%s::inet", (exporter,))
        total_flows = int(cur.fetchone()['total'] or 0)
        c.commit()

    _job_update(job_id, stage='Deleting raw flows', progress=8,
                message=f'Deleting {total_flows:,} raw flows', total_flows=total_flows)

    # Work directly on child partitions so ctid batching is unambiguous.
    with psycopg.connect(DB, row_factory=dict_row) as c, c.cursor() as cur:
        cur.execute("""SELECT child.relname AS partition
                       FROM pg_inherits
                       JOIN pg_class parent ON pg_inherits.inhparent=parent.oid
                       JOIN pg_class child ON pg_inherits.inhrelid=child.oid
                       JOIN pg_namespace ns ON child.relnamespace=ns.oid
                       WHERE parent.relname='flows' AND ns.nspname='public'
                       ORDER BY child.relname""")
        partitions = [r['partition'] for r in cur.fetchall()]

    deleted_flows = 0
    for part in partitions:
        while True:
            with psycopg.connect(DB, row_factory=dict_row) as c, c.cursor() as cur:
                ident = sql.Identifier(part)
                q = sql.SQL("""WITH doomed AS (
                               SELECT ctid FROM {p} WHERE exporter=%s::inet LIMIT %s
                             )
                             DELETE FROM {p} f USING doomed d
                             WHERE f.ctid=d.ctid""").format(p=ident)
                cur.execute(q, (exporter, batch_size))
                n = cur.rowcount
                c.commit()
            if not n:
                break
            deleted_flows += n
            frac = (deleted_flows / total_flows) if total_flows else 1.0
            progress = min(70, 8 + int(frac * 62))
            _job_update(job_id, stage='Deleting raw flows', progress=progress,
                        message=f'Deleted {deleted_flows:,} of {total_flows:,} raw flows',
                        deleted_flows=deleted_flows, total_flows=total_flows)

    _job_update(job_id, stage='Deleting interfaces and SNMP', progress=74,
                message='Deleting interfaces and SNMP metadata')
    with psycopg.connect(DB, row_factory=dict_row) as c, c.cursor() as cur:
        # Re-check once more before removing the inventory record.
        cur.execute("SELECT last_seen FROM exporters WHERE ip=%s::inet FOR UPDATE", (exporter,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Exporter disappeared during purge")
        cur.execute("SELECT (last_seen < now() - interval '5 minutes') idle FROM exporters WHERE ip=%s::inet", (exporter,))
        if not cur.fetchone()['idle']:
            raise HTTPException(409, "Exporter became Active during deletion. Purge stopped; disable NetFlow export and run Delete again.")

        cur.execute("DELETE FROM interfaces WHERE exporter=%s::inet", (exporter,))
        deleted_interfaces = cur.rowcount
        _job_update(job_id, stage='Deleting exporter aggregates', progress=78,
                    message='Deleting exporter/interface aggregates')
        cur.execute("DELETE FROM flow_agg_exporter_1m WHERE exporter=%s::inet", (exporter,))
        deleted_exporter_agg = cur.rowcount
        cur.execute("DELETE FROM flow_agg_interface_1m WHERE exporter=%s::inet", (exporter,))
        deleted_interface_agg = cur.rowcount

        _job_update(job_id, stage='Deleting exporter', progress=84,
                    message='Deleting exporter inventory record')
        cur.execute("DELETE FROM exporters WHERE ip=%s::inet", (exporter,))
        if cur.rowcount != 1:
            raise RuntimeError(f"Exporter purge failed for {exporter}")
        c.commit()

    SUMMARY_CACHE['data'] = None
    return {
        'status': 'deleted',
        'exporter': exporter,
        'deleted_flows': deleted_flows,
        'deleted_interfaces': deleted_interfaces,
        'deleted_exporter_aggregates': deleted_exporter_agg,
        'deleted_interface_aggregates': deleted_interface_agg,
    }


@app.get("/api/database-size")
def database_size():
    return storage_breakdown()


@app.get("/api/settings")
def settings():
    old=int(get_setting('retention_hours', int(get_setting('retention_days', DEFAULT_RETENTION_DAYS))*24))
    raw=max(1,int(get_setting('raw_retention_hours', DEFAULT_RAW_RETENTION_HOURS)))
    stats=max(6,int(get_setting('stats_retention_hours', DEFAULT_STATS_RETENTION_HOURS)))
    return {"raw_retention_days":raw//24,"raw_retention_hours":raw%24,"raw_retention_total_hours":raw,
            "stats_retention_days":stats//24,"stats_retention_hours":stats%24,"stats_retention_total_hours":stats,
            **storage_breakdown()}


def _retention_int(payload: dict, *names: str, default=None) -> int:
    value = default
    for name in names:
        if name in payload and payload[name] not in (None, ""):
            value = payload[name]
            break
    if value is None:
        raise HTTPException(422, f"Missing retention field: {names[0]}")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise HTTPException(422, f"Invalid retention value for {names[0]}")


@app.put("/api/settings/retention")
async def update_retention(request: Request):
    # Parse the JSON explicitly instead of relying on a strict Pydantic request
    # model. This keeps the endpoint compatible with the 0.5.x frontends and
    # produces a useful error string rather than a list of validation objects.
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON request body")
    if not isinstance(payload, dict):
        raise HTTPException(422, "Retention settings must be a JSON object")

    # Current names plus compatibility aliases used by earlier 0.5.x builds.
    raw_days = _retention_int(payload, "raw_days", "raw_retention_days", default=0)
    raw_hours = _retention_int(payload, "raw_hours", "raw_retention_hours", default=0)
    stats_days = _retention_int(payload, "stats_days", "stats_retention_days", default=0)
    stats_hours = _retention_int(payload, "stats_hours", "stats_retention_hours", default=0)

    if not 0 <= raw_days <= 3650 or not 0 <= stats_days <= 3650:
        raise HTTPException(422, "Retention days must be between 0 and 3650")
    if not 0 <= raw_hours <= 23 or not 0 <= stats_hours <= 23:
        raise HTTPException(422, "Retention hours must be between 0 and 23")

    raw = raw_days * 24 + raw_hours
    stats = stats_days * 24 + stats_hours
    if raw < 1:
        raise HTTPException(422, "Raw flows retention must be at least 1 hour")
    if stats < 6:
        raise HTTPException(422, "Statistics retention must be at least 6 hours")

    set_setting("raw_retention_hours", raw)
    set_setting("stats_retention_hours", stats)
    return {
        "status": "ok",
        "raw_retention_days": raw // 24,
        "raw_retention_hours": raw % 24,
        "raw_retention_total_hours": raw,
        "stats_retention_days": stats // 24,
        "stats_retention_hours": stats % 24,
        "stats_retention_total_hours": stats,
    }


@app.get("/api/exporters/{exporter}")
def exporter_detail(exporter: str):
    exporter = normalize_host(exporter)
    with conn() as c, c.cursor() as cur:
        cur.execute(
            """SELECT host(e.ip) exporter,e.hostname,e.sys_descr,e.first_seen,e.last_seen,e.snmp_enabled,e.snmp_version,e.snmp_port,
                      e.snmp_last_poll,e.snmp_last_error,e.snmp_community,(e.snmp_community IS NOT NULL) community_set,
                      (e.last_seen >= now() - interval '5 minutes') active
               FROM exporters e WHERE e.ip=%s::inet""",
            (exporter,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Exporter not found")
        return row


@app.get("/api/exporters/{exporter}/interfaces")
def exporter_interfaces(exporter: str):
    exporter = normalize_host(exporter)
    with conn() as c, c.cursor() as cur:
        cur.execute(
            """SELECT if_index,if_name,if_descr,if_alias,if_speed,admin_status,oper_status,updated_at
               FROM interfaces WHERE exporter=%s::inet ORDER BY if_index""",
            (exporter,),
        )
        return cur.fetchall()


@app.get("/api/exporter")
def exporter_detail_fixed(exporter: str):
    return exporter_detail(exporter)


@app.get("/api/interfaces")
def interfaces_fixed(exporter: Optional[str] = None):
    exporter = normalize_host(exporter) if exporter else None
    with conn() as c, c.cursor() as cur:
        if exporter:
            cur.execute(
                """WITH observed AS (
                       SELECT exporter,if_index FROM flow_agg_interface_1m WHERE exporter=%s::inet
                       UNION
                       SELECT exporter,if_index FROM flow_agg_interface_1m WHERE exporter=%s::inet
                   ), all_if AS (
                       SELECT exporter,if_index FROM observed
                       UNION
                       SELECT exporter,if_index FROM interfaces WHERE exporter=%s::inet
                   )
                   SELECT host(a.exporter) exporter,e.hostname,a.if_index,i.if_name,i.if_descr,i.if_alias,i.if_speed,i.admin_status,i.oper_status,i.updated_at
                   FROM all_if a
                   LEFT JOIN interfaces i ON i.exporter=a.exporter AND i.if_index=a.if_index
                   LEFT JOIN exporters e ON e.ip=a.exporter
                   ORDER BY a.if_index""",
                (exporter, exporter, exporter),
            )
        else:
            cur.execute(
                """WITH observed AS (
                       SELECT exporter,if_index FROM flow_agg_interface_1m
                       UNION
                       SELECT exporter,if_index FROM flow_agg_interface_1m
                   ), all_if AS (
                       SELECT exporter,if_index FROM observed
                       UNION
                       SELECT exporter,if_index FROM interfaces
                   )
                   SELECT host(a.exporter) exporter,e.hostname,a.if_index,i.if_name,i.if_descr,i.if_alias,i.if_speed,i.admin_status,i.oper_status,i.updated_at
                   FROM all_if a
                   LEFT JOIN interfaces i ON i.exporter=a.exporter AND i.if_index=a.if_index
                   LEFT JOIN exporters e ON e.ip=a.exporter
                   ORDER BY COALESCE(e.hostname,host(a.exporter)),a.if_index"""
            )
        return cur.fetchall()


@app.get("/api/snmp/config")
def snmp_config_get(exporter: str):
    return exporter_detail(exporter)


@app.post("/api/snmp/config")
def snmp_config_save(payload: SnmpConfigRequest):
    data = SnmpUpdate(enabled=payload.enabled, version=payload.version, community=payload.community, port=payload.port)
    return update_snmp(payload.exporter, data)


@app.post("/api/snmp/poll")
def snmp_poll_fixed(payload: SnmpPollRequest):
    return perform_snmp_poll(payload.exporter)


@app.put("/api/exporters/{exporter}/snmp")
def update_snmp(exporter: str, payload: SnmpUpdate):
    exporter = normalize_host(exporter)
    if payload.version != "2c":
        raise HTTPException(400, "This release supports SNMP v2c only")
    with conn() as c, c.cursor() as cur:
        cur.execute(
            """UPDATE exporters SET snmp_enabled=%s,snmp_version=%s,snmp_community=COALESCE(%s,snmp_community),snmp_port=%s
               WHERE ip=%s::inet""",
            (payload.enabled, payload.version, payload.community or None, payload.port, exporter),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Exporter not found")
    return {"status": "ok"}


@app.post("/api/exporters/{exporter}/snmp")
def update_snmp_post(exporter: str, payload: SnmpUpdate):
    return update_snmp(exporter, payload)


def snmp_agent(host, port):
    host = normalize_host(host)
    if ":" in host:
        return f"udp6:[{host}]:{port}"
    return f"udp:{host}:{port}"


def snmp_cmd(args, timeout=15):
    try:
        p = subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise RuntimeError("SNMP request timed out")
    if p.returncode != 0:
        msg = (p.stderr or p.stdout or "SNMP request failed").strip().splitlines()[-1]
        raise RuntimeError(msg[:400])
    return p.stdout


def parse_scalar(text):
    if " = " in text:
        text = text.split(" = ", 1)[1]
    text = re.sub(r"^[A-Z0-9-]+:\s*", "", text.strip())
    if text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    return text.strip()


def walk_indexed(host, port, community, oid):
    out = snmp_cmd(["snmpwalk", "-v2c", "-c", community, "-On", "-t", "2", "-r", "1", snmp_agent(host, port), oid], timeout=25)
    result = {}
    base = oid.strip(".")
    for line in out.splitlines():
        m = re.match(r"\.?(\d+(?:\.\d+)*)\s*=\s*(.*)$", line.strip())
        if not m:
            continue
        full_oid, value = m.groups()
        if not full_oid.startswith(base + "."):
            continue
        try:
            idx = int(full_oid.rsplit(".", 1)[1])
        except ValueError:
            continue
        result[idx] = parse_scalar(value)
    return result


def int_from_snmp(v):
    if v is None:
        return None
    m = re.search(r"(-?\d+)", str(v))
    return int(m.group(1)) if m else None


def perform_snmp_poll(exporter):
    exporter = normalize_host(exporter)
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT snmp_enabled,snmp_version,snmp_community,snmp_port FROM exporters WHERE ip=%s::inet", (exporter,))
        cfg = cur.fetchone()
    if not cfg:
        raise HTTPException(404, "Exporter not found")
    if not cfg["snmp_enabled"] or not cfg["snmp_community"]:
        raise HTTPException(400, "SNMP is not configured for this exporter")
    community = cfg["snmp_community"]
    port = cfg["snmp_port"] or 161
    try:
        name_out = snmp_cmd(["snmpget", "-v2c", "-c", community, "-Oqv", "-t", "2", "-r", "1", snmp_agent(exporter, port), "1.3.6.1.2.1.1.5.0"])
        descr_out = snmp_cmd(["snmpget", "-v2c", "-c", community, "-Oqv", "-t", "2", "-r", "1", snmp_agent(exporter, port), "1.3.6.1.2.1.1.1.0"])
        hostname = parse_scalar(name_out)
        sys_descr = parse_scalar(descr_out)
        names = walk_indexed(exporter, port, community, "1.3.6.1.2.1.31.1.1.1.1")
        descrs = walk_indexed(exporter, port, community, "1.3.6.1.2.1.2.2.1.2")
        aliases = walk_indexed(exporter, port, community, "1.3.6.1.2.1.31.1.1.1.18")
        speeds = walk_indexed(exporter, port, community, "1.3.6.1.2.1.31.1.1.1.15")
        old_speeds = walk_indexed(exporter, port, community, "1.3.6.1.2.1.2.2.1.5")
        admin = walk_indexed(exporter, port, community, "1.3.6.1.2.1.2.2.1.7")
        oper = walk_indexed(exporter, port, community, "1.3.6.1.2.1.2.2.1.8")
        indices = sorted(set(names) | set(descrs) | set(aliases) | set(speeds) | set(old_speeds))
        with conn() as c, c.cursor() as cur:
            cur.execute("UPDATE exporters SET hostname=%s,sys_descr=%s,snmp_last_poll=now(),snmp_last_error=NULL WHERE ip=%s::inet", (hostname, sys_descr, exporter))
            for idx in indices:
                high_mbps = int_from_snmp(speeds.get(idx))
                speed = high_mbps * 1_000_000 if high_mbps and high_mbps > 0 else int_from_snmp(old_speeds.get(idx))
                cur.execute(
                    """INSERT INTO interfaces(exporter,if_index,if_name,if_descr,if_alias,if_speed,admin_status,oper_status,updated_at)
                       VALUES(%s::inet,%s,%s,%s,%s,%s,%s,%s,now())
                       ON CONFLICT(exporter,if_index) DO UPDATE SET
                         if_name=excluded.if_name,if_descr=excluded.if_descr,if_alias=excluded.if_alias,if_speed=excluded.if_speed,
                         admin_status=excluded.admin_status,oper_status=excluded.oper_status,updated_at=now()""",
                    (exporter, idx, names.get(idx), descrs.get(idx), aliases.get(idx), speed, int_from_snmp(admin.get(idx)), int_from_snmp(oper.get(idx))),
                )
        return {"status": "ok", "hostname": hostname, "sys_descr": sys_descr, "interfaces": len(indices)}
    except HTTPException:
        raise
    except Exception as e:
        with conn() as c, c.cursor() as cur:
            cur.execute("UPDATE exporters SET snmp_last_poll=now(),snmp_last_error=%s WHERE ip=%s::inet", (str(e)[:500], exporter))
        raise HTTPException(502, f"SNMP poll failed: {e}")


@app.post("/api/exporters/{exporter}/snmp/poll")
def snmp_poll(exporter: str):
    return perform_snmp_poll(exporter)
