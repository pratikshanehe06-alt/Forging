"""CoreOT Platform Suite - APM Module Backend

FastAPI + MongoDB backend providing:
- JWT authentication (tenant + email + password)
- Multi-tenant Assets / Alarms / Plants / Areas
- Live telemetry ingestion (Node-RED / HTTP)
- WebSocket broadcast of telemetry to connected React clients
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional

import jwt
from dotenv import load_dotenv
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.security import OAuth2PasswordBearer
from pg_db import PostgresDB, create_pool
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from starlette.middleware.cors import CORSMiddleware

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("coreot")

POSTGRES_URL = os.environ["POSTGRES_URL"]  # e.g. postgresql://user:pass@host:5432/coreot
JWT_SECRET = os.environ.get("JWT_SECRET", "coreot-dev-secret-change-me")
JWT_ALG = "HS256"
JWT_EXPIRES_MIN = 60 * 24 * 7  # 7 days

ESCALATION_MINUTES = int(os.environ.get("ESCALATION_MINUTES", "5"))


MODULE_CATALOG: List[Dict[str, Any]] = [
    {"key": "APM", "name": "Asset Performance Management",
     "description": "Assets registry, health, live telemetry, digital-twin animation.",
     "default": True, "gates": ["assets", "hierarchy", "asset360", "operator"]},
    {"key": "EEMS", "name": "Enterprise Energy Management",
     "description": "EMS, PQI, DERMS and Utility metering across every plant.",
     "default": True, "gates": ["energy"]},
    {"key": "DIGITAL_TWIN", "name": "Digital Twin",
     "description": "Visual real-time twin of every machine on the floor.",
     "default": True, "gates": ["twin"]},
    {"key": "OEE_APS", "name": "OEE & APS",
     "description": "Availability × Performance × Quality plus advanced planning.",
     "default": True, "gates": ["oee", "aps"]},
    {"key": "AI_COPILOT", "name": "AI Copilot",
     "description": "Natural-language insights, downtime RCA and recommendations.",
     "default": False, "gates": ["copilot"]},
    {"key": "REPORTS", "name": "Reports & Forecasting",
     "description": "Production, energy, OEE, downtime — CSV/Excel/PDF exports.",
     "default": True, "gates": ["reports"]},
    {"key": "AUDIT", "name": "Audit & Compliance",
     "description": "Every config change, ack and login — searchable and exportable.",
     "default": True, "gates": ["audit"]},
]


async def get_tenant_modules(tenant_id: str) -> Dict[str, bool]:
    doc = await db.tenant_modules.find_one({"tenant_id": tenant_id}, {"_id": 0})
    if not doc:
        state = {m["key"]: m["default"] for m in MODULE_CATALOG}
        await db.tenant_modules.insert_one({"tenant_id": tenant_id, "modules": state})
        return state
    return doc.get("modules", {})


def require_module(module_key: str):
    async def _dep(user: "User" = Depends(get_current_user)) -> "User":
        modules = await get_tenant_modules(user.tenant_id)
        if not modules.get(module_key, False):
            raise HTTPException(status_code=403,
                                detail=f"Module {module_key} is disabled for this tenant")
        return user
    return _dep


def ensure_ingest_key() -> str:
    """Guarantee an INGEST_KEY exists; auto-generate + persist to backend/.env if missing."""
    existing = os.environ.get("INGEST_KEY", "").strip()
    if existing:
        return existing
    key = secrets.token_hex(24)
    env_path = ROOT_DIR / ".env"
    try:
        content = env_path.read_text() if env_path.exists() else ""
        if "INGEST_KEY=" not in content:
            if content and not content.endswith("\n"):
                content += "\n"
            content += f'INGEST_KEY="{key}"\n'
            env_path.write_text(content)
    except Exception as exc:
        logger.warning("Could not persist INGEST_KEY to .env: %s", exc)
    os.environ["INGEST_KEY"] = key
    logger.info("Generated CoreOT INGEST_KEY (add to Node-RED X-Ingest-Key header): %s", key)
    return key

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

db: "PostgresDB" = None  # set during lifespan startup (asyncpg pool is async)

oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class Tenant(BaseModel):
    id: str
    code: str
    name: str


class User(BaseModel):
    id: str
    tenant_id: str
    email: EmailStr
    name: str
    role: str  # TENANT_ADMIN | CXO | PRODUCTION_MANAGER | SUPERVISOR | OPERATOR
    employee_id: Optional[str] = None
    plants: List[str] = []
    active: bool = True
    assigned_asset_id: Optional[str] = None


class LoginRequest(BaseModel):
    tenant_code: str
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: User
    tenant: Tenant
    modules: Dict[str, bool] = {}


class Plant(BaseModel):
    id: str
    tenant_id: str
    name: str
    code: str
    location: str


class Area(BaseModel):
    id: str
    tenant_id: str
    plant_id: str
    name: str


class Asset(BaseModel):
    id: str
    tenant_id: str
    plant_id: str
    area_id: str
    asset_code: str
    name: str
    asset_type: str
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial: Optional[str] = None
    location: Optional[str] = None
    criticality: str = "MEDIUM"
    status: str = "OFFLINE"  # RUNNING | STOPPED | IDLE | WARNING | FAULT | CRITICAL | OFFLINE
    health: int = 100
    installation_date: Optional[str] = None
    last_seen: Optional[str] = None
    thresholds: Optional[Dict[str, Dict[str, float]]] = None


class AssetCreate(BaseModel):
    asset_code: str
    name: str
    asset_type: str
    plant_id: str
    area_id: str
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial: Optional[str] = None
    location: Optional[str] = None
    criticality: str = "MEDIUM"
    status: str = "OFFLINE"
    health: int = 100


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    asset_type: Optional[str] = None
    plant_id: Optional[str] = None
    area_id: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial: Optional[str] = None
    location: Optional[str] = None
    criticality: Optional[str] = None
    status: Optional[str] = None
    health: Optional[int] = None


class Alarm(BaseModel):
    id: str
    tenant_id: str
    asset_id: str
    asset_code: str
    severity: str  # CRITICAL | MAJOR | MINOR | INFO
    message: str
    acknowledged: bool = False
    created_at: str


class TelemetryIn(BaseModel):
    """Ingested from Node-RED / OT layer.

    Accepts either asset_id (UUID) or asset_code (e.g. CNC-DEMO-01)."""

    asset_id: Optional[str] = None
    asset_code: Optional[str] = None
    machine_status: Optional[str] = None  # RUNNING | STOPPED | IDLE | FAULT
    temperature: Optional[float] = None
    vibration: Optional[float] = None
    pressure: Optional[float] = None
    rpm: Optional[float] = None
    voltage: Optional[float] = None
    current: Optional[float] = None
    flow: Optional[float] = None
    power: Optional[float] = None
    energy: Optional[float] = None
    production_count: Optional[int] = None
    good_count: Optional[int] = None
    reject_count: Optional[int] = None
    alarm: Optional[bool] = None
    alarm_message: Optional[str] = None
    timestamp: Optional[str] = None


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def hash_password(p: str) -> str:
    return pwd_context.hash(p)


def verify_password(p: str, hashed: str) -> bool:
    return pwd_context.verify(p, hashed)


def create_token(user_id: str, tenant_id: str) -> str:
    payload = {
        "sub": user_id,
        "tid": tenant_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRES_MIN),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


async def get_current_user(token: Annotated[Optional[str], Depends(oauth2)]) -> User:
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = payload.get("sub")
    doc = await db.users.find_one({"id": user_id}, {"_id": 0, "password": 0})
    if not doc:
        raise HTTPException(status_code=401, detail="User not found")
    return User(**doc)


# ---------------------------------------------------------------------------
# WebSocket manager
# ---------------------------------------------------------------------------


class WSManager:
    def __init__(self) -> None:
        self.tenant_conns: Dict[str, List[WebSocket]] = {}

    async def connect(self, ws: WebSocket, tenant_id: str) -> None:
        await ws.accept()
        self.tenant_conns.setdefault(tenant_id, []).append(ws)

    def disconnect(self, ws: WebSocket, tenant_id: str) -> None:
        if tenant_id in self.tenant_conns and ws in self.tenant_conns[tenant_id]:
            self.tenant_conns[tenant_id].remove(ws)

    async def broadcast(self, tenant_id: str, message: Dict[str, Any]) -> None:
        conns = list(self.tenant_conns.get(tenant_id, []))
        for c in conns:
            try:
                await c.send_json(message)
            except Exception:
                self.disconnect(c, tenant_id)


ws_manager = WSManager()


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

TENANTS_SEED = [
    {"code": "PLATFORM", "name": "CoreOT Platform"},
    {"code": "SBF", "name": "SB Forgtech Pvt Ltd"},
    {"code": "ABC", "name": "ABC Manufacturing Pvt Ltd"},
]

USERS_SEED = [
    {
        "email": "superadmin@coreot.com",
        "name": "Platform Admin",
        "role": "PLATFORM_SUPER_ADMIN",
        "password": "Super@123",
        "tenant_code": "PLATFORM",
        "employee_id": "SA-001",
    },
    {
        "email": "tenantadmin@sbforgtech.com",
        "name": "Rajesh Kumar",
        "role": "TENANT_ADMIN",
        "password": "Admin@123",
        "tenant_code": "SBF",
        "employee_id": "EMP-001",
    },
    {
        "email": "cxo@sbforgtech.com",
        "name": "Anita Deshpande",
        "role": "CXO",
        "password": "Cxo@123",
        "tenant_code": "SBF",
        "employee_id": "EMP-002",
    },
    {
        "email": "production@sbforgtech.com",
        "name": "Vikas Shah",
        "role": "PRODUCTION_MANAGER",
        "password": "Prod@123",
        "tenant_code": "SBF",
        "employee_id": "EMP-003",
    },
    {
        "email": "supervisor@sbforgtech.com",
        "name": "Priya Menon",
        "role": "SUPERVISOR",
        "password": "Super@123",
        "tenant_code": "SBF",
        "employee_id": "EMP-004",
    },
    {
        "email": "operator@sbforgtech.com",
        "name": "Suresh Patil",
        "role": "OPERATOR",
        "password": "Operator@123",
        "tenant_code": "SBF",
        "employee_id": "EMP-005",
    },
]

AREAS_SEED = ["Forging Area", "Heat Treatment", "Utilities", "Storage"]

ASSET_TYPES = {
    "Forging Area": ["Hydraulic Press", "Forging Hammer", "CNC Machine"],
    "Heat Treatment": ["Induction Furnace", "Quench Tank", "Tempering Oven"],
    "Utilities": ["Air Compressor", "Water Chiller", "Cooling Tower"],
    "Storage": ["Overhead Crane", "Conveyor"],
}

STATUS_POOL = ["RUNNING"] * 6 + ["IDLE"] * 2 + ["FAULT"] + ["OFFLINE"]


async def seed_database() -> None:
    if await db.tenants.count_documents({}) > 0:
        logger.info("Database already seeded, skipping.")
        return

    logger.info("Seeding CoreOT demo data...")

    tenants_by_code: Dict[str, str] = {}
    for t in TENANTS_SEED:
        tid = str(uuid.uuid4())
        tenants_by_code[t["code"]] = tid
        await db.tenants.insert_one({"id": tid, "code": t["code"], "name": t["name"]})

    # Users
    for u in USERS_SEED:
        await db.users.insert_one(
            {
                "id": str(uuid.uuid4()),
                "tenant_id": tenants_by_code[u["tenant_code"]],
                "email": u["email"],
                "name": u["name"],
                "role": u["role"],
                "employee_id": u["employee_id"],
                "plants": [],
                "active": True,
                "password": hash_password(u["password"]),
            }
        )

    sbf = tenants_by_code["SBF"]

    # Plant + areas
    plant_id = str(uuid.uuid4())
    await db.plants.insert_one(
        {
            "id": plant_id,
            "tenant_id": sbf,
            "name": "Pune Plant",
            "code": "PUN-01",
            "location": "Pune, MH",
        }
    )

    # Additional plants for CXO Comparison Board
    other_plants: List[Dict[str, Any]] = []
    for pname, pcode, ploc in [
        ("Mumbai Plant", "MUM-01", "Mumbai, MH"),
        ("Nashik Plant", "NSK-01", "Nashik, MH"),
    ]:
        pid = str(uuid.uuid4())
        await db.plants.insert_one(
            {"id": pid, "tenant_id": sbf, "name": pname, "code": pcode, "location": ploc}
        )
        # one flagship area per plant
        aid = str(uuid.uuid4())
        await db.areas.insert_one(
            {"id": aid, "tenant_id": sbf, "plant_id": pid, "name": "Main Line"}
        )
        # seed a small asset pool for comparison KPIs
        for i in range(8):
            atype = random.choice(["Hydraulic Press", "Induction Furnace", "Air Compressor", "Water Chiller"])
            st = random.choice(STATUS_POOL)
            health_map = {"RUNNING": (75, 99), "IDLE": (60, 90), "FAULT": (30, 55), "OFFLINE": (0, 40)}
            low, high = health_map.get(st, (50, 90))
            await db.assets.insert_one(
                {
                    "id": str(uuid.uuid4()),
                    "tenant_id": sbf,
                    "plant_id": pid,
                    "area_id": aid,
                    "asset_code": f"{pcode}-{atype.split()[0][:3].upper()}-{i+1:02d}",
                    "name": f"{atype} {i+1}",
                    "asset_type": atype,
                    "manufacturer": random.choice(["Siemens", "ABB", "Bosch"]),
                    "model": f"M-{random.randint(100,999)}",
                    "serial": f"SN-{random.randint(10000,99999)}",
                    "criticality": random.choice(["LOW", "MEDIUM", "HIGH"]),
                    "status": st,
                    "health": random.randint(low, high),
                    "installation_date": f"20{random.randint(19,23)}-06-01",
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                }
            )
        other_plants.append({"id": pid, "name": pname})

    area_ids: Dict[str, str] = {}
    for a in AREAS_SEED:
        aid = str(uuid.uuid4())
        area_ids[a] = aid
        await db.areas.insert_one({"id": aid, "tenant_id": sbf, "plant_id": plant_id, "name": a})

    # Demo CNC anchor asset
    cnc_demo_id = str(uuid.uuid4())
    await db.assets.insert_one(
        {
            "id": cnc_demo_id,
            "tenant_id": sbf,
            "plant_id": plant_id,
            "area_id": area_ids["Forging Area"],
            "asset_code": "CNC-DEMO-01",
            "name": "CNC Demo Machine",
            "asset_type": "CNC Machine",
            "manufacturer": "Siemens",
            "model": "S840D",
            "serial": "SN-DEMO-001",
            "location": "Pune, MH · Forging Area · Bay 1",
            "criticality": "HIGH",
            "status": "RUNNING",
            "health": 91,
            "installation_date": "2022-04-10",
            "last_seen": datetime.now(timezone.utc).isoformat(),
        }
    )

    # Assign the CNC demo asset to the operator user for the Operator Runbook page
    await db.users.update_one(
        {"email": "operator@sbforgtech.com"},
        {"$set": {"assigned_asset_id": cnc_demo_id}},
    )

    # Generate remaining assets to reach ~45 total
    counter = {"Hydraulic Press": 0, "Forging Hammer": 0, "CNC Machine": 1, "Induction Furnace": 0,
               "Quench Tank": 0, "Tempering Oven": 0, "Air Compressor": 0, "Water Chiller": 0,
               "Cooling Tower": 0, "Overhead Crane": 0, "Conveyor": 0}

    async def add_asset(area: str, atype: str, status_hint: Optional[str] = None, health_hint: Optional[int] = None):
        counter[atype] += 1
        code_prefix_map = {
            "Hydraulic Press": "Press",
            "Forging Hammer": "Hammer",
            "CNC Machine": "CNC",
            "Induction Furnace": "Furnace",
            "Quench Tank": "Quench",
            "Tempering Oven": "Oven",
            "Air Compressor": "Compressor",
            "Water Chiller": "Chiller",
            "Cooling Tower": "Tower",
            "Overhead Crane": "Crane",
            "Conveyor": "Conveyor",
        }
        code = f"{code_prefix_map[atype]}-{counter[atype]:02d}"
        st = status_hint or random.choice(STATUS_POOL)
        health_map = {"RUNNING": (75, 99), "IDLE": (60, 90), "FAULT": (30, 55), "OFFLINE": (0, 40)}
        low, high = health_map.get(st, (50, 90))
        h = health_hint if health_hint is not None else random.randint(low, high)
        await db.assets.insert_one(
            {
                "id": str(uuid.uuid4()),
                "tenant_id": sbf,
                "plant_id": plant_id,
                "area_id": area_ids[area],
                "asset_code": code,
                "name": code,
                "asset_type": atype,
                "manufacturer": random.choice(["Siemens", "ABB", "Bosch", "Kirloskar", "L&T"]),
                "model": f"M-{random.randint(100,999)}",
                "serial": f"SN-{random.randint(10000,99999)}",
                "location": f"Pune, MH · {area} · Bay {random.randint(1, 6)}",
                "criticality": random.choice(["LOW", "MEDIUM", "HIGH"]),
                "status": st,
                "health": h,
                "installation_date": f"20{random.randint(18,23)}-0{random.randint(1,9)}-15",
                "last_seen": datetime.now(timezone.utc).isoformat(),
            }
        )

    # Match screenshot's hero assets
    await add_asset("Forging Area", "Hydraulic Press", "RUNNING", 98)
    await add_asset("Forging Area", "Hydraulic Press", "FAULT", 45)
    await add_asset("Heat Treatment", "Induction Furnace", "RUNNING", 70)
    await add_asset("Heat Treatment", "Induction Furnace", "IDLE", 68)
    await add_asset("Utilities", "Air Compressor", "RUNNING", 82)
    await add_asset("Utilities", "Water Chiller", "RUNNING", 80)

    # Fill to 45
    plan = [
        ("Forging Area", 12),
        ("Heat Treatment", 8),
        ("Utilities", 10),
        ("Storage", 8),
    ]
    for area, n in plan:
        for _ in range(n):
            atype = random.choice(ASSET_TYPES[area])
            await add_asset(area, atype)

    # Alarms
    all_assets = await db.assets.find({"tenant_id": sbf}, {"_id": 0}).to_list(500)
    alarm_msgs = [
        ("CRITICAL", "Hydraulic Pressure High"),
        ("CRITICAL", "Temperature Critical"),
        ("MAJOR", "Vibration High"),
        ("MAJOR", "Temperature High"),
        ("MINOR", "Coolant Flow Low"),
        ("MINOR", "Power Factor Drop"),
        ("MAJOR", "RPM Deviation"),
        ("MINOR", "Filter Clogged"),
        ("CRITICAL", "Bearing Overheat"),
        ("MAJOR", "Oil Pressure Drop"),
        ("MINOR", "Air Leak Detected"),
        ("MAJOR", "Motor Overload"),
    ]
    faulty_assets = [a for a in all_assets if a["status"] in ("FAULT", "IDLE")] or all_assets
    now = datetime.now(timezone.utc)
    for i, (sev, msg) in enumerate(alarm_msgs):
        a = random.choice(faulty_assets)
        await db.alarms.insert_one(
            {
                "id": str(uuid.uuid4()),
                "tenant_id": sbf,
                "asset_id": a["id"],
                "asset_code": a["asset_code"],
                "severity": sev,
                "message": msg,
                "acknowledged": False,
                "created_at": (now - timedelta(minutes=15 * i)).isoformat(),
            }
        )

    # ---- Lines (for OEE per-line breakdown) ----
    lines_seed = [
        ("Forging Area", "Forge Line 1"),
        ("Forging Area", "Forge Line 2"),
        ("Heat Treatment", "Anneal Line"),
        ("Heat Treatment", "Temper Line"),
        ("Utilities", "Utility Loop"),
    ]
    for area_name, line_name in lines_seed:
        await db.lines.insert_one({
            "id": str(uuid.uuid4()),
            "tenant_id": sbf,
            "plant_id": plant_id,
            "area_id": area_ids[area_name],
            "name": line_name,
            "ideal_rate_per_hr": random.randint(40, 80),
        })

    # ---- Downtime events (last 7 days) ----
    reasons = ["Tool change", "Material shortage", "Breakdown", "Setup", "No operator", "Power dip"]
    for i in range(24):
        a = random.choice(all_assets)
        started = now - timedelta(days=random.randint(0, 6), hours=random.randint(0, 23))
        duration = random.randint(5, 60)
        await db.downtime_events.insert_one({
            "id": str(uuid.uuid4()),
            "tenant_id": sbf,
            "asset_id": a["id"],
            "asset_code": a["asset_code"],
            "plant_id": a["plant_id"],
            "reason": random.choice(reasons),
            "duration_min": duration,
            "started_at": started.isoformat(),
            "ended_at": (started + timedelta(minutes=duration)).isoformat(),
        })

    # ---- Energy records (30 days per plant) ----
    all_plants = await db.plants.find({"tenant_id": sbf}, {"_id": 0}).to_list(50)
    rate_inr_per_kwh = 9.4
    for p in all_plants:
        seed_rng = random.Random(sum(ord(c) for c in p["code"]))
        base_load = 4500 + seed_rng.random() * 3000
        for d in range(30):
            day = (now - timedelta(days=d)).date().isoformat()
            kwh = round(base_load + seed_rng.random() * 800 - (200 if d % 7 in (5, 6) else 0), 1)
            pf = round(0.85 + seed_rng.random() * 0.13, 3)
            thd = round(2.0 + seed_rng.random() * 3.5, 2)
            peak_kw = round(kwh / 22 + seed_rng.random() * 40, 1)
            await db.energy_records.insert_one({
                "id": str(uuid.uuid4()),
                "tenant_id": sbf,
                "plant_id": p["id"],
                "plant_name": p["name"],
                "date": day,
                "kwh": kwh,
                "cost_inr": round(kwh * rate_inr_per_kwh, 0),
                "peak_kw": peak_kw,
                "power_factor": pf,
                "thd": thd,
                "renewable_pct": round(8 + seed_rng.random() * 22, 1),
                "carbon_kg": round(kwh * 0.82, 1),
            })

    # ---- Some initial production_log entries so OEE has real numbers ----
    op = await db.users.find_one({"email": "operator@sbforgtech.com"}, {"_id": 0})
    cnc = await db.assets.find_one({"asset_code": "CNC-DEMO-01"}, {"_id": 0})
    if op and cnc:
        for d in range(7):
            for _ in range(random.randint(2, 4)):
                produced = random.randint(60, 120)
                good = int(produced * random.uniform(0.9, 0.98))
                ts = (now - timedelta(days=d, hours=random.randint(0, 23))).isoformat()
                await db.production_log.insert_one({
                    "id": str(uuid.uuid4()),
                    "tenant_id": sbf,
                    "asset_id": cnc["id"],
                    "asset_code": cnc["asset_code"],
                    "operator_id": op["id"],
                    "operator_name": op["name"],
                    "produced": produced,
                    "good": good,
                    "reject": produced - good,
                    "ts": ts,
                })

    # ---- Maintenance history ----
    m_types = ["PREVENTIVE", "CORRECTIVE", "PREDICTIVE"]
    m_desc = {
        "PREVENTIVE": ["Oil change", "Filter replacement", "Belt inspection", "Lubrication", "Bolt torque check"],
        "CORRECTIVE": ["Bearing replaced", "Motor rewinding", "Sensor replaced", "Coupling repair"],
        "PREDICTIVE": ["Vibration diagnostics", "Thermal imaging", "Oil analysis"],
    }
    techs = ["A. Sharma", "R. Iyer", "M. Patil", "S. Khan", "N. Deshmukh"]
    for a in all_assets[:20]:
        n = random.randint(2, 5)
        for _ in range(n):
            mtype = random.choice(m_types)
            performed = now - timedelta(days=random.randint(2, 180))
            next_due = performed + timedelta(days=random.randint(30, 120))
            cost = random.randint(1500, 22000)
            await db.maintenance_records.insert_one({
                "id": str(uuid.uuid4()),
                "tenant_id": sbf,
                "asset_id": a["id"],
                "asset_code": a["asset_code"],
                "type": mtype,
                "description": random.choice(m_desc[mtype]),
                "technician": random.choice(techs),
                "cost_inr": cost,
                "performed_at": performed.isoformat(),
                "next_due_at": next_due.isoformat(),
            })

    logger.info("Seed complete.")


# ---------------------------------------------------------------------------
# Live telemetry simulator (for CNC-DEMO-01)
# ---------------------------------------------------------------------------


async def telemetry_simulator() -> None:
    """Nudges CNC-DEMO-01 telemetry so the UI feels alive even without Node-RED.

    Real Node-RED / MQTT bridge overrides these values via POST /api/telemetry/ingest.
    """
    await asyncio.sleep(5)
    while True:
        try:
            cnc = await db.assets.find_one({"asset_code": "CNC-DEMO-01"}, {"_id": 0})
            if cnc:
                last = await db.telemetry.find_one(
                    {"asset_id": cnc["id"]}, {"_id": 0}, sort=[("ts", -1)]
                )
                base = last or {
                    "temperature": 62.0,
                    "vibration": 2.5,
                    "pressure": 5.4,
                    "rpm": 1450,
                    "voltage": 415,
                    "current": 12.4,
                    "power": 8.7,
                    "energy": 126.8,
                    "production_count": 640,
                    "good_count": 625,
                    "reject_count": 15,
                    "machine_status": cnc.get("status", "RUNNING"),
                }
                if base.get("machine_status", "RUNNING") == "RUNNING":
                    temp = float(base.get("temperature", 62)) + random.uniform(-0.4, 0.6)
                    vib = max(0.1, float(base.get("vibration", 2.5)) + random.uniform(-0.2, 0.3))
                    rpm = max(1200, min(1600, float(base.get("rpm", 1450)) + random.uniform(-20, 20)))
                    power = max(6.0, float(base.get("power", 8.7)) + random.uniform(-0.4, 0.4))
                    energy = float(base.get("energy", 126.8)) + power / 3600 * 5
                    prod = int(base.get("production_count", 640)) + random.choice([0, 0, 1])
                    good = int(base.get("good_count", 625)) + (1 if prod > int(base.get("production_count", 640)) and random.random() > 0.05 else 0)
                    rej = int(prod) - good
                    payload = TelemetryIn(
                        asset_code="CNC-DEMO-01",
                        machine_status="RUNNING",
                        temperature=round(temp, 2),
                        vibration=round(vib, 2),
                        pressure=round(float(base.get("pressure", 5.4)) + random.uniform(-0.1, 0.1), 2),
                        rpm=round(rpm, 0),
                        voltage=round(415 + random.uniform(-2, 2), 1),
                        current=round(float(base.get("current", 12.4)) + random.uniform(-0.3, 0.3), 2),
                        power=round(power, 2),
                        energy=round(energy, 2),
                        production_count=prod,
                        good_count=good,
                        reject_count=rej,
                    )
                    await ingest_telemetry_internal(payload)
        except Exception as exc:
            logger.warning("Simulator tick failed: %s", exc)
        await asyncio.sleep(5)


async def ingest_telemetry_internal(payload: TelemetryIn) -> Dict[str, Any]:
    query: Dict[str, Any] = {}
    if payload.asset_id:
        query["id"] = payload.asset_id
    elif payload.asset_code:
        query["asset_code"] = payload.asset_code
    else:
        raise HTTPException(status_code=400, detail="asset_id or asset_code required")

    asset = await db.assets.find_one(query, {"_id": 0})
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    ts = payload.timestamp or datetime.now(timezone.utc).isoformat()
    doc = payload.model_dump(exclude_none=True)
    doc.update({"asset_id": asset["id"], "asset_code": asset["asset_code"], "ts": ts,
                "tenant_id": asset["tenant_id"]})
    await db.telemetry.insert_one(doc)

    # Per-asset thresholds (fall back to platform defaults)
    th = asset.get("thresholds") or {}
    t_warn = (th.get("temperature") or {}).get("warning", 85)
    t_crit = (th.get("temperature") or {}).get("critical", 100)
    v_warn = (th.get("vibration") or {}).get("warning", 8)
    v_crit = (th.get("vibration") or {}).get("critical", 12)

    # Derive status from telemetry + explicit override
    new_status = asset.get("status", "OFFLINE")
    if payload.machine_status:
        m = payload.machine_status.upper()
        mapping = {"RUNNING": "RUNNING", "STOPPED": "STOPPED", "IDLE": "IDLE", "FAULT": "FAULT",
                   "OFF": "OFFLINE", "ON": "RUNNING"}
        new_status = mapping.get(m, m)
    if payload.temperature is not None:
        if payload.temperature > t_crit:
            new_status = "CRITICAL"
        elif payload.temperature > t_warn and new_status in ("RUNNING", "IDLE"):
            new_status = "WARNING"
    if payload.vibration is not None:
        if payload.vibration > v_crit:
            new_status = "CRITICAL"
        elif payload.vibration > v_warn and new_status in ("RUNNING", "IDLE"):
            new_status = "WARNING"
    if payload.alarm:
        new_status = "FAULT"

    health = asset.get("health", 100)
    if payload.temperature is not None:
        if payload.temperature > t_crit:
            health = min(health, 40)
        elif payload.temperature > t_warn:
            health = min(health, 65)
    if payload.vibration is not None:
        if payload.vibration > v_crit:
            health = min(health, 45)
        elif payload.vibration > v_warn:
            health = min(health, 70)

    await db.assets.update_one(
        {"id": asset["id"]},
        {"$set": {"status": new_status, "health": health, "last_seen": ts}},
    )

    if payload.alarm and payload.alarm_message:
        await db.alarms.insert_one(
            {
                "id": str(uuid.uuid4()),
                "tenant_id": asset["tenant_id"],
                "asset_id": asset["id"],
                "asset_code": asset["asset_code"],
                "severity": "CRITICAL",
                "message": payload.alarm_message,
                "acknowledged": False,
                "created_at": ts,
            }
        )

    broadcast = {"type": "telemetry", "asset_id": asset["id"], "asset_code": asset["asset_code"],
                 "status": new_status, "health": health, "data": {k: v for k, v in doc.items() if k != "_id"}}
    await ws_manager.broadcast(asset["tenant_id"], broadcast)
    return {"ok": True, "asset_id": asset["id"], "status": new_status, "health": health}


async def escalation_scanner() -> None:
    """Every 30s, escalate CRITICAL alarms unacknowledged for > ESCALATION_MINUTES.

    Log-only escalation for now: create an entry in `escalations`, mark alarm as
    escalated, broadcast a WS event so the UI can flag it. Swap the notifier for
    Twilio/Telegram/Slack later without touching this scanner.
    """
    await asyncio.sleep(10)
    while True:
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(minutes=ESCALATION_MINUTES)).isoformat()
            cursor = db.alarms.find(
                {
                    "severity": "CRITICAL",
                    "acknowledged": False,
                    "escalated": {"$ne": True},
                    "created_at": {"$lte": cutoff},
                },
                {"_id": 0},
            )
            async for alarm in cursor:
                now = datetime.now(timezone.utc).isoformat()
                await db.alarms.update_one(
                    {"id": alarm["id"]},
                    {"$set": {"escalated": True, "escalated_at": now}},
                )
                event = {
                    "id": str(uuid.uuid4()),
                    "tenant_id": alarm["tenant_id"],
                    "alarm_id": alarm["id"],
                    "asset_id": alarm["asset_id"],
                    "asset_code": alarm["asset_code"],
                    "severity": alarm["severity"],
                    "message": alarm["message"],
                    "channel": "log",
                    "recipient": "on-call",
                    "status": "logged",
                    "escalated_at": now,
                }
                await db.escalations.insert_one(event.copy())
                logger.warning(
                    "ESCALATION [%s] alarm=%s asset=%s msg=%s (unacked >%dmin)",
                    alarm["tenant_id"], alarm["id"], alarm["asset_code"], alarm["message"], ESCALATION_MINUTES,
                )
                event.pop("_id", None)
                await ws_manager.broadcast(alarm["tenant_id"], {"type": "escalation", "event": event})
        except Exception as exc:
            logger.warning("Escalation scanner tick failed: %s", exc)
        await asyncio.sleep(30)


# ---------------------------------------------------------------------------
# App lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db
    pool = await create_pool(POSTGRES_URL)
    db = PostgresDB(pool)
    # Note: tables/indexes are created ahead of time by running schema.sql
    # against your Postgres/TimescaleDB instance (see schema.sql in this
    # folder) — there's no per-startup index creation needed here anymore.
    ensure_ingest_key()
    await seed_database()
    # Backfill: ensure REPORTS module is enabled for existing tenants (idempotent)
    async for tm in db.tenant_modules.find({}):
        mods = tm.get("modules", {}) or {}
        changed = False
        for m in MODULE_CATALOG:
            if m["key"] not in mods:
                mods[m["key"]] = m["default"]
                changed = True
        if not mods.get("REPORTS", False):
            mods["REPORTS"] = True
            changed = True
        if changed:
            await db.tenant_modules.update_one({"tenant_id": tm["tenant_id"]}, {"$set": {"modules": mods}})
    tasks = [
        # asyncio.create_task(telemetry_simulator()),  # disabled - using real Node-RED input
        asyncio.create_task(escalation_scanner()),
    ]
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
        await pool.close()


app = FastAPI(title="CoreOT APM API", lifespan=lifespan)
api = APIRouter(prefix="/api")


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------


@api.post("/auth/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    tenant = await db.tenants.find_one({"code": req.tenant_code.upper()}, {"_id": 0})
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid tenant / credentials")
    user_doc = await db.users.find_one({"email": req.email.lower(), "tenant_id": tenant["id"]})
    if not user_doc or not verify_password(req.password, user_doc["password"]):
        raise HTTPException(status_code=401, detail="Invalid tenant / credentials")
    if not user_doc.get("active", True):
        raise HTTPException(status_code=403, detail="Account disabled")
    token = create_token(user_doc["id"], tenant["id"])
    user_doc.pop("password", None)
    user_doc.pop("_id", None)
    modules = await get_tenant_modules(tenant["id"])
    return LoginResponse(access_token=token, user=User(**user_doc), tenant=Tenant(**tenant), modules=modules)


@api.get("/auth/me", response_model=User)
async def me(user: User = Depends(get_current_user)):
    return user


@api.get("/tenants")
async def list_tenants():
    docs = await db.tenants.find({}, {"_id": 0}).to_list(50)
    return docs


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@api.get("/dashboard/summary")
async def dashboard_summary(user: User = Depends(get_current_user),
                            plant_id: Optional[str] = None):
    query: Dict[str, Any] = {"tenant_id": user.tenant_id}
    if plant_id and plant_id != "all":
        query["plant_id"] = plant_id
    assets = await db.assets.find(query, {"_id": 0}).to_list(2000)
    total = len(assets)
    by_status = {"RUNNING": 0, "IDLE": 0, "FAULT": 0, "STOPPED": 0, "WARNING": 0, "CRITICAL": 0, "OFFLINE": 0}
    for a in assets:
        by_status[a.get("status", "OFFLINE")] = by_status.get(a.get("status", "OFFLINE"), 0) + 1
    running = by_status["RUNNING"] + by_status["WARNING"]
    fault = by_status["FAULT"] + by_status["CRITICAL"]
    healthy = sum(1 for a in assets if a["health"] >= 80)
    warning = sum(1 for a in assets if 55 <= a["health"] < 80)
    critical = sum(1 for a in assets if a["health"] < 55 and a["status"] != "OFFLINE")
    offline_h = sum(1 for a in assets if a["status"] == "OFFLINE")
    avg_health = round(sum(a["health"] for a in assets) / total, 1) if total else 0
    # Assets by area
    areas = await db.areas.find({"tenant_id": user.tenant_id}, {"_id": 0}).to_list(50)
    area_map = {a["id"]: a["name"] for a in areas}
    by_area: Dict[str, int] = {}
    for a in assets:
        by_area[area_map.get(a["area_id"], "Other")] = by_area.get(area_map.get(a["area_id"], "Other"), 0) + 1
    # Alarms - filtered by plant if specified
    alarm_query: Dict[str, Any] = {"tenant_id": user.tenant_id}
    if plant_id and plant_id != "all":
        asset_ids = [a["id"] for a in assets]
        alarm_query["asset_id"] = {"$in": asset_ids}
    alarms = await db.alarms.find(alarm_query, {"_id": 0}).sort("created_at", -1).to_list(50)
    active_alarms = len(alarms)
    critical_alarms = sum(1 for a in alarms if a["severity"] == "CRITICAL")
    # Alarms trend (last 7 days count per day)
    trend: List[Dict[str, Any]] = []
    today = datetime.now(timezone.utc).date()
    for i in range(6, -1, -1):
        d = today - timedelta(days=i)
        count = sum(1 for a in alarms if a["created_at"].startswith(d.isoformat()))
        # Simulate historical if none
        if count == 0:
            count = random.randint(3, 25)
        trend.append({"date": d.strftime("%d %b"), "count": count})
    # Top faulty assets
    top_faulty = sorted(assets, key=lambda a: a["health"])[:4]
    top_faulty_out = [{"asset_code": a["asset_code"], "health": a["health"],
                       "status": a["status"], "id": a["id"]} for a in top_faulty]

    return {
        "kpis": {
            "total_assets": total,
            "running": running,
            "idle": by_status["IDLE"],
            "fault": fault,
            "offline": by_status["OFFLINE"] + by_status["STOPPED"],
            "active_alarms": active_alarms,
            "critical_alarms": critical_alarms,
        },
        "health_overview": {
            "healthy": healthy,
            "warning": warning,
            "critical": critical,
            "offline": offline_h,
            "average": avg_health,
        },
        "assets_by_area": [{"area": k, "count": v} for k, v in sorted(by_area.items(), key=lambda x: -x[1])],
        "alarms_trend": trend,
        "recent_alarms": alarms[:8],
        "top_faulty_assets": top_faulty_out,
    }


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


@api.get("/assets")
async def list_assets(
    user: User = Depends(require_module("APM")),
    plant_id: Optional[str] = None,
    area_id: Optional[str] = None,
    asset_type: Optional[str] = None,
    asset_status: Optional[str] = Query(None, alias="status"),
    q: Optional[str] = None,
):
    query: Dict[str, Any] = {"tenant_id": user.tenant_id}
    if plant_id and plant_id != "all":
        query["plant_id"] = plant_id
    if area_id and area_id != "all":
        query["area_id"] = area_id
    if asset_type and asset_type != "all":
        query["asset_type"] = asset_type
    if asset_status and asset_status != "all":
        query["status"] = asset_status.upper()
    if q:
        query["$or"] = [
            {"name": {"$regex": q, "$options": "i"}},
            {"asset_code": {"$regex": q, "$options": "i"}},
        ]
    assets = await db.assets.find(query, {"_id": 0}).to_list(1000)
    areas = await db.areas.find({"tenant_id": user.tenant_id}, {"_id": 0}).to_list(50)
    area_map = {a["id"]: a["name"] for a in areas}
    for a in assets:
        a["area_name"] = area_map.get(a["area_id"], "-")
    return assets


@api.post("/assets", response_model=Asset)
async def create_asset(payload: AssetCreate, user: User = Depends(get_current_user)):
    if user.role not in ("TENANT_ADMIN", "PRODUCTION_MANAGER"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    doc = payload.model_dump()
    doc["id"] = str(uuid.uuid4())
    doc["tenant_id"] = user.tenant_id
    doc["last_seen"] = datetime.now(timezone.utc).isoformat()
    await db.assets.insert_one(doc.copy())
    doc.pop("_id", None)
    return Asset(**doc)


@api.get("/assets/hierarchy")
async def asset_hierarchy(user: User = Depends(get_current_user)):
    plants = await db.plants.find({"tenant_id": user.tenant_id}, {"_id": 0}).to_list(50)
    areas = await db.areas.find({"tenant_id": user.tenant_id}, {"_id": 0}).to_list(200)
    assets = await db.assets.find({"tenant_id": user.tenant_id}, {"_id": 0}).to_list(1000)
    tree = []
    for p in plants:
        p_areas = []
        for a in [x for x in areas if x["plant_id"] == p["id"]]:
            p_areas.append({
                "id": a["id"],
                "name": a["name"],
                "assets": [{"id": x["id"], "name": x["name"], "asset_code": x["asset_code"],
                            "status": x["status"], "asset_type": x["asset_type"]}
                           for x in assets if x["area_id"] == a["id"]],
            })
        tree.append({"id": p["id"], "name": p["name"], "areas": p_areas})
    return tree


@api.get("/assets/{asset_id}")
async def get_asset(asset_id: str, user: User = Depends(get_current_user)):
    a = await db.assets.find_one({"id": asset_id, "tenant_id": user.tenant_id}, {"_id": 0})
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    area = await db.areas.find_one({"id": a["area_id"]}, {"_id": 0})
    plant = await db.plants.find_one({"id": a["plant_id"]}, {"_id": 0})
    a["area_name"] = area["name"] if area else "-"
    a["plant_name"] = plant["name"] if plant else "-"
    return a


@api.put("/assets/{asset_id}", response_model=Asset)
async def update_asset(asset_id: str, payload: AssetUpdate, user: User = Depends(get_current_user)):
    if user.role not in ("TENANT_ADMIN", "PRODUCTION_MANAGER"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not update:
        raise HTTPException(status_code=400, detail="No fields to update")
    res = await db.assets.update_one({"id": asset_id, "tenant_id": user.tenant_id}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Asset not found")
    doc = await db.assets.find_one({"id": asset_id}, {"_id": 0})
    return Asset(**doc)


@api.get("/assets/{asset_id}/telemetry/latest")
async def latest_telemetry(asset_id: str, user: User = Depends(get_current_user)):
    a = await db.assets.find_one({"id": asset_id, "tenant_id": user.tenant_id}, {"_id": 0})
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    t = await db.telemetry.find_one({"asset_id": asset_id}, {"_id": 0}, sort=[("ts", -1)])
    return t or {}


@api.get("/assets/{asset_id}/telemetry/history")
async def telemetry_history(asset_id: str, user: User = Depends(get_current_user),
                            limit: int = 60):
    a = await db.assets.find_one({"id": asset_id, "tenant_id": user.tenant_id}, {"_id": 0})
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    rows = await db.telemetry.find({"asset_id": asset_id}, {"_id": 0}).sort("ts", -1).to_list(limit)
    return list(reversed(rows))


# ---------------------------------------------------------------------------
# Alarms
# ---------------------------------------------------------------------------


@api.get("/alarms")
async def list_alarms(user: User = Depends(get_current_user),
                      severity: Optional[str] = None,
                      acknowledged: Optional[bool] = None,
                      limit: int = 100):
    query: Dict[str, Any] = {"tenant_id": user.tenant_id}
    if severity:
        query["severity"] = severity.upper()
    if acknowledged is not None:
        query["acknowledged"] = acknowledged
    rows = await db.alarms.find(query, {"_id": 0}).sort("created_at", -1).to_list(limit)
    return rows


@api.post("/alarms/{alarm_id}/acknowledge")
async def acknowledge_alarm(alarm_id: str, user: User = Depends(get_current_user)):
    res = await db.alarms.update_one(
        {"id": alarm_id, "tenant_id": user.tenant_id},
        {"$set": {"acknowledged": True, "acknowledged_by": user.email,
                  "acknowledged_at": datetime.now(timezone.utc).isoformat()}},
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Alarm not found")
    await record_audit(user, "alarm.ack", "alarm", alarm_id, {})
    return {"ok": True}


# ---------------------------------------------------------------------------
# Areas / Plants
# ---------------------------------------------------------------------------


@api.get("/areas")
async def list_areas(user: User = Depends(get_current_user)):
    return await db.areas.find({"tenant_id": user.tenant_id}, {"_id": 0}).to_list(200)


@api.get("/plants")
async def list_plants(user: User = Depends(get_current_user)):
    return await db.plants.find({"tenant_id": user.tenant_id}, {"_id": 0}).to_list(50)


# ---------------------------------------------------------------------------
# Telemetry ingest (Node-RED)
# ---------------------------------------------------------------------------


@api.post("/telemetry/ingest")
async def telemetry_ingest(
    payload: TelemetryIn,
    x_ingest_key: Annotated[Optional[str], Header(alias="X-Ingest-Key")] = None,
):
    """Ingest endpoint for Node-RED / OT gateway. Requires X-Ingest-Key header
    matching the server's INGEST_KEY (auto-generated on first boot and stored in backend/.env).
    """
    expected = os.environ.get("INGEST_KEY", "")
    if not expected or not x_ingest_key or not secrets.compare_digest(x_ingest_key, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing X-Ingest-Key")
    return await ingest_telemetry_internal(payload)


@api.get("/ingest/key-hint")
async def ingest_key_hint(user: User = Depends(get_current_user)):
    """Return a masked hint of the current ingest key (tenant admins only)."""
    if user.role != "TENANT_ADMIN":
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    key = os.environ.get("INGEST_KEY", "")
    if not key:
        return {"configured": False}
    return {"configured": True, "hint": f"{key[:6]}…{key[-4:]}", "length": len(key)}


# ---------------------------------------------------------------------------
# Modules (activation / deactivation)
# ---------------------------------------------------------------------------


@api.get("/modules")
async def list_modules(user: User = Depends(get_current_user)):
    state = await get_tenant_modules(user.tenant_id)
    out = []
    for m in MODULE_CATALOG:
        out.append({
            "key": m["key"],
            "name": m["name"],
            "description": m["description"],
            "enabled": bool(state.get(m["key"], m["default"])),
        })
    return out


class ModuleToggle(BaseModel):
    enabled: bool


@api.put("/modules/{module_key}")
async def toggle_module(module_key: str, payload: ModuleToggle,
                        user: User = Depends(get_current_user)):
    if user.role != "TENANT_ADMIN":
        raise HTTPException(status_code=403, detail="Only Tenant Admin can toggle modules")
    if module_key not in {m["key"] for m in MODULE_CATALOG}:
        raise HTTPException(status_code=404, detail="Unknown module")
    state = await get_tenant_modules(user.tenant_id)
    state[module_key] = payload.enabled
    await db.tenant_modules.update_one(
        {"tenant_id": user.tenant_id},
        {"$set": {"modules": state}},
        upsert=True,
    )
    await ws_manager.broadcast(user.tenant_id,
                               {"type": "modules", "modules": state})
    await record_audit(user, "module.toggle", "module", module_key,
                       {"enabled": payload.enabled})
    return {"key": module_key, "enabled": payload.enabled, "modules": state}


# ---------------------------------------------------------------------------
# Users management (list + machine assignment)
# ---------------------------------------------------------------------------


class UserAssignment(BaseModel):
    assigned_asset_id: Optional[str] = None


@api.get("/users")
async def list_users(user: User = Depends(get_current_user)):
    if user.role not in ("TENANT_ADMIN", "SUPERVISOR", "PRODUCTION_MANAGER"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    docs = await db.users.find(
        {"tenant_id": user.tenant_id},
        {"_id": 0, "password": 0},
    ).to_list(500)
    # Enrich with assigned asset code
    asset_ids = {u.get("assigned_asset_id") for u in docs if u.get("assigned_asset_id")}
    asset_map: Dict[str, Dict[str, Any]] = {}
    if asset_ids:
        for a in await db.assets.find(
            {"id": {"$in": list(asset_ids)}, "tenant_id": user.tenant_id},
            {"_id": 0, "id": 1, "asset_code": 1, "name": 1},
        ).to_list(500):
            asset_map[a["id"]] = a
    for u in docs:
        aid = u.get("assigned_asset_id")
        u["assigned_asset"] = asset_map.get(aid) if aid else None
    return docs


@api.put("/users/{user_id}/assign")
async def assign_user_machine(user_id: str, payload: UserAssignment,
                              user: User = Depends(get_current_user)):
    if user.role not in ("TENANT_ADMIN", "SUPERVISOR"):
        raise HTTPException(status_code=403, detail="Only Supervisor or Tenant Admin can assign machines")
    target = await db.users.find_one({"id": user_id, "tenant_id": user.tenant_id})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.get("role") != "OPERATOR":
        raise HTTPException(status_code=400, detail="Machine assignment is only meaningful for Operators")
    if payload.assigned_asset_id:
        asset = await db.assets.find_one(
            {"id": payload.assigned_asset_id, "tenant_id": user.tenant_id},
            {"_id": 0, "id": 1, "asset_code": 1},
        )
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found in tenant")
    await db.users.update_one(
        {"id": user_id, "tenant_id": user.tenant_id},
        {"$set": {"assigned_asset_id": payload.assigned_asset_id}},
    )
    await record_audit(user, "user.assign", "user", user_id,
                       {"assigned_asset_id": payload.assigned_asset_id})
    return {"ok": True, "user_id": user_id, "assigned_asset_id": payload.assigned_asset_id}


# ---------------------------------------------------------------------------
# APM: metrics / maintenance / compare
# ---------------------------------------------------------------------------


class MaintenanceCreate(BaseModel):
    type: str  # PREVENTIVE | CORRECTIVE | PREDICTIVE
    description: str = Field(min_length=1)
    technician: Optional[str] = None
    cost_inr: float = Field(default=0, ge=0)
    performed_at: Optional[str] = None
    next_due_at: Optional[str] = None


async def _compute_asset_metrics(tenant_id: str, asset: Dict[str, Any]) -> Dict[str, Any]:
    aid = asset["id"]
    # runtime hours: number of RUNNING telemetry samples × sample interval (5s)
    running_samples = await db.telemetry.count_documents({"asset_id": aid, "machine_status": "RUNNING"})
    runtime_hours = round(running_samples * 5 / 3600, 2)

    # failures: count of critical/fault alarms for this asset
    failures = await db.alarms.count_documents({
        "tenant_id": tenant_id, "asset_id": aid,
        "severity": {"$in": ["CRITICAL", "MAJOR"]},
    })

    # downtime events
    dts = await db.downtime_events.find({"tenant_id": tenant_id, "asset_id": aid}, {"_id": 0}).to_list(500)
    total_downtime_min = sum(d.get("duration_min", 0) for d in dts)
    dt_count = len(dts) or 1
    mttr_hours = round((total_downtime_min / dt_count) / 60, 2) if dts else 0
    mtbf_hours = round(runtime_hours / failures, 2) if failures > 0 else runtime_hours

    # maintenance
    mnts = await db.maintenance_records.find(
        {"tenant_id": tenant_id, "asset_id": aid}, {"_id": 0}
    ).sort("performed_at", -1).to_list(200)
    year_start = f"{datetime.now(timezone.utc).year}-01-01"
    cost_ytd = round(sum(m.get("cost_inr", 0) for m in mnts if m.get("performed_at", "") >= year_start), 0)
    last_m = mnts[0] if mnts else None
    upcoming = [m for m in mnts if m.get("next_due_at") and m["next_due_at"] > datetime.now(timezone.utc).isoformat()]
    upcoming.sort(key=lambda m: m["next_due_at"])
    next_m = upcoming[0] if upcoming else None

    return {
        "asset_id": aid,
        "asset_code": asset["asset_code"],
        "name": asset["name"],
        "asset_type": asset["asset_type"],
        "status": asset["status"],
        "health": asset["health"],
        "runtime_hours": runtime_hours,
        "failure_count": failures,
        "mtbf_hours": mtbf_hours,
        "mttr_hours": mttr_hours,
        "downtime_min_total": total_downtime_min,
        "downtime_events": len(dts),
        "maintenance_count": len(mnts),
        "maintenance_cost_ytd": cost_ytd,
        "last_maintenance": last_m,
        "next_maintenance": next_m,
    }


@api.get("/assets/{asset_id}/metrics")
async def asset_metrics(asset_id: str, user: User = Depends(require_module("APM"))):
    a = await db.assets.find_one({"id": asset_id, "tenant_id": user.tenant_id}, {"_id": 0})
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    return await _compute_asset_metrics(user.tenant_id, a)


class ThresholdBand(BaseModel):
    warning: float = Field(ge=0)
    critical: float = Field(ge=0)


class ThresholdsPayload(BaseModel):
    temperature: Optional[ThresholdBand] = None
    vibration: Optional[ThresholdBand] = None


DEFAULT_THRESHOLDS = {
    "temperature": {"warning": 85.0, "critical": 100.0},
    "vibration": {"warning": 8.0, "critical": 12.0},
}


@api.get("/assets/{asset_id}/thresholds")
async def get_thresholds(asset_id: str, user: User = Depends(require_module("APM"))):
    a = await db.assets.find_one({"id": asset_id, "tenant_id": user.tenant_id},
                                 {"_id": 0, "thresholds": 1, "id": 1})
    if a is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"defaults": DEFAULT_THRESHOLDS, "thresholds": a.get("thresholds") or {}}


@api.put("/assets/{asset_id}/thresholds")
async def set_thresholds(asset_id: str, payload: ThresholdsPayload,
                         user: User = Depends(require_module("APM"))):
    if user.role not in ("TENANT_ADMIN", "PRODUCTION_MANAGER"):
        raise HTTPException(status_code=403, detail="Production Manager or Tenant Admin required")
    a = await db.assets.find_one({"id": asset_id, "tenant_id": user.tenant_id}, {"_id": 0})
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    thresholds: Dict[str, Dict[str, float]] = {}
    for k in ("temperature", "vibration"):
        band = getattr(payload, k)
        if band is not None:
            if band.warning > band.critical:
                raise HTTPException(status_code=400, detail=f"{k} warning must be ≤ critical")
            thresholds[k] = {"warning": band.warning, "critical": band.critical}
    if thresholds:
        await db.assets.update_one(
            {"id": asset_id, "tenant_id": user.tenant_id},
            {"$set": {"thresholds": thresholds}},
        )
    else:
        await db.assets.update_one(
            {"id": asset_id, "tenant_id": user.tenant_id},
            {"$unset": {"thresholds": ""}},
        )
    await record_audit(user, "asset.thresholds", "asset", asset_id, thresholds)
    return {"ok": True, "thresholds": thresholds}


@api.get("/assets/{asset_id}/downtime-breakdown")
async def asset_downtime_breakdown(asset_id: str, user: User = Depends(require_module("APM")),
                                   days: int = 30):
    a = await db.assets.find_one({"id": asset_id, "tenant_id": user.tenant_id}, {"_id": 0, "id": 1})
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    events = await db.downtime_events.find(
        {"tenant_id": user.tenant_id, "asset_id": asset_id, "started_at": {"$gte": cutoff}},
        {"_id": 0},
    ).to_list(500)
    totals: Dict[str, int] = {}
    for e in events:
        totals[e["reason"]] = totals.get(e["reason"], 0) + e.get("duration_min", 0)
    breakdown = [{"reason": k, "minutes": v} for k, v in sorted(totals.items(), key=lambda x: -x[1])]
    return {
        "days": days,
        "event_count": len(events),
        "total_minutes": sum(totals.values()),
        "breakdown": breakdown,
    }


@api.get("/assets/{asset_id}/maintenance")
async def list_maintenance(asset_id: str, user: User = Depends(require_module("APM"))):
    return await db.maintenance_records.find(
        {"tenant_id": user.tenant_id, "asset_id": asset_id}, {"_id": 0}
    ).sort("performed_at", -1).to_list(200)


@api.post("/assets/{asset_id}/maintenance")
async def add_maintenance(asset_id: str, payload: MaintenanceCreate,
                          user: User = Depends(require_module("APM"))):
    if user.role not in ("TENANT_ADMIN", "PRODUCTION_MANAGER", "SUPERVISOR"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    if payload.type not in ("PREVENTIVE", "CORRECTIVE", "PREDICTIVE"):
        raise HTTPException(status_code=400, detail="Invalid maintenance type")
    a = await db.assets.find_one({"id": asset_id, "tenant_id": user.tenant_id}, {"_id": 0})
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    now_iso = datetime.now(timezone.utc).isoformat()
    doc = {
        "id": str(uuid.uuid4()),
        "tenant_id": user.tenant_id,
        "asset_id": asset_id,
        "asset_code": a["asset_code"],
        "type": payload.type,
        "description": payload.description,
        "technician": payload.technician or user.name,
        "cost_inr": payload.cost_inr,
        "performed_at": payload.performed_at or now_iso,
        "next_due_at": payload.next_due_at,
    }
    await db.maintenance_records.insert_one(doc.copy())
    await record_audit(user, "maintenance.create", "asset", asset_id,
                       {"type": payload.type, "cost_inr": payload.cost_inr})
    doc.pop("_id", None)
    return doc


@api.get("/apm/compare")
async def compare_assets(user: User = Depends(require_module("APM")),
                         ids: str = Query(..., description="Comma-separated asset ids, up to 4"),
                         history_limit: int = 60):
    id_list = [x.strip() for x in ids.split(",") if x.strip()]
    if not id_list:
        raise HTTPException(status_code=400, detail="Provide at least one asset id")
    if len(id_list) > 4:
        raise HTTPException(status_code=400, detail="Compare up to 4 assets")
    out = []
    for aid in id_list:
        a = await db.assets.find_one({"id": aid, "tenant_id": user.tenant_id}, {"_id": 0})
        if not a:
            continue
        metrics = await _compute_asset_metrics(user.tenant_id, a)
        history = await db.telemetry.find(
            {"asset_id": aid}, {"_id": 0, "ts": 1, "temperature": 1, "vibration": 1, "rpm": 1, "power": 1}
        ).sort("ts", -1).to_list(history_limit)
        history.reverse()
        out.append({**metrics, "history": history, "location": a.get("location")})
    return out


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------


async def record_audit(user: "User", action: str, entity: Optional[str] = None,
                       entity_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None,
                       tenant_id: Optional[str] = None) -> None:
    try:
        await db.audit_logs.insert_one({
            "id": str(uuid.uuid4()),
            "tenant_id": tenant_id or user.tenant_id,
            "user_id": user.id,
            "user_email": user.email,
            "user_name": user.name,
            "role": user.role,
            "action": action,
            "entity": entity,
            "entity_id": entity_id,
            "details": details or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as exc:
        logger.warning("audit insert failed: %s", exc)


@api.get("/audit-logs")
async def list_audit_logs(user: User = Depends(get_current_user),
                          action: Optional[str] = None,
                          entity: Optional[str] = None,
                          q: Optional[str] = None,
                          limit: int = 100):
    query: Dict[str, Any] = {"tenant_id": user.tenant_id}
    if action:
        query["action"] = action
    if entity:
        query["entity"] = entity
    if q:
        query["$or"] = [
            {"user_email": {"$regex": q, "$options": "i"}},
            {"action": {"$regex": q, "$options": "i"}},
            {"entity_id": {"$regex": q, "$options": "i"}},
        ]
    rows = await db.audit_logs.find(query, {"_id": 0}).sort("created_at", -1).to_list(limit)
    return rows


# ---------------------------------------------------------------------------
# Users CRUD (Tenant Admin) + full editing
# ---------------------------------------------------------------------------


class UserCreate(BaseModel):
    email: EmailStr
    name: str
    role: str
    password: str
    employee_id: Optional[str] = None
    assigned_asset_id: Optional[str] = None


class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    employee_id: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None


@api.post("/users")
async def create_user(payload: UserCreate, user: User = Depends(get_current_user)):
    if user.role != "TENANT_ADMIN":
        raise HTTPException(status_code=403, detail="Only Tenant Admin can create users")
    if payload.role not in ("CXO", "PRODUCTION_MANAGER", "SUPERVISOR", "OPERATOR", "TENANT_ADMIN"):
        raise HTTPException(status_code=400, detail="Invalid role")
    exists = await db.users.find_one({"email": payload.email.lower(), "tenant_id": user.tenant_id})
    if exists:
        raise HTTPException(status_code=409, detail="Email already exists in this tenant")
    doc = {
        "id": str(uuid.uuid4()),
        "tenant_id": user.tenant_id,
        "email": payload.email.lower(),
        "name": payload.name,
        "role": payload.role,
        "employee_id": payload.employee_id,
        "plants": [],
        "active": True,
        "assigned_asset_id": payload.assigned_asset_id,
        "password": hash_password(payload.password),
    }
    await db.users.insert_one(doc.copy())
    await record_audit(user, "user.create", "user", doc["id"], {"email": doc["email"], "role": doc["role"]})
    doc.pop("password", None)
    doc.pop("_id", None)
    return doc


@api.put("/users/{user_id}")
async def update_user(user_id: str, payload: UserUpdate, user: User = Depends(get_current_user)):
    if user.role != "TENANT_ADMIN":
        raise HTTPException(status_code=403, detail="Only Tenant Admin can edit users")
    target = await db.users.find_one({"id": user_id, "tenant_id": user.tenant_id})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    update: Dict[str, Any] = {}
    for k in ("name", "role", "employee_id", "active"):
        v = getattr(payload, k)
        if v is not None:
            update[k] = v
    if payload.password:
        update["password"] = hash_password(payload.password)
    if not update:
        raise HTTPException(status_code=400, detail="No fields to update")
    await db.users.update_one({"id": user_id, "tenant_id": user.tenant_id}, {"$set": update})
    await record_audit(user, "user.update", "user", user_id,
                       {"fields": [k for k in update.keys() if k != "password"]})
    return {"ok": True}


@api.delete("/users/{user_id}")
async def delete_user(user_id: str, user: User = Depends(get_current_user)):
    """Soft-deactivate. Prevent removing the last active Tenant Admin."""
    if user.role != "TENANT_ADMIN":
        raise HTTPException(status_code=403, detail="Only Tenant Admin can deactivate users")
    if user_id == user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")
    target = await db.users.find_one({"id": user_id, "tenant_id": user.tenant_id})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target["role"] == "TENANT_ADMIN":
        active_admins = await db.users.count_documents(
            {"tenant_id": user.tenant_id, "role": "TENANT_ADMIN", "active": True, "id": {"$ne": user_id}}
        )
        if active_admins == 0:
            raise HTTPException(status_code=400, detail="Cannot deactivate the last Tenant Admin")
    await db.users.update_one({"id": user_id, "tenant_id": user.tenant_id}, {"$set": {"active": False}})
    await record_audit(user, "user.deactivate", "user", user_id, {"email": target["email"]})
    return {"ok": True}


# ---------------------------------------------------------------------------
# Platform Super Admin
# ---------------------------------------------------------------------------


async def require_super_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "PLATFORM_SUPER_ADMIN":
        raise HTTPException(status_code=403, detail="Platform Super Admin only")
    return user


class TenantCreate(BaseModel):
    code: str
    name: str
    admin_email: EmailStr
    admin_name: str
    admin_password: str


@api.get("/platform/tenants")
async def platform_list_tenants(user: User = Depends(require_super_admin)):
    tenants = await db.tenants.find({}, {"_id": 0}).to_list(200)
    out = []
    for t in tenants:
        users_ct = await db.users.count_documents({"tenant_id": t["id"]})
        assets_ct = await db.assets.count_documents({"tenant_id": t["id"]})
        plants_ct = await db.plants.count_documents({"tenant_id": t["id"]})
        out.append({**t, "users_count": users_ct, "assets_count": assets_ct, "plants_count": plants_ct})
    return out


@api.post("/platform/tenants")
async def platform_create_tenant(payload: TenantCreate, user: User = Depends(require_super_admin)):
    code = payload.code.upper().strip()
    if await db.tenants.find_one({"code": code}):
        raise HTTPException(status_code=409, detail="Tenant code already exists")
    tid = str(uuid.uuid4())
    await db.tenants.insert_one({"id": tid, "code": code, "name": payload.name})
    admin_id = str(uuid.uuid4())
    await db.users.insert_one({
        "id": admin_id,
        "tenant_id": tid,
        "email": payload.admin_email.lower(),
        "name": payload.admin_name,
        "role": "TENANT_ADMIN",
        "employee_id": None,
        "plants": [],
        "active": True,
        "assigned_asset_id": None,
        "password": hash_password(payload.admin_password),
    })
    # default modules
    await get_tenant_modules(tid)
    await record_audit(user, "tenant.create", "tenant", tid,
                       {"code": code, "admin_email": payload.admin_email})
    return {"id": tid, "code": code, "name": payload.name, "admin_id": admin_id}


@api.delete("/platform/tenants/{tenant_id}")
async def platform_delete_tenant(tenant_id: str, user: User = Depends(require_super_admin)):
    t = await db.tenants.find_one({"id": tenant_id})
    if not t:
        raise HTTPException(status_code=404, detail="Tenant not found")
    if t.get("code") == "PLATFORM":
        raise HTTPException(status_code=400, detail="Cannot delete PLATFORM tenant")
    # hard delete tenant + related docs
    for coll in ("users", "plants", "areas", "assets", "alarms", "telemetry",
                 "audit_logs", "escalations", "tenant_modules", "lines",
                 "downtime_events", "energy_records", "production_log"):
        await db[coll].delete_many({"tenant_id": tenant_id})
    await db.tenants.delete_one({"id": tenant_id})
    await record_audit(user, "tenant.delete", "tenant", tenant_id, {"code": t.get("code")})
    return {"ok": True}


# ---------------------------------------------------------------------------
# Energy (EEMS)
# ---------------------------------------------------------------------------


@api.get("/energy/summary")
async def energy_summary(user: User = Depends(require_module("EEMS")),
                         plant_id: Optional[str] = None,
                         range: str = "30d"):
    days = {"today": 1, "7d": 7, "30d": 30, "week": 7, "month": 30}.get(range, 30)
    cutoff = (datetime.now(timezone.utc).date() - timedelta(days=days - 1)).isoformat()
    q: Dict[str, Any] = {"tenant_id": user.tenant_id, "date": {"$gte": cutoff}}
    if plant_id and plant_id != "all":
        q["plant_id"] = plant_id
    rows = await db.energy_records.find(q, {"_id": 0}).sort("date", 1).to_list(2000)
    kpis = {
        "kwh": round(sum(r["kwh"] for r in rows), 1),
        "cost_inr": round(sum(r["cost_inr"] for r in rows), 0),
        "peak_kw": round(max((r["peak_kw"] for r in rows), default=0), 1),
        "avg_power_factor": round(sum(r["power_factor"] for r in rows) / len(rows), 3) if rows else 0,
        "avg_thd": round(sum(r["thd"] for r in rows) / len(rows), 2) if rows else 0,
        "renewable_pct": round(sum(r["renewable_pct"] for r in rows) / len(rows), 1) if rows else 0,
        "carbon_kg": round(sum(r["carbon_kg"] for r in rows), 1),
        "days": days,
    }
    # by-day series aggregated across selected plants
    by_day: Dict[str, Dict[str, float]] = {}
    for r in rows:
        d = by_day.setdefault(r["date"], {"kwh": 0.0, "cost": 0.0, "pf": 0.0, "n": 0})
        d["kwh"] += r["kwh"]; d["cost"] += r["cost_inr"]; d["pf"] += r["power_factor"]; d["n"] += 1
    series = [{"date": k, "kwh": round(v["kwh"], 1), "cost": round(v["cost"], 0),
               "power_factor": round(v["pf"] / v["n"], 3) if v["n"] else 0} for k, v in sorted(by_day.items())]
    # plant comparison (last 7d)
    week_cutoff = (datetime.now(timezone.utc).date() - timedelta(days=6)).isoformat()
    comp_rows = await db.energy_records.find(
        {"tenant_id": user.tenant_id, "date": {"$gte": week_cutoff}}, {"_id": 0}
    ).to_list(2000)
    by_plant: Dict[str, Dict[str, Any]] = {}
    for r in comp_rows:
        d = by_plant.setdefault(r["plant_id"], {"plant_name": r["plant_name"], "kwh": 0, "cost": 0,
                                                 "carbon": 0, "renewable": 0, "n": 0})
        d["kwh"] += r["kwh"]; d["cost"] += r["cost_inr"]; d["carbon"] += r["carbon_kg"]
        d["renewable"] += r["renewable_pct"]; d["n"] += 1
    plant_comparison = [{"plant_id": k, "plant_name": v["plant_name"],
                          "kwh": round(v["kwh"], 1), "cost": round(v["cost"], 0),
                          "carbon": round(v["carbon"], 1),
                          "renewable_pct": round(v["renewable"] / v["n"], 1) if v["n"] else 0}
                         for k, v in by_plant.items()]
    plant_comparison.sort(key=lambda x: -x["kwh"])
    return {"kpis": kpis, "series": series, "plant_comparison": plant_comparison}


# ---------------------------------------------------------------------------
# OEE
# ---------------------------------------------------------------------------


@api.get("/oee/summary")
async def oee_summary(user: User = Depends(require_module("OEE_APS")),
                      plant_id: Optional[str] = None,
                      days: int = 7):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    plants_q: Dict[str, Any] = {"tenant_id": user.tenant_id}
    if plant_id and plant_id != "all":
        plants_q["plant_id"] = plant_id

    lines = await db.lines.find(plants_q, {"_id": 0}).to_list(200)
    downtimes = await db.downtime_events.find(
        {"tenant_id": user.tenant_id, "started_at": {"$gte": cutoff},
         **({"plant_id": plant_id} if plant_id and plant_id != "all" else {})},
        {"_id": 0}
    ).to_list(1000)
    productions = await db.production_log.find(
        {"tenant_id": user.tenant_id, "ts": {"$gte": cutoff}}, {"_id": 0}
    ).to_list(2000)

    # shift assumption
    shifts_per_day = 3
    minutes_per_shift = 480
    total_planned = days * shifts_per_day * minutes_per_shift

    def score(produced, good, downtime_min, ideal_per_hr, planned_min):
        planned = max(1, planned_min)
        availability = max(0.0, (planned - downtime_min) / planned)
        run_time = max(1, planned - downtime_min)
        ideal = ideal_per_hr * (run_time / 60)
        performance = min(1.0, produced / ideal) if ideal else 0
        quality = (good / produced) if produced else 1.0
        oee = availability * performance * quality
        return {
            "availability": round(availability * 100, 1),
            "performance": round(performance * 100, 1),
            "quality": round(quality * 100, 1),
            "oee": round(oee * 100, 1),
        }

    # per-line
    lines_out = []
    seed = random.Random(42)
    for ln in lines:
        line_downtime = sum(d["duration_min"] for d in downtimes if d.get("plant_id") == ln["plant_id"]) // max(1, len(lines))
        line_prod = sum(p["produced"] for p in productions) // max(1, len(lines))
        line_good = sum(p["good"] for p in productions) // max(1, len(lines))
        # mix in a small deterministic variance per line
        variance = (seed.random() - 0.5) * 0.15
        base = score(line_prod, line_good, line_downtime, ln.get("ideal_rate_per_hr", 60), total_planned // max(1, len(lines)))
        base = {k: max(0, min(100, round(v * (1 + variance), 1))) for k, v in base.items()}
        lines_out.append({"line_id": ln["id"], "line_name": ln["name"], **base,
                          "downtime_min": line_downtime, "produced": line_prod, "good": line_good})

    # overall
    all_downtime = sum(d["duration_min"] for d in downtimes)
    all_prod = sum(p["produced"] for p in productions)
    all_good = sum(p["good"] for p in productions)
    overall = score(all_prod, all_good, all_downtime, 60, total_planned)

    # trend last N days
    trend = []
    for i in range(days - 1, -1, -1):
        day = (datetime.now(timezone.utc).date() - timedelta(days=i)).isoformat()
        day_prod = sum(p["produced"] for p in productions if p["ts"].startswith(day))
        day_good = sum(p["good"] for p in productions if p["ts"].startswith(day))
        day_dt = sum(d["duration_min"] for d in downtimes if d["started_at"].startswith(day))
        s = score(day_prod, day_good, day_dt, 60, shifts_per_day * minutes_per_shift)
        trend.append({"date": day, **s})

    # downtime breakdown by reason
    reasons: Dict[str, int] = {}
    for d in downtimes:
        reasons[d["reason"]] = reasons.get(d["reason"], 0) + d["duration_min"]
    reason_breakdown = [{"reason": k, "minutes": v} for k, v in
                        sorted(reasons.items(), key=lambda x: -x[1])]

    return {
        "overall": overall,
        "lines": lines_out,
        "trend": trend,
        "downtime_breakdown": reason_breakdown,
        "totals": {"produced": all_prod, "good": all_good, "reject": all_prod - all_good,
                   "downtime_min": all_downtime, "days": days},
    }


# ---------------------------------------------------------------------------
# CXO Comparison Board
# ---------------------------------------------------------------------------


@api.get("/dashboard/cxo-comparison")
async def cxo_comparison(user: User = Depends(get_current_user)):
    """Side-by-side plant KPIs for the CXO board."""
    plants = await db.plants.find({"tenant_id": user.tenant_id}, {"_id": 0}).to_list(50)
    assets = await db.assets.find({"tenant_id": user.tenant_id}, {"_id": 0}).to_list(2000)
    alarms = await db.alarms.find({"tenant_id": user.tenant_id, "acknowledged": False}, {"_id": 0}).to_list(500)

    out = []
    for p in plants:
        p_assets = [a for a in assets if a["plant_id"] == p["id"]]
        total = len(p_assets) or 1
        running = sum(1 for a in p_assets if a["status"] in ("RUNNING", "WARNING"))
        fault = sum(1 for a in p_assets if a["status"] in ("FAULT", "CRITICAL"))
        avg_health = round(sum(a["health"] for a in p_assets) / total, 1)
        # Deterministic mock KPIs seeded off plant code so demos are stable
        seed = sum(ord(c) for c in p["code"])
        rng = random.Random(seed)
        oee = round(65 + rng.random() * 25, 1)
        availability = round(80 + rng.random() * 18, 1)
        performance = round(75 + rng.random() * 22, 1)
        quality = round(90 + rng.random() * 9, 1)
        energy_kwh = round(4200 + rng.random() * 3200, 0)
        energy_cost = round(energy_kwh * 9.4, 0)  # INR/kWh
        carbon = round(energy_kwh * 0.82, 0)
        active_alarms = sum(1 for a in alarms if a["asset_id"] in {x["id"] for x in p_assets})
        out.append({
            "plant_id": p["id"],
            "name": p["name"],
            "location": p["location"],
            "code": p["code"],
            "total_assets": len(p_assets),
            "running_pct": round(running * 100 / total, 1),
            "fault_count": fault,
            "avg_health": avg_health,
            "oee": oee,
            "availability": availability,
            "performance": performance,
            "quality": quality,
            "energy_kwh": energy_kwh,
            "energy_cost_inr": energy_cost,
            "carbon_kg": carbon,
            "active_alarms": active_alarms,
        })
    # sort by OEE desc for a natural leaderboard
    out.sort(key=lambda x: x["oee"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# Operator Runbook
# ---------------------------------------------------------------------------


class ProductionEntry(BaseModel):
    produced: int
    good: int
    reject: int = 0


@api.get("/operator/my-machine")
async def operator_my_machine(user: User = Depends(get_current_user)):
    if user.role != "OPERATOR":
        raise HTTPException(status_code=403, detail="Operators only")
    asset_id = user.assigned_asset_id
    if not asset_id:
        # Fallback to CNC-DEMO-01 for the demo
        demo = await db.assets.find_one({"tenant_id": user.tenant_id, "asset_code": "CNC-DEMO-01"}, {"_id": 0})
        if not demo:
            raise HTTPException(status_code=404, detail="No machine assigned")
        asset_id = demo["id"]
    a = await db.assets.find_one({"id": asset_id, "tenant_id": user.tenant_id}, {"_id": 0})
    if not a:
        raise HTTPException(status_code=404, detail="Assigned machine not found")
    area = await db.areas.find_one({"id": a["area_id"]}, {"_id": 0})
    plant = await db.plants.find_one({"id": a["plant_id"]}, {"_id": 0})
    tele = await db.telemetry.find_one({"asset_id": a["id"]}, {"_id": 0}, sort=[("ts", -1)]) or {}
    alarms = await db.alarms.find(
        {"tenant_id": user.tenant_id, "asset_id": a["id"], "acknowledged": False},
        {"_id": 0},
    ).sort("created_at", -1).to_list(20)
    a["area_name"] = area["name"] if area else "-"
    a["plant_name"] = plant["name"] if plant else "-"
    return {"asset": a, "telemetry": tele, "alarms": alarms}


@api.post("/operator/production")
async def operator_submit_production(entry: ProductionEntry, user: User = Depends(get_current_user)):
    if user.role != "OPERATOR":
        raise HTTPException(status_code=403, detail="Operators only")
    if not user.assigned_asset_id:
        raise HTTPException(status_code=404, detail="No assigned machine")
    a = await db.assets.find_one({"id": user.assigned_asset_id, "tenant_id": user.tenant_id}, {"_id": 0})
    if not a:
        raise HTTPException(status_code=404, detail="Machine not found")
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "id": str(uuid.uuid4()),
        "tenant_id": user.tenant_id,
        "asset_id": a["id"],
        "asset_code": a["asset_code"],
        "operator_id": user.id,
        "operator_name": user.name,
        "produced": entry.produced,
        "good": entry.good,
        "reject": entry.reject or max(0, entry.produced - entry.good),
        "ts": now,
    }
    await db.production_log.insert_one(doc.copy())
    # roll forward telemetry counts
    latest = await db.telemetry.find_one({"asset_id": a["id"]}, {"_id": 0}, sort=[("ts", -1)]) or {}
    payload = TelemetryIn(
        asset_id=a["id"],
        production_count=int(latest.get("production_count", 0)) + entry.produced,
        good_count=int(latest.get("good_count", 0)) + entry.good,
        reject_count=int(latest.get("reject_count", 0)) + (entry.reject or max(0, entry.produced - entry.good)),
    )
    await ingest_telemetry_internal(payload)
    doc.pop("_id", None)
    return {"ok": True, "entry": doc}


# ---------------------------------------------------------------------------
# Escalations
# ---------------------------------------------------------------------------


@api.get("/escalations")
async def list_escalations(user: User = Depends(get_current_user), limit: int = 50):
    rows = await db.escalations.find({"tenant_id": user.tenant_id}, {"_id": 0}).sort("escalated_at", -1).to_list(limit)
    return rows


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------


@api.websocket("/ws/telemetry")
async def ws_telemetry(websocket: WebSocket, token: Optional[str] = Query(None)):
    if not token:
        await websocket.close(code=4401)
        return
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        tenant_id = payload["tid"]
    except jwt.PyJWTError:
        await websocket.close(code=4401)
        return
    await ws_manager.connect(websocket, tenant_id)
    try:
        while True:
            await websocket.receive_text()  # ignore inbound
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, tenant_id)


# ---------------------------------------------------------------------------
# Reports & Forecasting
# ---------------------------------------------------------------------------

from io import BytesIO, StringIO
import csv as _csv
import json as _json
import math as _math

REPORT_CATALOG = [
    {"key": "PRODUCTION", "name": "Production Report",
     "description": "Produced / good / reject units over time with per-asset breakdown.",
     "metrics": ["produced", "good", "reject", "yield_pct"], "default_metric": "produced"},
    {"key": "OEE", "name": "OEE Report",
     "description": "Availability × Performance × Quality trend and losses.",
     "metrics": ["oee", "availability", "performance", "quality"], "default_metric": "oee"},
    {"key": "ENERGY", "name": "Energy Consumption Report",
     "description": "kWh, cost, power factor, THD and carbon by plant.",
     "metrics": ["kwh", "cost_inr", "carbon_kg", "power_factor"], "default_metric": "kwh"},
    {"key": "DOWNTIME", "name": "Downtime & Alarms Report",
     "description": "Downtime minutes by reason with Pareto and trend.",
     "metrics": ["downtime_min", "events"], "default_metric": "downtime_min"},
    {"key": "MAINTENANCE", "name": "Maintenance Report",
     "description": "MTBF, MTTR and maintenance spend by asset.",
     "metrics": ["cost_inr", "count", "mtbf_hours", "mttr_hours"], "default_metric": "cost_inr"},
]


class ReportRunRequest(BaseModel):
    report_type: str
    start_date: Optional[str] = None  # YYYY-MM-DD
    end_date: Optional[str] = None    # YYYY-MM-DD
    plant_id: Optional[str] = None
    asset_id: Optional[str] = None
    aggregation: str = "daily"        # daily | weekly | monthly
    metric: Optional[str] = None
    include_forecast: bool = False
    forecast_periods: int = 7
    format: Optional[str] = None      # None | csv | pdf | json


def _parse_range(req: ReportRunRequest) -> tuple[datetime, datetime]:
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    try:
        end = datetime.fromisoformat(req.end_date).replace(tzinfo=timezone.utc) if req.end_date else today
        start = datetime.fromisoformat(req.start_date).replace(tzinfo=timezone.utc) if req.start_date \
            else end - timedelta(days=29)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid date: {e}") from e
    if start > end:
        start, end = end, start
    return start, end


def _bucket_key(dt: datetime, agg: str) -> str:
    if agg == "monthly":
        return dt.strftime("%Y-%m")
    if agg == "weekly":
        # ISO week start Monday
        monday = dt - timedelta(days=dt.weekday())
        return monday.date().isoformat()
    return dt.date().isoformat()


def _bucket_seq(start: datetime, end: datetime, agg: str) -> List[str]:
    out: List[str] = []
    cur = start
    seen = set()
    if agg == "monthly":
        d = start.replace(day=1)
        while d <= end:
            k = d.strftime("%Y-%m")
            if k not in seen: out.append(k); seen.add(k)
            # advance month
            year, month = d.year, d.month
            d = d.replace(year=year + 1, month=1, day=1) if month == 12 else d.replace(month=month + 1, day=1)
        return out
    step = timedelta(days=7 if agg == "weekly" else 1)
    while cur <= end:
        k = _bucket_key(cur, agg)
        if k not in seen: out.append(k); seen.add(k)
        cur += step
    return out


def _linear_forecast(y: List[float], periods: int) -> Dict[str, Any]:
    """Simple OLS linear regression forecast with 95% CI."""
    n = len(y)
    if n < 3 or periods <= 0:
        return {"points": [], "slope": 0.0, "intercept": (y[-1] if y else 0.0), "ci_half": 0.0}
    xs = list(range(n))
    mean_x = sum(xs) / n
    mean_y = sum(y) / n
    num = sum((xs[i] - mean_x) * (y[i] - mean_y) for i in range(n))
    den = sum((xs[i] - mean_x) ** 2 for i in range(n)) or 1e-9
    slope = num / den
    intercept = mean_y - slope * mean_x
    residuals = [y[i] - (slope * xs[i] + intercept) for i in range(n)]
    sse = sum(r * r for r in residuals)
    dof = max(1, n - 2)
    sigma = _math.sqrt(sse / dof)
    ci = 1.96 * sigma
    pts = []
    for k in range(1, periods + 1):
        x = n - 1 + k
        yhat = slope * x + intercept
        value = max(0.0, yhat)
        pts.append({"step": k, "value": round(value, 3),
                    "lower": round(max(0.0, yhat - ci), 3),
                    "upper": round(max(value, yhat + ci), 3)})
    return {"points": pts, "slope": round(slope, 4), "intercept": round(intercept, 4),
            "ci_half": round(ci, 3)}


async def _plant_lookup(tenant_id: str) -> Dict[str, str]:
    plants = await db.plants.find({"tenant_id": tenant_id}, {"_id": 0}).to_list(200)
    return {p["id"]: p["name"] for p in plants}


async def _asset_lookup(tenant_id: str) -> Dict[str, Dict[str, Any]]:
    assets = await db.assets.find({"tenant_id": tenant_id}, {"_id": 0}).to_list(2000)
    return {a["id"]: a for a in assets}


async def _run_production(tenant_id: str, req: ReportRunRequest, start: datetime, end: datetime):
    q: Dict[str, Any] = {"tenant_id": tenant_id, "ts": {"$gte": start.isoformat(), "$lte": (end + timedelta(days=1)).isoformat()}}
    if req.asset_id: q["asset_id"] = req.asset_id
    rows = await db.production_log.find(q, {"_id": 0}).sort("ts", 1).to_list(20000)
    assets_map = await _asset_lookup(tenant_id)
    plants_map = await _plant_lookup(tenant_id)
    if req.plant_id:
        rows = [r for r in rows if (assets_map.get(r["asset_id"], {}).get("plant_id") == req.plant_id)]
    buckets = _bucket_seq(start, end, req.aggregation)
    b_map: Dict[str, Dict[str, Any]] = {k: {"period": k, "produced": 0, "good": 0, "reject": 0} for k in buckets}
    for r in rows:
        dt = datetime.fromisoformat(r["ts"].replace("Z", "+00:00"))
        k = _bucket_key(dt, req.aggregation)
        if k not in b_map: continue
        b_map[k]["produced"] += int(r.get("produced", 0))
        b_map[k]["good"] += int(r.get("good", 0))
        b_map[k]["reject"] += int(r.get("reject", 0))
    series = [dict(v, yield_pct=round(v["good"] * 100 / v["produced"], 1) if v["produced"] else 0)
              for v in b_map.values()]
    # detail rows (per asset)
    per_asset: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        a = assets_map.get(r["asset_id"], {})
        pa = per_asset.setdefault(r["asset_id"], {"asset_code": r.get("asset_code"),
                                                   "asset_name": a.get("name", r.get("asset_code")),
                                                   "plant": plants_map.get(a.get("plant_id"), "-"),
                                                   "produced": 0, "good": 0, "reject": 0})
        pa["produced"] += int(r.get("produced", 0)); pa["good"] += int(r.get("good", 0))
        pa["reject"] += int(r.get("reject", 0))
    detail = sorted(per_asset.values(), key=lambda x: -x["produced"])
    for d in detail:
        d["yield_pct"] = round(d["good"] * 100 / d["produced"], 1) if d["produced"] else 0
    totals = {"produced": sum(v["produced"] for v in series),
              "good": sum(v["good"] for v in series),
              "reject": sum(v["reject"] for v in series)}
    totals["yield_pct"] = round(totals["good"] * 100 / totals["produced"], 1) if totals["produced"] else 0
    columns = [{"key": "period", "label": "Period"},
               {"key": "produced", "label": "Produced"},
               {"key": "good", "label": "Good"},
               {"key": "reject", "label": "Reject"},
               {"key": "yield_pct", "label": "Yield %"}]
    detail_columns = [{"key": "asset_code", "label": "Asset"},
                      {"key": "asset_name", "label": "Name"},
                      {"key": "plant", "label": "Plant"},
                      {"key": "produced", "label": "Produced"},
                      {"key": "good", "label": "Good"},
                      {"key": "reject", "label": "Reject"},
                      {"key": "yield_pct", "label": "Yield %"}]
    kpis = [{"label": "Total produced", "value": totals["produced"]},
            {"label": "Total good", "value": totals["good"]},
            {"label": "Total reject", "value": totals["reject"]},
            {"label": "Yield %", "value": totals["yield_pct"]}]
    return {"kpis": kpis, "columns": columns, "rows": series,
            "detail_columns": detail_columns, "detail_rows": detail}


async def _run_energy(tenant_id: str, req: ReportRunRequest, start: datetime, end: datetime):
    q: Dict[str, Any] = {"tenant_id": tenant_id,
                          "date": {"$gte": start.date().isoformat(), "$lte": end.date().isoformat()}}
    if req.plant_id: q["plant_id"] = req.plant_id
    rows = await db.energy_records.find(q, {"_id": 0}).sort("date", 1).to_list(20000)
    buckets = _bucket_seq(start, end, req.aggregation)
    b_map: Dict[str, Dict[str, Any]] = {k: {"period": k, "kwh": 0.0, "cost_inr": 0.0,
                                             "carbon_kg": 0.0, "_pf_sum": 0.0, "_n": 0} for k in buckets}
    for r in rows:
        dt = datetime.fromisoformat(r["date"])
        k = _bucket_key(dt.replace(tzinfo=timezone.utc), req.aggregation)
        if k not in b_map: continue
        b_map[k]["kwh"] += r["kwh"]; b_map[k]["cost_inr"] += r["cost_inr"]
        b_map[k]["carbon_kg"] += r["carbon_kg"]
        b_map[k]["_pf_sum"] += r["power_factor"]; b_map[k]["_n"] += 1
    series = []
    for v in b_map.values():
        series.append({"period": v["period"], "kwh": round(v["kwh"], 1),
                       "cost_inr": round(v["cost_inr"], 0),
                       "carbon_kg": round(v["carbon_kg"], 1),
                       "power_factor": round(v["_pf_sum"] / v["_n"], 3) if v["_n"] else 0})
    # per plant
    plants_map = await _plant_lookup(tenant_id)
    per_plant: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        pp = per_plant.setdefault(r["plant_id"], {"plant": plants_map.get(r["plant_id"], r.get("plant_name", "-")),
                                                    "kwh": 0.0, "cost_inr": 0.0, "carbon_kg": 0.0,
                                                    "_pf_sum": 0.0, "_n": 0})
        pp["kwh"] += r["kwh"]; pp["cost_inr"] += r["cost_inr"]; pp["carbon_kg"] += r["carbon_kg"]
        pp["_pf_sum"] += r["power_factor"]; pp["_n"] += 1
    detail = []
    for v in per_plant.values():
        detail.append({"plant": v["plant"], "kwh": round(v["kwh"], 1),
                       "cost_inr": round(v["cost_inr"], 0),
                       "carbon_kg": round(v["carbon_kg"], 1),
                       "power_factor": round(v["_pf_sum"] / v["_n"], 3) if v["_n"] else 0})
    detail.sort(key=lambda x: -x["kwh"])
    total_kwh = sum(v["kwh"] for v in series)
    total_cost = sum(v["cost_inr"] for v in series)
    total_carbon = sum(v["carbon_kg"] for v in series)
    kpis = [{"label": "Total kWh", "value": round(total_kwh, 1)},
            {"label": "Total cost (INR)", "value": round(total_cost, 0)},
            {"label": "Total carbon (kg)", "value": round(total_carbon, 1)},
            {"label": "Avg PF", "value": round(sum(s["power_factor"] for s in series) / len(series), 3) if series else 0}]
    columns = [{"key": "period", "label": "Period"},
               {"key": "kwh", "label": "kWh"},
               {"key": "cost_inr", "label": "Cost (INR)"},
               {"key": "carbon_kg", "label": "Carbon (kg)"},
               {"key": "power_factor", "label": "Power factor"}]
    detail_columns = [{"key": "plant", "label": "Plant"},
                      {"key": "kwh", "label": "kWh"},
                      {"key": "cost_inr", "label": "Cost (INR)"},
                      {"key": "carbon_kg", "label": "Carbon (kg)"},
                      {"key": "power_factor", "label": "Power factor"}]
    return {"kpis": kpis, "columns": columns, "rows": series,
            "detail_columns": detail_columns, "detail_rows": detail}


async def _run_downtime(tenant_id: str, req: ReportRunRequest, start: datetime, end: datetime):
    q: Dict[str, Any] = {"tenant_id": tenant_id,
                          "started_at": {"$gte": start.isoformat(),
                                          "$lte": (end + timedelta(days=1)).isoformat()}}
    if req.plant_id: q["plant_id"] = req.plant_id
    if req.asset_id: q["asset_id"] = req.asset_id
    rows = await db.downtime_events.find(q, {"_id": 0}).sort("started_at", 1).to_list(20000)
    buckets = _bucket_seq(start, end, req.aggregation)
    b_map: Dict[str, Dict[str, Any]] = {k: {"period": k, "downtime_min": 0, "events": 0} for k in buckets}
    for r in rows:
        dt = datetime.fromisoformat(r["started_at"].replace("Z", "+00:00"))
        k = _bucket_key(dt, req.aggregation)
        if k not in b_map: continue
        b_map[k]["downtime_min"] += int(r.get("duration_min", 0))
        b_map[k]["events"] += 1
    series = list(b_map.values())
    # Pareto by reason
    by_reason: Dict[str, Dict[str, int]] = {}
    for r in rows:
        bp = by_reason.setdefault(r.get("reason", "Unknown"), {"reason": r.get("reason", "Unknown"),
                                                                 "downtime_min": 0, "events": 0})
        bp["downtime_min"] += int(r.get("duration_min", 0))
        bp["events"] += 1
    detail = sorted(by_reason.values(), key=lambda x: -x["downtime_min"])
    total = sum(d["downtime_min"] for d in detail) or 1
    for d in detail:
        d["pct"] = round(d["downtime_min"] * 100 / total, 1)
    kpis = [{"label": "Total downtime (min)", "value": sum(v["downtime_min"] for v in series)},
            {"label": "Events", "value": sum(v["events"] for v in series)},
            {"label": "Avg / event (min)", "value": round(sum(v["downtime_min"] for v in series) /
                                                            max(1, sum(v["events"] for v in series)), 1)},
            {"label": "Top reason", "value": detail[0]["reason"] if detail else "-"}]
    columns = [{"key": "period", "label": "Period"},
               {"key": "downtime_min", "label": "Downtime (min)"},
               {"key": "events", "label": "Events"}]
    detail_columns = [{"key": "reason", "label": "Reason"},
                      {"key": "downtime_min", "label": "Downtime (min)"},
                      {"key": "events", "label": "Events"},
                      {"key": "pct", "label": "% of total"}]
    return {"kpis": kpis, "columns": columns, "rows": series,
            "detail_columns": detail_columns, "detail_rows": detail}


async def _run_maintenance(tenant_id: str, req: ReportRunRequest, start: datetime, end: datetime):
    q: Dict[str, Any] = {"tenant_id": tenant_id,
                          "performed_at": {"$gte": start.isoformat(),
                                            "$lte": (end + timedelta(days=1)).isoformat()}}
    if req.asset_id: q["asset_id"] = req.asset_id
    rows = await db.maintenance_records.find(q, {"_id": 0}).sort("performed_at", 1).to_list(20000)
    assets_map = await _asset_lookup(tenant_id)
    plants_map = await _plant_lookup(tenant_id)
    if req.plant_id:
        rows = [r for r in rows if assets_map.get(r["asset_id"], {}).get("plant_id") == req.plant_id]
    buckets = _bucket_seq(start, end, req.aggregation)
    b_map: Dict[str, Dict[str, Any]] = {k: {"period": k, "cost_inr": 0.0, "count": 0} for k in buckets}
    for r in rows:
        dt = datetime.fromisoformat(r["performed_at"].replace("Z", "+00:00"))
        k = _bucket_key(dt, req.aggregation)
        if k not in b_map: continue
        b_map[k]["cost_inr"] += float(r.get("cost_inr", 0))
        b_map[k]["count"] += 1
    series = [{"period": v["period"], "cost_inr": round(v["cost_inr"], 0), "count": v["count"]}
              for v in b_map.values()]
    # per asset MTBF/MTTR + spend
    dt_events_all = await db.downtime_events.find({"tenant_id": tenant_id}, {"_id": 0}).to_list(20000)
    per_asset: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        a = assets_map.get(r["asset_id"], {})
        pa = per_asset.setdefault(r["asset_id"], {"asset_code": r.get("asset_code"),
                                                    "asset_name": a.get("name", r.get("asset_code")),
                                                    "plant": plants_map.get(a.get("plant_id"), "-"),
                                                    "count": 0, "cost_inr": 0.0})
        pa["count"] += 1; pa["cost_inr"] += float(r.get("cost_inr", 0))
    for aid, pa in per_asset.items():
        dts = [d for d in dt_events_all if d.get("asset_id") == aid]
        pa["mtbf_hours"] = round((30 * 24) / max(1, len(dts)), 1)  # over ~30d window
        pa["mttr_hours"] = round(sum(d.get("duration_min", 0) for d in dts) / max(1, len(dts)) / 60, 2)
        pa["cost_inr"] = round(pa["cost_inr"], 0)
    detail = sorted(per_asset.values(), key=lambda x: -x["cost_inr"])
    kpis = [{"label": "Total spend (INR)", "value": round(sum(v["cost_inr"] for v in series), 0)},
            {"label": "Work orders", "value": sum(v["count"] for v in series)},
            {"label": "Assets serviced", "value": len(per_asset)},
            {"label": "Avg MTBF (h)", "value": round(sum(d["mtbf_hours"] for d in detail) / len(detail), 1) if detail else 0}]
    columns = [{"key": "period", "label": "Period"},
               {"key": "cost_inr", "label": "Spend (INR)"},
               {"key": "count", "label": "Work orders"}]
    detail_columns = [{"key": "asset_code", "label": "Asset"},
                      {"key": "asset_name", "label": "Name"},
                      {"key": "plant", "label": "Plant"},
                      {"key": "count", "label": "WOs"},
                      {"key": "cost_inr", "label": "Spend (INR)"},
                      {"key": "mtbf_hours", "label": "MTBF (h)"},
                      {"key": "mttr_hours", "label": "MTTR (h)"}]
    return {"kpis": kpis, "columns": columns, "rows": series,
            "detail_columns": detail_columns, "detail_rows": detail}


async def _run_oee(tenant_id: str, req: ReportRunRequest, start: datetime, end: datetime):
    prod_q: Dict[str, Any] = {"tenant_id": tenant_id,
                                "ts": {"$gte": start.isoformat(),
                                        "$lte": (end + timedelta(days=1)).isoformat()}}
    dt_q: Dict[str, Any] = {"tenant_id": tenant_id,
                              "started_at": {"$gte": start.isoformat(),
                                              "$lte": (end + timedelta(days=1)).isoformat()}}
    if req.plant_id: dt_q["plant_id"] = req.plant_id
    productions = await db.production_log.find(prod_q, {"_id": 0}).to_list(20000)
    downtimes = await db.downtime_events.find(dt_q, {"_id": 0}).to_list(20000)
    assets_map = await _asset_lookup(tenant_id)
    if req.plant_id:
        productions = [p for p in productions if assets_map.get(p["asset_id"], {}).get("plant_id") == req.plant_id]
    buckets = _bucket_seq(start, end, req.aggregation)

    def score(produced, good, downtime_min, planned_min, ideal_per_hr=60):
        planned = max(1, planned_min)
        availability = max(0.0, (planned - downtime_min) / planned)
        run_time = max(1, planned - downtime_min)
        ideal = ideal_per_hr * (run_time / 60)
        performance = min(1.0, produced / ideal) if ideal else 0
        quality = (good / produced) if produced else 1.0
        return {"availability": round(availability * 100, 1),
                "performance": round(performance * 100, 1),
                "quality": round(quality * 100, 1),
                "oee": round(availability * performance * quality * 100, 1)}

    minutes_per_bucket = {"daily": 3 * 480, "weekly": 7 * 3 * 480, "monthly": 30 * 3 * 480}
    planned = minutes_per_bucket.get(req.aggregation, 1440)
    b_map: Dict[str, Dict[str, Any]] = {k: {"period": k, "produced": 0, "good": 0, "downtime_min": 0} for k in buckets}
    for p in productions:
        dt = datetime.fromisoformat(p["ts"].replace("Z", "+00:00"))
        k = _bucket_key(dt, req.aggregation)
        if k not in b_map: continue
        b_map[k]["produced"] += int(p.get("produced", 0))
        b_map[k]["good"] += int(p.get("good", 0))
    for d in downtimes:
        dt = datetime.fromisoformat(d["started_at"].replace("Z", "+00:00"))
        k = _bucket_key(dt, req.aggregation)
        if k not in b_map: continue
        b_map[k]["downtime_min"] += int(d.get("duration_min", 0))
    series = []
    for v in b_map.values():
        s = score(v["produced"], v["good"], v["downtime_min"], planned)
        series.append({"period": v["period"], **s,
                       "produced": v["produced"], "good": v["good"],
                       "downtime_min": v["downtime_min"]})
    # overall
    total_prod = sum(v["produced"] for v in series)
    total_good = sum(v["good"] for v in series)
    total_dt = sum(v["downtime_min"] for v in series)
    overall = score(total_prod, total_good, total_dt, planned * max(1, len(series)))
    # per-reason detail
    reasons: Dict[str, int] = {}
    for d in downtimes:
        reasons[d.get("reason", "Unknown")] = reasons.get(d.get("reason", "Unknown"), 0) + int(d.get("duration_min", 0))
    detail = [{"reason": k, "downtime_min": v,
                "pct": round(v * 100 / max(1, total_dt), 1)} for k, v in
                sorted(reasons.items(), key=lambda x: -x[1])]
    kpis = [{"label": "OEE %", "value": overall["oee"]},
            {"label": "Availability %", "value": overall["availability"]},
            {"label": "Performance %", "value": overall["performance"]},
            {"label": "Quality %", "value": overall["quality"]}]
    columns = [{"key": "period", "label": "Period"},
               {"key": "oee", "label": "OEE %"},
               {"key": "availability", "label": "Availability %"},
               {"key": "performance", "label": "Performance %"},
               {"key": "quality", "label": "Quality %"},
               {"key": "downtime_min", "label": "Downtime (min)"}]
    detail_columns = [{"key": "reason", "label": "Downtime reason"},
                      {"key": "downtime_min", "label": "Minutes"},
                      {"key": "pct", "label": "% of total"}]
    return {"kpis": kpis, "columns": columns, "rows": series,
            "detail_columns": detail_columns, "detail_rows": detail}


_REPORT_RUNNERS = {
    "PRODUCTION": _run_production,
    "ENERGY": _run_energy,
    "OEE": _run_oee,
    "DOWNTIME": _run_downtime,
    "MAINTENANCE": _run_maintenance,
}


def _report_meta(key: str) -> Dict[str, Any]:
    for r in REPORT_CATALOG:
        if r["key"] == key: return r
    raise HTTPException(status_code=400, detail=f"Unknown report type: {key}")


async def _compute_report(user: "User", req: ReportRunRequest) -> Dict[str, Any]:
    meta = _report_meta(req.report_type)
    if req.aggregation not in ("daily", "weekly", "monthly"):
        raise HTTPException(status_code=400, detail="aggregation must be daily|weekly|monthly")
    metric = req.metric or meta["default_metric"]
    if metric not in meta["metrics"]:
        raise HTTPException(status_code=400, detail=f"metric '{metric}' not valid for {req.report_type}")
    start, end = _parse_range(req)
    runner = _REPORT_RUNNERS[req.report_type]
    data = await runner(user.tenant_id, req, start, end)
    forecast = None
    if req.include_forecast and len(data["rows"]) >= 3:
        y = [float(row.get(metric, 0) or 0) for row in data["rows"]]
        forecast = _linear_forecast(y, req.forecast_periods)
        forecast["metric"] = metric
    return {
        "report_type": req.report_type,
        "report_name": meta["name"],
        "range": {"start": start.date().isoformat(),
                    "end": end.date().isoformat(),
                    "aggregation": req.aggregation},
        "metric": metric,
        "kpis": data["kpis"],
        "columns": data["columns"],
        "rows": data["rows"],
        "detail_columns": data.get("detail_columns", []),
        "detail_rows": data.get("detail_rows", []),
        "forecast": forecast,
        "filters": {"plant_id": req.plant_id, "asset_id": req.asset_id},
    }


@api.get("/reports/catalog")
async def reports_catalog(user: User = Depends(require_module("REPORTS"))):
    return {"reports": REPORT_CATALOG,
            "aggregations": ["daily", "weekly", "monthly"],
            "export_formats": ["csv", "xlsx", "pdf", "json"]}


@api.post("/reports/run")
async def reports_run(req: ReportRunRequest, user: User = Depends(require_module("REPORTS"))):
    result = await _compute_report(user, req)
    await record_audit(user, "report.run", "report", req.report_type,
                        {"range": result["range"], "metric": result["metric"]})
    return result


def _csv_response(report: Dict[str, Any]):
    from fastapi.responses import StreamingResponse
    buf = StringIO()
    w = _csv.writer(buf)
    w.writerow([f"CoreOT — {report['report_name']}"])
    w.writerow([f"Range: {report['range']['start']} → {report['range']['end']} ({report['range']['aggregation']})"])
    w.writerow([])
    w.writerow(["KPI", "Value"])
    for k in report["kpis"]:
        w.writerow([k["label"], k["value"]])
    w.writerow([])
    w.writerow([c["label"] for c in report["columns"]])
    for row in report["rows"]:
        w.writerow([row.get(c["key"], "") for c in report["columns"]])
    if report.get("detail_rows"):
        w.writerow([])
        w.writerow([c["label"] for c in report["detail_columns"]])
        for row in report["detail_rows"]:
            w.writerow([row.get(c["key"], "") for c in report["detail_columns"]])
    if report.get("forecast"):
        w.writerow([])
        w.writerow([f"Forecast ({report['forecast']['metric']}, 95% CI)"])
        w.writerow(["Step", "Forecast", "Lower", "Upper"])
        for p in report["forecast"]["points"]:
            w.writerow([p["step"], p["value"], p["lower"], p["upper"]])
    filename = f"{report['report_type'].lower()}_{report['range']['start']}_{report['range']['end']}.csv"
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                              headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _pdf_response(report: Dict[str, Any]):
    from fastapi.responses import StreamingResponse
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle)

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                             topMargin=15 * mm, bottomMargin=15 * mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("t", parent=styles["Title"], textColor=colors.HexColor("#1e293b"))
    small = ParagraphStyle("s", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#64748b"))
    story = []
    story.append(Paragraph(f"CoreOT — {report['report_name']}", title_style))
    story.append(Paragraph(f"Range: {report['range']['start']} → {report['range']['end']} · "
                             f"Aggregation: {report['range']['aggregation']} · "
                             f"Metric: {report['metric']}", small))
    story.append(Spacer(1, 8))

    # KPIs table
    kpi_data = [["KPI", "Value"]] + [[k["label"], str(k["value"])] for k in report["kpis"]]
    t = Table(kpi_data, hAlign="LEFT", colWidths=[80 * mm, 80 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
    ]))
    story.append(t); story.append(Spacer(1, 10))

    def _make_table(cols, rows, title=None):
        story.append(Paragraph(title or "", styles["Heading4"]))
        header = [c["label"] for c in cols]
        data = [header] + [[str(r.get(c["key"], "")) for c in cols] for r in rows]
        tbl = Table(data, hAlign="LEFT", repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f1f5f9"), colors.white]),
        ]))
        story.append(tbl); story.append(Spacer(1, 10))

    _make_table(report["columns"], report["rows"], title="Trend")
    if report.get("detail_rows"):
        _make_table(report["detail_columns"], report["detail_rows"], title="Detail breakdown")
    if report.get("forecast"):
        _make_table(
            [{"key": "step", "label": "Step"}, {"key": "value", "label": "Forecast"},
             {"key": "lower", "label": "Lower 95%"}, {"key": "upper", "label": "Upper 95%"}],
            report["forecast"]["points"],
            title=f"Forecast — next {len(report['forecast']['points'])} periods (metric: {report['forecast']['metric']})",
        )
    doc.build(story)
    buf.seek(0)
    filename = f"{report['report_type'].lower()}_{report['range']['start']}_{report['range']['end']}.pdf"
    return StreamingResponse(buf, media_type="application/pdf",
                              headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _xlsx_response(report: Dict[str, Any]):
    from fastapi.responses import StreamingResponse
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook()

    header_fill = PatternFill("solid", fgColor="1E3A8A")
    header_font = Font(bold=True, color="FFFFFF")
    title_font = Font(bold=True, size=14, color="1E293B")
    subtitle_font = Font(italic=True, color="64748B")
    section_font = Font(bold=True, size=11, color="0F172A")

    def _autofit(ws, ncols):
        for i in range(1, ncols + 1):
            letter = get_column_letter(i)
            width = 12
            for row in ws.iter_rows(min_col=i, max_col=i, values_only=True):
                v = row[0]
                if v is None:
                    continue
                width = max(width, min(40, len(str(v)) + 2))
            ws.column_dimensions[letter].width = width

    def _write_table(ws, start_row, cols, rows):
        headers = [c["label"] for c in cols]
        for j, h in enumerate(headers, start=1):
            cell = ws.cell(row=start_row, column=j, value=h)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = Alignment(horizontal="left", vertical="center")
        for i, r in enumerate(rows, start=1):
            for j, c in enumerate(cols, start=1):
                v = r.get(c["key"], "")
                ws.cell(row=start_row + i, column=j, value=v)
        ws.freeze_panes = ws.cell(row=start_row + 1, column=1)
        _autofit(ws, len(cols))

    # ---- Summary sheet ----
    ws = wb.active
    ws.title = "Summary"
    ws["A1"] = f"CoreOT — {report['report_name']}"
    ws["A1"].font = title_font
    ws.merge_cells("A1:D1")
    ws["A2"] = (f"Range: {report['range']['start']} → {report['range']['end']}  "
                f"·  Aggregation: {report['range']['aggregation']}  "
                f"·  Metric: {report['metric']}")
    ws["A2"].font = subtitle_font
    ws.merge_cells("A2:D2")

    ws["A4"] = "KPIs"; ws["A4"].font = section_font
    _write_table(ws, 5,
                  [{"key": "label", "label": "KPI"}, {"key": "value", "label": "Value"}],
                  report["kpis"])

    # ---- Trend sheet ----
    ws2 = wb.create_sheet("Trend")
    _write_table(ws2, 1, report["columns"], report["rows"])

    # ---- Breakdown sheet ----
    if report.get("detail_rows"):
        ws3 = wb.create_sheet("Breakdown")
        _write_table(ws3, 1, report["detail_columns"], report["detail_rows"])

    # ---- Forecast sheet ----
    if report.get("forecast") and report["forecast"].get("points"):
        ws4 = wb.create_sheet("Forecast")
        ws4["A1"] = f"Forecast — metric: {report['forecast']['metric']} · 95% CI"
        ws4["A1"].font = section_font
        ws4.merge_cells("A1:D1")
        _write_table(ws4, 3,
                      [{"key": "step", "label": "Step"},
                       {"key": "value", "label": "Forecast"},
                       {"key": "lower", "label": "Lower 95%"},
                       {"key": "upper", "label": "Upper 95%"}],
                      report["forecast"]["points"])

    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)
    filename = f"{report['report_type'].lower()}_{report['range']['start']}_{report['range']['end']}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@api.post("/reports/export")
async def reports_export(req: ReportRunRequest, user: User = Depends(require_module("REPORTS"))):
    fmt = (req.format or "csv").lower()
    result = await _compute_report(user, req)
    await record_audit(user, "report.export", "report", req.report_type,
                        {"format": fmt, "range": result["range"]})
    if fmt == "csv":
        return _csv_response(result)
    if fmt == "pdf":
        return _pdf_response(result)
    if fmt == "xlsx":
        return _xlsx_response(result)
    if fmt == "json":
        from fastapi.responses import JSONResponse
        filename = f"{req.report_type.lower()}_{result['range']['start']}_{result['range']['end']}.json"
        return JSONResponse(result, headers={"Content-Disposition": f'attachment; filename="{filename}"'})
    raise HTTPException(status_code=400, detail="format must be csv, xlsx, pdf or json")


class ReportTemplateSave(BaseModel):
    name: str
    request: ReportRunRequest


@api.get("/reports/templates")
async def list_report_templates(user: User = Depends(require_module("REPORTS"))):
    docs = await db.report_templates.find(
        {"tenant_id": user.tenant_id}, {"_id": 0}
    ).sort("created_at", -1).to_list(200)
    return docs


@api.post("/reports/templates")
async def save_report_template(payload: ReportTemplateSave,
                                user: User = Depends(require_module("REPORTS"))):
    if not payload.name.strip():
        raise HTTPException(status_code=400, detail="Template name required")
    req_dict = payload.request.model_dump()
    req_dict.pop("format", None)
    doc = {
        "id": str(uuid.uuid4()),
        "tenant_id": user.tenant_id,
        "name": payload.name.strip(),
        "request": req_dict,
        "created_by": user.email,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.report_templates.insert_one(doc.copy())
    await record_audit(user, "report.template.save", "report_template", doc["id"], {"name": doc["name"]})
    doc.pop("_id", None)
    return doc


@api.delete("/reports/templates/{template_id}")
async def delete_report_template(template_id: str,
                                  user: User = Depends(require_module("REPORTS"))):
    res = await db.report_templates.delete_one({"id": template_id, "tenant_id": user.tenant_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Template not found")
    await record_audit(user, "report.template.delete", "report_template", template_id)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Mount
# ---------------------------------------------------------------------------


@api.get("/")
async def root():
    return {"service": "CoreOT APM", "status": "ok"}


app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)
