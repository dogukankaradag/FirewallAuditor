"""
FirewallAudit — FastAPI Backend v2
Auth, DB kalıcılığı, tarama geçmişi, bulgu durum yönetimi.
"""

import hashlib
import threading
import io
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

import openpyxl
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import db_models
from .analyzer import FirewallAnalyzer
from .auth import (
    authenticate_user,
    create_access_token,
    create_user,
    ensure_default_users,
    get_current_user,
    require_admin,
    SECRET_KEY,
    ALGORITHM,
)
from jose import JWTError, jwt as jose_jwt
from .database import SessionLocal, get_db, init_db
from .mock_data import FORTIMANAGER_MOCK, PALOALTO_MOCK
from .connectors import FIREWALL_DEVICES
from .fm_client import FortiManagerClient
from .pa_client import PaloAltoClient
from .scheduler import (
    get_scheduler_status,
    set_scheduler_enabled,
    setup_scheduler,
    shutdown_scheduler,
)

# ── Yardımcılar ───────────────────────────────────────────────────────

analyzer = FirewallAnalyzer()
SEV_ORDER = {"acil": 0, "critical": 1, "high": 2, "medium": 3, "low": 4}
EXCEL_COLORS = {
    "acil":     "CC00CC",
    "critical": "C0392B", "high": "E67E22",
    "medium":   "F1C40F", "low":  "27AE60",
    "header":   "2C3E50", "sub":  "34495E",
}


def make_fingerprint(platform: str, device_name: str, rule_id: str, check_name: str) -> str:
    raw = f"{platform}|{device_name}|{rule_id}|{check_name}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _do_scan_core(db: Session, session: db_models.ScanSession, device_ids: Optional[list[str]] = None):
    """Mevcut bir ScanSession kaydı için taramayı çalıştırır."""
    try:
        # Her fiziksel cihazı sırayla tara.
        # mock: True  → yerel mock_data kullanılır
        # mock: False → gerçek cihaz API'sına bağlanılır
        all_results = []
        # Belirli cihazlar seçildiyse yalnızca onları tara
        devices_to_scan = FIREWALL_DEVICES if not device_ids else [d for d in FIREWALL_DEVICES if d["id"] in device_ids]
        fm_devices = [d for d in devices_to_scan if d["type"] == "fortimanager"]
        pa_devices  = [d for d in devices_to_scan if d["type"] == "paloalto"]

        for dev in fm_devices:
            label = dev.get("label", dev["id"])
            try:
                if dev.get("mock", True):
                    fm_data = FORTIMANAGER_MOCK
                else:
                    client = FortiManagerClient(
                        host=dev["host"], port=dev["port"],
                        username=dev["username"], password=dev["password"],
                    )
                    fm_data = client.fetch_all()
                res = analyzer.scan_device(dev, fm_data=fm_data)
                all_results.extend(res)
            except Exception as e:
                import logging as _log
                _log.getLogger(__name__).error(
                    f"FortiManager cihazı '{label}' taranamadı: {e}", exc_info=True
                )

        for dev in pa_devices:
            label = dev.get("label", dev["id"])
            try:
                if dev.get("mock", True):
                    pa_data = PALOALTO_MOCK
                else:
                    client = PaloAltoClient(
                        host=dev["host"], port=dev["port"],
                        username=dev["username"], password=dev["password"],
                    )
                    pa_data = client.fetch_all()
                res = analyzer.scan_device(dev, pa_data=pa_data)
                all_results.extend(res)
            except Exception as e:
                import logging as _log
                _log.getLogger(__name__).error(
                    f"Palo Alto cihazı '{label}' taranamadı: {e}", exc_info=True
                )

        results = all_results
        total_rules = total_findings = 0

        for r in results:
            scan_res = db_models.ScanResult(
                session_id=session.id,
                device_id=r.device_id,
                device_name=r.device_name,
                device_label=r.device_label,
                device_host=r.device_host,
                platform=r.platform.value,
                customer=r.customer,
                total_rules=r.total_rules,
            )
            db.add(scan_res)
            db.flush()

            for f in r.findings:
                fp = make_fingerprint(f.platform.value, f.device_name, f.rule_id, f.check_name)
                rec = db_models.FindingRecord(
                    scan_result_id=scan_res.id,
                    fingerprint=fp,
                    platform=f.platform.value,
                    device_name=f.device_name,
                    customer=f.customer,
                    rule_id=f.rule_id,
                    rule_name=f.rule_name,
                    severity=f.severity.value,
                    check_name=f.check_name,
                    description=f.description,
                    recommendation=f.recommendation,
                    rule_details=f.rule_details,
                )
                db.add(rec)

            total_rules    += r.total_rules
            total_findings += len(r.findings)

        session.finished_at    = datetime.utcnow()
        session.status         = "completed"
        session.total_devices  = len(results)
        session.total_rules    = total_rules
        session.total_findings = total_findings
        db.commit()
        db.refresh(session)

    except Exception as exc:
        session.status      = "failed"
        session.finished_at = datetime.utcnow()
        db.commit()
        raise exc


def _do_scan(db: Session, triggered_by: str = "manual") -> db_models.ScanSession:
    """ScanSession oluşturup _do_scan_core'u çağırır (scheduler/startup için)."""
    session = db_models.ScanSession(triggered_by=triggered_by, status="running")
    db.add(session)
    db.commit()
    db.refresh(session)
    _do_scan_core(db, session)
    db.refresh(session)
    return session


def _scheduled_scan():
    """APScheduler arka plan thread'inden çağrılır — kendi DB oturumunu açar."""
    db = SessionLocal()
    try:
        _do_scan(db, triggered_by="scheduler")
    finally:
        db.close()


def _latest_session(db: Session) -> Optional[db_models.ScanSession]:
    return (
        db.query(db_models.ScanSession)
        .filter(db_models.ScanSession.status == "completed")
        .order_by(db_models.ScanSession.finished_at.desc())
        .first()
    )


def _status_map(db: Session, fingerprints: list[str]) -> dict:
    rows = db.query(db_models.FindingStatus).filter(
        db_models.FindingStatus.fingerprint.in_(fingerprints)
    ).all()
    return {r.fingerprint: r for r in rows}


# ── Uygulama yaşam döngüsü ────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        ensure_default_users(db)
        # İlk kez çalışıyorsa otomatik tarama yap
        if not _latest_session(db):
            _do_scan(db, triggered_by="startup")
    finally:
        db.close()
    setup_scheduler(_scheduled_scan)
    yield
    shutdown_scheduler()


app = FastAPI(title="FirewallAudit API", version="2.0.0", docs_url="/api/docs", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# ── Pydantic şemaları ─────────────────────────────────────────────────

class FindingStatusUpdate(BaseModel):
    status: str       # open | acknowledged | in_progress | resolved
    comment: Optional[str] = None
    assigned_to: Optional[str] = None


class UserCreate(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = ""
    role: str = "readonly"


class UserEdit(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    password: Optional[str] = None


class ScanRequest(BaseModel):
    device_ids: Optional[list[str]] = None   # None = tüm cihazlar


# ── Auth endpoint'leri ────────────────────────────────────────────────

@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form.username, form.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kullanıcı adı veya parola hatalı.",
        )
    token = create_access_token(user.username, user.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "full_name": user.full_name,
        "role": user.role,
    }


@app.get("/api/auth/me")
def me(current_user: db_models.User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "role": current_user.role,
    }


@app.get("/api/auth/users")
def list_users(
    db: Session = Depends(get_db),
    _: db_models.User = Depends(require_admin),
):
    users = db.query(db_models.User).order_by(db_models.User.id).all()
    return [
        {"id": u.id, "username": u.username, "full_name": u.full_name,
         "role": u.role, "is_active": u.is_active, "created_at": u.created_at.isoformat()}
        for u in users
    ]


@app.post("/api/auth/users", status_code=201)
def create_new_user(
    body: UserCreate,
    db: Session = Depends(get_db),
    _: db_models.User = Depends(require_admin),
):
    if db.query(db_models.User).filter(db_models.User.username == body.username).first():
        raise HTTPException(400, detail="Bu kullanıcı adı zaten kullanılıyor.")
    if body.role not in ("admin", "readonly"):
        raise HTTPException(400, detail="Rol 'admin' veya 'readonly' olmalıdır.")
    user = create_user(db, body.username, body.password, body.role, body.full_name or "")
    return {"id": user.id, "username": user.username, "role": user.role}


@app.patch("/api/auth/users/{user_id}")
def toggle_user(
    user_id: int,
    db: Session = Depends(get_db),
    current: db_models.User = Depends(require_admin),
):
    user = db.query(db_models.User).filter(db_models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Kullanıcı bulunamadı.")
    if user.id == current.id:
        raise HTTPException(400, "Kendi hesabınızı devre dışı bırakamazsınız.")
    user.is_active = not user.is_active
    db.commit()
    return {"id": user.id, "is_active": user.is_active}


@app.put("/api/auth/users/{user_id}")
def edit_user(
    user_id: int,
    body: UserEdit,
    db: Session = Depends(get_db),
    current: db_models.User = Depends(require_admin),
):
    user = db.query(db_models.User).filter(db_models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Kullanıcı bulunamadı.")
    if body.role and body.role not in ("admin", "readonly"):
        raise HTTPException(400, "Rol 'admin' veya 'readonly' olmalıdır.")
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.role is not None:
        user.role = body.role
    if body.password:
        from .auth import hash_password as _hp
        user.password_hash = _hp(body.password)
    db.commit()
    return {"id": user.id, "username": user.username, "full_name": user.full_name,
            "role": user.role, "is_active": user.is_active}


@app.delete("/api/auth/users/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current: db_models.User = Depends(require_admin),
):
    user = db.query(db_models.User).filter(db_models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Kullanıcı bulunamadı.")
    if user.id == current.id:
        raise HTTPException(400, "Kendi hesabınızı silemezsiniz.")
    db.delete(user)
    db.commit()


# ── Cihaz kayıt defteri ───────────────────────────────────────────────

@app.get("/api/connectors")
def list_connectors(_: db_models.User = Depends(get_current_user)):
    """Tanımlı fiziksel cihazların listesi (şifreler olmadan)."""
    from .connectors import list_devices
    return list_devices()


# ── Tarama endpoint'leri ──────────────────────────────────────────────

_scan_lock = threading.Lock()

@app.post("/api/scan")
def trigger_scan(
    body: ScanRequest = ScanRequest(),
    db: Session = Depends(get_db),
    current: db_models.User = Depends(require_admin),
):
    # Eş zamanlı taramayı engelle
    running = db.query(db_models.ScanSession).filter(
        db_models.ScanSession.status == "running"
    ).first()
    if running:
        return {"session_id": running.id, "status": "running", "already_running": True}

    # Session kaydını hemen oluştur, yanıtı döndür
    session = db_models.ScanSession(triggered_by=current.username, status="running")
    db.add(session); db.commit(); db.refresh(session)
    session_id = session.id

    # Taramayı arka plan thread'inde çalıştır (sunucu bloklanmaz)
    selected_ids = body.device_ids  # None = tüm cihazlar
    def _bg():
        bg_db = SessionLocal()
        try:
            bg_session = bg_db.query(db_models.ScanSession).filter(
                db_models.ScanSession.id == session_id
            ).first()
            _do_scan_core(bg_db, bg_session, device_ids=selected_ids)
        except Exception as e:
            import logging as _l
            _l.getLogger(__name__).error(f"Arka plan tarama hatası: {e}", exc_info=True)
        finally:
            bg_db.close()

    t = threading.Thread(target=_bg, daemon=True)
    t.start()

    return {"session_id": session_id, "status": "running"}


@app.get("/api/scan/history")
def scan_history(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _: db_models.User = Depends(get_current_user),
):
    sessions = (
        db.query(db_models.ScanSession)
        .order_by(db_models.ScanSession.started_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": s.id,
            "started_at": s.started_at.isoformat(),
            "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            "triggered_by": s.triggered_by,
            "status": s.status,
            "total_devices": s.total_devices,
            "total_rules": s.total_rules,
            "total_findings": s.total_findings,
        }
        for s in sessions
    ]


# ── Özet & Cihazlar ───────────────────────────────────────────────────

@app.get("/api/summary")
def get_summary(
    db: Session = Depends(get_db),
    _: db_models.User = Depends(get_current_user),
):
    sess = _latest_session(db)
    if not sess:
        return {"total_devices": 0, "total_rules": 0, "total_findings": 0,
                "findings_by_severity": {}, "findings_by_platform": {}, "top_risk_devices": [], "last_scan": None}

    findings = (
        db.query(db_models.FindingRecord)
        .join(db_models.ScanResult)
        .filter(db_models.ScanResult.session_id == sess.id)
        .all()
    )

    sev_counts  = {"acil": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    plat_counts = {"fortimanager": 0, "paloalto": 0}
    device_map: dict = {}

    for f in findings:
        sev_counts[f.severity]  = sev_counts.get(f.severity, 0) + 1
        plat_counts[f.platform] = plat_counts.get(f.platform, 0) + 1
        key = f.device_name
        if key not in device_map:
            device_map[key] = {"device": key, "customer": f.customer,
                               "platform": f.platform, "total": 0,
                               "critical": 0, "high": 0, "medium": 0, "low": 0}
        device_map[key]["total"] += 1
        device_map[key][f.severity] += 1

    top = sorted(device_map.values(), key=lambda x: (-x["critical"], -x["high"], -x["total"]))

    return {
        "total_devices":        sess.total_devices,
        "total_rules":          sess.total_rules,
        "total_findings":       sess.total_findings,
        "findings_by_severity": sev_counts,
        "findings_by_platform": plat_counts,
        "top_risk_devices":     top[:6],
        "last_scan":            sess.finished_at.isoformat() if sess.finished_at else None,
        "session_id":           sess.id,
    }


@app.get("/api/devices")
def get_devices(
    db: Session = Depends(get_db),
    _: db_models.User = Depends(get_current_user),
):
    sess = _latest_session(db)
    if not sess:
        return []

    results = (
        db.query(db_models.ScanResult)
        .filter(db_models.ScanResult.session_id == sess.id)
        .all()
    )

    devices = []
    for r in results:
        counts = {"acil": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in r.findings:
            counts[f.severity] += 1
        devices.append({
            "id":            r.device_id,
            "name":          r.device_name,
            "label":         r.device_label or r.device_name,
            "host":          r.device_host or "",
            "platform":      r.platform,
            "customer":      r.customer,
            "total_rules":   r.total_rules,
            "findings":      counts,
            "total_findings": sum(counts.values()),
            "last_scanned":  r.scanned_at.isoformat(),
        })

    devices.sort(key=lambda d: (-d["findings"]["critical"], -d["findings"]["high"], -d["total_findings"]))
    return devices


# ── Bulgular ──────────────────────────────────────────────────────────

@app.get("/api/findings/check-names")
def get_check_names(
    db: Session = Depends(get_db),
    _: db_models.User = Depends(get_current_user),
):
    """Son taramadaki tüm benzersiz check_name değerlerini döndürür."""
    sess = _latest_session(db)
    if not sess:
        return []
    rows = (
        db.query(db_models.FindingRecord.check_name)
        .join(db_models.ScanResult)
        .filter(db_models.ScanResult.session_id == sess.id)
        .distinct()
        .order_by(db_models.FindingRecord.check_name)
        .all()
    )
    return [r[0] for r in rows if r[0]]


@app.get("/api/findings")
def get_findings(
    device_id: Optional[str] = Query(None),
    severity:  Optional[str] = Query(None),
    platform:  Optional[str] = Query(None),
    fstatus:    Optional[str] = Query(None, alias="status"),
    check_name: Optional[str] = Query(None),
    search:     Optional[str] = Query(None),
    page:      int           = Query(1, ge=1),
    limit:     int           = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    _: db_models.User = Depends(get_current_user),
):
    sess = _latest_session(db)
    if not sess:
        return {"total": 0, "page": page, "limit": limit, "findings": []}

    q = (
        db.query(db_models.FindingRecord)
        .join(db_models.ScanResult)
        .filter(db_models.ScanResult.session_id == sess.id)
    )

    if device_id and device_id != "all":
        q = q.filter(db_models.ScanResult.device_id == device_id)
    if severity and severity != "all":
        q = q.filter(db_models.FindingRecord.severity == severity)
    if platform and platform != "all":
        q = q.filter(db_models.FindingRecord.platform == platform)
    if check_name and check_name != "all":
        q = q.filter(db_models.FindingRecord.check_name == check_name)
    if search:
        s = f"%{search.lower()}%"
        q = q.filter(
            db_models.FindingRecord.rule_name.ilike(s)
            | db_models.FindingRecord.customer.ilike(s)
            | db_models.FindingRecord.check_name.ilike(s)
            | db_models.FindingRecord.device_name.ilike(s)
        )

    all_recs = q.all()

    # Durum bilgisi ekle
    fps = [r.fingerprint for r in all_recs]
    status_map = _status_map(db, fps)

    result_list = []
    for r in all_recs:
        st = status_map.get(r.fingerprint)
        result_list.append({
            "id":             r.id,
            "fingerprint":    r.fingerprint,
            "platform":       r.platform,
            "device_id":      r.scan_result.device_id if r.scan_result else "",
            "device_name":    r.device_name,
            "device_label":   r.scan_result.device_label if r.scan_result else "",
            "device_host":    r.scan_result.device_host if r.scan_result else "",
            "customer":       r.customer,
            "rule_id":        r.rule_id,
            "rule_name":      r.rule_name,
            "severity":       r.severity,
            "check_name":     r.check_name,
            "description":    r.description,
            "recommendation": r.recommendation,
            "rule_details":   r.rule_details,
            "detected_at":    r.detected_at.isoformat(),
            "status":         st.status if st else "open",
            "status_comment": st.comment if st else None,
            "assigned_to":    st.assigned_to if st else None,
            "status_updated_by": st.updated_by if st else None,
            "status_updated_at": st.updated_at.isoformat() if st else None,
        })

    # Durum filtresi (DB'de join yerine bellekte — basitlik için)
    if fstatus and fstatus != "all":
        result_list = [f for f in result_list if f["status"] == fstatus]

    result_list.sort(key=lambda f: SEV_ORDER.get(f["severity"], 99))

    total = len(result_list)
    start = (page - 1) * limit
    return {"total": total, "page": page, "limit": limit, "findings": result_list[start: start + limit]}


@app.patch("/api/findings/{fingerprint}/status")
def update_finding_status(
    fingerprint: str,
    body: FindingStatusUpdate,
    db: Session = Depends(get_db),
    current: db_models.User = Depends(require_admin),
):
    valid = {"open", "acknowledged", "in_progress", "resolved"}
    if body.status not in valid:
        raise HTTPException(400, f"Geçersiz durum. Geçerli değerler: {valid}")

    st = db.query(db_models.FindingStatus).filter(
        db_models.FindingStatus.fingerprint == fingerprint
    ).first()

    if st:
        st.status      = body.status
        st.comment     = body.comment
        st.assigned_to = body.assigned_to
        st.updated_by  = current.username
        st.updated_at  = datetime.utcnow()
    else:
        st = db_models.FindingStatus(
            fingerprint=fingerprint,
            status=body.status,
            comment=body.comment,
            assigned_to=body.assigned_to,
            updated_by=current.username,
        )
        db.add(st)

    db.commit()
    return {"fingerprint": fingerprint, "status": st.status, "updated_by": st.updated_by}


# ── Zamanlayıcı endpoint'leri ─────────────────────────────────────────

@app.get("/api/scheduler")
def scheduler_status(_: db_models.User = Depends(require_admin)):
    return get_scheduler_status()


@app.post("/api/scheduler/toggle")
def toggle_scheduler(
    body: dict,
    _: db_models.User = Depends(require_admin),
):
    enabled = body.get("enabled", True)
    return set_scheduler_enabled(enabled)


# ── Excel raporu ──────────────────────────────────────────────────────

@app.get("/api/report/excel")
def download_excel(
    token_q: Optional[str] = Query(None, alias="token"),
    db: Session = Depends(get_db),
):
    # Accept token from query param (browser download) or Authorization header
    from fastapi import Request
    raw_token = token_q
    if not raw_token:
        raise HTTPException(401, "Token gereklidir. ?token=... parametresi ekleyin.")
    try:
        payload  = jose_jwt.decode(raw_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(401, "Geçersiz token.")
        user = db.query(db_models.User).filter(
            db_models.User.username == username,
            db_models.User.is_active == True,
        ).first()
        if not user:
            raise HTTPException(401, "Geçersiz token.")
    except JWTError:
        raise HTTPException(401, "Geçersiz veya süresi dolmuş token.")

    sess = _latest_session(db)
    if not sess:
        raise HTTPException(404, "Henüz tamamlanmış bir tarama yok.")

    findings_q = (
        db.query(db_models.FindingRecord)
        .join(db_models.ScanResult)
        .filter(db_models.ScanResult.session_id == sess.id)
        .all()
    )

    fps = [f.fingerprint for f in findings_q]
    status_map = _status_map(db, fps)

    results_q = (
        db.query(db_models.ScanResult)
        .filter(db_models.ScanResult.session_id == sess.id)
        .all()
    )

    wb   = openpyxl.Workbook()
    thin = Side(style="thin", color="CCCCCC")
    bdr  = Border(left=thin, right=thin, top=thin, bottom=thin)

    def fill(color): return PatternFill("solid", fgColor=color)
    sev_labels = {"critical": "🔴 KRİTİK", "high": "🟠 YÜKSEK", "medium": "🟡 ORTA", "low": "🟢 DÜŞÜK"}
    status_labels = {"open": "Açık", "acknowledged": "Onaylandı", "in_progress": "İşlemde", "resolved": "Çözüldü"}

    # ── Özet sayfası ──────────────────────────────────────────────────
    ws = wb.active
    ws.title = "Özet"
    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 20

    ws["A1"] = "🔐 FirewallAudit — Güvenlik Zafiyet Raporu"
    ws["A1"].font = Font(bold=True, size=14, color="FFFFFF")
    ws["A1"].fill = fill(EXCEL_COLORS["header"])
    ws.merge_cells("A1:B1")

    ws["A2"] = f"Tarama: {sess.finished_at.strftime('%d.%m.%Y %H:%M')} — {sess.triggered_by}"
    ws["A2"].font = Font(italic=True, color="888888")
    ws.merge_cells("A2:B2")

    sev_counts = {"acil": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings_q:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    rows = [
        ("Taranan Cihaz",  sess.total_devices),
        ("Toplam Kural",   sess.total_rules),
        ("🔴 Kritik",      sev_counts["critical"]),
        ("🟠 Yüksek",      sev_counts["high"]),
        ("🟡 Orta",        sev_counts["medium"]),
        ("🟢 Düşük",       sev_counts["low"]),
    ]
    for i, (label, val) in enumerate(rows, 4):
        ws[f"A{i}"] = label; ws[f"B{i}"] = val
        ws[f"A{i}"].font = Font(bold=True); ws[f"A{i}"].border = bdr; ws[f"B{i}"].border = bdr

    # ── Tüm bulgular ──────────────────────────────────────────────────
    ws2 = wb.create_sheet("Tüm Bulgular")
    hdrs = ["#","Önem","Durum","Platform","Müşteri","Cihaz","Kural ID","Kural Adı","Zafiyet","Açıklama","Öneri","Sorumlu"]
    widths = [5,12,14,14,22,26,10,28,26,50,50,20]
    for col, (h, w) in enumerate(zip(hdrs, widths), 1):
        c = ws2.cell(1, col, h)
        c.font = Font(bold=True, color="FFFFFF"); c.fill = fill(EXCEL_COLORS["header"])
        c.border = bdr; c.alignment = Alignment(horizontal="center")
        ws2.column_dimensions[c.column_letter].width = w

    for ri, f in enumerate(sorted(findings_q, key=lambda x: SEV_ORDER.get(x.severity, 9)), 2):
        st = status_map.get(f.fingerprint)
        st_label = status_labels.get(st.status if st else "open", "Açık")
        vals = [ri-1, sev_labels.get(f.severity,""), st_label,
                "FortiManager" if f.platform=="fortimanager" else "Palo Alto",
                f.customer, f.device_name, f.rule_id, f.rule_name,
                f.check_name, f.description, f.recommendation,
                st.assigned_to if st else ""]
        for col, v in enumerate(vals, 1):
            c = ws2.cell(ri, col, v if isinstance(v, int) else str(v or ""))
            c.border = bdr; c.alignment = Alignment(wrap_text=True, vertical="top")
            if col == 2:
                c.fill = fill(EXCEL_COLORS.get(f.severity, "FFFFFF"))
                c.font = Font(bold=True, color="FFFFFF" if f.severity in ("acil","critical","high") else "000000")
        ws2.row_dimensions[ri].height = 40

    # ── Cihaz bazlı sayfalar ──────────────────────────────────────────
    for res in results_q:
        ws3 = wb.create_sheet(res.device_name[:28])
        ws3["A1"] = f"{res.device_name} — {res.customer}"
        ws3["A1"].font = Font(bold=True, size=12, color="FFFFFF")
        ws3["A1"].fill = fill(EXCEL_COLORS["header"])
        ws3.merge_cells("A1:G1")
        hdrs3 = ["Önem","Durum","Kural ID","Kural Adı","Zafiyet","Açıklama","Öneri"]
        widths3 = [12,14,10,28,26,50,50]
        for col, (h,w) in enumerate(zip(hdrs3,widths3),1):
            c = ws3.cell(2,col,h); c.font=Font(bold=True,color="FFFFFF")
            c.fill=fill(EXCEL_COLORS["sub"]); c.border=bdr
            ws3.column_dimensions[c.column_letter].width=w
        dev_findings = sorted(res.findings, key=lambda x: SEV_ORDER.get(x.severity,9))
        for ri, f in enumerate(dev_findings, 3):
            st = status_map.get(f.fingerprint)
            st_label = status_labels.get(st.status if st else "open","Açık")
            row_vals = [sev_labels.get(f.severity,""), st_label, f.rule_id,
                        f.rule_name, f.check_name, f.description, f.recommendation]
            for col, v in enumerate(row_vals, 1):
                c = ws3.cell(ri, col, str(v or ""))
                c.border=bdr; c.alignment=Alignment(wrap_text=True,vertical="top")
                if col==1:
                    c.fill=fill(EXCEL_COLORS.get(f.severity,"FFFFFF"))
                    c.font=Font(bold=True, color="FFFFFF" if f.severity in ("acil","critical","high") else "000000")
            ws3.row_dimensions[ri].height=45

    buf = io.BytesIO(); wb.save(buf); buf.seek(0)
    fname = f"firewall_audit_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx"
    return StreamingResponse(buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={fname}"})


# ── Frontend ──────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    path = Path(__file__).parent.parent / "frontend" / "index.html"
    return HTMLResponse(content=path.read_text(encoding="utf-8"))
