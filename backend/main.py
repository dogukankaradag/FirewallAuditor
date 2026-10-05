"""
FirewallAudit — FastAPI Backend v2
Auth, DB kalıcılığı, tarama geçmişi, bulgu durum yönetimi.
"""

import hashlib
import json
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
from sqlalchemy import func, case as sql_case, or_

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
    apply_schedule,
    get_scheduler_status,
    set_scheduler_enabled,
    setup_scheduler,
    shutdown_scheduler,
)
from .mailer import (
    get_setting,
    get_all_settings,
    send_acil_report,
    set_setting,
)

import logging
log = logging.getLogger(__name__)

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
        all_results = []
        devices_to_scan = FIREWALL_DEVICES if not device_ids else [d for d in FIREWALL_DEVICES if d["id"] in device_ids]
        fm_devices = [d for d in devices_to_scan if d["type"] == "fortimanager"]
        pa_devices  = [d for d in devices_to_scan if d["type"] == "paloalto"]

        # Ham cihaz verileri — security profilleri kaydetmek için saklıyoruz
        raw_fm_data: list[tuple[dict, dict]] = []   # (dev, fm_data)
        raw_pa_data: list[tuple[dict, dict]] = []   # (dev, pa_data)

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
                raw_fm_data.append((dev, fm_data))
                res = analyzer.scan_device(dev, fm_data=fm_data)
                all_results.extend(res)
            except Exception as e:
                log.error(f"FortiManager cihazı '{label}' taranamadı: {e}", exc_info=True)

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
                raw_pa_data.append((dev, pa_data))
                res = analyzer.scan_device(dev, pa_data=pa_data)
                all_results.extend(res)
            except Exception as e:
                log.error(f"Palo Alto cihazı '{label}' taranamadı: {e}", exc_info=True)

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

                # Çözüldü değişiklik tespiti: daha önce resolved olarak işaretlenmiş bulgu
                # yeni taramada hâlâ çıkıyorsa kural değişip değişmediğini kontrol et
                st = db.query(db_models.FindingStatus).filter(
                    db_models.FindingStatus.fingerprint == fp
                ).first()
                if st and st.status == "resolved" and st.rule_snapshot:
                    try:
                        old_snapshot = st.rule_snapshot if isinstance(st.rule_snapshot, dict) else json.loads(st.rule_snapshot)
                        new_details  = f.rule_details if isinstance(f.rule_details, dict) else {}
                        if old_snapshot != new_details and not st.is_rule_changed:
                            st.is_rule_changed = True
                            st.rule_changed_at = datetime.utcnow()
                    except Exception:
                        pass

            total_rules    += r.total_rules
            total_findings += len(r.findings)

        # Security profile kayıtları — tüm kurallar için (sadece findings değil)
        _save_security_profiles(db, session, raw_fm_data, raw_pa_data)

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


def _save_security_profiles(
    db: Session,
    session: db_models.ScanSession,
    raw_fm_data: list,
    raw_pa_data: list,
):
    """Her cihazın tüm kuralları için SecurityProfileRecord kayıtları oluşturur."""
    for dev, fm_data in raw_fm_data:
        label = dev.get("label", dev["id"])
        for adom in fm_data.get("adoms", []):
            device_name = adom["name"]
            customer    = adom["customer"]
            for pol in adom.get("policies", []):
                sec = pol.get("security_profiles", {})
                db.add(db_models.SecurityProfileRecord(
                    session_id     = session.id,
                    device_name    = device_name,
                    customer       = customer,
                    platform       = "fortimanager",
                    rule_id        = str(pol.get("policyid", "")),
                    rule_name      = pol.get("name", ""),
                    has_av         = bool(sec.get("av", "")),
                    has_webfilter  = bool(sec.get("webfilter", "")),
                    has_filefilter = bool(sec.get("filefilter", "")),
                    has_ips        = bool(sec.get("ips", "")),
                    profile_names  = sec,
                ))

    for dev, pa_data in raw_pa_data:
        for vsys in pa_data.get("vsys_list", []):
            device_name = vsys["name"]
            customer    = vsys["customer"]
            for rule in vsys.get("rules", []):
                sec  = rule.get("security_profiles", {})
                grp  = str(sec.get("group", "") or "")
                # Grup profili varsa tüm profiller var sayılır (en yaygın PA yapılandırması)
                has_all_via_group = bool(grp)
                db.add(db_models.SecurityProfileRecord(
                    session_id     = session.id,
                    device_name    = device_name,
                    customer       = customer,
                    platform       = "paloalto",
                    rule_id        = rule.get("name", ""),
                    rule_name      = rule.get("name", ""),
                    has_av         = has_all_via_group or bool(sec.get("av", "")),
                    has_webfilter  = has_all_via_group or bool(sec.get("webfilter", "")),
                    has_filefilter = has_all_via_group or bool(sec.get("filefilter", "")),
                    has_ips        = has_all_via_group or bool(sec.get("ips", "")),
                    profile_names  = sec,
                ))

    db.flush()


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
        sess = _do_scan(db, triggered_by="scheduler")
        # Tarama tamamlandıktan sonra Acil bulguları mail ile bildir
        if sess and sess.id:
            try:
                result = send_acil_report(db, sess.id)
                if result["sent"]:
                    log.info("Acil rapor maili gönderildi (%d bulgu)", result["acil_count"])
                elif result["error"]:
                    log.warning("Mail gönderilemedi: %s", result["error"])
            except Exception as mail_exc:
                log.error("Mail hatası: %s", mail_exc, exc_info=True)
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
        # İlk kez çalışıyorsa otomatik taramayı ARKA PLANDA başlat
        # (sunucunun istekleri kabul etmesi engellenmez)
        if not _latest_session(db):
            def _startup_scan():
                bg_db = SessionLocal()
                try:
                    _do_scan(bg_db, triggered_by="startup")
                except Exception as e:
                    log.error(f"Startup tarama hatası: {e}", exc_info=True)
                finally:
                    bg_db.close()
            t = threading.Thread(target=_startup_scan, daemon=True)
            t.start()
    finally:
        db.close()
    setup_scheduler(_scheduled_scan)
    # DB'den zamanlayıcı ayarlarını oku ve uygula
    _sched_db = SessionLocal()
    try:
        _hour    = int(get_setting(_sched_db, "scheduler_hour",    "2"))
        _minute  = int(get_setting(_sched_db, "scheduler_minute",  "0"))
        _enabled = get_setting(_sched_db, "scheduler_enabled", "1") == "1"
        apply_schedule(_hour, _minute, _enabled)
    except Exception as _e:
        log.warning("Zamanlayıcı ayarı okunamadı: %s", _e)
        apply_schedule(2, 0, True)
    finally:
        _sched_db.close()
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


# ── FortiManager Diagnostik endpoint'leri ────────────────────────────

@app.get("/api/fm/adoms")
def fm_list_adoms(_: db_models.User = Depends(require_admin)):
    fm_devices = [d for d in FIREWALL_DEVICES if d["type"] == "fortimanager" and not d.get("mock", True)]
    if not fm_devices:
        raise HTTPException(status_code=404, detail="mock=False ayarlı FortiManager cihazı bulunamadı.")

    response = []
    for dev in fm_devices:
        client = FortiManagerClient(
            host=dev["host"], port=dev["port"],
            username=dev["username"], password=dev["password"],
        )
        try:
            client.login()
            adoms = client.get_adoms()
            response.append({
                "device_id":    dev["id"],
                "device_label": dev["label"],
                "device_host":  dev["host"],
                "adom_count":   len(adoms),
                "adoms":        adoms,
            })
        except Exception as exc:
            response.append({
                "device_id":    dev["id"],
                "device_label": dev["label"],
                "device_host":  dev["host"],
                "error":        str(exc),
            })
        finally:
            client.logout()

    return response


@app.get("/api/fm/packages")
def fm_list_packages(_: db_models.User = Depends(require_admin)):
    fm_devices = [d for d in FIREWALL_DEVICES if d["type"] == "fortimanager" and not d.get("mock", True)]
    if not fm_devices:
        raise HTTPException(status_code=404, detail="mock=False ayarlı FortiManager cihazı bulunamadı.")

    response = []
    for dev in fm_devices:
        client = FortiManagerClient(
            host=dev["host"], port=dev["port"],
            username=dev["username"], password=dev["password"],
        )
        try:
            client.login()
            adoms = client.get_adoms()
            adom_details = []
            for adom_name in adoms:
                try:
                    packages = client.get_policy_packages(adom_name)
                    adom_details.append({
                        "adom":          adom_name,
                        "package_count": len(packages),
                        "packages":      packages,
                    })
                except Exception as exc:
                    adom_details.append({
                        "adom":  adom_name,
                        "error": str(exc),
                    })
            response.append({
                "device_id":    dev["id"],
                "device_label": dev["label"],
                "adoms":        adom_details,
            })
        except Exception as exc:
            response.append({
                "device_id":    dev["id"],
                "device_label": dev["label"],
                "error":        str(exc),
            })
        finally:
            client.logout()

    return response


@app.get("/api/fm/policies/{adom_name}/{package_name}")
def fm_list_policies(
    adom_name: str,
    package_name: str,
    limit: int = Query(default=10, ge=1, le=100),
    _: db_models.User = Depends(require_admin),
):
    fm_devices = [d for d in FIREWALL_DEVICES if d["type"] == "fortimanager" and not d.get("mock", True)]
    if not fm_devices:
        raise HTTPException(status_code=404, detail="mock=False ayarlı FortiManager cihazı bulunamadı.")

    dev = fm_devices[0]
    client = FortiManagerClient(
        host=dev["host"], port=dev["port"],
        username=dev["username"], password=dev["password"],
    )
    try:
        client.login()
        policies = client.get_policies(adom_name, package_name)
        return {
            "device_label":   dev["label"],
            "adom":           adom_name,
            "package":        package_name,
            "total_fetched":  len(policies),
            "showing":        min(limit, len(policies)),
            "policies":       policies[:limit],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        client.logout()


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

    # Taramayı arka plan thread'inde çalıştır
    selected_ids = body.device_ids
    def _bg():
        bg_db = SessionLocal()
        try:
            bg_session = bg_db.query(db_models.ScanSession).filter(
                db_models.ScanSession.id == session_id
            ).first()
            _do_scan_core(bg_db, bg_session, device_ids=selected_ids)
        except Exception as e:
            log.error(f"Arka plan tarama hatası: {e}", exc_info=True)
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
        # Çalışan bir tarama var mı kontrol et
        running = db.query(db_models.ScanSession).filter(
            db_models.ScanSession.status == "running"
        ).first()
        return {
            "total_devices": 0, "total_rules": 0, "total_findings": 0,
            "findings_by_severity": {}, "findings_by_platform": {},
            "top_risk_devices": [], "last_scan": None,
            "scan_running": running is not None,
        }

    findings = (
        db.query(db_models.FindingRecord)
        .join(db_models.ScanResult)
        .filter(db_models.ScanResult.session_id == sess.id)
        .all()
    )

    # Resolved bulgular hariç: yalnızca açık olanları say
    fps = [f.fingerprint for f in findings]
    status_map = _status_map(db, fps)

    sev_counts  = {"acil": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    plat_counts = {"fortimanager": 0, "paloalto": 0}
    device_map: dict = {}
    resolved_count = 0
    resolved_changed_count = 0

    for f in findings:
        st = status_map.get(f.fingerprint)
        if st and st.status == "resolved":
            resolved_count += 1
            if st.is_rule_changed:
                resolved_changed_count += 1
            continue   # Çözüldü bulgular özet sayaçlarına dahil edilmez
        sev_counts[f.severity]  = sev_counts.get(f.severity, 0) + 1
        plat_counts[f.platform] = plat_counts.get(f.platform, 0) + 1
        key = f.device_name
        if key not in device_map:
            device_map[key] = {"device": key, "customer": f.customer,
                               "platform": f.platform, "total": 0,
                               "acil": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        device_map[key]["total"] += 1
        device_map[key][f.severity] += 1

    top = sorted(device_map.values(), key=lambda x: (-x.get("acil",0), -x["critical"], -x["high"], -x["total"]))

    # Çalışan tarama var mı?
    running = db.query(db_models.ScanSession).filter(
        db_models.ScanSession.status == "running"
    ).first()

    return {
        "total_devices":        sess.total_devices,
        "total_rules":          sess.total_rules,
        "total_findings":       sum(sev_counts.values()),
        "findings_by_severity": sev_counts,
        "findings_by_platform": plat_counts,
        "top_risk_devices":     top[:6],
        "last_scan":            (sess.finished_at.isoformat() + "Z") if sess.finished_at else None,
        "session_id":           sess.id,
        "scan_running":         running is not None,
        "resolved_count":       resolved_count,
        "resolved_changed_count": resolved_changed_count,
    }


@app.get("/api/devices")
def get_devices(
    db: Session = Depends(get_db),
    _: db_models.User = Depends(get_current_user),
):
    sess = _latest_session(db)
    if not sess:
        return []

    # Single aggregated query — avoids N+1 lazy-loading of r.findings
    rows = (
        db.query(
            db_models.ScanResult.device_id,
            db_models.ScanResult.device_name,
            db_models.ScanResult.device_label,
            db_models.ScanResult.device_host,
            db_models.ScanResult.platform,
            db_models.ScanResult.customer,
            db_models.ScanResult.total_rules,
            db_models.ScanResult.scanned_at,
            db_models.FindingRecord.severity,
            func.count(db_models.FindingRecord.id).label("cnt"),
        )
        .outerjoin(
            db_models.FindingRecord,
            db_models.FindingRecord.scan_result_id == db_models.ScanResult.id,
        )
        .filter(db_models.ScanResult.session_id == sess.id)
        .group_by(db_models.ScanResult.device_id, db_models.FindingRecord.severity)
        .all()
    )

    device_map: dict = {}
    for row in rows:
        did = row.device_id
        if did not in device_map:
            device_map[did] = {
                "id":            did,
                "name":          row.device_name,
                "label":         row.device_label or row.device_name,
                "host":          row.device_host or "",
                "platform":      row.platform,
                "customer":      row.customer,
                "total_rules":   row.total_rules or 0,
                "findings":      {"acil":0,"critical":0,"high":0,"medium":0,"low":0},
                "last_scanned":  row.scanned_at.isoformat(),
            }
        if row.severity:
            device_map[did]["findings"][row.severity] = (
                device_map[did]["findings"].get(row.severity, 0) + (row.cnt or 0)
            )

    devices = list(device_map.values())
    for d in devices:
        d["total_findings"] = sum(d["findings"].values())
    devices.sort(key=lambda d: (
        -d["findings"].get("acil", 0),
        -d["findings"].get("critical", 0),
        -d["findings"].get("high", 0),
        -d["total_findings"],
    ))
    return devices


# ── Bulgular ──────────────────────────────────────────────────────────

@app.get("/api/findings/check-names")
def get_check_names(
    db: Session = Depends(get_db),
    _: db_models.User = Depends(get_current_user),
):
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
    changed_only: bool        = Query(False),   # Yalnızca kural değişmiş çözülmüş bulgular
    session_id: Optional[int] = Query(None),   # Geçmiş oturum görünümü
    page:      int           = Query(1, ge=1),
    limit:     int           = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    _: db_models.User = Depends(get_current_user),
):
    if session_id:
        sess = db.query(db_models.ScanSession).filter(db_models.ScanSession.id == session_id).first()
    else:
        sess = _latest_session(db)
    if not sess:
        return {"total": 0, "page": page, "limit": limit, "findings": []}

    # LEFT JOIN FindingStatus — tüm filtreleme ve sayfalama DB'de yapılır
    q = (
        db.query(db_models.FindingRecord, db_models.FindingStatus, db_models.ScanResult)
        .join(db_models.ScanResult,
              db_models.FindingRecord.scan_result_id == db_models.ScanResult.id)
        .outerjoin(
            db_models.FindingStatus,
            db_models.FindingRecord.fingerprint == db_models.FindingStatus.fingerprint,
        )
        .filter(db_models.ScanResult.session_id == sess.id)
    )

    # Filtreler — DB düzeyinde uygulanır
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

    # Durum filtresi — DB düzeyinde
    if fstatus == "resolved":
        q = q.filter(db_models.FindingStatus.status == "resolved")
    elif fstatus == "open":
        q = q.filter(or_(
            db_models.FindingStatus.id == None,
            db_models.FindingStatus.status == "open",
        ))
    elif fstatus in ("acknowledged", "in_progress"):
        q = q.filter(db_models.FindingStatus.status == fstatus)
    elif not session_id:
        # Default (all, güncel görünüm): çözüldü bulgular hariç
        q = q.filter(or_(
            db_models.FindingStatus.id == None,
            db_models.FindingStatus.status != "resolved",
        ))
    # session_id varsa (geçmiş oturum): tüm bulgular, durum filtresi yok

    if changed_only:
        q = q.filter(db_models.FindingStatus.is_rule_changed == True)

    # Toplam sayı (sayfalama öncesi)
    total = q.count()

    # Önem sırasına göre DB'de sırala
    sev_order_expr = sql_case(
        (db_models.FindingRecord.severity == "acil",     0),
        (db_models.FindingRecord.severity == "critical", 1),
        (db_models.FindingRecord.severity == "high",     2),
        (db_models.FindingRecord.severity == "medium",   3),
        (db_models.FindingRecord.severity == "low",      4),
        else_=99,
    )
    rows = (
        q.order_by(sev_order_expr)
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    result_list = []
    for (r, st, sr) in rows:
        result_list.append({
            "id":             r.id,
            "fingerprint":    r.fingerprint,
            "platform":       r.platform,
            "device_id":      sr.device_id,
            "device_name":    r.device_name,
            "device_label":   sr.device_label,
            "device_host":    sr.device_host,
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
            "status_updated_at": st.updated_at.isoformat() if (st and st.updated_at) else None,
            "is_rule_changed":   bool(st.is_rule_changed) if st else False,
            "rule_changed_at":   st.rule_changed_at.isoformat() if (st and st.rule_changed_at) else None,
        })

    return {"total": total, "page": page, "limit": limit, "findings": result_list}


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

    # Bulgunun son taramadaki rule_details'ini al (snapshot için)
    current_rule_details = None
    sess = _latest_session(db)
    if sess and body.status == "resolved":
        latest_finding = (
            db.query(db_models.FindingRecord)
            .join(db_models.ScanResult)
            .filter(
                db_models.ScanResult.session_id == sess.id,
                db_models.FindingRecord.fingerprint == fingerprint,
            )
            .first()
        )
        if latest_finding:
            current_rule_details = latest_finding.rule_details

    st = db.query(db_models.FindingStatus).filter(
        db_models.FindingStatus.fingerprint == fingerprint
    ).first()

    if st:
        st.status      = body.status
        st.comment     = body.comment
        st.assigned_to = body.assigned_to
        st.updated_by  = current.username
        st.updated_at  = datetime.utcnow()
        # Çözüldü olarak işaretlenince snapshot al; is_rule_changed sıfırla
        if body.status == "resolved" and current_rule_details is not None:
            st.rule_snapshot   = current_rule_details
            st.is_rule_changed = False
            st.rule_changed_at = None
        elif body.status != "resolved":
            # Tekrar açılırsa snapshot temizle
            st.rule_snapshot   = None
            st.is_rule_changed = False
            st.rule_changed_at = None
    else:
        st = db_models.FindingStatus(
            fingerprint=fingerprint,
            status=body.status,
            comment=body.comment,
            assigned_to=body.assigned_to,
            updated_by=current.username,
            rule_snapshot=current_rule_details if body.status == "resolved" else None,
        )
        db.add(st)

    db.commit()
    return {"fingerprint": fingerprint, "status": st.status, "updated_by": st.updated_by}


# ── Security Profiller endpoint'i ─────────────────────────────────────

@app.get("/api/security-profiles")
def get_security_profiles(
    platform: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _: db_models.User = Depends(get_current_user),
):
    """
    Son taramanın security profile verilerini döndürür.

    Yanıt yapısı:
    {
      "by_customer": {
        "<customer>": {
          "total_rules": int,
          "has_av": int,         # AV profili olan kural sayısı
          "has_webfilter": int,
          "has_filefilter": int,
          "has_ips": int,
          "has_all": int,        # Tüm 4 profile sahip kural sayısı
          "platform": str,
          "rules": [...]         # Kural detayları
        }
      },
      "has_all_customers": ["customer1", ...]   # Tüm 4 profili kullanan müşteriler
    }
    """
    sess = _latest_session(db)
    if not sess:
        return {"by_customer": {}, "has_all_customers": []}

    q = db.query(db_models.SecurityProfileRecord).filter(
        db_models.SecurityProfileRecord.session_id == sess.id
    )
    if platform and platform != "all":
        q = q.filter(db_models.SecurityProfileRecord.platform == platform)

    records = q.all()

    by_customer: dict = {}
    for rec in records:
        cust = rec.customer or rec.device_name
        if cust not in by_customer:
            by_customer[cust] = {
                "total_rules":   0,
                "has_av":        0,
                "has_webfilter": 0,
                "has_filefilter":0,
                "has_ips":       0,
                "has_all":       0,
                "platform":      rec.platform,
                "device_name":   rec.device_name,
                "rules":         [],
            }
        entry = by_customer[cust]
        entry["total_rules"] += 1
        if rec.has_av:         entry["has_av"]         += 1
        if rec.has_webfilter:  entry["has_webfilter"]  += 1
        if rec.has_filefilter: entry["has_filefilter"] += 1
        if rec.has_ips:        entry["has_ips"]        += 1
        if rec.has_av and rec.has_webfilter and rec.has_filefilter and rec.has_ips:
            entry["has_all"] += 1
        entry["rules"].append({
            "rule_id":       rec.rule_id,
            "rule_name":     rec.rule_name,
            "has_av":        rec.has_av,
            "has_webfilter": rec.has_webfilter,
            "has_filefilter":rec.has_filefilter,
            "has_ips":       rec.has_ips,
            "profile_names": rec.profile_names or {},
        })

    # Tüm 4 profili kullanan müşteriler (en az bir kuralda)
    has_all_customers = [
        cust for cust, data in by_customer.items() if data["has_all"] > 0
    ]

    return {
        "by_customer":       by_customer,
        "has_all_customers": sorted(has_all_customers),
        "session_id":        sess.id,
        "last_scan":         (sess.finished_at.isoformat() + "Z") if sess.finished_at else None,
    }


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


# ── Sistem ayarları endpoint'leri ─────────────────────────────────────

@app.get("/api/settings")
def get_settings(
    _: db_models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Tüm sistem ayarlarını döner (şifre hariç)."""
    raw = get_all_settings(db)
    return raw


@app.post("/api/settings")
def save_settings(
    body: dict,
    current_user: db_models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Sistem ayarlarını kaydeder.
    Zamanlayıcı saati değiştiyse job yeniden planlanır.
    SMTP şifresi "••••••••" gelirse mevcut şifre korunur.
    """
    ALLOWED = {
        "scheduler_enabled", "scheduler_hour", "scheduler_minute",
        "mail_enabled",
        # SMTP ayarları .env dosyasından okunur, panel üzerinden değiştirilemez
    }
    for key, value in body.items():
        if key not in ALLOWED:
            continue
        # Şifre maskeliyse güncelleme
        if key == "mail_smtp_pass" and value == "••••••••":
            continue
        set_setting(db, key, str(value))

    # Zamanlayıcıyı yeniden planla
    try:
        hour    = int(get_setting(db, "scheduler_hour",    "2"))
        minute  = int(get_setting(db, "scheduler_minute",  "0"))
        enabled = get_setting(db, "scheduler_enabled", "1") == "1"
        apply_schedule(hour, minute, enabled)
    except Exception as e:
        log.warning("Zamanlayıcı güncellenemedi: %s", e)

    return {"ok": True, "scheduler": get_scheduler_status()}


@app.post("/api/settings/test-mail")
def test_mail(
    _: db_models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Son tarama session'ının Acil bulgularını test amaçlı gönderir."""
    sess = _latest_session(db)
    if not sess:
        raise HTTPException(404, "Henüz tamamlanmış tarama yok")
    result = send_acil_report(db, sess.id)
    return result


# ── Excel raporu ──────────────────────────────────────────────────────

@app.get("/api/report/excel")
def download_excel(
    token_q: Optional[str] = Query(None, alias="token"),
    db: Session = Depends(get_db),
):
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
    sev_labels = {"acil": "🟣 ACİL", "critical": "🔴 KRİTİK", "high": "🟠 YÜKSEK", "medium": "🟡 ORTA", "low": "🟢 DÜŞÜK"}
    status_labels = {"open": "Açık", "acknowledged": "Onaylandı", "in_progress": "İşlemde", "resolved": "Çözüldü"}

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
        ("🟣 Acil",        sev_counts.get("acil", 0)),
        ("🔴 Kritik",      sev_counts["critical"]),
        ("🟠 Yüksek",      sev_counts["high"]),
        ("🟡 Orta",        sev_counts["medium"]),
        ("🟢 Düşük",       sev_counts["low"]),
    ]
    for i, (label, val) in enumerate(rows, 4):
        ws[f"A{i}"] = label; ws[f"B{i}"] = val
        ws[f"A{i}"].font = Font(bold=True); ws[f"A{i}"].border = bdr; ws[f"B{i}"].border = bdr

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
