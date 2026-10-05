"""
SMTP mail gönderici — tarama sonrası Acil bulguları raporlar.

Ayar bölünmesi:
  .env   → SMTP_HOST, SMTP_PORT, SMTP_FROM, SMTP_USE_TLS  (sunucu altyapısı)
  DB     → mail_to, mail_cc, mail_subject, mail_enabled, scheduler_*
"""
import logging
import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

log = logging.getLogger(__name__)

DEFAULT_SUBJECT = "Firewall Auditor - ACİL BULGULAR RAPORU"


# ── DB ayar yardımcıları ─────────────────────────────────────────────

def get_setting(db, key: str, default: str = "") -> str:
    from .db_models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    return row.value if (row and row.value is not None) else default


def set_setting(db, key: str, value: str):
    from .db_models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(SystemSetting(key=key, value=value))
    db.commit()


def get_all_settings(db) -> dict:
    from .db_models import SystemSetting
    rows = db.query(SystemSetting).all()
    out = {r.key: r.value for r in rows}
    # Eksik mail alanları için varsayılanları doldur
    out.setdefault("mail_subject", DEFAULT_SUBJECT)
    return out


# ── .env parse ───────────────────────────────────────────────────────

def _load_env():
    """python-dotenv yoksa .env dosyasını manuel okur."""
    try:
        from dotenv import load_dotenv
        load_dotenv(override=False)
        return
    except ImportError:
        pass
    env_path = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", ".env")
    )
    if not os.path.isfile(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip()
            if k and k not in os.environ:
                os.environ[k] = v


# ── Mail gönderici ───────────────────────────────────────────────────

def send_acil_report(db, session_id: int) -> dict:
    """
    Belirtilen tarama session'ına ait Acil bulguları (çözüldü hariç) mail ile gönderir.
    Dönüş: {"sent": bool, "error": str|None, "acil_count": int}
    """
    from .db_models import FindingRecord, FindingStatus, ScanResult, ScanSession
    from sqlalchemy import or_

    # Mail etkin mi?
    if get_setting(db, "mail_enabled", "0") != "1":
        return {"sent": False, "error": "Mail bildirimi devre dışı", "acil_count": 0}

    # SMTP altyapısı — .env'den
    _load_env()
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    smtp_port = int(os.environ.get("SMTP_PORT", "25") or "25")
    smtp_from = os.environ.get("SMTP_FROM", "").strip()
    use_tls   = os.environ.get("SMTP_USE_TLS", "false").strip().lower() == "true"

    if not smtp_host:
        return {"sent": False, "error": "SMTP_HOST tanımlanmamış (.env)", "acil_count": 0}

    # Alıcılar ve konu — DB'den
    mail_to  = [a.strip() for a in get_setting(db, "mail_to",  "").split(",") if a.strip()]
    mail_cc  = [a.strip() for a in get_setting(db, "mail_cc",  "").split(",") if a.strip()]
    subject  = get_setting(db, "mail_subject", DEFAULT_SUBJECT) or DEFAULT_SUBJECT

    if not mail_to:
        return {"sent": False, "error": "Alıcı (To) tanımlanmamış — Ayarlar panelinden ekleyin", "acil_count": 0}

    # Acil bulgular (çözüldü hariç)
    rows = (
        db.query(FindingRecord, FindingStatus, ScanResult)
        .join(ScanResult, FindingRecord.scan_result_id == ScanResult.id)
        .outerjoin(FindingStatus, FindingRecord.fingerprint == FindingStatus.fingerprint)
        .filter(
            ScanResult.session_id == session_id,
            FindingRecord.severity == "acil",
            or_(FindingStatus.id == None, FindingStatus.status != "resolved"),
        )
        .order_by(FindingRecord.customer, FindingRecord.device_name, FindingRecord.rule_name)
        .all()
    )
    acil_count = len(rows)

    sess = db.query(ScanSession).filter(ScanSession.id == session_id).first()
    scan_time = sess.finished_at.strftime("%d.%m.%Y %H:%M") if (sess and sess.finished_at) else "—"

    # Mesaj oluştur
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = smtp_from or smtp_host
    msg["To"]      = ", ".join(mail_to)
    if mail_cc:
        msg["Cc"] = ", ".join(mail_cc)
    msg.attach(MIMEText(_build_html(rows, acil_count, scan_time, subject), "html", "utf-8"))

    recipients = mail_to + mail_cc

    try:
        if use_tls:
            ctx = ssl.create_default_context()
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
                s.ehlo(); s.starttls(context=ctx)
                s.sendmail(smtp_from, recipients, msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
                s.sendmail(smtp_from, recipients, msg.as_string())

        log.info("Acil rapor maili gönderildi — %d bulgu → %s", acil_count, recipients)
        return {"sent": True, "error": None, "acil_count": acil_count}
    except Exception as e:
        log.error("Mail gönderilemedi: %s", e, exc_info=True)
        return {"sent": False, "error": str(e), "acil_count": acil_count}


# ── HTML şablonu ─────────────────────────────────────────────────────

def _build_html(rows, acil_count: int, scan_time: str, subject: str) -> str:
    rows_html = ""
    for i, (f, st, sr) in enumerate(rows):
        bg = "#fff9f9" if i % 2 == 0 else "#fff3f3"
        status_map = {"open": "Açık", "acknowledged": "Farkında", "in_progress": "İşlemde"}
        status_label = status_map.get(st.status, st.status) if st else "Açık"
        details_html = ""
        if f.rule_details:
            items = [f"<b>{k}</b>: {v}" for k, v in f.rule_details.items() if v and k != "raw"]
            details_html = "<br>".join(items[:6])
        rows_html += f"""
        <tr style="background:{bg}">
          <td style="padding:8px 10px;border-bottom:1px solid #ffe0e0;color:#cc0000;font-weight:700">🚨 ACİL</td>
          <td style="padding:8px 10px;border-bottom:1px solid #ffe0e0">{sr.customer or '—'}</td>
          <td style="padding:8px 10px;border-bottom:1px solid #ffe0e0">{f.device_name or '—'}</td>
          <td style="padding:8px 10px;border-bottom:1px solid #ffe0e0;font-weight:600">{f.check_name or '—'}</td>
          <td style="padding:8px 10px;border-bottom:1px solid #ffe0e0">{f.rule_name or f.rule_id or '—'}</td>
          <td style="padding:8px 10px;border-bottom:1px solid #ffe0e0;font-size:12px;color:#555">{details_html}</td>
          <td style="padding:8px 10px;border-bottom:1px solid #ffe0e0;font-size:12px;color:#888">{status_label}</td>
        </tr>"""

    if not rows_html:
        rows_html = """<tr><td colspan="7" style="padding:20px;text-align:center;color:#555;font-style:italic">
            Bu taramada çözülmemiş Acil bulgu bulunamadı.</td></tr>"""

    return f"""<!DOCTYPE html>
<html lang="tr">
<head><meta charset="utf-8"><title>{subject}</title></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;padding:24px 0">
    <tr><td align="center">
      <table width="820" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)">
        <tr><td style="background:#cc0000;padding:20px 28px">
          <div style="color:#fff;font-size:20px;font-weight:700">🚨 {subject}</div>
          <div style="color:#ffcccc;font-size:13px;margin-top:4px">Tarama zamanı: {scan_time} (Europe/Istanbul)</div>
        </td></tr>
        <tr><td style="padding:16px 28px;background:#fff8f8;border-bottom:1px solid #ffe0e0">
          <span style="font-size:15px;color:#cc0000;font-weight:600">
            Toplam <b>{acil_count}</b> adet çözülmemiş Acil bulgu tespit edildi.
          </span>
          <span style="font-size:12px;color:#888;margin-left:12px">(Çözüldü işaretli bulgular bu raporda yer almaz.)</span>
        </td></tr>
        <tr><td style="padding:20px 28px">
          <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:13px">
            <thead>
              <tr style="background:#ffeeee">
                <th style="padding:8px 10px;text-align:left;border-bottom:2px solid #cc0000">Önem</th>
                <th style="padding:8px 10px;text-align:left;border-bottom:2px solid #cc0000">Müşteri</th>
                <th style="padding:8px 10px;text-align:left;border-bottom:2px solid #cc0000">Cihaz</th>
                <th style="padding:8px 10px;text-align:left;border-bottom:2px solid #cc0000">Kontrol</th>
                <th style="padding:8px 10px;text-align:left;border-bottom:2px solid #cc0000">Kural</th>
                <th style="padding:8px 10px;text-align:left;border-bottom:2px solid #cc0000">Detaylar</th>
                <th style="padding:8px 10px;text-align:left;border-bottom:2px solid #cc0000">Durum</th>
              </tr>
            </thead>
            <tbody>{rows_html}</tbody>
          </table>
        </td></tr>
        <tr><td style="padding:14px 28px;background:#f9f9f9;border-top:1px solid #eee;text-align:center">
          <span style="font-size:11px;color:#aaa">Bu mail FirewallAudit sistemi tarafından otomatik olarak gönderilmiştir.</span>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""
