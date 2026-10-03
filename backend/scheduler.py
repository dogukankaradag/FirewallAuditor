"""
APScheduler — ayarlanabilir günlük otomatik tarama (Europe/Istanbul).
scan_func: DB oturumunu kendisi açan ve kapatan callable.
"""

import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

_scheduler: BackgroundScheduler | None = None
_scan_func = None

JOB_ID       = "nightly_scan"
DEFAULT_HOUR = 2
DEFAULT_MIN  = 0


def setup_scheduler(scan_func) -> BackgroundScheduler:
    global _scheduler, _scan_func
    _scan_func = scan_func

    _scheduler = BackgroundScheduler(timezone="Europe/Istanbul")
    _scheduler.start()
    logger.info("Zamanlayıcı başlatıldı")
    return _scheduler


def apply_schedule(hour: int, minute: int, enabled: bool):
    """
    DB'den okunan ayarlara göre job'u günceller.
    Uygulama başlangıcında ve ayar değiştiğinde çağrılır.
    """
    if not _scheduler:
        return

    _scheduler.remove_job(JOB_ID) if _scheduler.get_job(JOB_ID) else None

    if not enabled or not _scan_func:
        logger.info("Zamanlayıcı devre dışı")
        return

    _scheduler.add_job(
        _scan_func,
        CronTrigger(hour=hour, minute=minute),
        id=JOB_ID,
        name=f"Günlük Otomatik Tarama ({hour:02d}:{minute:02d})",
        replace_existing=True,
        misfire_grace_time=300,
    )
    logger.info("Zamanlayıcı güncellendi — her gün %02d:%02d (Europe/Istanbul)", hour, minute)


def get_scheduler_status() -> dict:
    if not _scheduler:
        return {"enabled": False, "next_run": None, "hour": DEFAULT_HOUR, "minute": DEFAULT_MIN}

    job = _scheduler.get_job(JOB_ID)
    next_run = job.next_run_time if job else None
    hour, minute = DEFAULT_HOUR, DEFAULT_MIN
    if job:
        t = job.trigger
        # CronTrigger'dan saat/dakika alalım
        try:
            for field in t.fields:
                if field.name == "hour":
                    hour = int(str(field))
                elif field.name == "minute":
                    minute = int(str(field))
        except Exception:
            pass

    return {
        "enabled": bool(job),
        "next_run": next_run.isoformat() if next_run else None,
        "schedule": f"Her gün {hour:02d}:{minute:02d} (Europe/Istanbul)",
        "hour": hour,
        "minute": minute,
    }


def set_scheduler_enabled(enabled: bool) -> dict:
    if not _scheduler:
        return {"enabled": False}
    status = get_scheduler_status()
    apply_schedule(status["hour"], status["minute"], enabled)
    return get_scheduler_status()


def shutdown_scheduler():
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        _scheduler = None
