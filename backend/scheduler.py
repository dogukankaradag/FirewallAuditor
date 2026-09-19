"""
APScheduler — gece 02:00 otomatik tarama.
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
    _scheduler.add_job(
        scan_func,
        CronTrigger(hour=DEFAULT_HOUR, minute=DEFAULT_MIN),
        id=JOB_ID,
        name="Gece Otomatik Tarama",
        replace_existing=True,
        misfire_grace_time=300,
    )
    _scheduler.start()
    logger.info("Zamanlayıcı başlatıldı — her gece %02d:%02d'de tarama", DEFAULT_HOUR, DEFAULT_MIN)
    return _scheduler


def get_scheduler_status() -> dict:
    if not _scheduler:
        return {"enabled": False, "next_run": None}

    job = _scheduler.get_job(JOB_ID)
    if not job:
        return {"enabled": False, "next_run": None}

    next_run = job.next_run_time
    return {
        "enabled": True,
        "next_run": next_run.isoformat() if next_run else None,
        "schedule": f"Her gece {DEFAULT_HOUR:02d}:{DEFAULT_MIN:02d} (Europe/Istanbul)",
    }


def set_scheduler_enabled(enabled: bool) -> dict:
    if not _scheduler:
        return {"enabled": False}

    job = _scheduler.get_job(JOB_ID)
    if enabled:
        if not job and _scan_func:
            _scheduler.add_job(
                _scan_func,
                CronTrigger(hour=DEFAULT_HOUR, minute=DEFAULT_MIN),
                id=JOB_ID,
                name="Gece Otomatik Tarama",
                replace_existing=True,
                misfire_grace_time=300,
            )
        elif job:
            job.resume()
    else:
        if job:
            job.pause()

    return get_scheduler_status()


def shutdown_scheduler():
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        _scheduler = None
