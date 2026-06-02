import logging

from apscheduler.schedulers.background import BackgroundScheduler

from .config import get_settings
from .poller import run_poll

logger = logging.getLogger("cve.scheduler")
settings = get_settings()

_scheduler = BackgroundScheduler(timezone="UTC")


def start_scheduler() -> None:
    _scheduler.add_job(
        run_poll,
        "interval",
        minutes=settings.poll_interval_minutes,
        id="poll",
        max_instances=1,
        coalesce=True,
    )
    _scheduler.start()
    logger.info("scheduler started: every %d min", settings.poll_interval_minutes)


def shutdown_scheduler() -> None:
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
