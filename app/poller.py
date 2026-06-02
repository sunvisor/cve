import logging
from datetime import datetime, timedelta

import httpx

from . import notifier
from . import nvd
from . import repository as repo
from .config import get_settings
from .database import SessionLocal
from .models import Cve, utcnow

logger = logging.getLogger("cve.poller")
settings = get_settings()

_running = False


def run_poll() -> dict:
    """Entry point for both the scheduler and manual triggers. Reentrancy-safe."""
    global _running
    if _running:
        logger.info("poll already running; skipping")
        return {"status": "skipped"}
    _running = True
    try:
        return _do_poll()
    except Exception:
        logger.exception("poll failed")
        raise
    finally:
        _running = False


def _do_poll() -> dict:
    with SessionLocal() as session:
        watches = repo.enabled_watches(session)
        first_run = repo.get_meta(session, "seeded") != "1"
        start, end = _window(session)
        logger.info("polling %d keyword(s), window %s..%s", len(watches), start, end)
        new_ids = _fetch_all(session, watches, start, end)
        repo.set_meta(session, "last_polled_at", end.isoformat())
        repo.set_meta(session, "seeded", "1")
        session.commit()
        if first_run:
            logger.info("initial seed complete: %d CVE(s), notifications skipped", len(new_ids))
            return {"status": "seeded", "new": 0, "fetched": len(new_ids)}
        notified = _notify(session, new_ids)
        session.commit()
        logger.info("poll done: %d new, %d notified", len(new_ids), notified)
        return {"status": "ok", "new": len(new_ids), "notified": notified}


def _window(session) -> tuple[datetime, datetime]:
    end = utcnow()
    last = repo.get_meta(session, "last_polled_at")
    if last:
        # small overlap to avoid missing CVEs near the boundary
        start = datetime.fromisoformat(last) - timedelta(minutes=10)
    else:
        start = end - timedelta(days=settings.initial_lookback_days)
    return start, end


def _fetch_all(session, watches, start, end) -> set[str]:
    new_ids: set[str] = set()
    with httpx.Client(timeout=settings.request_timeout_seconds) as client:
        for watch in watches:
            items = nvd.fetch_by_keyword(
                client, watch.keyword, start, end,
                settings.nvd_api_key, settings.nvd_results_per_page,
            )
            for item in items:
                data = nvd.parse_cve(item)
                if repo.upsert_cve(session, data, watch.keyword):
                    new_ids.add(data["id"])
            session.commit()
    return new_ids


def _notify(session, new_ids: set[str]) -> int:
    count = 0
    for cve_id in new_ids:
        cve = session.get(Cve, cve_id)
        if cve is None or cve.notified:
            continue
        if (cve.cvss_score or 0.0) < settings.notify_min_cvss:
            continue
        keywords = [k.keyword for k in cve.keywords]
        if notifier.notify(cve, keywords):
            cve.notified = True
            count += 1
    return count
