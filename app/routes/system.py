import threading

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import repository as repo
from ..constants import SEVERITIES, STATUSES
from ..deps import get_session
from ..models import Cve
from ..poller import run_poll

router = APIRouter(tags=["system"])


@router.get("/stats")
def stats(session: Session = Depends(get_session)):
    rows = session.execute(
        select(Cve.status, func.count()).group_by(Cve.status)
    ).all()
    by_status = {status: count for status, count in rows}
    return {
        "total": sum(by_status.values()),
        "by_status": by_status,
        "statuses": STATUSES,
        "severities": SEVERITIES,
        "last_polled_at": repo.get_meta(session, "last_polled_at"),
    }


@router.post("/poll")
def trigger_poll():
    threading.Thread(target=run_poll, daemon=True).start()
    return {"status": "started"}
