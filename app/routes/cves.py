import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..constants import STATUSES
from ..deps import get_session
from ..models import Cve, CveKeyword, utcnow
from ..schemas import CveListOut, CveOut, CveUpdate

router = APIRouter(tags=["cves"])


def to_out(cve: Cve) -> CveOut:
    return CveOut(
        id=cve.id,
        published=cve.published,
        last_modified=cve.last_modified,
        cvss_score=cve.cvss_score,
        cvss_severity=cve.cvss_severity,
        description=cve.description,
        references=json.loads(cve.references or "[]"),
        status=cve.status,
        note=cve.note,
        keywords=[k.keyword for k in cve.keywords],
        first_seen=cve.first_seen,
    )


@router.get("/cves", response_model=CveListOut)
def list_cves(
    session: Session = Depends(get_session),
    status: str | None = None,
    keyword: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    sort: str = "published",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    stmt = _apply_filters(select(Cve), status, keyword, severity, q)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    stmt = _apply_sort(stmt, sort).limit(limit).offset(offset)
    items = list(session.scalars(stmt).unique())
    return CveListOut(total=total, items=[to_out(c) for c in items])


@router.get("/cves/{cve_id}", response_model=CveOut)
def get_cve(cve_id: str, session: Session = Depends(get_session)):
    cve = session.get(Cve, cve_id)
    if not cve:
        raise HTTPException(404, "CVE not found")
    return to_out(cve)


@router.patch("/cves/{cve_id}", response_model=CveOut)
def update_cve(cve_id: str, payload: CveUpdate, session: Session = Depends(get_session)):
    cve = session.get(Cve, cve_id)
    if not cve:
        raise HTTPException(404, "CVE not found")
    if payload.status is not None:
        if payload.status not in STATUSES:
            raise HTTPException(400, "invalid status")
        cve.status = payload.status
        cve.status_updated_at = utcnow()
    if payload.note is not None:
        cve.note = payload.note
    session.commit()
    return to_out(cve)


def _apply_filters(stmt, status, keyword, severity, q):
    if status:
        stmt = stmt.where(Cve.status == status)
    if severity:
        stmt = stmt.where(Cve.cvss_severity == severity.upper())
    if keyword:
        sub = select(CveKeyword.cve_id).where(CveKeyword.keyword == keyword)
        stmt = stmt.where(Cve.id.in_(sub))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Cve.id.ilike(like), Cve.description.ilike(like)))
    return stmt


def _apply_sort(stmt, sort):
    if sort == "score":
        return stmt.order_by(Cve.cvss_score.desc().nullslast())
    if sort == "first_seen":
        return stmt.order_by(Cve.first_seen.desc())
    return stmt.order_by(Cve.published.desc().nullslast())
