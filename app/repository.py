import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Cve, CveKeyword, Meta, Watch, utcnow


def get_meta(session: Session, key: str, default: str | None = None) -> str | None:
    row = session.get(Meta, key)
    return row.value if row else default


def set_meta(session: Session, key: str, value: str) -> None:
    row = session.get(Meta, key)
    if row:
        row.value = value
    else:
        session.add(Meta(key=key, value=value))


def enabled_watches(session: Session) -> list[Watch]:
    return list(session.scalars(select(Watch).where(Watch.enabled.is_(True))))


def ensure_default_watches(session: Session, keywords: list[str]) -> None:
    existing = set(session.scalars(select(Watch.keyword)))
    for kw in keywords:
        if kw not in existing:
            session.add(Watch(keyword=kw))
    session.commit()


def upsert_cve(session: Session, data: dict, keyword: str) -> bool:
    """Insert or update a CVE and link it to `keyword`. Returns True if newly inserted."""
    cve = session.get(Cve, data["id"])
    is_new = cve is None
    if is_new:
        cve = Cve(id=data["id"], first_seen=utcnow(), status="new")
        session.add(cve)
        session.flush()  # so a repeat id within the same batch resolves via get()
    _apply_fields(cve, data)
    _ensure_keyword(session, cve.id, keyword)
    return is_new


def _apply_fields(cve: Cve, data: dict) -> None:
    cve.published = data["published"]
    cve.last_modified = data["last_modified"]
    cve.description = data["description"]
    cve.references = json.dumps(data["references"])
    cve.cvss_score = data["cvss_score"]
    cve.cvss_severity = data["cvss_severity"]


def _ensure_keyword(session: Session, cve_id: str, keyword: str) -> None:
    exists = session.scalar(
        select(CveKeyword.id).where(
            CveKeyword.cve_id == cve_id, CveKeyword.keyword == keyword
        )
    )
    if not exists:
        session.add(CveKeyword(cve_id=cve_id, keyword=keyword))
