from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    """Naive UTC timestamp (kept naive for consistency with parsed NVD dates)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Watch(Base):
    __tablename__ = "watches"

    id: Mapped[int] = mapped_column(primary_key=True)
    keyword: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Cve(Base):
    __tablename__ = "cves"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    published: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_modified: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[str] = mapped_column(Text, default="[]")  # JSON-encoded list

    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    note: Mapped[str] = mapped_column(Text, default="")
    notified: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    status_updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    keywords: Mapped[list["CveKeyword"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan"
    )


class CveKeyword(Base):
    """Which watch keyword(s) matched a given CVE."""

    __tablename__ = "cve_keywords"
    __table_args__ = (UniqueConstraint("cve_id", "keyword", name="uq_cve_keyword"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("cves.id", ondelete="CASCADE"), index=True
    )
    keyword: Mapped[str] = mapped_column(String(120), index=True)

    cve: Mapped[Cve] = relationship(back_populates="keywords")


class Meta(Base):
    """Simple key/value store for poller bookkeeping."""

    __tablename__ = "meta"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
