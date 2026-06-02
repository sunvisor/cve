from datetime import datetime

from pydantic import BaseModel


class CveOut(BaseModel):
    id: str
    published: datetime | None
    last_modified: datetime | None
    cvss_score: float | None
    cvss_severity: str | None
    description: str
    references: list[str]
    status: str
    note: str
    keywords: list[str]
    first_seen: datetime


class CveListOut(BaseModel):
    total: int
    items: list[CveOut]


class CveUpdate(BaseModel):
    status: str | None = None
    note: str | None = None


class WatchOut(BaseModel):
    id: int
    keyword: str
    enabled: bool


class WatchCreate(BaseModel):
    keyword: str


class WatchUpdate(BaseModel):
    enabled: bool
