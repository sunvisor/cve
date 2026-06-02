from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..deps import get_session
from ..models import Watch
from ..schemas import WatchCreate, WatchOut, WatchUpdate

router = APIRouter(tags=["watches"])


@router.get("/watches", response_model=list[WatchOut])
def list_watches(session: Session = Depends(get_session)):
    return list(session.scalars(select(Watch).order_by(Watch.keyword)))


@router.post("/watches", response_model=WatchOut, status_code=201)
def create_watch(payload: WatchCreate, session: Session = Depends(get_session)):
    keyword = payload.keyword.strip()
    if not keyword:
        raise HTTPException(400, "keyword is required")
    if session.scalar(select(Watch).where(Watch.keyword == keyword)):
        raise HTTPException(409, "keyword already exists")
    watch = Watch(keyword=keyword)
    session.add(watch)
    session.commit()
    return watch


@router.patch("/watches/{watch_id}", response_model=WatchOut)
def update_watch(
    watch_id: int, payload: WatchUpdate, session: Session = Depends(get_session)
):
    watch = session.get(Watch, watch_id)
    if not watch:
        raise HTTPException(404, "watch not found")
    watch.enabled = payload.enabled
    session.commit()
    return watch


@router.delete("/watches/{watch_id}", status_code=204)
def delete_watch(watch_id: int, session: Session = Depends(get_session)):
    watch = session.get(Watch, watch_id)
    if not watch:
        raise HTTPException(404, "watch not found")
    session.delete(watch)
    session.commit()
