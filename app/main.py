import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import repository as repo
from .config import get_settings
from .database import SessionLocal, init_db
from .poller import run_poll
from .routes import cves, system, watches
from .scheduler import shutdown_scheduler, start_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with SessionLocal() as session:
        repo.ensure_default_watches(session, settings.default_watch_list)
    # Run the (potentially slow) initial seed off the request path.
    threading.Thread(target=run_poll, daemon=True).start()
    start_scheduler()
    yield
    shutdown_scheduler()


app = FastAPI(title="CVE Watch", lifespan=lifespan)

app.include_router(system.router, prefix="/api")
app.include_router(cves.router, prefix="/api")
app.include_router(watches.router, prefix="/api")

_static_dir = Path(__file__).parent / "static"
app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")
