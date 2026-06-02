import logging

import httpx

from .config import get_settings
from .models import Cve

logger = logging.getLogger("cve.notifier")
settings = get_settings()

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}


def notify(cve: Cve, keywords: list[str]) -> bool:
    """Send `cve` to every configured channel. Returns True if all succeeded
    (or no channel is configured)."""
    channels = _channels()
    if not channels:
        return True
    ok = True
    for name, sender, url in channels:
        try:
            sender(url, cve, keywords)
        except Exception as exc:  # one bad channel must not abort the poll
            logger.error("notify via %s failed for %s: %s", name, cve.id, exc)
            ok = False
    return ok


def _channels() -> list[tuple]:
    out: list[tuple] = []
    if settings.slack_webhook_url:
        out.append(("slack", send_slack, settings.slack_webhook_url))
    if settings.google_chat_webhook_url:
        out.append(("gchat", send_google_chat, settings.google_chat_webhook_url))
    return out


def _text(cve: Cve, keywords: list[str]) -> str:
    emoji = SEVERITY_EMOJI.get(cve.cvss_severity or "", "⚪")
    score = cve.cvss_score if cve.cvss_score is not None else "N/A"
    sev = cve.cvss_severity or "UNKNOWN"
    kw = ", ".join(keywords) or "-"
    desc = (cve.description or "").strip()[:300]
    nvd = f"https://nvd.nist.gov/vuln/detail/{cve.id}"
    admin = f"{settings.public_base_url.rstrip('/')}/#/cve/{cve.id}"
    return (
        f"{emoji} *新しい脆弱性: {cve.id}*\n"
        f"*深刻度:* {sev} (CVSS {score})\n"
        f"*該当ワード:* {kw}\n"
        f"{desc}\n"
        f"<{nvd}|NVD> | <{admin}|管理画面>"
    )


def send_slack(url: str, cve: Cve, keywords: list[str]) -> None:
    _post(url, {"text": _text(cve, keywords)})


def send_google_chat(url: str, cve: Cve, keywords: list[str]) -> None:
    _post(url, {"text": _text(cve, keywords)})


def _post(url: str, payload: dict) -> None:
    resp = httpx.post(url, json=payload, timeout=15)
    resp.raise_for_status()
