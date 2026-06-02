import logging
import time
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("cve.nvd")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_by_keyword(
    client: httpx.Client,
    keyword: str,
    start: datetime,
    end: datetime,
    api_key: str | None,
    per_page: int,
) -> list[dict]:
    """Fetch all CVEs matching `keyword` modified within [start, end], paginated."""
    results: list[dict] = []
    index = 0
    while True:
        params = {
            "keywordSearch": keyword,
            "lastModStartDate": _fmt(start),
            "lastModEndDate": _fmt(end),
            "resultsPerPage": per_page,
            "startIndex": index,
        }
        data = _request(client, params, api_key)
        vulns = data.get("vulnerabilities", [])
        results.extend(vulns)
        total = data.get("totalResults", 0)
        index += len(vulns)
        if not vulns or index >= total:
            break
        time.sleep(_delay(api_key))
    logger.info("NVD '%s': %d result(s)", keyword, len(results))
    return results


def _request(
    client: httpx.Client, params: dict, api_key: str | None, retries: int = 3
) -> dict:
    headers = {"apiKey": api_key} if api_key else {}
    for attempt in range(retries):
        resp = client.get(NVD_URL, params=params, headers=headers)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (403, 429, 503):
            wait = 6 * (attempt + 1)
            logger.warning("NVD %s; retrying in %ds", resp.status_code, wait)
            time.sleep(wait)
            continue
        resp.raise_for_status()
    resp.raise_for_status()
    return {}


def parse_cve(item: dict) -> dict:
    c = item["cve"]
    score, severity = _pick_cvss(c.get("metrics", {}))
    return {
        "id": c["id"],
        "published": _parse_dt(c.get("published")),
        "last_modified": _parse_dt(c.get("lastModified")),
        "description": _pick_description(c.get("descriptions", [])),
        "references": [r["url"] for r in c.get("references", []) if r.get("url")],
        "cvss_score": score,
        "cvss_severity": severity,
    }


def _pick_cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        entry = entries[0]
        data = entry.get("cvssData", {})
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return data.get("baseScore"), severity
    return None, None


def _pick_description(descriptions: list[dict]) -> str:
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _delay(api_key: str | None) -> float:
    # Stay under NVD rate limits: 50 req/30s with key, 5 req/30s without.
    return 0.7 if api_key else 6.5
