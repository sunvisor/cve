"""Offline smoke test: exercises core logic + API without hitting the network."""
import os
import tempfile

os.environ["DATABASE_URL"] = "sqlite:///" + tempfile.mkdtemp() + "/t.db"
os.environ["DEFAULT_WATCHES"] = "nginx,php"

from fastapi.testclient import TestClient

import app.main as main
from app import nvd, repository as repo
from app.database import SessionLocal
from app.notifier import _text
from app.models import Cve

# 1) NVD parsing
SAMPLE = {
    "cve": {
        "id": "CVE-2024-0001",
        "published": "2024-01-02T10:00:00.000",
        "lastModified": "2024-01-03T11:00:00.000Z",
        "descriptions": [{"lang": "en", "value": "An nginx buffer overflow."}],
        "references": [{"url": "https://example.com/a"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
    }
}
parsed = nvd.parse_cve(SAMPLE)
assert parsed["id"] == "CVE-2024-0001"
assert parsed["cvss_score"] == 9.8
assert parsed["cvss_severity"] == "CRITICAL"
assert parsed["published"].year == 2024
assert parsed["references"] == ["https://example.com/a"]
print("parse_cve OK")

# 2) Disable network poll + scheduler, then bring up the app via lifespan.
main.run_poll = lambda: None
main.start_scheduler = lambda: None
main.shutdown_scheduler = lambda: None

with TestClient(main.app) as client:
    # repository upsert (simulate a poll result)
    with SessionLocal() as s:
        assert repo.upsert_cve(s, parsed, "nginx") is True
        assert repo.upsert_cve(s, parsed, "php") is False  # second keyword, same CVE
        s.commit()

    # notifier formatting
    with SessionLocal() as s:
        cve = s.get(Cve, "CVE-2024-0001")
        msg = _text(cve, ["nginx", "php"])
        assert "CVE-2024-0001" in msg and "CRITICAL" in msg
    print("upsert + notifier OK")

    # stats: default watches seeded
    stats = client.get("/api/stats").json()
    assert "new" in stats["statuses"]
    print("stats OK:", stats["total"], "cves,", stats["by_status"])

    watches = client.get("/api/watches").json()
    assert {w["keyword"] for w in watches} >= {"nginx", "php"}
    print("watches OK:", [w["keyword"] for w in watches])

    # list + filter
    lst = client.get("/api/cves?keyword=nginx").json()
    assert lst["total"] == 1 and lst["items"][0]["id"] == "CVE-2024-0001"
    assert lst["items"][0]["keywords"] == ["nginx", "php"] or set(lst["items"][0]["keywords"]) == {"nginx", "php"}
    print("list/filter OK")

    # status update
    r = client.patch("/api/cves/CVE-2024-0001", json={"status": "todo", "note": "checking"})
    assert r.status_code == 200 and r.json()["status"] == "todo"
    r = client.patch("/api/cves/CVE-2024-0001", json={"status": "bogus"})
    assert r.status_code == 400
    print("status update OK")

    # add + delete watch
    r = client.post("/api/watches", json={"keyword": "openssl"})
    assert r.status_code == 201
    wid = r.json()["id"]
    assert client.post("/api/watches", json={"keyword": "openssl"}).status_code == 409
    assert client.delete(f"/api/watches/{wid}").status_code == 204
    print("watch CRUD OK")

    # static UI served
    assert "CVE Watch" in client.get("/").text
    print("static UI OK")

print("\nALL SMOKE TESTS PASSED")
