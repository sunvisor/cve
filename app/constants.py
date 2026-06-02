# Status codes (stored) -> Japanese label (shown). "new" is the default for
# freshly discovered CVEs.
STATUSES: dict[str, str] = {
    "new": "新規",
    "todo": "要対応",
    "in_progress": "対応中",
    "done": "対応済み",
    "ignore": "無視",
    "irrelevant": "関係ない",
}

SEVERITIES: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
