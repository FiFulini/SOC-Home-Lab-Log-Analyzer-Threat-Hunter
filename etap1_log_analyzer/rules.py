def filter_by_level(alerts: list[dict], min_level: int = 7) -> list[dict]:
    return [
        a for a in alerts
        if a.get("rule", {}).get("level", 0) >= min_level
    ]

def filter_by_group(alerts: list[dict], group: str) -> list[dict]:
    return [
        a for a in alerts
        if group in a.get("rule", {}).get("groups", [])
    ]