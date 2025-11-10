import json
from datetime import datetime

def create_detection_rule_body(rule_id, name, description, query, index, risk_score, severity, tags, interval, from_time, enabled):
    """Generate the JSON body for creating an Elastic SIEM detection rule."""
    rule_body = {
        "rule_id": rule_id,
        "name": name,
        "description": description,
        "risk_score": int(risk_score),
        "severity": severity,
        "type": "query",
        "index": [i.strip() for i in index.split(",")],
        "query": query,
        "tags": [t.strip() for t in tags.split(",")],
        "enabled": enabled.lower() == "true",
        "interval": interval,
        "from": from_time,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    return rule_body


if __name__ == "__main__":
    print("=== Elastic SIEM Rule Body Generator ===\n")

    rule_id = input("Enter Rule ID: ").strip()
    name = input("Enter Rule Name: ").strip()
    description = input("Enter Rule Description: ").strip()
    query = input("Enter KQL/Lucene Query: ").strip()
    index = input("Enter Target Index Pattern(s) (comma-separated, e.g. winlogbeat-*,logs-*): ").strip() or "winlogbeat-*"
    risk_score = input("Enter Risk Score (0-100): ").strip() or "70"
    severity = input("Enter Severity (low/medium/high/critical): ").strip() or "medium"
    tags = input("Enter Tags (comma-separated): ").strip() or "auto,github-action"
    interval = input("Enter Rule Interval (e.g., 5m, 1h): ").strip() or "5m"
    from_time = input("Enter Lookback Window (e.g., now-5m): ").strip() or "now-5m"
    enabled = input("Enable Rule? (true/false): ").strip() or "true"

    rule = create_detection_rule_body(rule_id, name, description, query, index, risk_score, severity, tags, interval, from_time, enabled)

    # Save to JSON file
    with open("rule.json", "w") as f:
        json.dump(rule, f, indent=2)

    print("\n✅ Rule body saved to rule.json")
    print(json.dumps(rule, indent=2))
