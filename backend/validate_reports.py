import json
import os

REPORTS = [
    "../reports/noise_summary.json",
    "../reports/raw_logs.json",
    "../reports/soar_actions.json",
    "../reports/threat_hunts.json",
    "../reports/behavioral_baseline.json",
    "../reports/alert_stories.json",
    "../reports/multi_stage_attacks.json",
    "../reports/grouped_behaviors.json",
    "../reports/incidents.json",
    "../reports/killchains.json",
    "../reports/search_index.json",
    "../reports/scored_killchains.json",
    "../reports/final_decisions.json",
    "../reports/priority_queue.json",
    "../reports/device_summary.json",
    "../reports/live_attack_map.json",
    "../reports/important_logs_summary.json",
    "../reports/iocs.json",
    "../reports/dashboard_data.json"
]


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate():
    print("\n=== ClearSOC Report Validator ===")

    errors = 0

    for report in REPORTS:
        if not os.path.exists(report):
            print(f"[MISSING] {report}")
            errors += 1
            continue

        try:
            data = load_json(report)
            print(f"[OK] {report}")
        except Exception as e:
            print(f"[BROKEN JSON] {report} -> {e}")
            errors += 1

    if errors == 0:
        print("\nAll reports are valid JSON.")
    else:
        print(f"\nValidation finished with {errors} issue(s).")


if __name__ == "__main__":
    validate()
