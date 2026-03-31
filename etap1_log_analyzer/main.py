from parser import load_wazuh_logs
from rules import filter_by_level
from reporter import save_to_csv

if __name__ == "__main__":
    alerts = load_wazuh_logs("sample_logs/wazuh_alerts.json")
    high_risk = filter_by_level(alerts, min_level=7)
    save_to_csv(high_risk, f"raport_high_risk.csv")
    print(f"Znaleziono {len(high_risk)} alertów wysokiego ryzyka z {len(alerts)} wszystkich")