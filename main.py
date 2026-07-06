from parser import process_log_file
from detector import detect_threats

def main():
    log_file = "logs.log"
    print("[*] Avvio di LogWarden v1.0-Beta...")
    print(f"[+] Avvio del parsing del file di log: {log_file}")
    #1. Parsing dei log

    results = process_log_file(log_file)
    print(f"[+] Parsing completato. Righe totali: {len(results)}")

    #2. Rilevamento minacce
    detected_alerts = detect_threats(results)

    #3. Output dei risultati
    print(f"[!] Rilevate {len(detected_alerts)} potenziali minacce:")
    for alert in detected_alerts:  
        print(f"IP: {alert['ip']}, Request: {alert['request']}, Status: {alert['status']}, Threat Type: {alert['threat_type']}")

if __name__ == "__main__":
    main()