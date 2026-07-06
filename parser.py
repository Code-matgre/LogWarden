import re
import os
from typing import List, Dict
from detector import detect_threats

# Regex pre-compilata per ottimizzare le prestazioni su file di grandi dimensioni.
# Utilizza i Named Groups (?P<nome>...) per mappare direttamente i dati estratti.
LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'       # IP
    r'.*?'                                   # toglie i campi intermedi (identikit, user)
    r'\"(?P<request>[^\"]+)\"'               # Estrae la richiesta (es: "GET /index.html HTTP/1.1")
    r'\s+(?P<status>\d{3})'                  # Estrae status code (es: 200)
)



def parse_line(line: str) -> Dict[str, str]:
    """Analizza una singola riga di log estraendo IP, richiesta e codice di stato.

    Usa la regex pre-compilata LOG_PATTERN. Se la riga corrisponde al formato
    standard, i dati vengono restituiti come dizionario. In caso di righe corrotte
    o non conformi, restituisce valori di default per evitare eccezioni nel programma.

    Args:
        line (str): La stringa di testo che rappresenta la singola riga del log.

    Returns:
        Dict[str, str]: Un dizionario con chiavi 'ip', 'request' e 'status'.
    """

    match = LOG_PATTERN.search(line)
    if match:
        return match.groupdict()
    #Fallback in caso di fallimento del parsing, restituisce valori di default.
    return {'ip': 'none', 'request': 'none', 'status': 'none'}


def process_log_file(file_path: str) -> List[Dict[str, str]]:
    """Gestisce l'apertura sicura del file e avvia il parsing riga per riga.

    Verifica preventivamente l'esistenza del file sul file system. Legge il file
    in modo efficiente (stream riga per riga) per evitare sovraccarichi di memoria RAM
    con file di log di grandi dimensioni.

    Args:
        file_path (str): Il percorso relativo o assoluto del file di log da analizzare.

    Returns:
        List[Dict[str, str]]: Una lista di dizionari, dove ogni dizionario rappresenta 
                              una riga di log formattata correttamente.
    """
    #controllo di sicurezza: verifica se il file esiste prima di tentare di aprirlo.
    if not os.path.exists(file_path):
        print(f"[-] Errore: Il file '{file_path}' non esiste.")
        return []

    parsed_d = []
    try:
        #apertura del file in modalità lettura con gestione sicura delle eccezioni.
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line: #salta righe vuote per evitare parsing inutili.
                    parsed_result = parse_line(line)
                    parsed_d.append(parsed_result)
    except Exception as e:
        #TODO : Loggare l'errore in un file di log dedicato per analisi future.
        print(f"[-] Errore durante la lettura del file: {e}")
    return parsed_d

if __name__ == "__main__":
    log_file = "logs.log"
    results = process_log_file(log_file)
    
    print(f"[+] Parsing completato. Righe totali: {len(results)}")
    
    # Avviamo il modulo di rilevamento minacce
    detected_alerts = detect_threats(results)
    
    print(f"[!] Rilevate {len(detected_alerts)} potenziali minacce:")
    for alert in detected_alerts:
        print(f"[-] IP: {alert['ip']} | Attacco: {alert['threat_type']} | Richiesta: {alert['request']}")