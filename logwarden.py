import re
            print(line.strip())
import os

LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'       # IP
    r'.*?'                                   # toglie i campi intermedi (identikit, user)
    r'\"(?P<request>[^\"]+)\"'               # Estrae la richiesta (es: "GET /index.html HTTP/1.1")
    r'\s+(?P<status>\d{3})'                  # Estrae status code (es: 200)
)


def parse_line(line):
    match = LOG_PATTERN.search(line)
    if match:
        return match.groupdict()
    
    return {'ip': 'none', 'request': 'none', 'status': 'none'}

def process_log_file(file_path):
    if not os.path.exists(file_path):
        print(f"[-] Errore: Il file '{file_path}' non esiste.")
        return []

    parsed_d = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    parsed_result = parse_line(line)
                    parsed_d.append(parsed_result)
    except Exception as e:
        print(f"[-] Errore durante la lettura del file: {e}")
    return parsed_d

if __name__ == "__main__":
    log_file = "Logs/mockaccess.log"
    results = process_log_file(log_file)
    
    for entry in results[:5]:
        print(entry)