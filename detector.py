import re
from typing import List, Dict, Any

Attack_signatures = {
    "SQL Injection (SQLi)": re.compile(r"('|\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|WHERE|OR)\b)", re.IGNORECASE),
    "Directory Traversal": re.compile(r"(\.\.\/|\.\.\\)", re.IGNORECASE),
    "Cross-Site Scripting (XSS)": re.compile(r"(<script>|javascript:|onerror=|alert\()", re.IGNORECASE),
    "Sensitive File Access": re.compile(r"(\.env|\.git|wp-config|wp-admin|admin|config\.php|/etc/passwd)", re.IGNORECASE)
}


def analyze_request(request: str) -> str:
    """Analizza la stringa di una richiesta HTTP alla ricerca di firme di attacco.

    Args:
        request (str): La richiesta HTTP (es. "GET /index.php?id=1' OR '1'='1 HTTP/1.1")

    Returns:
        str: Il tipo di attacco rilevato, oppure "Clean" se la richiesta è sicura.
    """
    for attack_type, pattern in Attack_signatures.items():
        if pattern.search(request):
            return attack_type
    return "Clean"

def detect_threats(parsed_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analizza una lista di log parsati per rilevare potenziali minacce.

    Args:
        parsed_logs (List[Dict[str, Any]]): Lista di dizionari contenenti i log parsati.

    Returns:
        List[Dict[str, Any]]: Lista di dizionari con informazioni sulle minacce rilevate.
    """
    threats = []

    for log in parsed_logs:

        request = log.get('request', 'none')

        if request == 'none':
            continue
        
        attack_type = analyze_request(request)

        if attack_type != "Clean":
            threats.append({
                'ip': log.get('ip', 'none'),
                'request': request,
                'status': log.get('status', 'none'),
                'threat_type': attack_type
            })
    return threats