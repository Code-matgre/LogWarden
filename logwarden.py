import re
def read_file(file_path):
    with open(file_path, 'r') as f:
        for line in f:
            print(line.strip())

def parse_line(line):
    result = {}
    #searching matching
    patternip = r"(\d{1,3}(?:\.\d{1,3}){3})" #ip patterns
    matchip = re.search(patternip, line)

    patternreq = r'"([^"]+)"' #requests pattern
    matchreq = re.search(patternreq, line) 

    patternstat = r'"\s+(\d{3})' #status pattern
    matchstat = re.search(patternstat, line)
    
    if matchip:
        result['ip'] = matchip.group(1)
    else:
        result['ip'] = "none"

    if matchreq:
        result['request'] = matchreq.group(1)
    else:
        result['request'] = "none"

    if matchstat:
        result['status'] = matchstat.group(1)
    else:
        result['status'] = "none"
    
    return result