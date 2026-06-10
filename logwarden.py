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
    
    result['ip'] = matchip.group(1) if matchip else "none"
    result['request'] = matchreq.group(1) if matchreq else "none"
    result['status'] = matchstat.group(1) if matchstat else "none"
    
    return result