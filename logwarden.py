def read_file(file_path):
    with open(file_path, 'r') as f:
        for line in f:
            print(line.strip())

