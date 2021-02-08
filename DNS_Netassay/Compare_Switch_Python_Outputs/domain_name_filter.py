from sys import argv
import csv

# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 3:
        print('usage: python domain_name_filter.py csv_file known_domains.txt')
        exit(-1)

    python_results = []
    domain_names = []
    switch_results = []

    with open(argv[1], 'r') as csvfile:
        csvreader = csv.reader(csvfile)

        for row in csvreader:
            if row[0] == 'Domain':
                continue
            python_results.append(int(row[1]))
            domain_names.append(row[0])

    switch_file = open(argv[2], 'r')
    switch_dns_queried = switch_file.read().split('\n')
    for i in range(len(python_results)):
        switch_results.append(int(switch_dns_queried[i].split(', ')[1][:-1]))

    python_missing_count = 0
    for i in range(len(python_results)):
        if (switch_results[i] > python_results[i]):
            python_missing_count += (switch_results[i] - python_results[i])
            print(domain_names[i], switch_results[i], python_results[i])
    
    print('python missing count', python_missing_count)
    print(sum(switch_results)/float(sum(python_results)))
    print(sum(python_results))
    print(sum(switch_results))

