from sys import argv
import csv

def matchDomain(known, domain):
    knownparts = known.split('.')
    domainparts = domain.split('.')
    if len(knownparts) != len(domainparts):
        return False
    
    for i in range(0, len(knownparts)):
        if (knownparts[i] == '*'):
            continue
        if (knownparts[i] != domainparts[i]):
            return False
    return True


# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 3:
        print('usage: python domain_name_filter.py csv_file known_domains.txt')
        exit(-1)

    knownlist = open(argv[2], 'r')
    domains = knownlist.read().split()
    knownlist.close()

    with open('out_domains.csv', 'w') as csvwritefile:
        csvwriter = csv.writer(csvwritefile)

        with open(argv[1], 'r') as csvfile:
            csvreader = csv.reader(csvfile)

            for row in csvreader:
                if row[0] == 'Domain':
                    continue
                found = False
                for d in domains:
                    if (matchDomain(d, row[0])):
                        found = True
                        break
                
                if (found == False and float(row[2]) > 0):
                    csvwriter.writerow(row)
