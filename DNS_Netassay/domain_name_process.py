from sys import argv

# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 2:
        print('usage: python domain_name_filter.py known_domains.txt')
        exit(-1)

    knownlist = open(argv[1], 'r')
    domains = knownlist.read().split()
    knownlist.close()

    shortdomains = []

    for d in domains:
        if len(d.split('.')) > 4:
            continue
        shortdomains.append(d)
    
    finaldomains = []
    for d in shortdomains:
        finaldomains.append(d)

        if len(d.split('.')) == 3:
            if not '*.' + d in shortdomains:
                finaldomains.append('*.' + d)
        elif len(d.split('.')) == 2:
            if not '*.*.' + d in shortdomains:
                finaldomains.append('*.*.' + d)
            if not '*.' + d in shortdomains:
                finaldomains.append('*.' + d)
        elif len(d.split('.')) == 1:
            if not '*.*.*.' + d in shortdomains:
                finaldomains.append('*.*.*.' + d)
            if not '*.*.' + d in shortdomains:
                finaldomains.append('*.*.' + d)
            if not '*.' + d in shortdomains:
                finaldomains.append('*.' + d)

    outFile = open('known_d.txt', 'w')
    for d in finaldomains:
        outFile.write('\''+d + '\',\n')
    outFile.close()
