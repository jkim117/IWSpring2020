import csv
import pickle

outFile = open('iot_known_domains.txt', 'w')

allDomains = []
rules = {} # key is device + detection level, value is list of tuple of domain, port, grouped domain

with open('alexa_enabled.csv') as csv1:
    reader = csv.reader(csv1)

    isFirst = True
    for row in reader:
        if (isFirst):
            isFirst = False
            continue

        domain = row[0]
        if (domain[-1] == '.'):
            domain = domain[:-1]
        
        rules_key = row[2] + '/' + row[1]
        if rules_key in rules:
            rules[rules_key].append([domain, row[5], row[3]])
        else:
            rules[rules_key] = [[domain, row[5], row[3]]]
        
        if domain in allDomains:
            continue

        allDomains.append(domain)
        
        outFile.write(domain + '\n')

with open('samsung_IoT.csv') as csv1:
    reader = csv.reader(csv1)

    isFirst = True
    for row in reader:
        if (isFirst):
            isFirst = False
            continue

        domain = row[0]
        if (domain[-1] == '.'):
            domain = domain[:-1]
        
        rules_key = row[2] + '/' + row[1]
        if rules_key in rules:
            rules[rules_key].append([domain, row[5], row[3]])
        else:
            rules[rules_key] = [[domain, row[5], row[3]]]

        if domain in allDomains:
            continue

        allDomains.append(domain)
        
        outFile.write(domain + '\n')

with open('other_devices.csv') as csv1:
    reader = csv.reader(csv1)

    isFirst = True
    for row in reader:
        if (isFirst):
            isFirst = False
            continue

        domain = row[0]
        if (domain[-1] == '.'):
            domain = domain[:-1]

        rules_key = row[2] + '/' + row[1]
        if rules_key in rules:
            rules[rules_key].append([domain, row[5], row[3]])
        else:
            rules[rules_key] = [[domain, row[5], row[3]]]
        
        if domain in allDomains:
            continue

        allDomains.append(domain)
        
        outFile.write(domain + '\n')

outFile.close()

pickleFile = open('rules_list', 'wb')
pickle.dump(rules, pickleFile)
pickleFile.close()

