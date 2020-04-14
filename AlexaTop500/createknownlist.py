import csv

fileOut = open('known_domains_no_wildcard.txt', 'w')

with open('top500Domains.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter = ',')
    rowCount = 0
    for row in csv_reader:
        if (rowCount == 0):
            rowCount = rowCount + 1
            continue
        fileOut.write(row[1])
        fileOut.write('\n')
fileOut.close()
