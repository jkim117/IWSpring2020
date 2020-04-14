import sys

fileOut = open('known_domains.txt', 'w')
totalLines = 0

def onelabel(labels, num):
    fileOut.write(labels[0] + '\n')
    fileOut.write('*.' + labels[0] + '\n')
    fileOut.write('*.*.' + labels[0] + '\n')
    fileOut.write('*.*.*.' + labels[0] + '\n')
    global totalLines
    totalLines = totalLines + 4
    if (num == 5):
        fileOut.write('*.*.*.*.' + labels[0] + '\n')
        totalLines = totalLines + 1

def twolabel(labels, num):
    fileOut.write(labels[0] + '.' + labels[1] + '\n')
    fileOut.write('*.' + labels[0] + '.' + labels[1] + '\n')
    fileOut.write('*.*.' + labels[0] + '.' + labels[1] + '\n')
    global totalLines
    totalLines = totalLines + 3
    if (num == 5):
        fileOut.write('*.*.*.' + labels[0] + '.' + labels[1] + '\n')
        totalLines = totalLines + 1

def threelabel(labels, num):
    fileOut.write(labels[0] + '.' + labels[1] + '.' + labels[2] + '\n')
    fileOut.write('*.' + labels[0] + '.' + labels[1] + '.' + labels[2] + '\n')
    global totalLines
    totalLines = totalLines + 2
    if (num == 5):
        fileOut.write('*.*.' + labels[0] + '.' + labels[1] + '.' + labels[2] + '\n')
        totalLines = totalLines + 1

def fourlabel(labels, num):
    fileOut.write(labels[0] + '.' + labels[1] + '.' + labels[2] + '.' + labels[3] + '\n')
    global totalLines
    totalLines = totalLines + 1
    if (num == 5):
        fileOut.write('*.' + labels[0] + '.' + labels[1] + '.' + labels[2] + '.' + labels[3] + '\n')
        totalLines = totalLines + 1

def fivelabel(labels, num):
    if (num == 5):
        fileOut.write(labels[0] + '.' + labels[1] + '.' + labels[2] + '.' + labels[3] + '.' + labels[4] + '\n')
        totalLines = totalLines + 1


numLabels = sys.argv[1]
if (numLabels != '4' and numLabels != '5'):
    sys.exit('ERROR: Arg must be 4 or 5: gave ' + str(numLabels))
numLabels = int(numLabels)

with open('known_domains_no_wildcard.txt') as f:
    domainList = f.read().split('\n')
    for d in domainList:
        labels = d.split('.')
        skip = False

        for l in labels:
            if len(l) > 15 and numLabels == 4:
                print('WARNING: label in domain too long. Max is 15 ' + d)
                skip = True
            if len(l) > 31 and numLabels == 5:
                print('WARNING: label in domain too long. Max is 31 ' + d)
                skip = True
        
        if (skip):
            continue
        if len(labels) == 5:
            fivelabel(labels, numLabels)
        elif len(labels) == 4:
            fourlabel(labels, numLabels)
        elif len(labels) == 3:
            threelabel(labels, numLabels)
        elif len(labels) == 2:
            twolabel(labels, numLabels)
        elif len(labels) == 1:
            onelabel(labels, numLabels)
        else:
            print('WARNING: Too many labels' + str(d))

if numLabels == 5:
    fileOut.write('*.*.*.*.*\n')
    totalLines = totalLines + 1
fileOut.write('*.*.*.*\n')
fileOut.write('*.*.*\n')
fileOut.write('*.*\n')
fileOut.write('*\n')
totalLines = totalLines + 4
fileOut.close()
print(totalLines)
