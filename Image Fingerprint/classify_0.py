from sys import argv
import matplotlib
import matplotlib.pyplot as plt
import csv
import json
from scipy.stats import norm
import statistics

rawWebpageDicts = [] # List of dicts. Each dict has url of a webpage and a list of dicts. Each of those dicts is keyed by domain name with value being sequence diff. See below
'''
[
    {
        url: https://www.bbc.com/news/world-us-canada-53481383
        pcaps: []
    }
]
'''
pageDicts = [] # processed version of rawWebpageDicts. List of dicts. Each dict is a pageDict with keys being domains and value being a list of portion, mean, stdev (see determinePercentMatch below)

'''
Format of pageDict:
{
    url: https://www.bbc.com/news/world-us-canada-53481383
    example.com: [portion, mean, stdev]
    example2.com: [0.5, 4322, 23]
    example3.com: [0.25, 1223, 2]
    example4.com: [0.25, 543, 26]
}

Format of matchDict:
{
    example.com: seq_dif
    example2.com: 4320
    example3.com: 1223
}
This function determines the percentage of match between matchDict and pageDict. matchDict is an collection of sequence diffs for a set of domain names that needs to be classified to a webpage.
pageDict is a collection of data accumulated from training data for a particular web page. pageDict is keyed by domain names where the value is a list of values: [portion, mean, stdev]
portion refers to the frequency that this particular domain names appears in DNS requests for this web page. mean refers to the mean sequence number diff. stdev refers to the standard deviation
of the sequence diffs for this domain
'''
def determinePercentMatch(matchDict, pageDict):
    totalMatchPercent = 0

    for domain in pageDict:
        if domain in matchDict:
            domainMatchPercent = pageDict[domain][0]
            seq_num = matchDict[domain]
            mean = pageDict[domain][1]
            stdev = pageDict[domain][2]
            if (stdev == 0):
                if (mean != seq_num):
                    continue
            else:

                domainMatchPercent = domainMatchPercent * norm.pdf(seq_num, mean, stdev) / norm.pdf(mean, mean, stdev)
                #x = abs(mean - seq_num)
                #domainMatchPercent = domainMatchPercent * norm.pdf(mean + x, mean, stdev)
            totalMatchPercent = totalMatchPercent + domainMatchPercent
    return totalMatchPercent

# This function takes the rawWebpageDicts and converts it into the pageDicts for use in determinePercentMatch
def processRawWebpageDicts():
    # for each webpage
    for d in rawWebpageDicts:
        intermediatePageDict = {}

        total_freq = 0.0
        for p in d['pcaps']:
            
            for domain in p:
                seqdiff = p[domain]
                total_freq = total_freq + 1
                if domain in intermediatePageDict:
                    entry = intermediatePageDict[domain]
                    seqList = entry[1]
                    seqList.append(seqdiff)
                    intermediatePageDict[domain] = [entry[0] + 1, seqList]
                else:
                    intermediatePageDict[domain] = [1, [seqdiff]]

        pageDict = {}
        for domain in intermediatePageDict:
            intEntry = intermediatePageDict[domain]
            freq = intEntry[0]
            seq_diff_list = intEntry[1]
            if len(seq_diff_list) < 2:
                total_freq = total_freq - freq

        for domain in intermediatePageDict:
            intEntry = intermediatePageDict[domain]
            freq = intEntry[0]
            seq_diff_list = intEntry[1]
            if len(seq_diff_list) < 2:
                continue

            portion = freq / total_freq
            mean = statistics.mean(seq_diff_list)
            stdev = statistics.stdev(seq_diff_list)
            pageDict[domain] = [portion, mean, stdev]

        pageDict['url'] = d['url']
        pageDicts.append(pageDict)

def processTrainingData():
    readMore = True
    while(readMore):
        url = input('Enter URL for this web page: ')
        rawPageDict = {}
        rawPageDict['url'] = url
        rawPageDict['pcaps'] = []

        morePcaps = True
        while (morePcaps):
            file_name = input('Enter training pcap csv file name (use web_fp_setup_2.py): ')

            with open(file_name, 'r') as csvfile:
                r = csv.reader(csvfile)

                rawPcapDict = {}
                firstrow = True
                for row in r:
                    if firstrow == True:
                        firstrow = False
                        continue
                    rawPcapDict[row[0]] = float(row[1])
                
                rawPageDict['pcaps'].append(rawPcapDict)
            
            res2 = input('Add another pcap csv file for this web page? (y/n): ')
            if (res2.lower() == 'n'):
                morePcaps = False
            
        res1 = input('Add another web page entry? (y/n): ')
        if (res1.lower() == 'n'):
            readMore = False
        
        rawWebpageDicts.append(rawPageDict)

def classifyUnknownPcap():
    file_name = input('Enter pcap csv file name (use web_fp_setup_2.py): ')
    with open(file_name, 'r') as csvfile:
        r = csv.reader(csvfile)

        matchDict = {}
        firstrow = True
        for row in r:
            if firstrow == True:
                firstrow = False
                continue
            matchDict[row[0]] = float(row[1])
        
        for p in pageDicts:
            score = determinePercentMatch(matchDict, p)
            print('Match with ' + str(p['url']) + ': Score: ' + str(score))


def main2():
    print('ENTER TRAINING DATA: ')
    processTrainingData()
    processRawWebpageDicts()

    print('\nENTER TESTING DATA: ')
    testMore = True
    while (testMore):
        classifyUnknownPcap()
        res = input('\nTest another pcap csv entry? (y/n): ')
        if (res.lower() == 'n'):
            testMore = False

# Easy hardcoded example
def main1():
    hardcoded = {
        'https://www.bbc.com/news/world-us-canada-53481383-JUN20': ['page_0_1.csv', 'page_0_2.csv', 'page_0_3.csv'],
        'https://www.bbc.com/news/world-us-canada-53481383-JUN21': ['page_1_1.csv', 'page_1_2.csv', 'page_1_3.csv', 'page_1_4.csv'],
        'https://www.bbc.com/news/world-europe-53481542': ['page_2_1.csv', 'page_2_2.csv']
    }
    for url in hardcoded:
        rawPageDict = {}
        rawPageDict['url'] = url
        rawPageDict['pcaps'] = []

        for file_name in hardcoded[url]:

            with open(file_name, 'r') as csvfile:
                r = csv.reader(csvfile)

                rawPcapDict = {}
                firstrow = True
                for row in r:
                    if firstrow == True:
                        firstrow = False
                        continue
                    rawPcapDict[row[0]] = float(row[1])
                
                rawPageDict['pcaps'].append(rawPcapDict)
        rawWebpageDicts.append(rawPageDict)
    processRawWebpageDicts()

    file_name = 'page_1_5.csv'
    with open(file_name, 'r') as csvfile:
        r = csv.reader(csvfile)

        matchDict = {}
        firstrow = True
        for row in r:
            if firstrow == True:
                firstrow = False
                continue
            matchDict[row[0]] = float(row[1])
        
        for p in pageDicts:
            score = determinePercentMatch(matchDict, p)
            print('Match with ' + str(p['url']) + ': Score: ' + str(score))
    

if __name__ == '__main__':
    main1()



    
