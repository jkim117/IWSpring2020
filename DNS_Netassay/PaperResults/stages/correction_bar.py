import operator
from sys import argv
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import csv

dns_60_total = 0
packets_60_total = 0
bytes_60_total = 0 # key thing is here

domain_names = []
bytes_counted = []
bytes_estimated = []
bytes_true = []

dns_true = []

with open('parse_limit60_15min.csv') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        if row[0] == 'Domain' or row[0] == '*.steamcontent.com':
        #if row[0] == 'Domain':
            continue
        byte_c = float(row[4])
        if byte_c > 0:
            domain_names.append(row[0])
            bytes_true.append(byte_c)
            dns_true.append(int(row[1]))

with open('stage_limit2_16_timeout100.csv') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        #if row[0] == 'Domain':
        if row[0] == 'Domain' or row[0] == '*.steamcontent.com':
            continue

        if row[0] in domain_names:
            bytes_counted.append(float(row[4]))
            bytes_estimated.append(float(row[6]))

assert len(domain_names) == len(bytes_counted)
print(len(domain_names))

dns_true = np.array(dns_true)
domain_names = np.array(domain_names)
bytes_counted = np.array(bytes_counted)
bytes_estimated = np.array(bytes_estimated)
bytes_true = np.array(bytes_true)

idx = np.argsort(bytes_true)
domain_names = domain_names[idx]
bytes_counted = bytes_counted[idx]
bytes_estimated = bytes_estimated[idx]
bytes_true = bytes_true[idx]

domain_names = domain_names[-20:]
bytes_counted = bytes_counted[-20:]
bytes_estimated = bytes_estimated[-20:]
bytes_true = bytes_true[-20:]


xAxis = 2 * np.arange(0, len(domain_names))


fig, ax = plt.subplots()

width = 0.25

'''selectedIndicies = [6,7,8,9,10]
stage_1 = [stage_arrs[0][i] for i in selectedIndicies]
stage_2 = [stage_arrs[1][i] for i in selectedIndicies]
stage_4 = [stage_arrs[2][i] for i in selectedIndicies]
stage_8 = [stage_arrs[3][i] for i in selectedIndicies]
memoryList = [memoryList[i] for i in selectedIndicies]
memoryList = np.array(memoryList)'''

plt.bar(xAxis-width, bytes_counted, label='Bytes Counted', width=0.25, color='lightsteelblue')
plt.bar(xAxis, bytes_estimated, label='Bytes Estimated', width=0.25, color='cornflowerblue')
plt.bar(xAxis+width, bytes_true, label='Ground Truth', width=0.25, color='royalblue')

'''line9, = ax.plot(memoryList, stage_arrs[8])
line9.set_label('9 Stages')

line10, = ax.plot(memoryList, stage_arrs[9])
line10.set_label('10 Stages')'''

#plt.axvline(x=65536, color='red')

ax.legend()

plt.xticks(xAxis, domain_names, rotation=80, fontsize=5)

ax.set(xlabel='Domain Names', ylabel='Bytes', title='Byte Count of Domain Names with Correction Applied')
#ax.grid()
#ax.set_xscale('log', base=2)
fig.savefig("bar_correction_15min_timeout100.png")

plt.show()
#scatter_compare(python_byt, p4_byt)
#rank_compare(python_byt, p4_byt)


'''fig, ax = plt.subplots()

def reverse_dict_sort(d):
    return dict(sorted(d.items(), key=operator.itemgetter(1),reverse=True))

def cumulative_graph(d, words, descrip):
    sum_d = 0

    for i in d.values():
        sum_d = sum_d + i

    cumulative = 0
    cum_percent = [1]
    keys = [0]
    rank = 1
    for i in d.items():
        if i[1] == 0:
            break
        cumulative = cumulative + i[1] / sum_d
        cum_percent.append(1-cumulative)
        if (words):
            keys.append(i[0])
        else:
            keys.append(rank)
            rank = rank + 1

    
    line, = ax.plot(keys, cum_percent)
    line.set_label(descrip)
    ax.legend()
    if words:
        ax.tick_params(axis='x', rotation=70, labelsize = 5)
    ax.set(xlabel='Domain Rank', ylabel='Cumulative Ratio of Traffic', title='Cumulative Fraction of Traffic Contributed By Top Domains')
    ax.grid()
    fig.savefig("byt_p4_cumulative.png")





python_dns = {}
python_pac = {}
python_byt = {}

# Python script file
f = open('DNS_name_2.txt', 'r')
flist = f.read().split('\n')

numBytesList = []
percentDNSLost = []
percentPacketsLost = []
percentBytesLost = []

count = 4
for i in flist:
    row = i.split()
    numBytesList.append(count)
    count = count + 4

    percentDNSLost.append(1 - float(row[1]))
    percentPacketsLost.append(1 - float(row[2]))
    percentBytesLost.append(1 - float(row[3]))

line1, = ax.plot(numBytesList, percentDNSLost)
line1.set_label('Traffic by DNS Queries')

line2, = ax.plot(numBytesList, percentPacketsLost)
line2.set_label('Traffic by Packets')

line3, = ax.plot(numBytesList, percentBytesLost)
line3.set_label('Traffic by Bytes')

ax.legend()

ax.set(xlabel='Maximum Bytes allowed in Domain Name Parser', ylabel='Ratio of Traffic Lost', title='Percentage of Traffic Lost Due to Domain Name Parser Limitations')
ax.grid()
fig.savefig("dns_parser_limit.png")

plt.show()
#scatter_compare(python_byt, p4_byt)
#rank_compare(python_byt, p4_byt)

'''
