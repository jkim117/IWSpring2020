import operator
from sys import argv
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import csv

dns_60_total = 0
packets_60_total = 0
bytes_60_total = 0 # key thing is here

with open('parse_limit60_15min.csv') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        if row[0] == 'Domain':
            continue
        dns_60_total += float(row[1])
        packets_60_total += float(row[3])
        bytes_60_total += float(row[4])

stage_1 = 1 - (np.array([542916086,496062574,472849486]) / bytes_60_total)
stage_2 = 1 - (np.array([618468806,537250266,544050940]) / bytes_60_total)
stage_4 = 1 - (np.array([645560072,614920014,561580932]) / bytes_60_total)
stage_8 = 1 - (np.array([664872786,634735918,579924026]) / bytes_60_total)

xList = np.array([2, 4, 6])

fig, ax = plt.subplots()

width = 0.25

plt.bar(xList, stage_1, label='1 Stage', width=0.25, color='lightsteelblue')
plt.bar(xList+width, stage_2, label='2 Stage', width=0.25, color='cornflowerblue')
plt.bar(xList+2*width, stage_4, label='4 Stage', width=0.25, color='royalblue')
plt.bar(xList+3*width, stage_8, label='8 Stage', width=0.25, color='navy')

'''line9, = ax.plot(memoryList, stage_arrs[8])
line9.set_label('9 Stages')

line10, = ax.plot(memoryList, stage_arrs[9])
line10.set_label('10 Stages')'''

#plt.axvline(x=65536, color='red')

ax.legend()

plt.xticks(xList+1.5*width, [100, 300, 500])

ax.set(xlabel='Timeout (s)', ylabel='Ratio of Traffic Lost', title='Ratio of Traffic Lost Varied by Timeout')
ax.grid()
#ax.set_xscale('log', base=2)
fig.savefig("timeout_bar_15min.png")

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
