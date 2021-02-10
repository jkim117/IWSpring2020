import operator
from sys import argv
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import csv

true_dns_total = 0
true_packets_total = 0
true_bytes_total = 0

with open('unlimited0000.csv') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        if row[0] == 'Domain':
            continue
        true_dns_total += float(row[1])
        true_packets_total += float(row[3])
        true_bytes_total += float(row[4])

dns_60_total = 26419
packets_60_total = 122386
bytes_60_total = 7171016 # key thing is here

f = open('stage_limits.txt', 'r')
by_stage = f.read().split('*')


stage_arrs = [[],[],[],[],[],[],[],[],[],[]]
memoryList = []

for i in range(0, 10):
    rows = by_stage[i].split()

    count = 0
    for r in rows:
        if i == 0:
            memoryList.append(2**count)
        values = r.split(',')
        stage_arrs[i].append(1 - float(values[2]) / true_bytes_total)
        count += 1


fig, ax = plt.subplots()

line1, = ax.plot(memoryList, stage_arrs[0])
line1.set_label('1 Stage')

line2, = ax.plot(memoryList, stage_arrs[1], color='red')
line2.set_label('2 Stages')

#line3, = ax.plot(memoryList, stage_arrs[2])
#line3.set_label('3 Stages')

line4, = ax.plot(memoryList, stage_arrs[3])
line4.set_label('4 Stages')

'''line5, = ax.plot(memoryList, stage_arrs[4])
line5.set_label('5 Stages')

line6, = ax.plot(memoryList, stage_arrs[5])
line6.set_label('6 Stages')

line7, = ax.plot(memoryList, stage_arrs[6])
line7.set_label('7 Stages')'''

line8, = ax.plot(memoryList, stage_arrs[7])
line8.set_label('8 Stages')

'''line9, = ax.plot(memoryList, stage_arrs[8])
line9.set_label('9 Stages')

line10, = ax.plot(memoryList, stage_arrs[9])
line10.set_label('10 Stages')'''

plt.axvline(x=65536, color='red')

ax.legend()

ax.set(xlabel='Memory Length', ylabel='Ratio of Traffic Lost', title='Ratio of Traffic Lost Due to Memory Size Limitations')
ax.grid()
ax.set_xscale('log', base=2)
fig.savefig("dns_parser_limit.png")

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
