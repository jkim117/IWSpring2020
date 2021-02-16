import operator
from sys import argv
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import csv

true_dns_total = 0
true_packets_total = 0
true_bytes_total = 0

with open('unlimited_15min.csv') as csvfile:
#with open('unlimited0000.csv') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        if row[0] == 'Domain':
            continue
        true_dns_total += float(row[1])
        true_packets_total += float(row[3])
        true_bytes_total += float(row[4])

f = open('timeout_limits_test.txt', 'r')
#f = open('timeout_limits.txt', 'r')
rows = f.read().split('\n')

dns_60_total = 26419
packets_60_total = 122386
bytes_60_total = 7171016

packets_arr = []
bytes_arr = []
timeoutList = []

count = 0
for r in rows:
    timeoutList.append(count)
    values = r.split(',')
    packets_arr.append(1 - float(values[1]) / packets_60_total)
    bytes_arr.append(1 - float(values[2]) / bytes_60_total)
    # count += 10 change for real
    count += 1


fig, ax = plt.subplots()

line3, = ax.plot(timeoutList, bytes_arr)
line3.set_label('Bytes')

line2, = ax.plot(timeoutList, packets_arr)
line2.set_label('Packets')

plt.axvline(x=3, color='red')

ax.legend()


ax.set(xlabel='Timemout (s)', ylabel='Ratio of Traffic Lost', title='Ratio of Traffic Lost Due to Timeout Limitation')
ax.grid()
fig.savefig("timeout_limit.png")

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
