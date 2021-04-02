import operator
from sys import argv
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import csv

dns_60_total = 0
packets_60_total = 0
bytes_60_total = 0 # key thing is here


error_before = []
error_after = []

domain_names = []
bytes_true = {}
dns_true = {}

banned_domains = ['*.*.*.net', '*.*.*', '*.*.com', '*.*.*.com', '*.*.net', '*.edu', '*.com', '*.*.org']

with open('parse_limit60_15min.csv') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        if row[0] == 'Domain' or row[0] in banned_domains:
        #if row[0] == 'Domain':
            continue
        byte_c = float(row[4])
        if byte_c > 0:
            domain_names.append(row[0])
            bytes_true[row[0]] = (byte_c)
            dns_true[row[0]] = int(row[1])

domains_final = []
bytes_true_final = []
dns_true_final = []
with open('./15min_timeout100/stage_limit2_16.csv') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        #if row[0] == 'Domain':
        if row[0] == 'Domain' or row[0] in banned_domains:
            continue

        if row[0] in domain_names:
            if (bytes_true[row[0]] > 0):
                domains_final.append(row[0])
                bytes_true_final.append(bytes_true[row[0]])
                dns_true_final.append(dns_true[row[0]])
                error_before.append(abs(bytes_true[row[0]] - float(row[4])) / bytes_true[row[0]])
                error_after.append(abs(bytes_true[row[0]] - float(row[6])) / bytes_true[row[0]])

print(len(domain_names))

dns_true = np.array(dns_true_final)
domain_names = np.array(domains_final)
bytes_true = np.array(bytes_true_final)
error_before = np.array(error_before)
error_after = np.array(error_after)

idx = np.argsort(dns_true)
domain_names = domain_names[idx]
bytes_true = bytes_true[idx]
error_before = error_before[idx]
error_after = error_after[idx]

domain_names = domain_names[-15:]
bytes_true = bytes_true[-15:]
error_before = error_before[-15:]
error_after = error_after[-15:]

idx = np.argsort(-error_before)
domain_names = domain_names[idx]
bytes_true = bytes_true[idx]
error_before = error_before[idx]
error_after = error_after[idx]


xAxis = 2 * np.arange(0, len(domain_names))


fig, ax = plt.subplots()

width = 0.5

'''selectedIndicies = [6,7,8,9,10]
stage_1 = [stage_arrs[0][i] for i in selectedIndicies]
stage_2 = [stage_arrs[1][i] for i in selectedIndicies]
stage_4 = [stage_arrs[2][i] for i in selectedIndicies]
stage_8 = [stage_arrs[3][i] for i in selectedIndicies]
memoryList = [memoryList[i] for i in selectedIndicies]
memoryList = np.array(memoryList)'''

plt.bar(xAxis-width, error_before, label='Error Before Correction', width=0.5, color='lightsteelblue')
plt.bar(xAxis, error_after, label='Error After Correction', width=0.5, color='cornflowerblue')

'''line9, = ax.plot(memoryList, stage_arrs[8])
line9.set_label('9 Stages')

line10, = ax.plot(memoryList, stage_arrs[9])
line10.set_label('10 Stages')'''

#plt.axvline(x=65536, color='red')

ax.legend()

plt.xticks(xAxis-0.5*width, domain_names, rotation=70, fontsize=8)

ax.set(xlabel='Domain Names', ylabel='Relative Error', title='Relative Error of Domain Names with Correction Applied')
#ax.grid()
#ax.set_xscale('log', base=2)

plt.tight_layout()
fig.savefig("comp_bar_15min_2_16.png")

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
