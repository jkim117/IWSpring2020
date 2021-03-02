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

with open('parse_limit60_15min.csv') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        if row[0] == 'Domain':
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

dns_requests = []
dns_missed = []
bytes_counted = []
bytes_corrected = []
error_diff = []
with open('./15min_timeout100/stage_limit2_16.csv') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        #if row[0] == 'Domain':
        if row[0] == 'Domain':
            continue

        if row[0] in domain_names:
            if (bytes_true[row[0]] > 0):
                domains_final.append(row[0])
                bytes_true_final.append(bytes_true[row[0]])
                dns_true_final.append(dns_true[row[0]])

                error_b = abs(bytes_true[row[0]] - float(row[4])) / bytes_true[row[0]]
                error_a = abs(bytes_true[row[0]] - float(row[6])) / bytes_true[row[0]]
                error_before.append(error_b)
                error_after.append(error_a)

                dns_requests.append(row[1])
                dns_missed.append(row[2])
                bytes_counted.append(row[4])
                bytes_corrected.append(row[6])
                error_diff.append(error_b - error_a)


with open('comp_csv.csv', 'w') as csvfile:
    w = csv.writer(csvfile)
    w.writerow(['Domain', 'True DNS requests', 'DNS Missed', 'Ground Truth Number of Bytes', "Bytes Counted Before Correction", "Bytes After Correction", "Error Before Correction", "Error After Correction", "Error Before - Error After"])

    for i in range(len(dns_requests)):
        w.writerow([domains_final[i], dns_requests[i], dns_missed[i], bytes_true_final[i], bytes_counted[i], bytes_corrected[i], error_before[i], error_after[i], error_diff[i]])
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
