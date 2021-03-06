import operator
from sys import argv
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import csv
import statistics

byte_true_values = {} # key is domain, value is true bytes

with open('parse_limit60_3hr.csv') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        if row[0] == 'Domain':
            continue
        byte_true_values[row[0]] = float(row[4])


med_error_before_correction = []
med_error_post_correction = []
memoryList = []

for i in range(0, 34, 2):
    memoryList.append(2 ** i)
    error_before_correction = []
    error_post_correction = []

    with open('./08_19_2020_T08-11/stage_limit2_' + str(i)+'.csv') as csvfile:
        reader = csv.reader(csvfile)

        for row in reader:
            if row[0] == 'Domain':
                continue
            bytes_counted = float(row[4])
            if int(row[1]) > 0:
                bytes_corrected = float(row[6])
            else:
                bytes_corrected = float(row[4])
            true_value = byte_true_values[row[0]]

            if (true_value > 0):
                error_before_correction.append(abs(true_value - bytes_counted) / true_value)
                error_post_correction.append(abs(true_value - bytes_corrected) / true_value)

    med_error_before_correction.append(statistics.mean(error_before_correction))
    med_error_post_correction.append(statistics.mean(error_post_correction))
    

fig, ax = plt.subplots()

line1, = ax.plot(memoryList, med_error_before_correction, color='r')
line1.set_label('Median Error Before Correction')

line2, = ax.plot(memoryList, med_error_post_correction, color='b')
line2.set_label('Median Error After Correction')

'''line9, = ax.plot(memoryList, stage_arrs[8])
line9.set_label('9 Stages')

line10, = ax.plot(memoryList, stage_arrs[9])
line10.set_label('10 Stages')'''

plt.axvline(x=65536, color='red')

ax.legend()

ax.set(xlabel='Memory Length', ylabel='Mean Relative Error', title='Mean Relative Error Due to Memory Size Limitations')
ax.grid()
ax.set_xscale('log', base=2)
fig.savefig("rel_error_comp_3hr.png")

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
