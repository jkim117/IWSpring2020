import csv
import pickle


devices = {} # key is device + detection level, value is a list of strings of domain:port
domains = {} # key is domain:port string, value is a list of device + detection level

with open('alexa_enabled.csv') as csv1:
    reader = csv.reader(csv1)

    isFirst = True
    for row in reader:
        if (isFirst):
            isFirst = False
            continue

        domain = row[0]
        if (domain[-1] == '.'):
            domain = domain[:-1]

        device = row[2] + '/' + row[1]
        domain_port = domain + ':' + row[5]

        if device in devices:
            if domain_port not in devices[device]:
                devices[device].append(domain_port)
        else:
            devices[device] = [domain_port]

        if domain_port in domains:
            if device not in domains[domain_port]:
                domains[domain_port].append(device)
        else:
            domains[domain_port] = [device]
        

with open('samsung_IoT.csv') as csv1:
    reader = csv.reader(csv1)

    isFirst = True
    for row in reader:
        if (isFirst):
            isFirst = False
            continue

        domain = row[0]
        if (domain[-1] == '.'):
            domain = domain[:-1]

        device = row[2] + '/' + row[1]
        domain_port = domain + ':' + row[5]

        if device in devices:
            if domain_port not in devices[device]:
                devices[device].append(domain_port)
        else:
            devices[device] = [domain_port]

        if domain_port in domains:
            if device not in domains[domain_port]:
                domains[domain_port].append(device)
        else:
            domains[domain_port] = [device]

with open('other_devices.csv') as csv1:
    reader = csv.reader(csv1)

    isFirst = True
    for row in reader:
        if (isFirst):
            isFirst = False
            continue

        domain = row[0]
        if (domain[-1] == '.'):
            domain = domain[:-1]

        device = row[2] + '/' + row[1]
        domain_port = domain + ':' + row[5]

        if device in devices:
            if domain_port not in devices[device]:
                devices[device].append(domain_port)
        else:
            devices[device] = [domain_port]

        if domain_port in domains:
            if device not in domains[domain_port]:
                domains[domain_port].append(device)
        else:
            domains[domain_port] = [device]

device_file = open('rules_by_device.txt', 'w')

for k in devices.keys():
    num_domains = len(devices[k])
    device_file.write(k+', '+str(num_domains))
    for d in devices[k]:
        device_file.write(', '+d)
    device_file.write('\n\n')

device_file.close()

domain_file = open('rules_by_domain.txt', 'w')

for k in domains.keys():
    num_devices = len(domains[k])
    domain_file.write(k+', '+str(num_devices))
    for d in domains[k]:
        domain_file.write(', '+d)
    domain_file.write('\n\n')

domain_file.close()

