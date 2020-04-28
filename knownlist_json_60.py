import json

globalID = 0
globalPriority = 0
data = {}
data["target"] = "bmv2"
data["p4info"] = "build/calc2.p4.p4info.txt"
data["bmv2_json"] = "build/calc2.json"
data["table_entries"] = []

def dictSetUp():
    partsDict = {
        "headers.q1_part1.part": [0, 255],
        "headers.q1_part2.part": [0, 65535],
        "headers.q1_part4.part": [0, 4294967295],
        "headers.q1_part8_1.part": [0, 4294967295],
        "headers.q1_part8_2.part": [0, 4294967295],
        "headers.q2_part1.part": [0, 255],
        "headers.q2_part2.part": [0, 65535],
        "headers.q2_part4.part": [0, 4294967295],
        "headers.q2_part8_1.part": [0, 4294967295],
        "headers.q2_part8_2.part": [0, 4294967295],
        "headers.q3_part1.part": [0, 255],
        "headers.q3_part2.part": [0, 65535],
        "headers.q3_part4.part": [0, 4294967295],
        "headers.q3_part8_1.part": [0, 4294967295],
        "headers.q3_part8_2.part": [0, 4294967295],
        "headers.q4_part1.part": [0, 255],
        "headers.q4_part2.part": [0, 65535],
        "headers.q4_part4.part": [0, 4294967295],
        "headers.q4_part8_1.part": [0, 4294967295],
        "headers.q4_part8_2.part": [0, 4294967295]
    }
    return partsDict

    
# Outputs a reversed, 5 digit, binary representation
def toReversedBinary(num):
    num1 = bin(num)[2::] # cut out 0b prefix
    if len(num1) >= 5:
        num1 = num1[len(num1)-5:len(num1):]
    else:
        for i in range(0, 5-len(num1)):
            num1 = '0' + num1
    return num1[::-1]

def addPart1ToDict(part, partsDict):
    if (part == '*'):
        partsDict.pop("headers.q1_part1.part")
        partsDict.pop("headers.q1_part2.part")
        partsDict.pop("headers.q1_part4.part")
        partsDict.pop("headers.q1_part8_1.part")
        partsDict.pop("headers.q1_part8_2.part")
        return partsDict

    part1Spec = toReversedBinary(len(part))

    charIndex = 0
    if part1Spec[0] == '1':
        partsDict["headers.q1_part1.part"] = [part[charIndex], 255]
        charIndex = charIndex + 1
    if part1Spec[1] == '1':
        partsDict["headers.q1_part2.part"] = [part[charIndex:charIndex+2], 65535]
        charIndex = charIndex + 2
    if part1Spec[2] == '1':
        partsDict["headers.q1_part4.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    if part1Spec[3] == '1':
        partsDict["headers.q1_part8_1.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q1_part8_2.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    return partsDict

def addPart2ToDict(part, partsDict):
    if (part == '*'):
        partsDict.pop("headers.q2_part1.part")
        partsDict.pop("headers.q2_part2.part")
        partsDict.pop("headers.q2_part4.part")
        partsDict.pop("headers.q2_part8_1.part")
        partsDict.pop("headers.q2_part8_2.part")
        return partsDict

    part2Spec = toReversedBinary(len(part))

    charIndex = 0
    if part2Spec[0] == '1':
        partsDict["headers.q2_part1.part"] = [part[charIndex], 255]
        charIndex = charIndex + 1
    if part2Spec[1] == '1':
        partsDict["headers.q2_part2.part"] = [part[charIndex:charIndex+2], 65535]
        charIndex = charIndex + 2
    if part2Spec[2] == '1':
        partsDict["headers.q2_part4.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    if part2Spec[3] == '1':
        partsDict["headers.q2_part8_1.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q2_part8_2.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    return partsDict

def addPart3ToDict(part, partsDict):
    if (part == '*'):
        partsDict.pop("headers.q3_part1.part")
        partsDict.pop("headers.q3_part2.part")
        partsDict.pop("headers.q3_part4.part")
        partsDict.pop("headers.q3_part8_1.part")
        partsDict.pop("headers.q3_part8_2.part")
        return partsDict

    part3Spec = toReversedBinary(len(part))

    charIndex = 0
    if part3Spec[0] == '1':
        partsDict["headers.q3_part1.part"] = [part[charIndex], 255]
        charIndex = charIndex + 1
    if part3Spec[1] == '1':
        partsDict["headers.q3_part2.part"] = [part[charIndex:charIndex+2], 65535]
        charIndex = charIndex + 2
    if part3Spec[2] == '1':
        partsDict["headers.q3_part4.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    if part3Spec[3] == '1':
        partsDict["headers.q3_part8_1.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q3_part8_2.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    return partsDict

def addPart4ToDict(part, partsDict):
    if (part == '*'):
        partsDict.pop("headers.q4_part1.part")
        partsDict.pop("headers.q4_part2.part")
        partsDict.pop("headers.q4_part4.part")
        partsDict.pop("headers.q4_part8_1.part")
        partsDict.pop("headers.q4_part8_2.part")
        return partsDict

    part4Spec = toReversedBinary(len(part))

    charIndex = 0
    if part4Spec[0] == '1':
        partsDict["headers.q4_part1.part"] = [part[charIndex], 255]
        charIndex = charIndex + 1
    if part4Spec[1] == '1':
        partsDict["headers.q4_part2.part"] = [part[charIndex:charIndex+2], 65535]
        charIndex = charIndex + 2
    if part4Spec[2] == '1':
        partsDict["headers.q4_part4.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    if part4Spec[3] == '1':
        partsDict["headers.q4_part8_1.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q4_part8_2.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    return partsDict

# If len(parts)==1
def oneparts(parts):
    global globalID
    global globalPriority
    globalID = globalID + 1

    dict_t = dictSetUp()
    addPart1ToDict(parts[0], dict_t)
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list",
        "match": dict_t,
        "action_name": "TopIngress.match_domain",
        "priority": globalPriority,
        "action_params": {"id": globalID}
    })

    globalPriority = globalPriority - 1
    return globalID

# If len(parts)==2
def twoparts(parts):
    global globalID
    global globalPriority
    globalID = globalID + 1

    dict_t = dictSetUp()
    addPart1ToDict(parts[0], dict_t)
    addPart2ToDict(parts[1], dict_t)
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list",
        "match": dict_t,
        "action_name": "TopIngress.match_domain",
        "priority": globalPriority,
        "action_params": {"id": globalID}
    })

    globalPriority = globalPriority - 1
    return globalID

# If len(parts)==3
def threeparts(parts):
    global globalID
    global globalPriority
    globalID = globalID + 1

    dict_t = dictSetUp()
    addPart1ToDict(parts[0], dict_t)
    addPart2ToDict(parts[1], dict_t)
    addPart3ToDict(parts[2], dict_t)
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list",
        "match": dict_t,
        "action_name": "TopIngress.match_domain",
        "priority": globalPriority,
        "action_params": {"id": globalID}
    })

    globalPriority = globalPriority - 1
    return globalID

# If len(parts)==4
def fourparts(parts):
    global globalID
    global globalPriority
    globalID = globalID + 1

    dict_t = dictSetUp()
    addPart1ToDict(parts[0], dict_t)
    addPart2ToDict(parts[1], dict_t)
    addPart3ToDict(parts[2], dict_t)
    addPart4ToDict(parts[3], dict_t)
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list",
        "match": dict_t,
        "action_name": "TopIngress.match_domain",
        "priority": globalPriority,
        "action_params": {"id": globalID}
    })

    globalPriority = globalPriority - 1
    return globalID

def addDomainToTable(domain):
    parts = domain.split('.')
    numParts = len(parts)
    if numParts > 4:
        print("error: " + domain)
        return -1
    if numParts == 1:
        oneparts(parts)
    elif numParts == 2:
        twoparts(parts)
    elif numParts == 3:
        threeparts(parts)
    elif numParts == 4:
        fourparts(parts)

def addBannedIpToTable(ip):
    ipList = ip.split('/')
    if (len(ipList) == 2):
        mask = int(ipList[1])
    elif (len(ipList) == 1):
        mask = 32
    else:
        exit(-1)
    ipaddr = ipList[0]
    ip_dict = {
        "headers.ipv4.dst": [ipaddr, mask]
    }
    ip_dict['headers.ipv4.dst']
    data["table_entries"].append({
        "table": "TopIngress.banned_dns_dst",
        "match": ip_dict,
        "action_name": "TopIngress.match_banned_dns_dst"
    })

def addAllowedIpToTable(ip):
    ipList = ip.split('/')
    if (len(ipList) == 2):
        mask = int(ipList[1])
    elif (len(ipList) == 1):
        mask = 32
    else:
        exit(-1)
    ipaddr = ipList[0]
    ip_dict = {
        "headers.ipv4.dst": [ipaddr, mask]
    }
    ip_dict['headers.ipv4.dst']
    data["table_entries"].append({
        "table": "TopIngress.allowable_dns_dst",
        "match": ip_dict,
        "action_name": "NoAction"
    })
    
knownlist = open('known_domains.txt', 'r')
domains = knownlist.read().split()
knownlist.close()

globalPriority = len(domains)

for d in domains:
    addDomainToTable(d)

bannedlist = open('banned_dns_dst.txt', 'r')
bannedip = bannedlist.read().split()
bannedlist.close()

for ip in bannedip:
    addBannedIpToTable(ip)

allowedlist = open('allowed_dns_dst.txt', 'r')
allowedip = allowedlist.read().split()
allowedlist.close()

for ip in allowedip:
    addAllowedIpToTable(ip)

with open('s1-runtime.json', 'w') as outFile:
    json.dump(data, outFile, indent='\t')

