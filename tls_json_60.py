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
        "headers.q1_1.char": [0, 255],
        "headers.q1_2.char": [0, 255],
        "headers.q1_3.char": [0, 255],
        "headers.q1_4.char": [0, 255],
        "headers.q1_5.char": [0, 255],
        "headers.q1_6.char": [0, 255],
        "headers.q1_7.char": [0, 255],
        "headers.q1_8.char": [0, 255],
        "headers.q1_9.char": [0, 255],
        "headers.q1_10.char": [0, 255],
        "headers.q1_11.char": [0, 255],
        "headers.q1_12.char": [0, 255],
        "headers.q1_13.char": [0, 255],
        "headers.q1_14.char": [0, 255],
        "headers.q1_15.char": [0, 255],
        "headers.q1_16.char": [0, 255],
        "headers.q2_1.char": [0, 255],
        "headers.q2_2.char": [0, 255],
        "headers.q2_3.char": [0, 255],
        "headers.q2_4.char": [0, 255],
        "headers.q2_5.char": [0, 255],
        "headers.q2_6.char": [0, 255],
        "headers.q2_7.char": [0, 255],
        "headers.q2_8.char": [0, 255],
        "headers.q2_9.char": [0, 255],
        "headers.q2_10.char": [0, 255],
        "headers.q2_11.char": [0, 255],
        "headers.q2_12.char": [0, 255],
        "headers.q2_13.char": [0, 255],
        "headers.q2_14.char": [0, 255],
        "headers.q2_15.char": [0, 255],
        "headers.q2_16.char": [0, 255],
        "headers.q3_1.char": [0, 255],
        "headers.q3_2.char": [0, 255],
        "headers.q3_3.char": [0, 255],
        "headers.q3_4.char": [0, 255],
        "headers.q3_5.char": [0, 255],
        "headers.q3_6.char": [0, 255],
        "headers.q3_7.char": [0, 255],
        "headers.q3_8.char": [0, 255],
        "headers.q3_9.char": [0, 255],
        "headers.q3_10.char": [0, 255],
        "headers.q3_11.char": [0, 255],
        "headers.q3_12.char": [0, 255],
        "headers.q3_13.char": [0, 255],
        "headers.q3_14.char": [0, 255],
        "headers.q3_15.char": [0, 255],
        "headers.q3_16.char": [0, 255],
        "headers.q4_1.char": [0, 255],
        "headers.q4_2.char": [0, 255],
        "headers.q4_3.char": [0, 255],
        "headers.q4_4.char": [0, 255],
        "headers.q4_5.char": [0, 255],
        "headers.q4_6.char": [0, 255],
        "headers.q4_7.char": [0, 255],
        "headers.q4_8.char": [0, 255],
        "headers.q4_9.char": [0, 255],
        "headers.q4_10.char": [0, 255],
        "headers.q4_11.char": [0, 255],
        "headers.q4_12.char": [0, 255],
        "headers.q4_13.char": [0, 255],
        "headers.q4_14.char": [0, 255],
        "headers.q4_15.char": [0, 255]
    }
    return partsDict

def addPart1ToDict(part, partsDict):
    if (part == '*' or part == '*.'):
        partsDict.pop("headers.q1_1.char")
        partsDict.pop("headers.q1_2.char")
        partsDict.pop("headers.q1_3.char")
        partsDict.pop("headers.q1_4.char")
        partsDict.pop("headers.q1_5.char")
        partsDict.pop("headers.q1_6.char")
        partsDict.pop("headers.q1_7.char")
        partsDict.pop("headers.q1_8.char")
        partsDict.pop("headers.q1_9.char")
        partsDict.pop("headers.q1_10.char")
        partsDict.pop("headers.q1_11.char")
        partsDict.pop("headers.q1_12.char")
        partsDict.pop("headers.q1_13.char")
        partsDict.pop("headers.q1_14.char")
        partsDict.pop("headers.q1_15.char")
        partsDict.pop("headers.q1_16.char")
        return partsDict

    part_len = len(part)
    if (part_len > 16):
        print("Domain with part longer than 15 characters")
        exit(-1)

    for i in range(part_len):
        if (i == 0):
            partsDict["headers.q1_1.char"] = [part[i], 255]
        elif (i == 1):
            partsDict["headers.q1_2.char"] = [part[i], 255]
        elif (i == 2):
            partsDict["headers.q1_3.char"] = [part[i], 255]
        elif (i == 3):
            partsDict["headers.q1_4.char"] = [part[i], 255]
        elif (i == 4):
            partsDict["headers.q1_5.char"] = [part[i], 255]
        elif (i == 5):
            partsDict["headers.q1_6.char"] = [part[i], 255]
        elif (i == 6):
            partsDict["headers.q1_7.char"] = [part[i], 255]
        elif (i == 7):
            partsDict["headers.q1_8.char"] = [part[i], 255]
        elif (i == 8):
            partsDict["headers.q1_9.char"] = [part[i], 255]
        elif (i == 9):
            partsDict["headers.q1_10.char"] = [part[i], 255]
        elif (i == 10):
            partsDict["headers.q1_11.char"] = [part[i], 255]
        elif (i == 11):
            partsDict["headers.q1_12.char"] = [part[i], 255]
        elif (i == 12):
            partsDict["headers.q1_13.char"] = [part[i], 255]
        elif (i == 13):
            partsDict["headers.q1_14.char"] = [part[i], 255]
        elif (i == 14):
            partsDict["headers.q1_15.char"] = [part[i], 255]
        elif (i == 15):
            partsDict["headers.q1_16.char"] = [part[i], 255]

    return partsDict

def addPart2ToDict(part, partsDict):
    if (part == '*' or part == '*.'):
        partsDict.pop("headers.q2_1.char")
        partsDict.pop("headers.q2_2.char")
        partsDict.pop("headers.q2_3.char")
        partsDict.pop("headers.q2_4.char")
        partsDict.pop("headers.q2_5.char")
        partsDict.pop("headers.q2_6.char")
        partsDict.pop("headers.q2_7.char")
        partsDict.pop("headers.q2_8.char")
        partsDict.pop("headers.q2_9.char")
        partsDict.pop("headers.q2_10.char")
        partsDict.pop("headers.q2_11.char")
        partsDict.pop("headers.q2_12.char")
        partsDict.pop("headers.q2_13.char")
        partsDict.pop("headers.q2_14.char")
        partsDict.pop("headers.q2_15.char")
        partsDict.pop("headers.q2_16.char")
        return partsDict

    part_len = len(part)
    if (part_len > 16):
        print("Domain with part longer than 15 characters")
        exit(-1)

    for i in range(part_len):
        if (i == 0):
            partsDict["headers.q2_1.char"] = [part[i], 255]
        elif (i == 1):
            partsDict["headers.q2_2.char"] = [part[i], 255]
        elif (i == 2):
            partsDict["headers.q2_3.char"] = [part[i], 255]
        elif (i == 3):
            partsDict["headers.q2_4.char"] = [part[i], 255]
        elif (i == 4):
            partsDict["headers.q2_5.char"] = [part[i], 255]
        elif (i == 5):
            partsDict["headers.q2_6.char"] = [part[i], 255]
        elif (i == 6):
            partsDict["headers.q2_7.char"] = [part[i], 255]
        elif (i == 7):
            partsDict["headers.q2_8.char"] = [part[i], 255]
        elif (i == 8):
            partsDict["headers.q2_9.char"] = [part[i], 255]
        elif (i == 9):
            partsDict["headers.q2_10.char"] = [part[i], 255]
        elif (i == 10):
            partsDict["headers.q2_11.char"] = [part[i], 255]
        elif (i == 11):
            partsDict["headers.q2_12.char"] = [part[i], 255]
        elif (i == 12):
            partsDict["headers.q2_13.char"] = [part[i], 255]
        elif (i == 13):
            partsDict["headers.q2_14.char"] = [part[i], 255]
        elif (i == 14):
            partsDict["headers.q2_15.char"] = [part[i], 255]
        elif (i == 15):
            partsDict["headers.q2_16.char"] = [part[i], 255]
    return partsDict

def addPart3ToDict(part, partsDict):
    if (part == '*' or part == '*.'):
        partsDict.pop("headers.q3_1.char")
        partsDict.pop("headers.q3_2.char")
        partsDict.pop("headers.q3_3.char")
        partsDict.pop("headers.q3_4.char")
        partsDict.pop("headers.q3_5.char")
        partsDict.pop("headers.q3_6.char")
        partsDict.pop("headers.q3_7.char")
        partsDict.pop("headers.q3_8.char")
        partsDict.pop("headers.q3_9.char")
        partsDict.pop("headers.q3_10.char")
        partsDict.pop("headers.q3_11.char")
        partsDict.pop("headers.q3_12.char")
        partsDict.pop("headers.q3_13.char")
        partsDict.pop("headers.q3_14.char")
        partsDict.pop("headers.q3_15.char")
        partsDict.pop("headers.q3_16.char")
        return partsDict

    part_len = len(part)
    if (part_len > 16):
        print("Domain with part longer than 15 characters")
        exit(-1)

    for i in range(part_len):
        if (i == 0):
            partsDict["headers.q3_1.char"] = [part[i], 255]
        elif (i == 1):
            partsDict["headers.q3_2.char"] = [part[i], 255]
        elif (i == 2):
            partsDict["headers.q3_3.char"] = [part[i], 255]
        elif (i == 3):
            partsDict["headers.q3_4.char"] = [part[i], 255]
        elif (i == 4):
            partsDict["headers.q3_5.char"] = [part[i], 255]
        elif (i == 5):
            partsDict["headers.q3_6.char"] = [part[i], 255]
        elif (i == 6):
            partsDict["headers.q3_7.char"] = [part[i], 255]
        elif (i == 7):
            partsDict["headers.q3_8.char"] = [part[i], 255]
        elif (i == 8):
            partsDict["headers.q3_9.char"] = [part[i], 255]
        elif (i == 9):
            partsDict["headers.q3_10.char"] = [part[i], 255]
        elif (i == 10):
            partsDict["headers.q3_11.char"] = [part[i], 255]
        elif (i == 11):
            partsDict["headers.q3_12.char"] = [part[i], 255]
        elif (i == 12):
            partsDict["headers.q3_13.char"] = [part[i], 255]
        elif (i == 13):
            partsDict["headers.q3_14.char"] = [part[i], 255]
        elif (i == 14):
            partsDict["headers.q3_15.char"] = [part[i], 255]
        elif (i == 15):
            partsDict["headers.q3_16.char"] = [part[i], 255]
    return partsDict

def addPart4ToDict(part, partsDict):
    if (part == '*' or part == '*.'):
        partsDict.pop("headers.q4_1.char")
        partsDict.pop("headers.q4_2.char")
        partsDict.pop("headers.q4_3.char")
        partsDict.pop("headers.q4_4.char")
        partsDict.pop("headers.q4_5.char")
        partsDict.pop("headers.q4_6.char")
        partsDict.pop("headers.q4_7.char")
        partsDict.pop("headers.q4_8.char")
        partsDict.pop("headers.q4_9.char")
        partsDict.pop("headers.q4_10.char")
        partsDict.pop("headers.q4_11.char")
        partsDict.pop("headers.q4_12.char")
        partsDict.pop("headers.q4_13.char")
        partsDict.pop("headers.q4_14.char")
        partsDict.pop("headers.q4_15.char")
        return partsDict

    part_len = len(part)
    if (part_len > 15):
        print("Domain with part longer than 15 characters")
        exit(-1)

    for i in range(part_len):
        if (i == 0):
            partsDict["headers.q4_1.char"] = [part[i], 255]
        elif (i == 1):
            partsDict["headers.q4_2.char"] = [part[i], 255]
        elif (i == 2):
            partsDict["headers.q4_3.char"] = [part[i], 255]
        elif (i == 3):
            partsDict["headers.q4_4.char"] = [part[i], 255]
        elif (i == 4):
            partsDict["headers.q4_5.char"] = [part[i], 255]
        elif (i == 5):
            partsDict["headers.q4_6.char"] = [part[i], 255]
        elif (i == 6):
            partsDict["headers.q4_7.char"] = [part[i], 255]
        elif (i == 7):
            partsDict["headers.q4_8.char"] = [part[i], 255]
        elif (i == 8):
            partsDict["headers.q4_9.char"] = [part[i], 255]
        elif (i == 9):
            partsDict["headers.q4_10.char"] = [part[i], 255]
        elif (i == 10):
            partsDict["headers.q4_11.char"] = [part[i], 255]
        elif (i == 11):
            partsDict["headers.q4_12.char"] = [part[i], 255]
        elif (i == 12):
            partsDict["headers.q4_13.char"] = [part[i], 255]
        elif (i == 13):
            partsDict["headers.q4_14.char"] = [part[i], 255]
        elif (i == 14):
            partsDict["headers.q4_15.char"] = [part[i], 255]
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
    addPart1ToDict(parts[0] + '.', dict_t)
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
    addPart1ToDict(parts[0] + '.', dict_t)
    addPart2ToDict(parts[1] + '.', dict_t)
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
    addPart1ToDict(parts[0] + '.', dict_t)
    addPart2ToDict(parts[1] + '.', dict_t)
    addPart3ToDict(parts[2] + '.', dict_t)
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
    
knownlist = open('known_domains.txt', 'r')
domains = knownlist.read().split()
knownlist.close()

globalPriority = len(domains)

for d in domains:
    addDomainToTable(d)

with open('s1-runtime.json', 'w') as outFile:
    json.dump(data, outFile, indent='\t')

