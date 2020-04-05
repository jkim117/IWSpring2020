import json

globalID = 0
data = {}
data["target"] = "bmv2"
data["p4info"] = "build/calc2.p4.p4info.txt"
data["bmv2_json"] = "build/calc2.json"
data["table_entries"] = []

def dictSetUp(partNum):
    if (partNum == 1):
        partsDict = {
            "headers.q1_part1.part": 0,
            "headers.q1_part2.part": 0,
            "headers.q1_part4.part": 0,
            "headers.q1_part8.part": 0,
            "headers.q1_part16.part": 0,
            "user_metadata.domain_id": 0
        }
        return partsDict
    elif (partNum == 2):
        partsDict = {
            "headers.q2_part1.part": 0,
            "headers.q2_part2.part": 0,
            "headers.q2_part4.part": 0,
            "headers.q2_part8.part": 0,
            "headers.q2_part16.part": 0,
            "user_metadata.domain_id": 0
        }
        return partsDict
    elif (partNum == 3):
        partsDict = {
            "headers.q3_part1.part": 0,
            "headers.q3_part2.part": 0,
            "headers.q3_part4.part": 0,
            "headers.q3_part8.part": 0,
            "headers.q3_part16.part": 0,
            "user_metadata.domain_id": 0
        }
        return partsDict
    elif (partNum == 4):
        partsDict = {
            "headers.q4_part1.part": 0,
            "headers.q4_part2.part": 0,
            "headers.q4_part4.part": 0,
            "headers.q4_part8.part": 0,
            "headers.q4_part16.part": 0
        }
        return partsDict
    return -1

    
# Outputs a reversed, 5 digit, binary representation
def toReversedBinary(num):
    num1 = bin(num)[2::] # cut out 0b prefix
    if len(num1) >= 5:
        num1 = num1[len(num1)-5:len(num1):]
    else:
        for i in range(0, 5-len(num1)):
            num1 = '0' + num1
    return num1[::-1]

def addPart1ToDict(id2, part, partsDict):
    part1Spec = toReversedBinary(len(part))

    charIndex = 0
    if part1Spec[0] == '1':
        partsDict["headers.q1_part1.part"] = part[charIndex]
        charIndex = charIndex + 1
    if part1Spec[1] == '1':
        partsDict["headers.q1_part2.part"] = part[charIndex:charIndex+2]
        charIndex = charIndex + 2
    if part1Spec[2] == '1':
        partsDict["headers.q1_part4.part"] = part[charIndex:charIndex+4]
        charIndex = charIndex + 4
    if part1Spec[3] == '1':
        partsDict["headers.q1_part8.part"] = part[charIndex:charIndex+8]
        charIndex = charIndex + 8
    if part1Spec[4] == '1':
        partsDict["headers.q1_part16.part"] = part[charIndex:charIndex+16]
        charIndex = charIndex + 16
    partsDict["user_metadata.domain_id"] = id2
    return partsDict

def addPart2ToDict(id3, part, partsDict):
    part2Spec = toReversedBinary(len(part))
    charIndex = 0

    if part2Spec[0] == '1':
        partsDict["headers.q2_part1.part"] = part[charIndex]
        charIndex = charIndex + 1
    if part2Spec[1] == '1':
        partsDict["headers.q2_part2.part"] = part[charIndex:charIndex+2]
        charIndex = charIndex + 2
    if part2Spec[2] == '1':
        partsDict["headers.q2_part4.part"] = part[charIndex:charIndex+4]
        charIndex = charIndex + 4
    if part2Spec[3] == '1':
        partsDict["headers.q2_part8.part"] = part[charIndex:charIndex+8]
        charIndex = charIndex + 8
    if part2Spec[4] == '1':
        partsDict["headers.q2_part16.part"] = part[charIndex:charIndex+16]
        charIndex = charIndex + 16
    partsDict["user_metadata.domain_id"] = id3
    return partsDict

def addPart3ToDict(id4, part, partsDict):
    part3Spec = toReversedBinary(len(part))
    charIndex = 0

    if part3Spec[0] == '1':
        partsDict["headers.q3_part1.part"] = part[charIndex]
        charIndex = charIndex + 1
    if part3Spec[1] == '1':
        partsDict["headers.q3_part2.part"] = part[charIndex:charIndex+2]
        charIndex = charIndex + 2
    if part3Spec[2] == '1':
        partsDict["headers.q3_part4.part"] = part[charIndex:charIndex+4]
        charIndex = charIndex + 4
    if part3Spec[3] == '1':
        partsDict["headers.q3_part8.part"] = part[charIndex:charIndex+8]
        charIndex = charIndex + 8
    if part3Spec[4] == '1':
        partsDict["headers.q3_part16.part"] = part[charIndex:charIndex+16]
        charIndex = charIndex + 16
    partsDict["user_metadata.domain_id"] = id4
    return partsDict

def addPart4ToDict(part, partsDict):
    part4Spec = toReversedBinary(len(part))
    charIndex = 0

    if part4Spec[0] == '1':
        partsDict["headers.q4_part1.part"] = part[charIndex]
        charIndex = charIndex + 1
    if part4Spec[1] == '1':
        partsDict["headers.q4_part2.part"] = part[charIndex:charIndex+2]
        charIndex = charIndex + 2
    if part4Spec[2] == '1':
        partsDict["headers.q4_part4.part"] = part[charIndex:charIndex+4]
        charIndex = charIndex + 4
    if part4Spec[3] == '1':
        partsDict["headers.q4_part8.part"] = part[charIndex:charIndex+8]
        charIndex = charIndex + 8
    if part4Spec[4] == '1':
        partsDict["headers.q4_part16.part"] = part[charIndex:charIndex+16]
        charIndex = charIndex + 16
    return partsDict


def packageDict(dict_t):
    global globalID
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list",
        "match": dict_t,
        "action_name": "TopIngress.match_domain",
        "action_params": {"id": globalID}
    })

part4Dict = {}
part3Dict = {}
part2Dict = {}
part1Dict = {}

# If len(parts)==1
def oneparts(parts):
    if parts[0] in part4Dict:
        return part4Dict[parts[0]]
    global globalID
    globalID = globalID + 1
    part4Dict[parts[0]] = globalID

    dict_t = dictSetUp(4)
    addPart4ToDict(parts[0], dict_t)
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list_q4",
        "match": dict_t,
        "action_name": "TopIngress.match_domain4",
        "action_params": {"id": globalID}
    })
    return globalID

# If len(parts)==2
def twoparts(parts):
    id4 = oneparts([parts[1]])
    
    if parts[0] + str(id4) in part3Dict:
        return part3Dict[parts[0] + str(id4)]
    global globalID
    globalID = globalID + 1
    part3Dict[parts[0] + str(id4)] = globalID

    dict_t = dictSetUp(3)
    addPart3ToDict(id4, parts[0], dict_t)
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list_q3",
        "match": dict_t,
        "action_name": "TopIngress.match_domain3",
        "action_params": {"id": globalID}
    })
    return globalID

# If len(parts)==3
def threeparts(parts):
    id3 = twoparts([parts[1], parts[2]])
    
    if parts[0] + str(id3) in part2Dict:
        return part2Dict[parts[0] + str(id3)]
    global globalID
    globalID = globalID + 1
    part2Dict[parts[0] + str(id3)] = globalID

    dict_t = dictSetUp(2)
    addPart2ToDict(id3, parts[0], dict_t)
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list_q2",
        "match": dict_t,
        "action_name": "TopIngress.match_domain2",
        "action_params": {"id": globalID}
    })
    return globalID

# If len(parts)==4
def fourparts(parts):
    id2 = threeparts([parts[1], parts[2], parts[3]])
    
    if parts[0] + str(id2) in part1Dict:
        return part1Dict[parts[0] + str(id2)]
    global globalID
    globalID = globalID + 1
    part1Dict[parts[0] + str(id2)] = globalID

    dict_t = dictSetUp(1)
    addPart1ToDict(id2, parts[0], dict_t)
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list_q1",
        "match": dict_t,
        "action_name": "TopIngress.match_domain1",
        "action_params": {"id": globalID}
    })
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

addDomainToTable("com")
addDomainToTable("net")
addDomainToTable("gov")
addDomainToTable("edu")
addDomainToTable("mil")
addDomainToTable("org")
addDomainToTable("princeton.edu")
for d in domains:
    addDomainToTable(d)

with open('s1-runtime.json', 'w') as outFile:
    json.dump(data, outFile, indent='\t')

