import json

globalID1 = 0
globalID2 = 0
globalID3 = 0
globalID4 = 0
globalID5 = 0
priority1 = 0
priority2 = 0
priority3 = 0
priority4 = 0
priority5 = 0

data = {}
data["target"] = "bmv2"
data["p4info"] = "build/calc2.p4.p4info.txt"
data["bmv2_json"] = "build/calc2.json"
data["table_entries"] = []

def dictSetUp(partNum):
    if (partNum == 1):
        partsDict = {
            "headers.q1_part1.part": [0, 255],
            "headers.q1_part2.part": [0, 65535],
            "headers.q1_part4.part": [0, 4294967295],
            "headers.q1_part8_1.part": [0, 4294967295],
            "headers.q1_part8_2.part": [0, 4294967295],
            "headers.q1_part16_1.part": [0, 4294967295],
            "headers.q1_part16_2.part": [0, 4294967295],
            "headers.q1_part16_3.part": [0, 4294967295],
            "headers.q1_part16_4.part": [0, 4294967295]
        }
        return partsDict
    elif (partNum == 2):
        partsDict = {
            "headers.q2_part1.part": [0, 255],
            "headers.q2_part2.part": [0, 65535],
            "headers.q2_part4.part": [0, 4294967295],
            "headers.q2_part8_1.part": [0, 4294967295],
            "headers.q2_part8_2.part": [0, 4294967295],
            "headers.q2_part16_1.part": [0, 4294967295],
            "headers.q2_part16_2.part": [0, 4294967295],
            "headers.q2_part16_3.part": [0, 4294967295],
            "headers.q2_part16_4.part": [0, 4294967295],
            "user_metadata.q1_id": [0, 4294967295]
        }
        return partsDict
    elif (partNum == 3):
        partsDict = {
            "headers.q3_part1.part": [0, 255],
            "headers.q3_part2.part": [0, 65535],
            "headers.q3_part4.part": [0, 4294967295],
            "headers.q3_part8_1.part": [0, 4294967295],
            "headers.q3_part8_2.part": [0, 4294967295],
            "headers.q3_part16_1.part": [0, 4294967295],
            "headers.q3_part16_2.part": [0, 4294967295],
            "headers.q3_part16_3.part": [0, 4294967295],
            "headers.q3_part16_4.part": [0, 4294967295],
            "user_metadata.q2_id": [0, 4294967295],
        }
        return partsDict
    elif (partNum == 4):
        partsDict = {
            "headers.q4_part1.part": [0, 255],
            "headers.q4_part2.part": [0, 65535],
            "headers.q4_part4.part": [0, 4294967295],
            "headers.q4_part8_1.part": [0, 4294967295],
            "headers.q4_part8_2.part": [0, 4294967295],
            "headers.q4_part16_1.part": [0, 4294967295],
            "headers.q4_part16_2.part": [0, 4294967295],
            "headers.q4_part16_3.part": [0, 4294967295],
            "headers.q4_part16_4.part": [0, 4294967295],
            "user_metadata.q3_id": [0, 4294967295],
        }
        return partsDict
    elif (partNum == 5):
        partsDict = {
            "headers.q5_part1.part": [0, 255],
            "headers.q5_part2.part": [0, 65535],
            "headers.q5_part4.part": [0, 4294967295],
            "headers.q5_part8_1.part": [0, 4294967295],
            "headers.q5_part8_2.part": [0, 4294967295],
            "headers.q5_part16_1.part": [0, 4294967295],
            "headers.q5_part16_2.part": [0, 4294967295],
            "headers.q5_part16_3.part": [0, 4294967295],
            "headers.q5_part16_4.part": [0, 4294967295],
            "user_metadata.q4_id": [0, 4294967295],
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

def addPart1ToDict(part, partsDict):
    if (part == '*'):
        partsDict.pop("headers.q1_part1.part")
        partsDict.pop("headers.q1_part2.part")
        partsDict.pop("headers.q1_part4.part")
        partsDict.pop("headers.q1_part8_1.part")
        partsDict.pop("headers.q1_part8_2.part")
        partsDict.pop("headers.q1_part16_1.part")
        partsDict.pop("headers.q1_part16_2.part")
        partsDict.pop("headers.q1_part16_3.part")
        partsDict.pop("headers.q1_part16_4.part")
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
    if part1Spec[4] == '1':
        partsDict["headers.q1_part16_1.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q1_part16_2.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q1_part16_3.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q1_part16_4.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    return partsDict

def addPart2ToDict(id1, part, partsDict):
    if (id1 == -1):
        partsDict.pop("user_metadata.q1_id")
    else:
        partsDict["user_metadata.q1_id"] = [id1, 4294967295]
    if (part == '*'):
        partsDict.pop("headers.q2_part1.part")
        partsDict.pop("headers.q2_part2.part")
        partsDict.pop("headers.q2_part4.part")
        partsDict.pop("headers.q2_part8_1.part")
        partsDict.pop("headers.q2_part8_2.part")
        partsDict.pop("headers.q2_part16_1.part")
        partsDict.pop("headers.q2_part16_2.part")
        partsDict.pop("headers.q2_part16_3.part")
        partsDict.pop("headers.q2_part16_4.part")
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
    if part2Spec[4] == '1':
        partsDict["headers.q2_part16_1.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q2_part16_2.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q2_part16_3.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q2_part16_4.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    return partsDict

def addPart3ToDict(id2, part, partsDict):
    if (id2 == -1):
        partsDict.pop("user_metadata.q2_id")
    else:
        partsDict["user_metadata.q2_id"] = [id2, 4294967295]
    if (part == '*'):
        partsDict.pop("headers.q3_part1.part")
        partsDict.pop("headers.q3_part2.part")
        partsDict.pop("headers.q3_part4.part")
        partsDict.pop("headers.q3_part8_1.part")
        partsDict.pop("headers.q3_part8_2.part")
        partsDict.pop("headers.q3_part16_1.part")
        partsDict.pop("headers.q3_part16_2.part")
        partsDict.pop("headers.q3_part16_3.part")
        partsDict.pop("headers.q3_part16_4.part")
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
    if part3Spec[4] == '1':
        partsDict["headers.q3_part16_1.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q3_part16_2.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q3_part16_3.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q3_part16_4.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    return partsDict

def addPart4ToDict(id3, part, partsDict):
    if (id3 == -1):
        partsDict.pop("user_metadata.q3_id")
    else:
        partsDict["user_metadata.q3_id"] = [id3, 4294967295]
    if (part == '*'):
        partsDict.pop("headers.q4_part1.part")
        partsDict.pop("headers.q4_part2.part")
        partsDict.pop("headers.q4_part4.part")
        partsDict.pop("headers.q4_part8_1.part")
        partsDict.pop("headers.q4_part8_2.part")
        partsDict.pop("headers.q4_part16_1.part")
        partsDict.pop("headers.q4_part16_2.part")
        partsDict.pop("headers.q4_part16_3.part")
        partsDict.pop("headers.q4_part16_4.part")
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
    if part4Spec[4] == '1':
        partsDict["headers.q4_part16_1.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q4_part16_2.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q4_part16_3.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q4_part16_4.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    return partsDict

def addPart5ToDict(id4, part, partsDict):
    if (id4 == -1):
        partsDict.pop("user_metadata.q4_id")
    else:
        partsDict["user_metadata.q4_id"] = [id4, 4294967295]
    if (part == '*'):
        partsDict.pop("headers.q5_part1.part")
        partsDict.pop("headers.q5_part2.part")
        partsDict.pop("headers.q5_part4.part")
        partsDict.pop("headers.q5_part8_1.part")
        partsDict.pop("headers.q5_part8_2.part")
        partsDict.pop("headers.q5_part16_1.part")
        partsDict.pop("headers.q5_part16_2.part")
        partsDict.pop("headers.q5_part16_3.part")
        partsDict.pop("headers.q5_part16_4.part")
        return partsDict

    part5Spec = toReversedBinary(len(part))

    charIndex = 0
    if part5Spec[0] == '1':
        partsDict["headers.q5_part1.part"] = [part[charIndex], 255]
        charIndex = charIndex + 1
    if part5Spec[1] == '1':
        partsDict["headers.q5_part2.part"] = [part[charIndex:charIndex+2], 65535]
        charIndex = charIndex + 2
    if part5Spec[2] == '1':
        partsDict["headers.q5_part4.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    if part5Spec[3] == '1':
        partsDict["headers.q5_part8_1.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q5_part8_2.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    if part5Spec[4] == '1':
        partsDict["headers.q5_part16_1.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q5_part16_2.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q5_part16_3.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
        partsDict["headers.q5_part16_4.part"] = [part[charIndex:charIndex+4], 4294967295]
        charIndex = charIndex + 4
    return partsDict

part5Dict = {}
part4Dict = {}
part3Dict = {}
part2Dict = {}
part1Dict = {}

# If len(parts)==1
def oneparts(parts):
    if parts[0] in part1Dict:
        if (parts[0] == '*'):
            return -1
        return part1Dict[parts[0]]
    global globalID1
    global priority1
    globalID1 = globalID1 + 1
    part1Dict[parts[0]] = globalID1

    dict_t = dictSetUp(1)
    addPart1ToDict(parts[0], dict_t)

    if (parts[0] == '*'):
        data["table_entries"].append({
            "table": "TopIngress.known_domain_list_q1",
            "match": dict_t,
            "action_name": "TopIngress.match_q1",
            "priority": 1,
            "action_params": {"q1id": globalID1}
        })
        return -1
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list_q1",
        "match": dict_t,
        "action_name": "TopIngress.match_q1",
        "priority": priority1,
        "action_params": {"q1id": globalID1}
    })
    priority1 = priority1 - 1

    return globalID1

# If len(parts)==2
def twoparts(parts):
    id1 = oneparts(parts)
    
    if parts[1] + str(id1) in part2Dict:
        if (parts[1] == '*'):
            return -1
        return part2Dict[parts[1] + str(id1)]
    global globalID2
    global priority2
    globalID2 = globalID2 + 1
    part2Dict[parts[1] + str(id1)] = globalID2

    dict_t = dictSetUp(2)
    addPart2ToDict(id1, parts[1], dict_t)

    if (parts[1] == '*'):
        data["table_entries"].append({
            "table": "TopIngress.known_domain_list_q2",
            "match": dict_t,
            "action_name": "TopIngress.match_q2",
            "priority": 1,
            "action_params": {"q2id": globalID2}
        })
        return -1
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list_q2",
        "match": dict_t,
        "action_name": "TopIngress.match_q2",
        "priority": priority2,
        "action_params": {"q2id": globalID2}
    })
    priority2 = priority2 - 1
    return globalID2

# If len(parts)==3
def threeparts(parts):
    id2 = twoparts(parts)
    
    if parts[2] + str(id2) in part3Dict:
        if (parts[2] == '*'):
            return -1
        return part3Dict[parts[2] + str(id2)]
    global globalID3
    global priority3
    globalID3 = globalID3 + 1
    part3Dict[parts[2] + str(id2)] = globalID3

    dict_t = dictSetUp(3)
    addPart3ToDict(id2, parts[2], dict_t)

    if (parts[2] == '*'):
        data["table_entries"].append({
            "table": "TopIngress.known_domain_list_q3",
            "match": dict_t,
            "action_name": "TopIngress.match_q3",
            "priority": 1,
            "action_params": {"q3id": globalID3}
        })
        return -1
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list_q3",
        "match": dict_t,
        "action_name": "TopIngress.match_q3",
        "priority": priority3,
        "action_params": {"q3id": globalID3}
    })
    priority3 = priority3 - 1
    return globalID3

# If len(parts)==4
def fourparts(parts):
    id3 = threeparts(parts)
    
    if parts[3] + str(id3) in part4Dict:
        if (parts[3] == '*'):
            return -1
        return part4Dict[parts[3] + str(id3)]
    global globalID4
    global priority4
    globalID4 = globalID4 + 1
    part4Dict[parts[3] + str(id3)] = globalID4

    dict_t = dictSetUp(4)
    addPart4ToDict(id3, parts[3], dict_t)

    if (parts[3] == '*'):
        data["table_entries"].append({
            "table": "TopIngress.known_domain_list_q4",
            "match": dict_t,
            "action_name": "TopIngress.match_q4",
            "priority": 1,
            "action_params": {"q4id": globalID4}
        })
        return -1
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list_q4",
        "match": dict_t,
        "action_name": "TopIngress.match_q4",
        "priority": priority4,
        "action_params": {"q4id": globalID4}
    })
    priority4 = priority4 - 1
    return globalID4

# If len(parts)==5
def fiveparts(parts):
    id4 = fourparts(parts)
    
    if parts[4] + str(id4) in part5Dict:
        if (parts[4] == '*'):
            return -1
        return part5Dict[parts[4] + str(id4)]
    global globalID5
    global priority5
    globalID5 = globalID5 + 1
    part5Dict[parts[4] + str(id4)] = globalID5

    dict_t = dictSetUp(5)
    addPart5ToDict(id4, parts[4], dict_t)

    if (parts[4] == '*'):
        data["table_entries"].append({
            "table": "TopIngress.known_domain_list_q5",
            "match": dict_t,
            "action_name": "TopIngress.match_domain",
            "priority": 1,
            "action_params": {"id": globalID5}
        })
        return -1
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list_q5",
        "match": dict_t,
        "action_name": "TopIngress.match_domain",
        "priority": priority5,
        "action_params": {"id": globalID5}
    })
    priority5 = priority5 - 1
    return globalID5

def addDomainToTable(domain):
    parts = domain.split('.')
    numParts = len(parts)
    if numParts > 5:
        print("error: " + domain)
        return -1
    if numParts == 1:
        #oneparts(parts)
        parts.append('')
        parts.append('')
        parts.append('')
        parts.append('')
        fiveparts(parts)
    elif numParts == 2:
        #twoparts(parts)
        parts.append('')
        parts.append('')
        parts.append('')
        fiveparts(parts)
    elif numParts == 3:
        #threeparts(parts)
        parts.append('')
        parts.append('')
        fiveparts(parts)
    elif numParts == 4:
        #fourparts(parts)
        parts.append('')
        fiveparts(parts)
    elif numParts == 5:
        fiveparts(parts)

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

priority1 = len(domains) + 1
priority2 = len(domains) + 1
priority3 = len(domains) + 1
priority4 = len(domains) + 1
priority5 = len(domains) + 1

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

