import json

def dictSetUp():
    partsDict = {
        "headers.q1_part1.part": "",
        "headers.q1_part2.part": "",
        "headers.q1_part4.part": "",
        "headers.q1_part8.part": "",
        "headers.q2_part1.part": "",
        "headers.q2_part2.part": "",
        "headers.q2_part4.part": "",
        "headers.q2_part8.part": "",
        "headers.q2_part16.part": "",
        "headers.q3_part1.part": "",
        "headers.q3_part2.part": "",
        "headers.q3_part4.part": "",
        "headers.q3_part8.part": "",
        "headers.q3_part16.part": "",
        "headers.q4_part1.part": "",
        "headers.q4_part2.part": "",
        "headers.q4_part4.part": ""
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
    return partsDict

def addPart2ToDict(part, partsDict):
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
    return partsDict

def addPart3ToDict(part, partsDict):
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
    return partsDict


def packageDict(dict_t):
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list",
        "match": dict_t,
        "action_name": "TopIngress.match_domain",
        "action_params": {"id": globalID}
    })

# If len(parts)==1
def oneparts(parts):
    if (len(parts[0]) <= 15):
        dict_t = dictSetUp()
        addPart1ToDict(parts[0], dict_t)
        packageDict(dict_t)
    if (len(parts[0]) <= 31):
        dict_t = dictSetUp()
        addPart2ToDict(parts[0], dict_t)
        packageDict(dict_t)
        dict_t = dictSetUp()
        addPart3ToDict(parts[0], dict_t)
        packageDict(dict_t)
    if (len(parts[0]) <= 7):
        dict_t = dictSetUp()
        addPart4ToDict(parts[0], dict_t)
        packageDict(dict_t)


# If len(parts)==2
def twoparts(parts):
    if (len(parts[0]) <= 15 and len(parts[1]) <= 31):
        dict_t = dictSetUp()
        addPart1ToDict(parts[0], dict_t)
        addPart2ToDict(parts[1], dict_t)
        packageDict(dict_t)
    if (len(parts[0]) <= 31 and len(parts[1]) <= 31):
        dict_t = dictSetUp()
        addPart2ToDict(parts[0], dict_t)
        addPart3ToDict(parts[1], dict_t)
        packageDict(dict_t)
    if (len(parts[0]) <= 31 and len(parts[1]) <= 7):
        dict_t = dictSetUp()
        addPart3ToDict(parts[0], dict_t)
        addPart4ToDict(parts[1], dict_t)
        packageDict(dict_t)

# If len(parts)==3
def threeparts(parts):
    if (len(parts[0]) <= 15 and len(parts[1]) <= 31 and len(parts[2]) <= 31):
        dict_t = dictSetUp()
        addPart1ToDict(parts[0], dict_t)
        addPart2ToDict(parts[1], dict_t)
        addPart3ToDict(parts[2], dict_t)
        packageDict(dict_t)
    if (len(parts[0]) <= 31 and len(parts[1]) <= 31 and len(parts[2]) <= 7):
        dict_t = dictSetUp()
        addPart2ToDict(parts[0], dict_t)
        addPart3ToDict(parts[1], dict_t)
        addPart4ToDict(parts[2], dict_t)
        packageDict(dict_t)

# If len(parts)==4
def fourparts(parts):
    if (len(parts[0]) <= 15 and len(parts[1]) <= 31 and len(parts[2]) <= 31 and len(parts[3]) <= 7):
        dict_t = dictSetUp()
        addPart1ToDict(parts[0], dict_t)
        addPart2ToDict(parts[1], dict_t)
        addPart3ToDict(parts[2], dict_t)
        addPart3ToDict(parts[3], dict_t)
        packageDict(dict_t)

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

globalID = 0
data = {}
data["target"] = "bmv2"
data["p4info"] = "build/calc2.p4.p4info.txt"
data["bmv2_json"] = "build/calc2.json"
data["table_entries"] = []

for d in domains:
    addDomainToTable(d)
    globalID = globalID + 1

addDomainToTable("princeton.edu")
addDomainToTable("com")
addDomainToTable("gov")
addDomainToTable("edu")
addDomainToTable("mil")
addDomainToTable("")

with open('s1-runtime.json', 'w') as outFile:
    json.dump(data, outFile)

