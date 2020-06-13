import json

globalID1 = 0
globalID2 = 0
globalID3 = 0
globalID4 = 0
globalID5 = 0
globalID = 0
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
            "headers.q1_17.char": [0, 255],
            "headers.q1_18.char": [0, 255],
            "headers.q1_19.char": [0, 255],
            "headers.q1_20.char": [0, 255],
            "headers.q1_21.char": [0, 255],
            "headers.q1_22.char": [0, 255],
            "headers.q1_23.char": [0, 255],
            "headers.q1_24.char": [0, 255],
            "headers.q1_25.char": [0, 255],
            "headers.q1_26.char": [0, 255],
            "headers.q1_27.char": [0, 255],
            "headers.q1_28.char": [0, 255],
            "headers.q1_29.char": [0, 255],
            "headers.q1_30.char": [0, 255],
            "headers.q1_31.char": [0, 255],
            "headers.q1_32.char": [0, 255]
        }
        return partsDict
    elif (partNum == 2):
        partsDict = {
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
            "headers.q2_17.char": [0, 255],
            "headers.q2_18.char": [0, 255],
            "headers.q2_19.char": [0, 255],
            "headers.q2_20.char": [0, 255],
            "headers.q2_21.char": [0, 255],
            "headers.q2_22.char": [0, 255],
            "headers.q2_23.char": [0, 255],
            "headers.q2_24.char": [0, 255],
            "headers.q2_25.char": [0, 255],
            "headers.q2_26.char": [0, 255],
            "headers.q2_27.char": [0, 255],
            "headers.q2_28.char": [0, 255],
            "headers.q2_29.char": [0, 255],
            "headers.q2_30.char": [0, 255],
            "headers.q2_31.char": [0, 255],
            "headers.q2_32.char": [0, 255]
        }
        return partsDict
    elif (partNum == 3):
        partsDict = {
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
            "headers.q3_17.char": [0, 255],
            "headers.q3_18.char": [0, 255],
            "headers.q3_19.char": [0, 255],
            "headers.q3_20.char": [0, 255],
            "headers.q3_21.char": [0, 255],
            "headers.q3_22.char": [0, 255],
            "headers.q3_23.char": [0, 255],
            "headers.q3_24.char": [0, 255],
            "headers.q3_25.char": [0, 255],
            "headers.q3_26.char": [0, 255],
            "headers.q3_27.char": [0, 255],
            "headers.q3_28.char": [0, 255],
            "headers.q3_29.char": [0, 255],
            "headers.q3_30.char": [0, 255],
            "headers.q3_31.char": [0, 255],
            "headers.q3_32.char": [0, 255]
        }
        return partsDict
    elif (partNum == 4):
        partsDict = {
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
            "headers.q4_15.char": [0, 255],
            "headers.q4_17.char": [0, 255],
            "headers.q4_18.char": [0, 255],
            "headers.q4_19.char": [0, 255],
            "headers.q4_20.char": [0, 255],
            "headers.q4_21.char": [0, 255],
            "headers.q4_22.char": [0, 255],
            "headers.q4_23.char": [0, 255],
            "headers.q4_24.char": [0, 255],
            "headers.q4_25.char": [0, 255],
            "headers.q4_26.char": [0, 255],
            "headers.q4_27.char": [0, 255],
            "headers.q4_28.char": [0, 255],
            "headers.q4_29.char": [0, 255],
            "headers.q4_30.char": [0, 255],
            "headers.q4_31.char": [0, 255],
            "headers.q4_32.char": [0, 255]
        }
        return partsDict
    elif (partNum == 5):
        partsDict = {
            "headers.q5_1.char": [0, 255],
            "headers.q5_2.char": [0, 255],
            "headers.q5_3.char": [0, 255],
            "headers.q5_4.char": [0, 255],
            "headers.q5_5.char": [0, 255],
            "headers.q5_6.char": [0, 255],
            "headers.q5_7.char": [0, 255],
            "headers.q5_8.char": [0, 255],
            "headers.q5_9.char": [0, 255],
            "headers.q5_10.char": [0, 255],
            "headers.q5_11.char": [0, 255],
            "headers.q5_12.char": [0, 255],
            "headers.q5_13.char": [0, 255],
            "headers.q5_14.char": [0, 255],
            "headers.q5_15.char": [0, 255],
            "headers.q5_17.char": [0, 255],
            "headers.q5_18.char": [0, 255],
            "headers.q5_19.char": [0, 255],
            "headers.q5_20.char": [0, 255],
            "headers.q5_21.char": [0, 255],
            "headers.q5_22.char": [0, 255],
            "headers.q5_23.char": [0, 255],
            "headers.q5_24.char": [0, 255],
            "headers.q5_25.char": [0, 255],
            "headers.q5_26.char": [0, 255],
            "headers.q5_27.char": [0, 255],
            "headers.q5_28.char": [0, 255],
            "headers.q5_29.char": [0, 255],
            "headers.q5_30.char": [0, 255],
            "headers.q5_31.char": [0, 255],
        }
        return partsDict
    return -1

def addPart1ToDict(part, partsDict):

    part_len = len(part)
    if (part_len > 32):
        print("Domain with part longer than 31 characters")
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
        elif (i == 16):
            partsDict["headers.q1_17.char"] = [part[i], 255]
        elif (i == 17):
            partsDict["headers.q1_18.char"] = [part[i], 255]
        elif (i == 18):
            partsDict["headers.q1_19.char"] = [part[i], 255]
        elif (i == 19):
            partsDict["headers.q1_20.char"] = [part[i], 255]
        elif (i == 20):
            partsDict["headers.q1_21.char"] = [part[i], 255]
        elif (i == 21):
            partsDict["headers.q1_22.char"] = [part[i], 255]
        elif (i == 22):
            partsDict["headers.q1_23.char"] = [part[i], 255]
        elif (i == 23):
            partsDict["headers.q1_24.char"] = [part[i], 255]
        elif (i == 24):
            partsDict["headers.q1_25.char"] = [part[i], 255]
        elif (i == 25):
            partsDict["headers.q1_26.char"] = [part[i], 255]
        elif (i == 26):
            partsDict["headers.q1_27.char"] = [part[i], 255]
        elif (i == 27):
            partsDict["headers.q1_28.char"] = [part[i], 255]
        elif (i == 28):
            partsDict["headers.q1_29.char"] = [part[i], 255]
        elif (i == 29):
            partsDict["headers.q1_30.char"] = [part[i], 255]
        elif (i == 30):
            partsDict["headers.q1_31.char"] = [part[i], 255]
        elif (i == 31):
            partsDict["headers.q1_32.char"] = [part[i], 255]

    return partsDict

def addPart2ToDict(part, partsDict):

    part_len = len(part)
    if (part_len > 32):
        print("Domain with part longer than 31 characters")
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
        elif (i == 16):
            partsDict["headers.q2_17.char"] = [part[i], 255]
        elif (i == 17):
            partsDict["headers.q2_18.char"] = [part[i], 255]
        elif (i == 18):
            partsDict["headers.q2_19.char"] = [part[i], 255]
        elif (i == 19):
            partsDict["headers.q2_20.char"] = [part[i], 255]
        elif (i == 20):
            partsDict["headers.q2_21.char"] = [part[i], 255]
        elif (i == 21):
            partsDict["headers.q2_22.char"] = [part[i], 255]
        elif (i == 22):
            partsDict["headers.q2_23.char"] = [part[i], 255]
        elif (i == 23):
            partsDict["headers.q2_24.char"] = [part[i], 255]
        elif (i == 24):
            partsDict["headers.q2_25.char"] = [part[i], 255]
        elif (i == 25):
            partsDict["headers.q2_26.char"] = [part[i], 255]
        elif (i == 26):
            partsDict["headers.q2_27.char"] = [part[i], 255]
        elif (i == 27):
            partsDict["headers.q2_28.char"] = [part[i], 255]
        elif (i == 28):
            partsDict["headers.q2_29.char"] = [part[i], 255]
        elif (i == 29):
            partsDict["headers.q2_30.char"] = [part[i], 255]
        elif (i == 30):
            partsDict["headers.q2_31.char"] = [part[i], 255]
        elif (i == 31):
            partsDict["headers.q2_32.char"] = [part[i], 255]

    return partsDict

def addPart3ToDict(part, partsDict):

    part_len = len(part)
    if (part_len > 32):
        print("Domain with part longer than 31 characters")
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
        elif (i == 16):
            partsDict["headers.q3_17.char"] = [part[i], 255]
        elif (i == 17):
            partsDict["headers.q3_18.char"] = [part[i], 255]
        elif (i == 18):
            partsDict["headers.q3_19.char"] = [part[i], 255]
        elif (i == 19):
            partsDict["headers.q3_20.char"] = [part[i], 255]
        elif (i == 20):
            partsDict["headers.q3_21.char"] = [part[i], 255]
        elif (i == 21):
            partsDict["headers.q3_22.char"] = [part[i], 255]
        elif (i == 22):
            partsDict["headers.q3_23.char"] = [part[i], 255]
        elif (i == 23):
            partsDict["headers.q3_24.char"] = [part[i], 255]
        elif (i == 24):
            partsDict["headers.q3_25.char"] = [part[i], 255]
        elif (i == 25):
            partsDict["headers.q3_26.char"] = [part[i], 255]
        elif (i == 26):
            partsDict["headers.q3_27.char"] = [part[i], 255]
        elif (i == 27):
            partsDict["headers.q3_28.char"] = [part[i], 255]
        elif (i == 28):
            partsDict["headers.q3_29.char"] = [part[i], 255]
        elif (i == 29):
            partsDict["headers.q3_30.char"] = [part[i], 255]
        elif (i == 30):
            partsDict["headers.q3_31.char"] = [part[i], 255]
        elif (i == 31):
            partsDict["headers.q3_32.char"] = [part[i], 255]

    return partsDict

def addPart4ToDict(part, partsDict):

    part_len = len(part)
    if (part_len > 32):
        print("Domain with part longer than 31 characters")
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
        elif (i == 15):
            partsDict["headers.q4_16.char"] = [part[i], 255]
        elif (i == 16):
            partsDict["headers.q4_17.char"] = [part[i], 255]
        elif (i == 17):
            partsDict["headers.q4_18.char"] = [part[i], 255]
        elif (i == 18):
            partsDict["headers.q4_19.char"] = [part[i], 255]
        elif (i == 19):
            partsDict["headers.q4_20.char"] = [part[i], 255]
        elif (i == 20):
            partsDict["headers.q4_21.char"] = [part[i], 255]
        elif (i == 21):
            partsDict["headers.q4_22.char"] = [part[i], 255]
        elif (i == 22):
            partsDict["headers.q4_23.char"] = [part[i], 255]
        elif (i == 23):
            partsDict["headers.q4_24.char"] = [part[i], 255]
        elif (i == 24):
            partsDict["headers.q4_25.char"] = [part[i], 255]
        elif (i == 25):
            partsDict["headers.q4_26.char"] = [part[i], 255]
        elif (i == 26):
            partsDict["headers.q4_27.char"] = [part[i], 255]
        elif (i == 27):
            partsDict["headers.q4_28.char"] = [part[i], 255]
        elif (i == 28):
            partsDict["headers.q4_29.char"] = [part[i], 255]
        elif (i == 29):
            partsDict["headers.q4_30.char"] = [part[i], 255]
        elif (i == 30):
            partsDict["headers.q4_31.char"] = [part[i], 255]
        elif (i == 31):
            partsDict["headers.q4_32.char"] = [part[i], 255]

    return partsDict

def addPart5ToDict(part, partsDict):

    part_len = len(part)
    if (part_len > 31):
        print("Domain with part longer than 31 characters")
        exit(-1)

    for i in range(part_len):
        if (i == 0):
            partsDict["headers.q5_1.char"] = [part[i], 255]
        elif (i == 1):
            partsDict["headers.q5_2.char"] = [part[i], 255]
        elif (i == 2):
            partsDict["headers.q5_3.char"] = [part[i], 255]
        elif (i == 3):
            partsDict["headers.q5_4.char"] = [part[i], 255]
        elif (i == 4):
            partsDict["headers.q5_5.char"] = [part[i], 255]
        elif (i == 5):
            partsDict["headers.q5_6.char"] = [part[i], 255]
        elif (i == 6):
            partsDict["headers.q5_7.char"] = [part[i], 255]
        elif (i == 7):
            partsDict["headers.q5_8.char"] = [part[i], 255]
        elif (i == 8):
            partsDict["headers.q5_9.char"] = [part[i], 255]
        elif (i == 9):
            partsDict["headers.q5_10.char"] = [part[i], 255]
        elif (i == 10):
            partsDict["headers.q5_11.char"] = [part[i], 255]
        elif (i == 11):
            partsDict["headers.q5_12.char"] = [part[i], 255]
        elif (i == 12):
            partsDict["headers.q5_13.char"] = [part[i], 255]
        elif (i == 13):
            partsDict["headers.q5_14.char"] = [part[i], 255]
        elif (i == 14):
            partsDict["headers.q5_15.char"] = [part[i], 255]
        elif (i == 15):
            partsDict["headers.q5_16.char"] = [part[i], 255]
        elif (i == 16):
            partsDict["headers.q5_17.char"] = [part[i], 255]
        elif (i == 17):
            partsDict["headers.q5_18.char"] = [part[i], 255]
        elif (i == 18):
            partsDict["headers.q5_19.char"] = [part[i], 255]
        elif (i == 19):
            partsDict["headers.q5_20.char"] = [part[i], 255]
        elif (i == 20):
            partsDict["headers.q5_21.char"] = [part[i], 255]
        elif (i == 21):
            partsDict["headers.q5_22.char"] = [part[i], 255]
        elif (i == 22):
            partsDict["headers.q5_23.char"] = [part[i], 255]
        elif (i == 23):
            partsDict["headers.q5_24.char"] = [part[i], 255]
        elif (i == 24):
            partsDict["headers.q5_25.char"] = [part[i], 255]
        elif (i == 25):
            partsDict["headers.q5_26.char"] = [part[i], 255]
        elif (i == 26):
            partsDict["headers.q5_27.char"] = [part[i], 255]
        elif (i == 27):
            partsDict["headers.q5_28.char"] = [part[i], 255]
        elif (i == 28):
            partsDict["headers.q5_29.char"] = [part[i], 255]
        elif (i == 29):
            partsDict["headers.q5_30.char"] = [part[i], 255]
        elif (i == 30):
            partsDict["headers.q5_31.char"] = [part[i], 255]
    return partsDict

part5Dict = {}
part4Dict = {}
part3Dict = {}
part2Dict = {}
part1Dict = {}

# If len(parts)==1
def oneparts(parts):
    if parts[0] in part1Dict:
        return part1Dict[parts[0]]
    global globalID1
    global priority1
    globalID1 = globalID1 + 1
    part1Dict[parts[0]] = globalID1

    if (parts[0] == '*' or parts[0] == '*.'):
        data["table_entries"].append({
            "table": "TopIngress.known_domain_list_q1",
            "match": {},
            "action_name": "TopIngress.match_q1",
            "priority": 1,
            "action_params": {"q1id": globalID1}
        })
        return globalID1

    dict_t = dictSetUp(1)
    addPart1ToDict(parts[0], dict_t)
    
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
    
    if parts[1] in part2Dict:
        return part2Dict[parts[1]]
    global globalID2
    global priority2
    globalID2 = globalID2 + 1
    part2Dict[parts[1]] = globalID2

    if (parts[1] == '*' or parts[1] == '*.'):
        data["table_entries"].append({
            "table": "TopIngress.known_domain_list_q2",
            "match": {},
            "action_name": "TopIngress.match_q2",
            "priority": 1,
            "action_params": {"q2id": globalID2}
        })
        return globalID2

    dict_t = dictSetUp(2)
    addPart2ToDict(parts[1], dict_t)

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
    
    if parts[2] in part3Dict:
        return part3Dict[parts[2]]
    global globalID3
    global priority3
    globalID3 = globalID3 + 1
    part3Dict[parts[2]] = globalID3

    if (parts[2] == '*' or parts[2] == '*.'):
        data["table_entries"].append({
            "table": "TopIngress.known_domain_list_q3",
            "match": {},
            "action_name": "TopIngress.match_q3",
            "priority": 1,
            "action_params": {"q3id": globalID3}
        })
        return globalID3

    dict_t = dictSetUp(3)
    addPart3ToDict(parts[2], dict_t)
    
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
    
    if parts[3] in part4Dict:
        return part4Dict[parts[3]]
    global globalID4
    global priority4
    globalID4 = globalID4 + 1
    part4Dict[parts[3]] = globalID4

    if (parts[3] == '*' or parts[3] == '*.'):
        data["table_entries"].append({
            "table": "TopIngress.known_domain_list_q4",
            "match": {},
            "action_name": "TopIngress.match_q4",
            "priority": 1,
            "action_params": {"q4id": globalID4}
        })
        return globalID4

    dict_t = dictSetUp(4)
    addPart4ToDict(parts[3], dict_t)
    
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
    
    if parts[4] in part5Dict:
        return part5Dict[parts[4]]
    global globalID5
    global priority5
    globalID5 = globalID5 + 1
    part5Dict[parts[4]] = globalID5

    if (parts[4] == '*' or parts[4] == '*.'):
        data["table_entries"].append({
            "table": "TopIngress.known_domain_list_q5",
            "match": {},
            "action_name": "TopIngress.match_q5",
            "priority": 1,
            "action_params": {"q5id": globalID5}
        })
        return globalID5

    dict_t = dictSetUp(5)
    addPart5ToDict(parts[4], dict_t)
    
    data["table_entries"].append({
        "table": "TopIngress.known_domain_list_q5",
        "match": dict_t,
        "action_name": "TopIngress.match_q5",
        "priority": priority5,
        "action_params": {"q5id": globalID5}
    })
    priority5 = priority5 - 1
    return globalID5

def creatDomainEntry(parts):
    id5 = fiveparts(parts)
    id4 = fourparts(parts)
    id3 = threeparts(parts)
    id2 = twoparts(parts)
    id1 = oneparts(parts)

    global globalID
    globalID = globalID + 1

    idDict = {
        "user_metadata.q1_id": id1,
        "user_metadata.q2_id": id2,
        "user_metadata.q3_id": id3,
        "user_metadata.q4_id": id4,
        "user_metadata.q5_id": id5
    }

    data["table_entries"].append({
            "table": "TopIngress.match_known_domain_list",
            "match": idDict,
            "action_name": "TopIngress.match_domain",
            "action_params": {"id": globalID}
    })


def addDomainToTable(domain):
    parts = domain.split('.')
    numParts = len(parts)
    if numParts > 5:
        print("error: " + domain)
        return -1
    if numParts == 1:
        parts.append('')
        parts.append('')
        parts.append('')
        parts.append('')
        creatDomainEntry(parts)
    elif numParts == 2:
        parts.append('')
        parts.append('')
        parts.append('')
        parts[0] = parts[0] + '.'
        creatDomainEntry(parts)
    elif numParts == 3:
        parts.append('')
        parts.append('')
        parts[0] = parts[0] + '.'
        parts[1] = parts[1] + '.'
        creatDomainEntry(parts)
    elif numParts == 4:
        parts.append('')
        parts[0] = parts[0] + '.'
        parts[1] = parts[1] + '.'
        parts[2] = parts[2] + '.'
        creatDomainEntry(parts)
    elif numParts == 5:
        parts[0] = parts[0] + '.'
        parts[1] = parts[1] + '.'
        parts[2] = parts[2] + '.'
        parts[3] = parts[3] + '.'
        creatDomainEntry(parts)
    
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

with open('s1-runtime.json', 'w') as outFile:
    json.dump(data, outFile, indent='\t')

