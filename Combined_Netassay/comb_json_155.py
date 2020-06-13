import json

globalID1T = 0
globalID2T = 0
globalID3T = 0
globalID4T = 0
globalID5T = 0
globalIDT = 0
priority1T = 0
priority2T = 0
priority3T = 0
priority4T = 0
priority5T = 0

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

def dictSetUpT(partNum):
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

def addPart1ToDictT(part, partsDict):

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

def addPart2ToDictT(part, partsDict):

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

def addPart3ToDictT(part, partsDict):

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

def addPart4ToDictT(part, partsDict):

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

def addPart5ToDictT(part, partsDict):

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

part5DictT = {}
part4DictT = {}
part3DictT = {}
part2DictT = {}
part1DictT = {}

# If len(parts)==1
def onepartsT(parts):
    if parts[0] in part1DictT:
        return part1DictT[parts[0]]
    if (parts[0] == '*' and '*.' in part1DictT):
        return part1DictT['*.']
    if (parts[0] == '*.' and '*' in part1DictT):
        return part1DictT['*']

    global globalID1T
    global priority1T
    globalID1T = globalID1T + 1
    part1DictT[parts[0]] = globalID1T

    if (parts[0] == '*' or parts[0] == '*.'):
        data["table_entries"].append({
            "table": "TopIngress.tlsknown_domain_list_q1",
            "match": {},
            "action_name": "TopIngress.match_q1",
            "priority": 1,
            "action_params": {"q1id": globalID1T}
        })
        return globalID1T

    dict_t = dictSetUpT(1)
    addPart1ToDictT(parts[0], dict_t)
    
    data["table_entries"].append({
        "table": "TopIngress.tlsknown_domain_list_q1",
        "match": dict_t,
        "action_name": "TopIngress.match_q1",
        "priority": priority1T,
        "action_params": {"q1id": globalID1T}
    })
    priority1T = priority1T - 1

    return globalID1T

# If len(parts)==2
def twopartsT(parts):
    
    if parts[1] in part2DictT:
        return part2DictT[parts[1]]
    if (parts[1] == '*' and '*.' in part2DictT):
        return part2DictT['*.']
    if (parts[1] == '*.' and '*' in part2DictT):
        return part2DictT['*']

    global globalID2T
    global priority2T
    globalID2T = globalID2T + 1
    part2DictT[parts[1]] = globalID2T

    if (parts[1] == '*' or parts[1] == '*.'):
        data["table_entries"].append({
            "table": "TopIngress.tlsknown_domain_list_q2",
            "match": {},
            "action_name": "TopIngress.match_q2",
            "priority": 1,
            "action_params": {"q2id": globalID2T}
        })
        return globalID2T

    dict_t = dictSetUpT(2)
    addPart2ToDictT(parts[1], dict_t)

    data["table_entries"].append({
        "table": "TopIngress.tlsknown_domain_list_q2",
        "match": dict_t,
        "action_name": "TopIngress.match_q2",
        "priority": priority2T,
        "action_params": {"q2id": globalID2T}
    })
    priority2T = priority2T - 1
    return globalID2T

# If len(parts)==3
def threepartsT(parts):
    
    if parts[2] in part3DictT:
        return part3DictT[parts[2]]
    if (parts[2] == '*' and '*.' in part3DictT):
        return part3DictT['*.']
    if (parts[2] == '*.' and '*' in part3DictT):
        return part3DictT['*']

    global globalID3T
    global priority3T
    globalID3T = globalID3T + 1
    part3DictT[parts[2]] = globalID3T

    if (parts[2] == '*' or parts[2] == '*.'):
        data["table_entries"].append({
            "table": "TopIngress.tlsknown_domain_list_q3",
            "match": {},
            "action_name": "TopIngress.match_q3",
            "priority": 1,
            "action_params": {"q3id": globalID3T}
        })
        return globalID3T

    dict_t = dictSetUpT(3)
    addPart3ToDictT(parts[2], dict_t)
    
    data["table_entries"].append({
        "table": "TopIngress.tlsknown_domain_list_q3",
        "match": dict_t,
        "action_name": "TopIngress.match_q3",
        "priority": priority3T,
        "action_params": {"q3id": globalID3T}
    })
    priority3T = priority3T - 1
    return globalID3T

# If len(parts)==4
def fourpartsT(parts):
    
    if parts[3] in part4DictT:
        return part4DictT[parts[3]]
    if (parts[3] == '*' and '*.' in part4DictT):
        return part4DictT['*.']
    if (parts[3] == '*.' and '*' in part4DictT):
        return part4DictT['*']

    global globalID4T
    global priority4T
    globalID4T = globalID4T + 1
    part4DictT[parts[3]] = globalID4T

    if (parts[3] == '*' or parts[3] == '*.'):
        data["table_entries"].append({
            "table": "TopIngress.tlsknown_domain_list_q4",
            "match": {},
            "action_name": "TopIngress.match_q4",
            "priority": 1,
            "action_params": {"q4id": globalID4T}
        })
        return globalID4T

    dict_t = dictSetUpT(4)
    addPart4ToDictT(parts[3], dict_t)
    
    data["table_entries"].append({
        "table": "TopIngress.tlsknown_domain_list_q4",
        "match": dict_t,
        "action_name": "TopIngress.match_q4",
        "priority": priority4T,
        "action_params": {"q4id": globalID4T}
    })
    priority4T = priority4T - 1
    return globalID4T

# If len(parts)==5
def fivepartsT(parts):
    
    if parts[4] in part5DictT:
        return part5DictT[parts[4]]
    if (parts[4] == '*' and '*.' in part5DictT):
        return part5DictT['*.']
    if (parts[4] == '*.' and '*' in part5DictT):
        return part5DictT['*']

    global globalID5T
    global priority5T
    globalID5T = globalID5T + 1
    part5DictT[parts[4]] = globalID5T

    if (parts[4] == '*' or parts[4] == '*.'):
        data["table_entries"].append({
            "table": "TopIngress.tlsknown_domain_list_q5",
            "match": {},
            "action_name": "TopIngress.match_q5",
            "priority": 1,
            "action_params": {"q5id": globalID5T}
        })
        return globalID5T

    dict_t = dictSetUpT(5)
    addPart5ToDictT(parts[4], dict_t)
    
    data["table_entries"].append({
        "table": "TopIngress.tlsknown_domain_list_q5",
        "match": dict_t,
        "action_name": "TopIngress.match_q5",
        "priority": priority5T,
        "action_params": {"q5id": globalID5T}
    })
    priority5T = priority5T - 1
    return globalID5T

def creatDomainEntryT(parts):
    id5 = fivepartsT(parts)
    id4 = fourpartsT(parts)
    id3 = threepartsT(parts)
    id2 = twopartsT(parts)
    id1 = onepartsT(parts)

    global globalIDT
    globalIDT = globalIDT + 1

    idDict = {
        "user_metadata.q1_id": id1,
        "user_metadata.q2_id": id2,
        "user_metadata.q3_id": id3,
        "user_metadata.q4_id": id4,
        "user_metadata.q5_id": id5
    }

    data["table_entries"].append({
            "table": "TopIngress.tlsmatch_known_domain_list",
            "match": idDict,
            "action_name": "TopIngress.match_domain",
            "action_params": {"id": globalID}
    })

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

def addPart2ToDict(part, partsDict):
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

def addPart3ToDict(part, partsDict):
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

def addPart4ToDict(part, partsDict):
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

def addPart5ToDict(part, partsDict):
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
        return part1Dict[parts[0]]
    global globalID1
    global priority1
    globalID1 = globalID1 + 1
    part1Dict[parts[0]] = globalID1

    dict_t = dictSetUp(1)
    addPart1ToDict(parts[0], dict_t)

    if (parts[0] == '*'):
        data["table_entries"].append({
            "table": "TopIngress.dnsknown_domain_list_q1",
            "match": dict_t,
            "action_name": "TopIngress.match_q1",
            "priority": 1,
            "action_params": {"q1id": globalID1}
        })
        return globalID1
    
    data["table_entries"].append({
        "table": "TopIngress.dnsknown_domain_list_q1",
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

    dict_t = dictSetUp(2)
    addPart2ToDict(parts[1], dict_t)

    if (parts[1] == '*'):
        data["table_entries"].append({
            "table": "TopIngress.dnsknown_domain_list_q2",
            "match": dict_t,
            "action_name": "TopIngress.match_q2",
            "priority": 1,
            "action_params": {"q2id": globalID2}
        })
        return globalID2
    
    data["table_entries"].append({
        "table": "TopIngress.dnsknown_domain_list_q2",
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

    dict_t = dictSetUp(3)
    addPart3ToDict(parts[2], dict_t)

    if (parts[2] == '*'):
        data["table_entries"].append({
            "table": "TopIngress.dnsknown_domain_list_q3",
            "match": dict_t,
            "action_name": "TopIngress.match_q3",
            "priority": 1,
            "action_params": {"q3id": globalID3}
        })
        return globalID3
    
    data["table_entries"].append({
        "table": "TopIngress.dnsknown_domain_list_q3",
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

    dict_t = dictSetUp(4)
    addPart4ToDict(parts[3], dict_t)

    if (parts[3] == '*'):
        data["table_entries"].append({
            "table": "TopIngress.dnsknown_domain_list_q4",
            "match": dict_t,
            "action_name": "TopIngress.match_q4",
            "priority": 1,
            "action_params": {"q4id": globalID4}
        })
        return globalID4
    
    data["table_entries"].append({
        "table": "TopIngress.dnsknown_domain_list_q4",
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

    dict_t = dictSetUp(5)
    addPart5ToDict(parts[4], dict_t)

    if (parts[4] == '*'):
        data["table_entries"].append({
            "table": "TopIngress.dnsknown_domain_list_q5",
            "match": dict_t,
            "action_name": "TopIngress.match_q5",
            "priority": 1,
            "action_params": {"q5id": globalID5}
        })
        return globalID5
    
    data["table_entries"].append({
        "table": "TopIngress.dnsknown_domain_list_q5",
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
            "table": "TopIngress.dnsmatch_known_domain_list",
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
        creatDomainEntryT(parts)
    elif numParts == 2:
        parts.append('')
        parts.append('')
        parts.append('')
        creatDomainEntry(parts)
        parts[0] = parts[0] + '.'
        creatDomainEntryT(parts)
    elif numParts == 3:
        parts.append('')
        parts.append('')
        creatDomainEntry(parts)
        parts[0] = parts[0] + '.'
        parts[1] = parts[1] + '.'
        creatDomainEntryT(parts)
    elif numParts == 4:
        parts.append('')
        creatDomainEntry(parts)
        parts[0] = parts[0] + '.'
        parts[1] = parts[1] + '.'
        parts[2] = parts[2] + '.'
        creatDomainEntryT(parts)
    elif numParts == 5:
        creatDomainEntry(parts)
        parts[0] = parts[0] + '.'
        parts[1] = parts[1] + '.'
        parts[2] = parts[2] + '.'
        parts[3] = parts[3] + '.'
        creatDomainEntryT(parts)

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
        "action_name": "TopIngress.match_banned_dns_dst",
        "action_params": {}
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
        "action_name": "NoAction",
        "action_params": {}
    })
    
knownlist = open('known_domains.txt', 'r')
domains = knownlist.read().split()
knownlist.close()

priority1T = len(domains) + 1
priority2T = len(domains) + 1
priority3T = len(domains) + 1
priority4T = len(domains) + 1
priority5T = len(domains) + 1

for d in domains:
    addDomainToTable(d)

bannedlist = open('banned_dns_dst.txt', 'r')
bannedip = bannedlist.read().split()
bannedlist.close()

data["table_entries"].append({
        "table": "TopIngress.banned_dns_dst",
        "default_action": True,
        "action_name": "NoAction",
        "action_params": {}
})

for ip in bannedip:
    addBannedIpToTable(ip)

allowedlist = open('allowed_dns_dst.txt', 'r')
allowedip = allowedlist.read().split()
allowedlist.close()

data["table_entries"].append({
        "table": "TopIngress.allowable_dns_dst",
        "default_action": True,
        "action_name": "TopIngress.match_banned_dns_dst",
        "action_params": {}
})

for ip in allowedip:
    addAllowedIpToTable(ip)

with open('s1-runtime.json', 'w') as outFile:
    json.dump(data, outFile, indent='\t')

