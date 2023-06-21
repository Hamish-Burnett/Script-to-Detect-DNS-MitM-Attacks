# -*- coding: utf-8 -*-
"""
@author: Hamish Burnett
"""
# Import Scapy library, to handle the PCAP file.
from scapy.all import *

# Declare some variables used throughout the program.
newPCAP = []
checkedPackets = []
maliciousPackets = []


# Load the PCAP file, and make a new List of all packets, and each packet's packet number.
def readPCAPFile():
    print("Loading PCAP...")
    # Update the filename with the filepath of the PCAP you wish to analyse.
    pcapFile = rdpcap("FileToUse.pcap")
    
    # Create new pcap file in List format (newPCAP[]), with each packet containing the 
    # equivalent packet number presented in Wireshark. 
    packetWithID = []
    packetWithID.append(0)
    packetWithID.append(1)
    i = 0
    while i < len(pcapFile):
           
        # Make a List containing the individual packet number, and the corrosponding
        # packet data, and update the values for each packet.
        packetWithID[0] = i + 1
        packetWithID[1] = pcapFile[i]
                
        # Add each individual List containing packet number and packet data, to a new
        # List, which will contain all packets.
        newPCAP.append(list(packetWithID))
        i += 1

    print("\nPCAP Loaded Successfully\n")
    

# Check whether the Packet Passed into the Method has the Same DNS ID, as any other packets
# in the checkedPackets List. If the current DNS ID is found, add that packet to the maliciousPackets
# List.
def searchForID(j, currentPacket):
    i = 1
    while i < len(checkedPackets):
        if checkedPackets[i][1][DNS].id == currentPacket[1][DNS].id:
            while j < 1:
                maliciousPackets.append(checkedPackets[i])
                j += 1 
            maliciousPackets.append(currentPacket)
            
        i += 1
        

# A bug occured where duplicates of packets were added to maliciousPackets list. This deletes them.
def maliciousPacketsDuplicateIDs(index, number):
    index += 1
    while index < len(maliciousPackets):
        if number == maliciousPackets[index][0]:
            maliciousPackets.pop(index)
        index += 1
        
        
# Check if the maliciousPackets List contains entries, and if it does, print a summary of each
# malicious packet.
def printMaliciousPackets():
    if len(maliciousPackets) < 1:
        print("No DNS MitM Attack Found - No Duplicates of ID in DNS Responses.")
    else: 
        print("****ALERT****")
        print("DNS Attack Detected. See Following Packets:")
        print("\n\nMalicious Packets:")

        for i in range(len(maliciousPackets)):
            print("\n",maliciousPackets[i][0], ":", maliciousPackets[i][1])


# Searches for the DNS packets that are responses, and checks whether the current DNS ID
# is already in the checkedPackets List (which would indicate a DNS MitM Attack).
# Then add the current packet to the checkedPackets List.
def checkPackets():
    j = 0
    i = 1
    while i < len(newPCAP):
        if newPCAP[i][1].haslayer(DNS):
            if newPCAP[i][1][DNS].an != None:
                searchForID(j, newPCAP[i])
                checkedPackets.append(newPCAP[i])
        i += 1


# Cycle Through all Elements in maliciousPackets List, to determine if there are any
# duplicate entries, indicated by the same packet number.
def searchForDuplicates():
    i = 0
    while i < len(maliciousPackets):
        maliciousPacketsDuplicateIDs(i, maliciousPackets[i][0])
        i += 1
        
        
# Print Detailed Information about the Malicious Packets.
def printInfoAboutPackets():
    for i in range(len(maliciousPackets)):
        print(maliciousPackets[i][0],":", maliciousPackets[i][1])
        print("\nPacket Number: ", maliciousPackets[i][0])
        print("Packet Information:")
        print(maliciousPackets[i][1].show())
        print("\n\n\n")









quit = False
while quit == False:
    # Display the menu
    print("Please choose which option you would like:")
    print("1 - Load PCAP File")
    print("2 - Test PCAP File for DNS MitM Attack")
    print("3 - Print Summary of Malicious Packets")
    print("4 - Display More Information about each Malicious Packet")
    print("5 - Quit")

    
    try:
        userChoice = int(input())
        print("\n")
        
        if userChoice == 1:
            readPCAPFile()
            
        elif userChoice == 2: 
            checkPackets()
            searchForDuplicates()            
            printMaliciousPackets()
            print("\n\n")

        elif userChoice == 3:
            printMaliciousPackets()
            print("\n\n")

        elif userChoice == 4:
            printInfoAboutPackets()
            print("\n\n")
            
        elif userChoice == 5:
            print("Quiting. . .")
            quit = True
        
        else:
            print("Your option was invalid. Please make another choice.")
    except Exception:
        print("Please enter a number")