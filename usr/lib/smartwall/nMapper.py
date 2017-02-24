import socket, sys
import subprocess as sub
import os
import re
import json
import time

global macList
global ipList

fileDir = "/usr/lib/smartwall/nmaps/"
reportPath = "/usr/lib/smartwall/nmaps/portReport"
nmapData = {}

if os.path.exists(reportPath):
	file = open(reportPath).read()
	nmapData = json.loads(file)

print nmapData

def getMACs ():
    #Function that gets the IP addresses from the configuration file

    #First accesses config file for monitored IPsf
    ipConfigFile = open('/etc/config/cbi_file', 'r')

    #Scans through file looking for DeviceIP objects and trims the string accordingly to get the IP address
    List = []
    for line in ipConfigFile:
        if "option mac" in line:
            value = line[13:(len(line)-2)]
            if value not in nmapData:
            	List.append(value)
    return List


def getIPs (macList):
    #gets IP addresses to be monitored from mac addresses
    global ipList
    ipList = []
    #runs commands on command line to get fresh arp lookup to tell us IPs vs MAC addresses
    os.system("rm /tmp/arplookup")
    os.system("cat /proc/net/arp >> /tmp/arplookup")
    #opens file we just made
    arpFile = open('/tmp/arplookup', 'r')
    for item in macList:
        ipList.append('999.999.999.999')
    #reads file line by line to check if MACs exist in it and if so will fetch matching IP
    for line in arpFile:
        for item in macList:
            if item in line:
                deviceIP = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)[0]
                index = macList.index(item)
                ipList[index] = deviceIP

macList = getMACs()
getIPs(macList)
print ipList

for ip in ipList:
	mapProc = sub.Popen(("nmap", ip, "-T5", "-F"), stdout=sub.PIPE)
	data = mapProc.communicate()[0].splitlines()
	startFound = False
	openPortList = []
	mac = ""

	for line in data:
		if "MAC Address:" in line:
			mac = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', line, re.I).group()
			mac = mac.lower()
			startFound = False
		elif startFound:
			openPortList.append(line.split(" ")[0])

		if "PORT" in line:
			startFound = True
	if mac != "":
		nmapData[mac] = openPortList

with open(reportPath, 'w') as outfile:
	json.dump(nmapData, outfile)

print "Complete"