import subprocess as sub
import time
import re
import sqlite3 as sql
import os

#Defines refresh rate of the IP addresses to be monitored
refresh_rate = 30
interface_name = 'br-lan'

#establishes connection to a database creating it if it doesn't exist
conn = sql.connect('/usr/lib/smartwall/tempHistory.db')
cur = conn.cursor()
tableName = 'connectionHistory'


def getTime():
	#Function that gets the system time in seconds
	return int(round(time.time()))


def getMACs ():
	#Function that gets the IP addresses from the configuration file

	#First accesses config file for monitored IPsf
	ipConfigFile = open('/etc/config/cbi_file', 'r')

	#Scans through file looking for DeviceIP objects and trims the string accordinglu to get the IP address
	List = []
	for line in ipConfigFile:
		if "option mac" in line:
			value = line[13:(len(line)-2)]
			List.append(value)
	print List
	return List


def checkTables ():
		#Function to check if table exists to hold data
		cur.execute("CREATE TABLE IF NOT EXISTS connectionHistory (monitorMAC text, toIP text, connection text, lastConnection real, port real, length real)")
		#print 'Created master table'


def tablePush (list, ip, macList, portNumber):
	#Checks list is in correct order

	#create variable to capture whether connection is going in or out
	connectionType = 'out'

	if list[0] != ip:
		#if monitored ip is second in list, reverse list and change connection type to in
		list.reverse()
		connectionType = 'in'

	index = ipList.index(list[0])
	macAddress = macList[index]

	#print macAddress

	#Tries to update values in table
	cur.execute("UPDATE connectionHistory SET lastConnection = ?, length = length + 1 WHERE monitorMAC = ? AND toIP = ? AND port = ? AND connection = ?", (getTime(), macAddress, list[1], portNumber, connectionType))
	if cur.rowcount == 0:
		cur.execute("INSERT INTO connectionHistory VALUES (?,?,?,?,?,?)", (macAddress, list[1], connectionType, getTime(), portNumber, 1))
		#print 'added value'

def getIPs (macList):
	#gets IP addresses to be monitored from mac addresses
	generatedList = []
	#runs commands on command line to get fresh arp lookup to tell us IPs vs MAC addresses
	os.system("rm /tmp/arplookup")
	os.system("cat /proc/net/arp >> /tmp/arplookup")

	#opens file we just made
	arpFile = open('/tmp/arplookup', 'r')

	for item in macList:
		generatedList.append('999.999.999.999')

	#reads file line by line to check if MACs exist in it and if so will fetch matching IP
	for line in arpFile:
		for item in macList:
			if item in line:
				deviceIP = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)[0]
				index = macList.index(item)
				generatedList[index] = deviceIP

	print generatedList
	return generatedList

#first generate macs from config file using method
macList = getMACs()

#generate our IPs to monitor and call checkTables to ensure our SQL table exists
ipList = getIPs(macList)
checkTables()

#begin running the tcpdump subprocess piping output to stdout
proc = sub.Popen(('tcpdump', '-l', '-n', '-t', '-q', '-i', interface_name), stdout=sub.PIPE)

#capture start time of the process and save to clock variable
clock = getTime()

with proc.stdout:
	#Level 1 loop
	#takes each time of stdout and reads it
    for line in iter(proc.stdout.readline, b''):

    	#if the time has surpassed old time + refreshrate, run methods
    	if getTime() - refresh_rate > clock:

    		#update monitored IPs and update clock
    		ipList = getIPs(getMACs())
    		clock = getTime()
    		#print 'updatedIPs'
    		#commit changes to database
    		conn.commit()

    	#level 2 loop
    	#for each ip in our iplist
        for ip in ipList:
        	#checks if the ip is in the command line and ensures the tcpdump line is not an ARP transaction
        	if ip in line and "ARP" not in line:

        		#uses regular expressions to capture IPs and IPs with port numbers from line
        		fromToIPs = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line)
        		IPwithPorts = re.findall( r'[0-9]+(?:\.[0-9]+){4}', line)

        		#print line

        		#extracts port from connection grabbing ip on the side of the connection which does not match monitored IP
        		port = ''

        		if len(IPwithPorts) > 0 and IPwithPorts[0] in ipList:
        			port = ''.join(IPwithPorts[1].split('.')[-1:])
        		elif len(IPwithPorts) > 0:
        			port = ''.join(IPwithPorts[0].split('.')[-1:])

        		#push values to table
        		if port is not '' and len(fromToIPs) == 2:
        			tablePush(fromToIPs, ip, macList, int(port))
        		
proc.wait()