import socket, sys
from struct import *
import subprocess as sub
import time
import re
import sqlite3 as sql
import os
import json
import threading

#Defines refresh rate
refresh_rate = 5
#Define interface to monitor traffic on
interface_name = 'br-lan'

#establishes connection to a database creating it if it doesn't exist
conn = sql.connect('/tmp/connections.db')
#Create cursor to interface with DB
cur = conn.cursor()

#Set path to nmap report file
reportPath = "/usr/lib/smartwall/nmaps/portReport"
#Set path to tool to call nMap program
nMapTool = "/usr/lib/smartwall/nMapper.py"

#Initiate global variables
#nmapData holds open ports on a device
global nmapData
nmapData = {}
#holds ip addresses mac address is allowed to talk to in case it is limited by IP tables
global allowedMacIPs
allowedMacIPs = {}
#Tells us if nmap is locked in usage or not
global mapLock
mapUnlock = True


#Function to get nmap Data
def nmapGen():
	#access global variable for nmapdata
    global nmapData
    #if we can access the reportPath
    if os.path.exists(reportPath):
    	#Open the reportPath and read contents
        file = open(reportPath).read()
        #decode contents as using json api
        nmapData = json.loads(file)

#runs port mapping using nmap
def portNMap():
	#if unlocked
    if mapUnlock:
    	#set global unlock to false
        global mapUnlock
        mapUnlock = False
        #call python function to with nmapping tool
        mapProc = sub.Popen(("python", nMapTool), stdout=sub.PIPE)
        #Wait until function completes
        onComplete = mapProc.communicate()[0]
        #Get results using nmapGen function
        nmapGen()
        #set unlocked again
        mapProc = True

#set table name in DB
tableName = 'connectionHistory'
#Define maclist and dnscommands and initiate dnscommands to null
global macList
global dnsCommands
dnsCommands = []

#Function that gets the system time in seconds
def getTime():
    return int(round(time.time()))
#Function to set a global clock variable to current time in seconds
def setTime():
    global clock
    clock = getTime()

#Gets current hour
def getHour():
    return int(time.strftime("%H"))
#Sets current hour to global hour variable
def setHour():
    global hour
    hour = getHour()

#Destroys file at given location
def newList():
    file = open('/tmp/sqlCommands', 'w')
    file.close()

def getMACs ():
    #Function that gets the IP addresses from the configuration file

    #First accesses config file for monitored IPsf
    ipConfigFile = open('/etc/config/cbi_file', 'r')

    #Scans through file looking for DeviceIP objects and trims the string accordingly to get the IP address
    List = []
    for line in ipConfigFile:
    	#If option mac is in the line trim it to get the mac and add to list
        if "option mac" in line:
            value = line[13:(len(line)-2)]
            List.append(value)
    #Deletes entries from SQL table in case of removed values
    clearHistory(List)
    #
    getMACIPs(List)
    return List

#Gets IP Addresses a mac address is allowed to talk to if its limited by iptables
def getMACIPs(macs):
	#access global variable
    global allowedMacIPs
    #loop over macs we are logging
    for mac in macs:
    	#gets all IP addresses from chain that matches name of the mac address and saves to lines
        command = "iptables -L " + mac + " -n | grep -E -o \"([0-9]{1,3}[\.]){3}[0-9]{1,3}\w\""
        iptableproc = sub.Popen((command), stdout=sub.PIPE, shell=True)
        results = iptableproc.communicate()[0]
        lines = results.split("\n")
        #if no results, set empty list
        if lines[0] == '':
            allowedMacIPs[mac] = []
        #else, return lines
        else:
            allowedMacIPs[mac] = lines
        
#Deletes results from database of devices we are no longer  monitoring
def clearHistory(macs):
	#Gets all distinct macs and fetches data
    cur.execute("SELECT DISTINCT monitorMAC FROM connectionHistory")
    results = cur.fetchall()
    #loop over results
    for res in results:
    	#if a mac does no longer exist
        if res[0] not in macs:
        	#Delete results from both databases
            cur.execute("DELETE FROM connectionHistory WHERE monitorMAC = ?", (res[0],))
            cur.execute("DELETE FROM dataRate WHERE monitorMac = ?", (res[0],))

#Executes SQL statements in the dns commands queue
def pushDns():
    global dnsCommands
    for item in dnsCommands:
        cur.execute(item)
    dnsCommands = []

#Function to check if table exists to hold data and if not creates them
def checkTables ():
    cur.execute("CREATE TABLE IF NOT EXISTS connectionHistory (monitorMAC text, toIP text, connection text, port integer, length integer, PRIMARY KEY (monitorMAC, toIP, connection, port))")
    cur.execute("CREATE TABLE IF NOT EXISTS dnsLookups (toIP text PRIMARY KEY, hostname text)")
    cur.execute("CREATE TABLE IF NOT EXISTS dataRate (monitorMAC text, hour int, dataSize int, dataIN int, dataOut int, PRIMARY KEY(monitorMAC, hour))")

#Initiatises values in tables where appropriate
def dataRateInit():
	#For every mac in  maclist,
    for mac in macList:
    	#insert or ignore into every value from 0-23 blank values
        for num in range (0,24):
            cur.execute("INSERT OR IGNORE INTO dataRate VALUES (?,?,0,0,0)", (mac, num))

#Function that gets DNS record of an ip address
def enterDNS (ipAddr):
    #if ip address does not already exist in table do following
    nslookupProc = sub.Popen(('nslookup', ipAddr), stdout=sub.PIPE)
    results = nslookupProc.communicate()[0]
    #regular expression to pull hostname
    dnsRecord = re.findall( r'([^\s]+\.[a-z]+)', results)
    #if hostname exists, update it to table
    if dnsRecord != []:
        entry = dnsRecord[0]
        dnsCommands.append('INSERT OR IGNORE INTO dnsLookups VALUES ("'+ipAddr+'","'+entry+'")')
    #else insert blank entry
    else:
        dnsCommands.append('INSERT OR IGNORE INTO dnsLookups VALUES ("'+ipAddr+'","")')

#Class for dns entry used with threads
class dnsThread (threading.Thread):
    def __init__(self, ipAddr):
        threading.Thread.__init__(self)
        self.ipAddr = ipAddr
    def run(self):
        enterDNS(self.ipAddr)

#class for nmap entry updates with threads
class mapThread (threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        portNMap()

#Pushes results of connection to SQL database
def tablePush (items):
	#get ip addresses allowed for each mac address
    global allowedMacIPs
    #if the mac address (item[0]) is in the list then continue
    if items[0] in allowedMacIPs:
    	#if the ip is in the object value for that mac address of its object value is empty continue
        if items[1] in allowedMacIPs[items[0]] or allowedMacIPs[items[0]] == []:
            #Tries to update values in table
            cur.execute("UPDATE connectionHistory SET length = length + ? WHERE monitorMAC = ? AND toIP = ? AND port = ? AND connection = ?", (items[3], items[0], items[1], items[2], items[4]))
            cur.execute("INSERT OR IGNORE INTO connectionHistory (length, monitorMAC, toIP, port, connection) VALUES (?,?,?,?,?)", (items[3], items[0], items[1], items[2], items[4]))
            #if we inserted a new value into the database, we need a new dns entry to associate with it
            #hence, run a thread to get the DNS value of the ip address
            if cur.rowcount > 0:
                t = dnsThread(items[1])
                t.start()

#Takes total connectionn flow for each hour and  updates  in an sql table
def pushHourTotals(hour):
	#for each mac in the maclist
    for item in macList:
    	#get the total inbound and outbound connections for external ip addresses
        cur.execute("SELECT SUM(a.length), SUM(b.length) FROM connectionHistory a, connectionHistory b WHERE a.connection = 'Inbound' AND b.connection = 'Outbound' AND a.monitorMAC = b.monitorMAC AND a.toIP = b.toIP AND a.port = b.port AND a.monitorMAC = ? AND a.toIP NOT LIKE '192.168.%' AND a.toIP NOT LIKE '10.%' AND a.toIP NOT LIKE '172.[0-9].%' AND a.toIP NOT LIKE '172.[1-2][0-9].%' AND a.toIP NOT LIKE '172.3[1-2].%';", (item,))
        #save value
        val = cur.fetchone()
        #if values are not none then size is their combined sum
        if val[0] != None and val[1] != None:
            size = val[0] + val[1]
        #else their size is 0
        else:
            size = 0
        #if size is greater than 0 then set values respectively
        if size > 0:
        	cur.execute("UPDATE dataRate SET dataSize = ?, dataIN = ?, dataOut = ? WHERE monitorMAC = ? and hour = ?", (size, val[0], val[1], item, hour))
        #else update database with blank values
        else:
        	cur.execute("UPDATE dataRate SET dataSize = 0, dataIN = 0, dataOut = 0 WHERE monitorMAC = ? and hour = ?", (item, hour))

#generate our IPs to monitor and call checkTables to ensure our SQL table exists
checkTables()

#first generate macs from config file using method
macList = getMACs()

#begin running the tcpdump subprocess piping output to stdout

#capture start time of the process and save to clock variable
setTime()
setHour()
newList()
pushHourTotals(getHour())
dataRateInit()
nmapGen()

#begin running the tcpdump subprocess piping output to stdout
proc = sub.Popen(('tcpdump', '-l', '-nn', '-t', '-q', '-i', 'br-lan', '-e', '-B', '65536', '-s', '128', 'tcp', 'or', 'udp'), stdout=sub.PIPE)

with proc.stdout:
	#Level 1 loop
	#takes each time of stdout and reads it

    for line in iter(proc.stdout.readline, b''):
    	#if the time has surpassed old time + refreshrate, run methods
    	if getTime() - refresh_rate > clock:

    		#update monitored IPs, initialise datarate table and update clock
    		macList = getMACs()
                dataRateInit()
    		clock = getTime()
    		#read and execute line in the  sqlcommands file
            	with open('/tmp/sqlCommands', 'r') as f:
                	lines = f.readlines()
                        for line in lines:
                            cur.execute(line)
                        newList()

    		#commit changes to database
                pushDns()
    		conn.commit()
                curHour = getHour()
		global hour
                if curHour != hour:
                    pushHourTotals(curHour)
                    setHour()


    	#level 2 loop
    	#for each ip in our iplist
    	items = line.split(" ")

        
        for mac in macList:
        	#checks if the mac is in the command line
        	if mac in line and mac in nmapData:
        		#if mac address of  is first item in line
        		if mac in items[0]:
        			#if the ip addresses has 3 .'s then call push table to capture portless UDP packets
        			if items[6].count(".") == 3 or items[8].count(".") == 3:
					tablePush([items[0], items[8][:-1], 0, items[5][:-1], 'Outbound'])
				#else 
				else: 
                    			portOut = (items[6].split("."))[-1].strip(":")
                    			portIn = (items[8].split("."))[-1].strip(":")

					if (portOut + "/" + items[9][0:3].lower()) in nmapData[mac]:
						port = portOut
                     			else:
						port = portIn
						if items[8][:items[8].rfind(".")].count(".") != 3 and "IPv6" not in line:
							f = open("/text", "a")
							f.write(line)
							f.close()
        				tablePush([items[0], items[8][:items[8].rfind(".")], port, items[5][:-1], 'Outbound'])
        		else:
        			portOut = (items[6].split("."))[-1].strip(":")
                    		portIn = (items[8].split("."))[-1].strip(":")

				if (portIn + "/" + items[9][0:3].lower()) in nmapData[mac]:
					port = portIn
				else:
					port = portOut

					if items[6][:items[6].rfind(".")].count(".") != 3 and "IPv6" not in line:
						f = open("/text", "a")
						f.write(line)
						f.close()
        			tablePush([items[2][:-1], items[6][:items[6].rfind(".")], port, items[5][:-1], 'Inbound'])
        	elif mac not in nmapData:
            	    t = mapThread()
                    t.start()      
proc.wait()