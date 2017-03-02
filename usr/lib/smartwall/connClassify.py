import socket, sys
from struct import *
import subprocess as sub
import time
import re
import sqlite3 as sql
import os
import json
import threading

#Defines refresh rate of the IP addresses to be monitored
refresh_rate = 5
interface_name = 'br-lan'

#establishes connection to a database creating it if it doesn't exist
conn = sql.connect('/tmp/connections.db')
cur = conn.cursor()

reportPath = "/usr/lib/smartwall/nmaps/portReport"
nMapTool = "/usr/lib/smartwall/nMapper.py"

global nmapData
nmapData = {}

def nmapGen():
    global nmapData
    if os.path.exists(reportPath):
        file = open(reportPath).read()
        nmapData = json.loads(file)

global mapLock
mapUnlock = True

def portNMap():
    if mapUnlock:

        global mapUnlock
        mapUnlock = False
        print "Running NMap"
        mapProc = sub.Popen(("python", nMapTool), stdout=sub.PIPE)

        onComplete = mapProc.communicate()[0]
        print onComplete
        nmapGen()
        mapProc = True


tableName = 'connectionHistory'
global macList
global dnsCommands
dnsCommands = []

def getTime():
    #Function that gets the system time in seconds
    return int(round(time.time()))
def setTime():
    global clock
    clock = getTime()

def getHour():
    return int(time.strftime("%H"))
def setHour():
    global hour
    hour = getHour()

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
        if "option mac" in line:
            value = line[13:(len(line)-2)]
            List.append(value)
    return List


def pushDns():
    global dnsCommands
    for item in dnsCommands:
        cur.execute(item)
    dnsCommands = []


def checkTables ():
    #Function to check if table exists to hold data
    cur.execute("CREATE TABLE IF NOT EXISTS connectionHistory (monitorMAC text, toIP text, connection text, port integer, length integer, PRIMARY KEY (monitorMAC, toIP, connection, port))")
    cur.execute("CREATE TABLE IF NOT EXISTS dnsLookups (toIP text PRIMARY KEY, hostname text)")
    cur.execute("CREATE TABLE IF NOT EXISTS dataRate (monitorMAC, hour int, dataSize int, dataIN int, dataOut int, PRIMARY KEY(monitorMAC, hour))")

def dataRateInit():
    for mac in macList:
        for num in range (0,24):
            cur.execute("INSERT OR IGNORE INTO dataRate VALUES (?,?,0,0,0)", (mac, num))

def enterDNS (ipAddr):

    #if ip address does not already exist in table do following
    nslookupProc = sub.Popen(('nslookup', ipAddr), stdout=sub.PIPE)
    results = nslookupProc.communicate()[0]
    #regular expression to pull hostname
    dnsRecord = re.findall( r'([^\s]+\.[a-z]+)', results)
    if dnsRecord != []:
        entry = dnsRecord[0]
        #print entry
        dnsCommands.append('INSERT OR IGNORE INTO dnsLookups VALUES ("'+ipAddr+'","'+entry+'")')
    else:
        dnsCommands.append('INSERT OR IGNORE INTO dnsLookups VALUES ("'+ipAddr+'","")')

class dnsThread (threading.Thread):
    def __init__(self, ipAddr):
        threading.Thread.__init__(self)
        self.ipAddr = ipAddr
    def run(self):
        enterDNS(self.ipAddr)

class mapThread (threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        portNMap()

def tablePush (items):
    #Tries to update values in table
    cur.execute("UPDATE connectionHistory SET length = length + ? WHERE monitorMAC = ? AND toIP = ? AND port = ? AND connection = ?", (items[3], items[0], items[1], items[2], items[4]))
    cur.execute("INSERT OR IGNORE INTO connectionHistory (length, monitorMAC, toIP, port, connection) VALUES (?,?,?,?,?)", (items[3], items[0], items[1], items[2], items[4]))

    if cur.rowcount > 0:
        t = dnsThread(items[1])
        t.start()

def pushHourTotals(hour):
    for item in macList:
        cur.execute("SELECT SUM(a.length), SUM(b.length) FROM connectionHistory a, connectionHistory b WHERE a.connection = 'Inbound' AND b.connection = 'Outbound' AND a.monitorMAC = b.monitorMAC AND a.toIP = b.toIP AND a.port = b.port AND a.monitorMAC = ? AND a.toIP NOT LIKE '192.168.%' AND a.toIP NOT LIKE '10.%' AND a.toIP NOT LIKE '172.[0-9].%' AND a.toIP NOT LIKE '172.[1-2][0-9].%' AND a.toIP NOT LIKE '172.3[1-2].%';", (item,))
        val = cur.fetchone()
        print val
        if val[0] != None and val[1] != None:
            size = val[0] + val[1]
        else:
            size = 0
        if size > 0:
        	cur.execute("UPDATE dataRate SET dataSize = ?, dataIN = ?, dataOut = ? WHERE monitorMAC = ? and hour = ?", (size, val[0], val[1], item, hour))
        else:
        	cur.execute("UPDATE dataRate SET dataSize = 0, dataIN = 0, dataOut = 0 WHERE monitorMAC = ? and hour = ?", (item, hour))

#first generate macs from config file using method

macList = getMACs()

#generate our IPs to monitor and call checkTables to ensure our SQL table exists
checkTables()

#begin running the tcpdump subprocess piping output to stdout

#capture start time of the process and save to clock variable
setTime()
setHour()
newList()
pushHourTotals(getHour())
dataRateInit()
nmapGen()

#begin running the tcpdump subprocess piping output to stdout
proc = sub.Popen(('tcpdump', '-l', '-n', '-t', '-q', '-i', 'br-lan', '-e', '-B', '65536', '-s', '128', 'tcp', 'or', 'udp'), stdout=sub.PIPE)

with proc.stdout:
	
	#Level 1 loop
	#takes each time of stdout and reads it

    for line in iter(proc.stdout.readline, b''):
    	#if the time has surpassed old time + refreshrate, run methods
    	if getTime() - refresh_rate > clock:

    		#update monitored IPs and update clock
    		
    		macList = getMACs()
                dataRateInit()
    		clock = getTime()
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
        	#checks if the ip is in the command line and ensures the tcpdump line is not an ARP transaction
        	if mac in line and mac in nmapData:
        		#uses regular expressions to capture IPs and IPs with port numbers from line
        		if mac in items[0]:
        			
                    		portOut = (items[6].split("."))[-1].strip(":")
                    		portIn = (items[8].split("."))[-1].strip(":")

				if (portOut + "/" + items[9][0:3].lower()) in nmapData[mac]:
					port = portOut
                     		else:
					port = portIn

        			tablePush([items[0], items[8][:items[8].rfind(".")], port, items[5][:-1], 'Outbound'])
        		else:

        			portOut = (items[6].split("."))[-1].strip(":")
                    		portIn = (items[8].split("."))[-1].strip(":")

				if (portIn + "/" + items[9][0:3].lower()) in nmapData[mac]:
					port = portIn
				else:
					port = portOut

        			tablePush([items[2][:-1], items[6][:items[6].rfind(".")], port, items[5][:-1], 'Inbound'])
        	elif mac not in nmapData:
            	    t = mapThread()
                    t.start()      
proc.wait()