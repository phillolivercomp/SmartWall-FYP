import socket, sys
from struct import *
import subprocess as sub
import time
import re
import sqlite3 as sql
import os
import threading

#Defines refresh rate of the IP addresses to be monitored
refresh_rate = 5
interface_name = 'br-lan'

#establishes connection to a database creating it if it doesn't exist
conn = sql.connect('/tmp/connections.db')
cur = conn.cursor()

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
    print hour

def newList():
    file = open('/tmp/sqlCommands', 'w')
    file.close()

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
    #print List
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
    cur.execute("CREATE TABLE IF NOT EXISTS dataRate (monitorMAC, hour int, dataSize int, PRIMARY KEY(monitorMAC, hour))")
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

def tablePush (items):

    #Tries to update values in table
    cur.execute("UPDATE connectionHistory SET length = length + ? WHERE monitorMAC = ? AND toIP = ? AND port = ? AND connection = ?", (items[3], items[0], items[1], items[2], items[4]))
    cur.execute("INSERT OR IGNORE INTO connectionHistory VALUES (?,?,?,?,?)", (items[0], items[1], items[4], items[2], items[3]))

    if cur.rowcount > 0:
        t = dnsThread(items[1])
        t.start()

def pushHourTotals(hour):
    for item in macList:
        cur.execute("SELECT SUM(length) FROM connectionHistory WHERE monitorMAC = ?", (item,))
        size = cur.fetchone()[0]
        print size
        cur.execute("INSERT OR IGNORE INTO dataRate VALUES (?,?,?)", (item, hour, size))
        cur.execute("UPDATE dataRate SET dataSize = ? WHERE monitorMAC = ? and hour = ?", (size, item, hour))
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

#begin running the tcpdump subprocess piping output to stdout
proc = sub.Popen(('tcpdump', '-l', '-n', '-t', '-q', '-i', 'br-lan', '-e'), stdout=sub.PIPE)

with proc.stdout:
	
	#Level 1 loop
	#takes each time of stdout and reads it

    for line in iter(proc.stdout.readline, b''):
    	#if the time has surpassed old time + refreshrate, run methods
    	if getTime() - refresh_rate > clock:

    		#update monitored IPs and update clock
    		
    		macList = getMACs()
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
        	if mac in line and 'ARP' not in line and 'igmp' not in line and 'ICMP' not in line:
        		#uses regular expressions to capture IPs and IPs with port numbers from line

        		if mac in items[0]:
        			port = (items[8].split("."))[-1].strip(":")
        			tablePush([items[0], items[8][:-len(port) -2], port, items[5][:-1], 'out'])
        		else:
        			port = (items[6].split("."))[-1].strip(":")
        			tablePush([items[2][:-1], items[6][:-len(port) -1], port, items[5][:-1], 'in'])
proc.wait()