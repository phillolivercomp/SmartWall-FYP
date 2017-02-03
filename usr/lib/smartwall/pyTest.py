import socket, sys
from struct import *
import subprocess as sub
import time
import re
import sqlite3 as sql
import os

#Defines refresh rate of the IP addresses to be monitored
refresh_rate = 5
interface_name = 'br-lan'

#establishes connection to a database creating it if it doesn't exist
conn = sql.connect('/tmp/tempHistory.db')
cur = conn.cursor()

tableName = 'connectionHistory'
global macList


def getTime():
    #Function that gets the system time in seconds
    return int(round(time.time()))
def setTime():
    global clock
    clock = getTime()

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

def checkTables ():
    #Function to check if tables exists to hold data
    cur.execute("CREATE TABLE IF NOT EXISTS connectionHistory (monitorMAC text, toIP text, connection text, port integer, length integer, PRIMARY KEY (monitorMAC, toIP, connection, port))")
    cur.execute("CREATE TABLE IF NOT EXISTS dnsLookups (toIP text PRIMARY KEY, hostname text)")
    cur.execute("CREATE TABLE IF NOT EXISTS dataRate (monitorMAC text, hour int, dataSize int, PRIMARY KEY (monitorMAC, hour))")

def enterDNS (ipAddr):

    #if ip address does not already exist in table do following
    nslookupProc = sub.Popen(('nslookup', ipAddr), stdout=sub.PIPE)
    results = nslookupProc.communicate()[0]
    #regular expression to pull hostname
    dnsRecord = re.findall( r'([^\s]+\.[a-z]+)', results)
    if dnsRecord != []:
        entry = dnsRecord[0]
        #print entry
        cur.execute("INSERT OR IGNORE INTO dnsLookups VALUES (?,?)", (ipAddr, entry))
    else:
        cur.execute("INSERT OR IGNORE INTO dnsLookups VALUES (?,?)", (ipAddr, ""))


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

    #print generatedList

#first generate macs from config file using method

macList = getMACs()

#generate our IPs to monitor and call checkTables to ensure our SQL table exists
checkTables()

#begin running the tcpdump subprocess piping output to stdout

#capture start time of the process and save to clock variable
setTime()
newList()

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
    		conn.commit()

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