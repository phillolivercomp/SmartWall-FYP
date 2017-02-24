import socket, sys
from struct import *
import subprocess as sub
import time
import re
import sqlite3 as sql
import os
import json
import threading

###########################################
# Configuration
#
# Set details needed for methods
###########################################

refresh_rate = 5
changeRatio = 0.5

conn = sql.connect('/tmp/connections.db')
cur = conn.cursor()

rep = sql.connect('/tmp/reports.db')
repcur = rep.cursor()
global hour

def getHour():
    return int(time.strftime("%H"))
def setHour():
    global hour
    hour = getHour()

setHour()

def checkTables ():
    #Function to check if table exists to hold data
    repcur.execute("CREATE TABLE IF NOT EXISTS reports (ruleBroke text, value text, length int, datePlusTime datetime default current_timestamp);")

##########################################
# Report Gen
#
# Methods to generate report from data
##########################################

def getMACs ():
    #Scans through file looking for DeviceIP objects and trims the string accordinglu to get the IP address
    List = []
    for file in os.listdir("/usr/lib/smartwall/reports/active"):
    	List.append(file);
    return List

def generate_Report(mac):

	data = {}
	ipValues = ips_Used(mac)
	portValues = ports_Used(mac)
	data['IPs'] = ipValues[0]
	data['IPLen'] = ipValues[1]
	data['ports'] = portValues[0]
	data['portLen'] = portValues[1]
	data['dataIN'] = data_IN(mac)
	data['dataOUT'] = data_OUT(mac)
	data['max'] = max_data(mac)
	return data

def ips_Used(mac):
	cur.execute("SELECT toIP, SUM(length) FROM connectionHistory WHERE monitorMAC = ? AND toIP NOT LIKE '192.168.%' AND toIP NOT LIKE '10.%' AND toIP NOT LIKE '172.[0-9].%' AND toIP NOT LIKE '172.[1-2][0-9].%' AND toIP NOT LIKE '172.3[1-2].%' GROUP BY toIP ORDER BY SUM(length) DESC", (mac,))
	ipListSQL = cur.fetchall()
	
	ipList = []
	ipListLen = []
	for item in ipListSQL:
		ipList.append(item[0])
		ipListLen.append(item[1])
	return [ipList, ipListLen]

def ports_Used(mac):
	cur.execute("SELECT port, SUM(length) FROM connectionHistory WHERE monitorMAC = ? AND toIP NOT LIKE '192.168.%' AND toIP NOT LIKE '10.%' AND toIP NOT LIKE '172.[0-9].%' AND toIP NOT LIKE '172.[1-2][0-9].%' AND toIP NOT LIKE '172.3[1-2].%' GROUP BY port ORDER BY SUM(length) DESC", (mac,))
	portListSQL = cur.fetchall()

	portList = []
	portListLen = []
	for item in portListSQL:
		portList.append(item[0])
		portListLen.append(item[1])
	return [portList, portListLen]

def data_IN(mac):
	cur.execute("SELECT dataIN FROM dataRate WHERE monitorMAC = ? ORDER BY hour ASC", (mac,))
	results = cur.fetchall()
	if hour > 0:
		inBytes = results[hour][0] - results[hour-1][0]
	else:
		inBytes = results[hour][0] - results[23][0]
	print inBytes
	return inBytes

def data_OUT(mac):
	cur.execute("SELECT dataOUT FROM dataRate WHERE monitorMAC = ? ORDER BY hour ASC", (mac,))
	results = cur.fetchall()
	print results
	if hour > 0:
		outBytes = results[hour][0] - results[hour-1][0]
	else:
		outBytes = results[hour][0] - results[23][0]
	print outBytes
	return outBytes


def max_data(mac):
	cur.execute("SELECT dataSize FROM dataRate WHERE monitorMAC = ? ORDER BY hour ASC", (mac,))
	dataVals = cur.fetchall()
	
	maxData = 0
	dataVals.insert(24, dataVals[0])

	for x in range(1,24):
		testVal = dataVals[x][0] - dataVals[x-1][0]
		if testVal > maxData:
			maxData = testVal
	return maxData

####################################
# Comparison section
#
# Defines behaviour for comparing reports
####################################

def compare(old, new):
	ipCompare(old, new)
	portCompare(old, new)
	#if hour != getHour():
	dataUsage(old, new)
	setHour()

def ipCompare(old, new):
	if "IPs" in old:
		for item in new["IPs"]:
			if item not in old["IPs"]:
				pos = new["IPs"].index(item)
				data = new["IPLen"][pos]
				ruleBroke("IP", item, data)

def portCompare(old, new):
	if "ports" in old:
		for item in new["ports"]:
			if item not in old["ports"]:
				pos = new["ports"].index(item)
				data = new["portLen"][pos]
				ruleBroke("Port", item, data)

def dataUsage(old, new):
	if "dataIN" in old and "dataOUT" in old:
		oldRatio = float(old["dataOUT"][0]) / old["dataIN"][0]
		newRatio = float(new["dataOUT"]) / new["dataIN"]
		diffRatio = oldRatio/newRatio
		print diffRatio
		print oldRatio
		print newRatio
		if (diffRatio - 1.0) > changeRatio:
			ruleBroke("Unexpected behvaiour", "Too much data sent" , diffRatio)
		elif(diffRatio  - 1.0) < changeRatio:
			ruleBroke("Unexpected behvaiour", "Too much data received" , diffRatio)

def ruleBroke(rule, value, data):
	repcur.execute("UPDATE reports SET length = length + ? WHERE ruleBroke = ? AND value = ?", (data, rule, value))
	repcur.execute("INSERT OR IGNORE INTO reports (ruleBroke, value, length) VALUES (?,?,?)", (rule, value, data))

checkTables()

while True:

	macList = getMACs()
	for item in macList:
		curReport = generate_Report(item)
		file = open('/usr/lib/smartwall/reports/active/' + item).read()
		definedRep = json.loads(file)
		compare(definedRep, curReport)

	rep.commit()
	time.sleep(refresh_rate)
