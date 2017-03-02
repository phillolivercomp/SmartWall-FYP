import sqlite3 as sql
import json
import sys

conn = sql.connect('/tmp/connections.db')
cur = conn.cursor()

mac = str(sys.argv[1])
fileName = "/usr/lib/smartwall/reports/" + mac
activeFileName = "/usr/lib/smartwall/reports/active/" + mac

outfile = open(fileName, 'w')


def generate_Report(mac):

	data = {}
	ipValues = ips_Used(mac)
	privipValues = privips_used(mac)
	portValues = ports_Used(mac)
	privportValues = privports_used(mac)
	data['IPs'] = ipValues[0]
	data['IPLen'] = ipValues[1]
	data['ports'] = portValues[0]
	data['portLen'] = portValues[1]
	data['dataIN'] = data_IN(mac)
	data['dataOUT'] = data_OUT(mac)
	data['dataINmax'] = data_IN_max(mac)
	data['dataOUTmax'] = data_OUT_max(mac)
	data['max'] = max_data(mac)
	data['privIPs'] = privipValues[0]
	data['privIPsLen'] = privipValues[1]
	data['privPorts'] = privportValues[0]
	data['privPortsLen'] = privportValues[1]
	data['privdataIN'] = privdata_IN(mac)
	data['privdataOUT'] = privdata_OUT(mac)
	json.dump(data, outfile)
	outfile.close()

def generate_Report_Active(mac, command):
	data = {}
	activeOutFile = open(activeFileName, 'w')
	if "i" in command:
		ipValues = ips_Used(mac)
		data['IPs'] = ipValues[0]
		data['IPLen'] = ipValues[1]
	if "p" in command:
		portValues = ports_Used(mac)
		data['ports'] = portValues[0]
		data['portLen'] = portValues[1]
	if "d" in command:
		data['dataIN'] = data_IN(mac)
		data['dataOUT'] = data_OUT(mac)
	if "m" in command:
		data['max'] = max_data(mac)

	json.dump(data, activeOutFile)
	activeOutFile.close()

############################################
#Public IP section
#
#Section that gets data concerning public IPs
############################################
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
	cur.execute("SELECT SUM(length) FROM connectionHistory WHERE monitorMAC = ? AND connection = 'Inbound' AND toIP NOT LIKE '192.168.%' AND toIP NOT LIKE '10.%' AND toIP NOT LIKE '172.[0-9].%' AND toIP NOT LIKE '172.[1-2][0-9].%' AND toIP NOT LIKE '172.3[1-2].%' GROUP BY connection", (mac,))
	inBytes = cur.fetchone()
	return inBytes

def data_IN_max(mac):
	cur.execute("SELECT dataIN FROM dataRate WHERE monitorMAC = ? ORDER BY hour ASC", (mac,))
	dataVals = cur.fetchall()
	
	maxData = 0
	dataVals.insert(24, dataVals[0])

	for x in range(1,24):
		testVal = dataVals[x][0] - dataVals[x-1][0]
		if testVal > maxData:
			maxData = testVal
	return maxData

def data_OUT(mac):
					cur.execute("SELECT SUM(length) FROM connectionHistory WHERE monitorMAC = ? AND connection = 'Outbound' AND toIP NOT LIKE '192.168.%' AND toIP NOT LIKE '10.%' AND toIP NOT LIKE '172.[0-9].%' AND toIP NOT LIKE '172.[1-2][0-9].%' AND toIP NOT LIKE '172.3[1-2].%' GROUP BY connection", (mac,))
					outBytes = cur.fetchone()
					return outBytes

def data_OUT_max(mac):
	cur.execute("SELECT dataOUT FROM dataRate WHERE monitorMAC = ? ORDER BY hour ASC", (mac,))
	dataVals = cur.fetchall()
	
	maxData = 0
	dataVals.insert(24, dataVals[0]) 

	for x in range(1,24):
		testVal = dataVals[x][0] - dataVals[x-1][0]
		if testVal > maxData:
			maxData = testVal
	return maxData

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

#############################################
#Private IP section
#
#Methods for gathering data on private IPs
#############################################
def privips_used(mac):
	cur.execute("SELECT toIP, SUM(length) FROM connectionHistory WHERE monitorMAC = ? AND (toIP LIKE '192.168.%' OR toIP LIKE '10.%' OR toIP LIKE '172.[0-9].%' OR toIP LIKE '172.[1-2][0-9].%' OR toIP LIKE '172.3[1-2].%') GROUP BY toIP ORDER BY SUM(length) DESC", (mac,))
	ipListSQL = cur.fetchall()
	
	ipList = []
	ipListLen = []
	for item in ipListSQL:
		ipList.append(item[0])
		ipListLen.append(item[1])
	return [ipList, ipListLen]

def privports_used(mac):
	cur.execute("SELECT port, SUM(length) FROM connectionHistory WHERE monitorMAC = ? AND (toIP LIKE '192.168.%' OR toIP LIKE '10.%' OR toIP LIKE '172.[0-9].%' OR toIP LIKE '172.[1-2][0-9].%' OR toIP LIKE '172.3[1-2].%') GROUP BY port ORDER BY SUM(length) DESC", (mac,))
	portListSQL = cur.fetchall()

	portList = []
	portListLen = []
	for item in portListSQL:
		portList.append(item[0])
		portListLen.append(item[1])
	return [portList, portListLen]

def privdata_IN(mac):
	cur.execute("SELECT SUM(length) FROM connectionHistory WHERE monitorMAC = ? AND connection = 'Inbound' AND (toIP LIKE '192.168.%' OR toIP LIKE '10.%' OR toIP LIKE '172.[0-9].%' OR toIP LIKE '172.[1-2][0-9].%' OR toIP LIKE '172.3[1-2].%') GROUP BY connection", (mac,))
	inBytes = cur.fetchone()
	return inBytes

def privdata_OUT(mac):
	cur.execute("SELECT SUM(length) FROM connectionHistory WHERE monitorMAC = ? AND connection = 'Outbound' AND (toIP LIKE '192.168.%' OR toIP LIKE '10.%' OR toIP LIKE '172.[0-9].%' OR toIP LIKE '172.[1-2][0-9].%' OR toIP LIKE '172.3[1-2].%') GROUP BY connection", (mac,))
	outBytes = cur.fetchone()
	return outBytes

#############################################
#Run of report
#
#One run dependant on arguments given
#############################################

if len(sys.argv) < 3:
	generate_Report(mac)
else:
	generate_Report_Active(mac, sys.argv[2])