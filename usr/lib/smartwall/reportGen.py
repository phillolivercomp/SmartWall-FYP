import sqlite3 as sql
import json
import sys

conn = sql.connect('/tmp/connections.db')
cur = conn.cursor()

mac = str(sys.argv[1])
fileName = "/usr/lib/smartwall/reports/" + mac

outfile = open(fileName, 'w')

def generate_Report(mac):

	data = {}
	data['IPs'] = ips_Used(mac)
	data['ports'] = ports_Used(mac)
	data['dataIN'] = data_IN(mac)
	data['dataOUT'] = data_OUT(mac)
	data['max'] = max_data(mac)
	json.dump(data, outfile)

def ips_Used(mac):
	cur.execute("SELECT toIP FROM connectionHistory WHERE monitorMAC = ? GROUP BY toIP ORDER BY SUM(length) DESC", (mac,))
	ipListSQL = cur.fetchall()
	
	ipList = []
	for item in ipListSQL:
		ipList.append(item[0])
	return ipList

def ports_Used(mac):
	cur.execute("SELECT port FROM connectionHistory WHERE monitorMAC = ? GROUP BY port ORDER BY SUM(length) DESC", (mac,))
	portListSQL = cur.fetchall()

	portList = []
	for item in portListSQL:
		portList.append(item[0])
	return portList

def data_IN(mac):
	cur.execute("SELECT SUM(length) FROM connectionHistory WHERE monitorMAC = ? AND connection = 'in' GROUP BY connection", (mac,))
	inBytes = cur.fetchone()[0]
	return inBytes

def data_OUT(mac):
	cur.execute("SELECT SUM(length) FROM connectionHistory WHERE monitorMAC = ? AND connection = 'out' GROUP BY connection", (mac,))
	outBytes = cur.fetchone()[0]
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

generate_Report(mac)