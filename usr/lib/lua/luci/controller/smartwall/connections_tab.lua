module("luci.controller.smartwall.connections_tab", package.seeall)
-- Sets up global parameters for use
-- SQLite package
luasql = require 'luasql.sqlite3'
-- Assigning name to library
sql = assert (luasql.sqlite3())
-- Establish connection to database
db = assert(sql:connect('/tmp/connections.db'))
-- Connect to config file
configFile = "/etc/config/cbi_file"	

-- function which is called when generating the tabs in the web UI
function index()

	-- Viewable tab for the webpage
	page = entry({"admin", "smart_tab", "connections_tab"}, template("smartwall/connections_select"), _("Connections"), 3)
	page.i18n = "base"
	page.dependent = true

	-- Creates address which can be accessed and will run the list_devices function
	page = entry({"admin", "smart_tab", "connections_select"}, call("list_devices"), nil)
	page.leaf = true

	-- Creates address which can be accessed and will run the list_connections function
	page = entry({"admin", "smart_tab", "connections_list"}, call("list_connections"), nil)
	page.leaf = true

	-- Creates address to check tcpdump is running
	page = entry({"admin", "smart_tab", "check_tcpdump"}, call ("check_Execution"), nil)
	page.leaf = true

	-- Creates address to return breakdown of connections on device
	page = entry({"admin", "smart_tab", "connection_breakdown"}, call ("result_Breakdown"), nil)
	page.leaf = true

	-- Creates address allowing user to change DNS entry for an IP
	page = entry({"admin", "smart_tab", "rename_host"}, call ("rename_host"), nil)
	page.leaf = true

	-- Creates address to return traffic seen on other devices from an IP
	page = entry({"admin", "smart_tab", "get_other"}, call ("get_Other_Results"), nil)
	page.leaf = true

end

-- Function that will return list of objects to web server being an SQL lookup
function list_connections()
	-- Gets value ip from webpage
	local mac = luci.http.formvalue("MAC")
	-- Function call to get_results
	sqlResults = assert(get_results(mac))

	-- Will write out results to luci web server if there are any
	if #sqlResults > 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json(sqlResults)
		return
	end
	-- Ends function cal
	return sqlResults
end

-- Function that is called with list_connections to create results objects
function get_results(mac)

	-- initialise variables
	local index, list = 0, {}
	-- Create sql statement to be run
	local sql = string.format('SELECT ipTable.monitorMAC, ipTable.toIP, dnsTable.hostname, SUM(ipTable.length) AS length FROM connectionHistory ipTable, dnsLookups dnsTable WHERE monitorMAC = "%s" AND (dnsTable.toIP = ipTable.toIP)  GROUP BY ipTable.toIP ORDER BY length DESC;', mac)
	-- Run statement
	local currResults = assert(db:execute(sql))
	-- Get first row of results
	local row = currResults:fetch({}, "a")
	-- Loop until we dont get a results populating list
	while row do
		index = index + 1
		list[index] = row
		row = currResults:fetch({}, "a")
	end
	-- return list
	return list
end

-- helper to list_devices and will read config file to generate objects representing devices
function list_devices_helper()
	-- Creates variables needed for function including opening config file
	local list, count, file = {}, 0, io.open(configFile, "r")
	-- Loop starts
	while true do
		-- Reads line of file
		local line = file:read("*line")
		if line == nil then
			-- break if end of file
			break
		-- if line contains config monitor, we have found mac address entry
		elseif string.find(line, "config monitor") then
			-- if find config monitor we found a device
			count = count + 1
			deviceObject = {}
			
			while true do
				-- Another loop reads subsequent lines until it finds either an empty, end of file or the name or deviceIP
				local line = file:read("*line")
				-- If end of file, stop
				if line == nul or line == "" then 
					break
				-- if we find name of device, save in deviceObject
				elseif string.find(line, "option name") then
					deviceObject.devName = string.sub(line, 15, string.len(line)-1)
				-- if we find mac of object, save in deviceObject
				elseif string.find(line, "option mac") then
					deviceObject.devMAC = string.match(line, "%w+:%w+:%w+:%w+:%w+:%w+")	
				end
			end
			-- Save device to list
			list[count] = deviceObject
		end

	end
	return list
end

-- Returns list of devices to web UI
function list_devices()
	-- generates results with helper method
	results = assert(list_devices_helper())
	print(results)

	-- if results exist write to luci web server
	if #results > 0 then 
		luci.http.prepare_content("application/json")
		luci.http.write_json(results)
		return
	end

	return results
end

-- Function to check whether or not monitoring software is running
function check_Execution()
	-- check if tcpdump exists using subproccess
	local procFunction = io.popen("pgrep tcpdump")
	-- read result
	local result = procFunction:read("*a")
	-- close function
	procFunction:close()

	-- if it doesn't find number of process (pid) then return false
	container = {}
	if string.match(result, "[0-9]+") == nil then
		container.value = "False"
		container.contents = result
		luci.http.prepare_content("application/json")
		luci.http.write_json(container)
	-- else return true
	else
		container.value = "True"
		container.contents = result
		luci.http.prepare_content("application/json")
		luci.http.write_json(container)
	end
end

-- Generates results of ips connections to a mac address
function result_Breakdown()
	-- Getting data of IP and mac address from webpage
	local index, sqlResults = 0, {}
	-- Get ip from web UI
	local ip = luci.http.formvalue("ip")
	-- Get mac address from web UI
	local mac = luci.http.formvalue("mac")
	-- Generate SQL statement from mac and IP
	local sql = string.format('SELECT * FROM connectionHistory WHERE monitorMAC = "%s" AND toIP = "%s" ORDER BY port;', mac, ip)
	-- Execute statement and fect results
	local currResults = assert(db:execute(sql))

	-- Get first result
	local row = currResults:fetch({}, "a")
	-- Loop until we dont get a result, populating list
	while row do
		-- Save to index and fetch next row
		index = index + 1
		sqlResults[index] = row
		row = currResults:fetch({}, "a")
	end

	-- If we have more than 0 results, return to web UI
	if #sqlResults > 0 then 
		luci.http.prepare_content("application/json")
		luci.http.write_json(sqlResults)
		return
	end	
end

-- Function to rename DNS entry of IP address
function rename_host()
	-- Get IP address from web UI
	local ip = luci.http.formvalue("ip")
	-- Get new name from web  UI
	local name = luci.http.formvalue("newName")

	-- Access sqlCommands file and open in append mode
	local file = io.open("/tmp/sqlCommands", "a")
	-- Generate new sql command and place new line at the end.
	local sql = string.format('UPDATE dnsLookups SET hostname = "%s" WHERE toIP = "%s"\n;',name, ip)
	-- Write command to file and close it
	file:write(sql)
	file:close()

end

-- Gets details of an IPs connections to all monitored devices
function get_Other_Results()
	-- Get IP from web UI
	local ip = luci.http.formvalue("ip")
	-- Generate web UI 
	local sql = string.format('SELECT monitorMAC, SUM(length) AS len FROM connectionHistory WHERE toIP = "%s" GROUP BY monitorMAC', ip)

	-- Execute sql statement and save results to variable
	local currResults = assert(db:execute(sql))

	-- Initiate variables to use later
	local index, sqlResults = 0, {}
	local row = currResults:fetch({}, "a")
	-- Loop until we dont get a result, populating list
	while row do
		index = index + 1
		sqlResults[index] = row
		row = currResults:fetch({}, "a")
	end

	-- Return results if any exist
	if #sqlResults > 0 then 
		luci.http.prepare_content("application/json")
		luci.http.write_json(sqlResults)
		return
	end	
end