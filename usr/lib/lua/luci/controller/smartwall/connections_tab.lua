module("luci.controller.smartwall.connections_tab", package.seeall)
-- Sets up global parameters for use
-- SQLite package
luasql = require 'luasql.sqlite3'
-- Assigning name to library
sql = assert (luasql.sqlite3())
-- Establish connection to database
db = assert(sql:connect('/usr/lib/smartwall/tempHistory.db'))
-- Connect to config file
configFile = "/etc/config/cbi_file"	

-- function which is called when generating the tabs in the web UI
function index()

	-- Viewable tab for the webpage
	page = entry({"admin", "smart_tab", "connections_tab"}, template("smartwall/connections_select"), _("Connections"), 50)
	page.i18n = "base"
	page.dependent = true

	-- Creates address which can be accessed and will run the list_devices function
	page = entry({"admin", "smart_tab", "connections_select"}, call("list_devices"), nil)
	page.leaf = true

	-- Creates address which can be accessed and will run the list_connections function
	page = entry({"admin", "smart_tab", "connections_list"}, call("list_connections"), nil)
	page.leaf = true

end

-- Function that will return list of objects to web server being an SQL lookup
function list_connections()
	-- Gets value ip from webpage
	local mac = luci.http.formvalue("MAC")
	sqlResults = assert(get_results(mac))
	print(sqlResults)

	-- Will write out results to luci web server if there are any
	if #sqlResults > 0 then 
		luci.http.prepare_content("application/json")
		luci.http.write_json(sqlResults)
		return
	end
	return sqlResults
end

-- Function that is called with list_connections to create results objects
function get_results(mac)

	-- initialise variables
	local index, list = 0, {}
	-- Create sql statement to be run
	local sql = string.format('SELECT monitorMAC, toIP, SUM(length) AS length FROM connectionHistory WHERE monitorMAC = "%s" GROUP BY toIP ORDER BY length DESC', mac)
	-- Run statement
	local currResults = assert(db:execute(sql))
	-- Get first row of results
	local row = currResults:fetch({}, "a")
	-- Loop 50 times or until we dont get a results populating list
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

	local list, count, file = {}, 0, io.open(configFile, "r")

	-- Loop starts
	while true do
		local line = file:read("*line")
		if line == nil then
			-- break if end of file
			break

		elseif string.find(line, "config monitor") then
			-- if find config monitor we found a device
			count = count + 1
			deviceObject = {}
			
			while true do
				-- Another loop reads subsequent lines until it finds either an empty, end of file or the name or deviceIP
				local line = file:read("*line")
				if line == nul or line == "" then 
					break
				elseif string.find(line, "option name") then
					deviceObject.devName = string.sub(line, 15, string.len(line)-1)
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