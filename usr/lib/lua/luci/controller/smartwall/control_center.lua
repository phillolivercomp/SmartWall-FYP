module("luci.controller.smartwall.control_center", package.seeall)
-- Sets up global parameters for use
-- SQLite package
luasql = require 'luasql.sqlite3'
-- Assigning name to library
sql = assert (luasql.sqlite3())
-- Establish connection to database
db = assert(sql:connect('/tmp/connections.db'))
repdb = assert(sql:connect('/tmp/reports.db'))
-- Connect to config file
configFile = "/etc/config/cbi_file"	
-- json module
json = require ("luci.json")

-- Function that creates web addresses necessary for interfacing web UI and system
function index()

	-- Creates address for loading web pageg and the htm file specified to be loaded
	page = entry({"admin", "smart_tab", "control_center"}, template("smartwall/control_center"), _("Control Center"), 2)
	page.i18n = "base"
	page.dependent = true

	-- Creates address for sending data about devices' history to web UI
	page = entry({"admin", "smart_tab", "generate_results"}, call("send_data"), nil)
	page.leaf = true

	-- Creates address for creating a report
	page = entry({"admin", "smart_tab", "report_call"}, call("report_call"), nil)
	page.leaf = true

	-- Creates address for obtaining current active report for a device
	page = entry({"admin", "smart_tab", "get_active"}, call("get_active"), nil)
	page.leaf = true

	-- Creates address to add a device to active monitoring
	page = entry({"admin", "smart_tab", "add_active"}, call("add_active"), nil)
	page.leaf = true

	-- Creates address to remove a device being actively monitored
	page = entry({"admin", "smart_tab", "remove_active"}, call("remove_active"), nil)
	page.leaf = true

	-- 
	page = entry({"admin", "smart_tab", "active_report_call"}, call("active_report_call"), nil)
	page.leaf = true

	page = entry({"admin", "smart_tab", "return_report_table"}, call("return_report_table"), nil)
	page.leaf = true

	page = entry({"admin", "smart_tab", "get_blocked"}, call("get_blocked"), nil)
	page.leaf = true

end

-- Sends data about devices' history to web UI
function send_data()
	-- Send data to web UI
	local mac = luci.http.formvalue("mac")
	results = assert(get_data(mac))

	if #results > 0 then 
		luci.http.prepare_content("application/json")
		luci.http.write_json(results)
		return
	end
end

-- Gets data of past connections of devices' connection history 
function get_data(mac)
	-- initialise variables
	local index, list = 0, {}
	-- Create sql statement to be run
	local sql = string.format('SELECT *, ROUND(dataSize/4294967296.0) AS bitNum FROM dataRate WHERE monitorMAC = "%s" ORDER BY hour;', mac)
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
	print(list)
	-- return list
	return list
end

-- Get report on device and pass back to web UI
function report_call()
	-- Get mac value from web UI
	local mac = luci.http.formvalue("mac")
	-- Call report_generate
	local results = assert(report_generate(mac))

	-- If results exist, send them to web UI
	if #results > 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json(results[1])
		return
	end
end

-- Creates report on a device taking in mac address
function report_generate(mac)

	-- set location of file to be made
	path = "/usr/lib/smartwall/reports/" .. mac
	-- sets command to generate a report
	command = "python /usr/lib/smartwall/reportGen.py " .. mac
	-- execute report
	os.execute(command)

	-- open file specified
	local file = io.open(path, "r")
	-- initiate our content string variable and JSON object to hold data
	local content = ""
	local jsonObj = {}

	-- If the file exists, read data and decode the data into the jsonObj variable
	if file then
		local contents = file:read("*a")
		jsonObj[1] = json.decode(contents);
		return jsonObj
	end
	return nil
end

-- Creates active report and tells web UI if successful
function active_report_call()
	-- Get mac address from web UI
	local mac = luci.http.formvalue("mac")
	-- get command arguments from web UI
	local command = luci.http.formvalue("command")
	-- Call active_report_generate
	local results = assert(active_report_generate(mac, command))

	-- return results to web UI
	if results then
		luci.http.prepare_content("application/json")
		luci.http.write_json(results)
		return
	end
end

-- Creates active report from arguments
function active_report_generate(mac, command)
	-- Set path of file to be generated
	path = "/usr/lib/smartwall/reports/active/" .. mac
	-- Set command given arguments to generate report
	command = "python /usr/lib/smartwall/reportGen.py " .. mac .. " " .. command
	-- Execute command
	os.execute(command)

	-- Open file
	local file = io.open(path, "r")
	-- If file exists return true
	if file then
		return true
	else-- otherwise return false
		return false
	end
end

-- Returns list of macs in the active report folder
function get_active()
	-- Execute list directory command on active report folder
	local f = io.popen("ls /usr/lib/smartwall/reports/active")
	-- Initiate variables for use
	local list, count = {}, 0

	-- if folder exists then continue
	if f then
	    while true do
	    	-- Read in linen
	    	local line = f:read("*line")
	    	-- If we have reached end of file or empty line then break
	    	if line == nul or line == "" then 
				break
			-- Otherwise continue loop
			else
				-- Increase count
				count = count +1
				-- Find mac using pattern
				local mac = string.match(line, "%w+:%w+:%w+:%w+:%w+:%w+")
				-- If the result isn't empty, save it to list
				if mac ~= "" then
					list[count] = mac
				end
			end
		end
	end
	-- If list is not empty, send it to web UI
	if #list > 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json(list)
		return
	end
end

function add_active()
	local mac = luci.http.formvalue("mac")
	local macFix = string.sub(mac, 1, 2) .. "\:" .. string.sub(mac, 4, 5) .. "\:" .. string.sub(mac, 7, 8) .. "\:" .. string.sub(mac, 10, 11) .. "\:" .. string.sub(mac, 13)
	local command = "mv /usr/lib/smartwall/reports/" .. macFix .. " /usr/lib/smartwall/reports/active"

	os.execute(command)
end

function remove_active()
	local mac = luci.http.formvalue("mac")
	local command = "rm /usr/lib/smartwall/reports/active/" .. mac

	os.execute(command)
end

-- Takes mac and gets reports from sql database against it
function return_report_table()
	-- Get mac from web UI
	local mac = luci.http.formvalue("mac")
	-- Create SQL command from mac address
	local sql = string.format('SELECT * FROM reports WHERE mac = "%s" ORDER BY datePlusTime DESC', mac)

	-- Execute command and save results
	local results = assert(repdb:execute(sql))
	-- Get first result and initiate variables.
	local row = results:fetch({}, "a")
	local list = {}
	local index = 0

	-- If row exists continue
	while row do
		-- Increase index, save row and get next row
		index = index + 1
		list[index] = row
		row = results:fetch({}, "a")
	end

	-- If list is not empty, return list
	if #list > 0 then 
		luci.http.prepare_content("application/json")
		luci.http.write_json(list)
		return
	end
end


function get_blocked()
	local path = "/tmp/iptablesTemp"
	local command = "iptables-save > " .. path
	os.execute(command)
	local file = io.open(path, "rb")
	local list = {}
	if file then
		local content = file:read("*all")
		list.macs = {string.match(content, ":(%w+:%w+:%w+:%w+:%w+:%w+)")}
		print(list.macs)
		luci.http.prepare_content("application/json")
		luci.http.write_json(list)
		return
	end
	return
end