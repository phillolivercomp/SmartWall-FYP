module("luci.controller.smartwall.control_center", package.seeall)
-- Sets up global parameters for use
-- SQLite package
luasql = require 'luasql.sqlite3'
-- Assigning name to library
sql = assert (luasql.sqlite3())
-- Establish connection to database
db = assert(sql:connect('/tmp/connections.db'))
-- Connect to config file
configFile = "/etc/config/cbi_file"	
-- json module
json = require ("luci.json")

function index()

	page = entry({"admin", "smart_tab", "control_center"}, template("smartwall/control_center"), _("Control Center"), 2)
	page.i18n = "base"
	page.dependent = true

	page = entry({"admin", "smart_tab", "generate_results"}, call("send_data"), nil)
	page.leaf = true

	page = entry({"admin", "smart_tab", "report_call"}, call("report_call"), nil)
	page.leaf = true

end

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

function get_data(mac)
	-- initialise variables
	local index, list = 0, {}
	-- Create sql statement to be run
	local sql = string.format('SELECT * FROM dataRate WHERE monitorMAC = "%s" ORDER BY hour;', mac)
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

function report_call()
	local mac = luci.http.formvalue("mac")
	local results = assert(report_generate(mac))
	print(results)

	if #results > 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json(results[1])
		return
	end
end

function report_generate(mac)

	path = "/usr/lib/smartwall/reports/" .. mac
	command = "python /usr/lib/smartwall/reportGen.py " .. mac
	os.execute(command)

	local file = io.open(path, "r")
	local content = ""
	local jsonObj = {}

	if file then
		local contents = file:read("*a")
		jsonObj[1] = json.decode(contents);
		return jsonObj
	end
	return nil
end