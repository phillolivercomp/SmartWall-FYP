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

function index()

	page = entry({"admin", "smart_tab", "control_center"}, template("smartwall/control_center"), _("Control Center"), 2)
	page.i18n = "base"
	page.dependent = true

	page = entry({"admin", "smart_tab", "generate_results"}, call("send_data"), nil)
	page.leaf = true

end

function send_data()
	results = assert(send_data())

	if #results > 0 then 
		luci.http.prepare_content("application/json")
		luci.http.write_json(results)
		return
	end
end

function get_data()

	local mac = luci.http.formvalue("macValue")
	-- initialise variables
	local list = {}
	-- Create sql statement to be run
	local sql = string.format('SELECT * FROM dataRate WHERE monitorMAC = "%s" ORDER BY hour;', mac)
	-- Run statement
	local currResults = assert(db:execute(sql))
	-- Get first row of results
	local row = currResults:fetch({}, "a")
	-- Loop 50 times or until we dont get a results populating list
	while row do
		list[index] = row
		row = currResults:fetch({}, "a")
	end
	print(list)
	-- return list
	return list
end
