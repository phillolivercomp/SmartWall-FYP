module("luci.controller.smartwall.iptable_if", package.seeall)
-- Connect to config file
configFile = "/etc/config/cbi_file"
require "luci.sys.iptparser"
json = require ("luci.json")

function index()

	-- Creates address to get rules from iptables
	page = entry({"admin", "smart_tab", "get_rules"}, call("get_rules"), nil)
	page.leaf = true

	-- Creates address to create chain for iptable against mac address where default drop
	page = entry({"admin", "smart_tab", "init_chain"}, call("init_chain"), nil)
	page.leaf = true

	-- Creates address to create chain for iptable against mac address where default is accept
	page = entry({"admin", "smart_tab", "init_chain_acc"}, call("init_chain_acc"), nil)
	page.leaf = true

	-- Creates address to destroy chain for mac address
	page = entry({"admin", "smart_tab", "destruct_chain"}, call("destruct_chain"), nil)
	page.leaf = true

	-- Creates address to add rule to iptable
	page = entry({"admin", "smart_tab", "add_rule_allow"}, call("add_rule_allow"), nil)
	page.leaf = true

	-- Creates address to add rule to iptable
	page = entry({"admin", "smart_tab", "add_rule_drop"}, call("add_rule_drop"), nil)
	page.leaf = true

	-- Creates address to delete rule from iptable
	page = entry({"admin", "smart_tab", "delete_rule"}, call("delete_rule"), nil)
	page.leaf = true

end

-- Initialises chain and rules for mac address
function init_chain()
	-- Gets mac address from web UI
	local mac = luci.http.formvalue("mac")
	-- Create new chain named after mac
	os.execute("iptables -N " .. mac)
	
	-- Generate new report for the device
	local table = assert(report_generate(mac))

	-- Get IP address from report
	local ips = table[1].IPs
	-- Loop over IPs and execute command to insert new rule to allow the connection
	for _, j in pairs(ips) do
		os.execute("iptables -A " .. mac .. " -d " .. j .. " -j delegate_forward")
	end

	-- Create return value and set to true
	local pass = {}
	pass.complete = true
	-- Add final rule to iptable chain to reject any other traffic
	os.execute("iptables -A " .. mac .. " -j DROP")
	-- Add rule to forward table passing all new connections from FORWARD chain to mac chain is mac source is that mac and packet it new
	os.execute("iptables -I FORWARD 1 -m mac --mac-source " .. mac .. " -m state --state NEW -j " .. mac)
	-- Pass return value back to web UI
	luci.http.prepare_content("application/json")
	luci.http.write_json(pass)
end

function init_chain_acc()
	local mac = luci.http.formvalue("mac")
	os.execute("iptables -N " .. mac)

	os.execute("iptables -A " .. mac .. " -j delegate_forward")
	os.execute("iptables -I FORWARD 1 -m mac --mac-source " .. mac .. " -m state --state NEW -j " .. mac)

	local pass = {}
	pass.complete = true
	luci.http.prepare_content("application/json")
	luci.http.write_json(pass)
end

-- Generate report from mac address
function report_generate(mac)

	-- Generate path for report
	path = "/usr/lib/smartwall/reports/" .. mac

	-- Open report file from path
	local file = io.open(path, "r")
	-- Initiate content and JSON variables
	local content = ""
	local jsonObj = {}

	-- If file exists then continue
	if file then
		-- Read content string
		local contents = file:read("*a")
		-- Decode content into JSON object
		jsonObj[1] = json.decode(contents);
		--Return object
		return jsonObj
	end
	-- Else return nil
	return nil
end

-- Adds rule to mac address' iptable chain to allow
function add_rule_allow()
	-- Get mac address from web UI
	local mac = luci.http.formvalue("mac")
	-- Get IP from web UI
	local ip = luci.http.formvalue("ip")

	-- Executet command to add rule allowing IP address to mac address iptable chain
	os.execute("iptables -I " .. mac .. " -d " .. ip .. " -j delegate_forward -w")

	-- Create return value telling web UI it has completed
	local pass = {}
	pass.complete = true
	-- Return value
	luci.http.prepare_content("application/json")
	luci.http.write_json(pass)
end

--Adds rule to mac address's iptable chain to block
function add_rule_drop()
	-- Get mac address from web UI
	local mac = luci.http.formvalue("mac")
	-- Get IP from web UI
	local ip = luci.http.formvalue("ip")

	-- Executet command to add rule allowing IP address to mac address iptable chain
	os.execute("iptables -I " .. mac .. " -d " .. ip .. " -j DROP -w")

	-- Create return value telling web UI it has completed
	local pass = {}
	pass.complete = true
	-- Return value
	luci.http.prepare_content("application/json")
	luci.http.write_json(pass)
end

-- Delete rule from iptable
function delete_rule()
	-- Get mac address from web UI
	local mac = luci.http.formvalue("mac")
	-- Get index from web UI
	local index = luci.http.formvalue("index")

	-- Execute command to delete rule from iptable of mac address chain
	os.execute("iptables -D " .. mac .. " " .. index)

	-- Create return value to tell web UI it has completed
	local pass = {}
	pass.complete = true
	-- Return value
	luci.http.prepare_content("application/json")
	luci.http.write_json(pass)
end

-- Function to destroy iptable chain
function destruct_chain()
	-- Gets mac address from web UI
	local mac = luci.http.formvalue("mac")

	-- Initiate iptparser
	-- Set mode to IPv4
	local mode = 4
	-- Initiate parser
	local ipt = luci.sys.iptparser.IptParser(mode)
	-- Get rules from FORWARD chain of filter table
	local rules = ipt:find({table = "filter", chain = "FORWARD"})
	-- Create count variable
	local count = 1

	-- For each item in the rules table
	for _, item in pairs(rules) do
		-- If target is equal to mac address, delete that rule
		if item.target == mac then
			os.execute("iptables -D FORWARD " .. count)
		-- Else increade count variable by 1
		else
			count = count + 1
		end
	end
	-- Execute command to flush chain of rules
	os.execute("iptables -F " .. mac)
	-- Execute command to destroy chain
	os.execute("iptables -X " .. mac)

	-- Create return value and set to true
	local stat = {}
	stat.complete=true
	-- Return value to web UI
	luci.http.prepare_content("application/json")
	luci.http.write_json(stat)
	return
end

-- Get rules from mac address chain and send to web UI
function get_rules()
	-- Get mac address from web UI
	local mac = luci.http.formvalue("mac")
	-- Set mode to IPv4 mode
	local mode = 4
	-- Initiate IPTParser with mode
	local ipt = luci.sys.iptparser.IptParser(mode)
	-- Get chains from filter table
	local chains = ipt:chains("filter")

	-- For results in chains loop
	for _, t in pairs(chains) do
		-- if mac equals chain
		if mac == t then
			-- Get rules from chain an write to web UI
			local rules = ipt:find({table = "filter", chain = mac})
			luci.http.prepare_content("application/json")
			luci.http.write_json(rules)
			return
		end
	end

	-- Else, set return value to false
	local rules = {}
	rules.complete=false
	-- Return to web UI
	luci.http.prepare_content("application/json")
	luci.http.write_json(rules)
	return
end

-- Checks if mac address is in locked state
function is_locked()
	-- Get mac address from web UI
	local mac = luci.http.formvalue("mac")
	-- Initiate test variable
	local test = {}

	-- Set testComplete to result of in_forward
	test.complete = in_forward(mac)

	-- Return value to web UI
	luci.http.prepare_content("application/json")
	luci.http.write_json(test)
	return
end

-- In forward takes mac address and checks if its in locked state
function in_forward(mac)
	-- Set mode to IPv4
	local mode = 4
	-- Initiate IPTParser and set mode
	local ipt = luci.sys.iptparser.IptParser(mode)
	-- Get rules from Forward chain of filter table
	local rules = ipt:find({table = "filter", chain = "FORWARD"})

	-- Loop over rules
	for _, item in pairs(rules) do
		-- If target equals given mac then true
		if item.target == mac then
			return "true"
		end
	end
	-- Else return false
	return "false"
end