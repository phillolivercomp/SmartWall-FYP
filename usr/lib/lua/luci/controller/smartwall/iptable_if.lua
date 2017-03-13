module("luci.controller.smartwall.iptable_if", package.seeall)
-- Connect to config file
configFile = "/etc/config/cbi_file"
require "luci.sys.iptparser"
json = require ("luci.json")

function index()

	page = entry({"admin", "smart_tab", "get_rules"}, call("get_rules"), nil)
	page.leaf = true

	page = entry({"admin", "smart_tab", "init_chain"}, call("init_chain"), nil)
	page.leaf = true

	page = entry({"admin", "smart_tab", "destruct_chain"}, call("destruct_chain"), nil)
	page.leaf = true

end

function init_chain()
	local mac = luci.http.formvalue("mac")
	os.execute("iptables -N " .. mac)
	
	local table = assert(report_generate(mac))

	local ips = table[1].IPs
	for _, j in pairs(ips) do
		os.execute("iptables -A " .. mac .. " -d " .. j .. " -j delegate_forward")
	end

	local pass = {}
	pass.complete = true
	os.execute("iptables -A " .. mac .. " -j DROP")
	os.execute("iptables -I FORWARD 1 -m mac --mac-source " .. mac .. " -m state --state NEW -j " .. mac)
	luci.http.prepare_content("application/json")
	luci.http.write_json(pass)
end

function report_generate(mac)

	path = "/usr/lib/smartwall/reports/" .. mac

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

function destruct_chain()
	local mac = luci.http.formvalue("mac")

	local mode = 4
	local ipt = luci.sys.iptparser.IptParser(mode)
	local rules = ipt:find({table = "filter", chain = "FORWARD"})

	for _, item in pairs(rules) do
		print(item.target)
		if item.target == mac then
			os.execute("iptables -D FORWARD 1")
		end
	end
	os.execute("iptables -F " .. mac)
	os.execute("iptables -X " .. mac)

	local stat = {}
	stat.complete=true
	luci.http.prepare_content("application/json")
	luci.http.write_json(stat)
	return
end


function get_rules()
	local mac = luci.http.formvalue("mac")
	--local mac = "40:b4:cd:76:8b:2d"
	local mode = 4
	local ipt = luci.sys.iptparser.IptParser(mode)
	local chains = ipt:chains("filter")

	for _, t in pairs(chains) do
		if mac == t then
			local rules = ipt:find({table = "filter", chain = mac})
			luci.http.prepare_content("application/json")
			luci.http.write_json(rules)
			return
		end
	end

	local rules = {}
	rules.complete=false
	luci.http.prepare_content("application/json")
	luci.http.write_json(rules)
	return
end

function is_locked()
	local mac = luci.http.formvalue("mac")
	local test = {}

	test.complete = in_forward(mac)

	luci.http.prepare_content("application/json")
	luci.http.write_json(test)
	return
end

function in_forward(mac)

	local mode = 4
	local ipt = luci.sys.iptparser.IptParser(mode)
	local rules = ipt:find({table = "filter", chain = "FORWARD"})

	for _, item in pairs(rules) do
		if item.target == mac then
			return "true"
		end
	end
	return "false"
end


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
	return results
end