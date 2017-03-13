require "luci.sys.iptparser"
configFile = "/etc/config/cbi_file"	

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

local mode = 4
local ipt = luci.sys.iptparser.IptParser(mode)
local rules = ipt:find({table = "filter", chain = "FORWARD"})

for _, w in pairs(rules) do
	print(w.index)
	print(w.chain)
	print(w.target)
	list_devices()
end